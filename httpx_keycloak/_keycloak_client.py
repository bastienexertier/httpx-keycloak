
import datetime
from typing import TypedDict, Optional

import httpx

from ._interfaces import DatetimeProvider, KeycloakError, Credentials
from ._model import KeycloakToken


class OpenIDConfiguration(TypedDict):
	issuer: str
	authorization_endpoint: str
	token_endpoint: str
	introspection_endpoint: str
	userinfo_endpoint: str
	end_session_endpoint: str
	token_endpoint_auth_methods_supported: list[str]


class KeycloakClient:

	def __init__(self, http: httpx.Client, datetime_provider: Optional[DatetimeProvider]=None):
		self.http = http
		self.datetime_provider = datetime_provider or datetime.datetime.now
		self.openid_config = self.__get_openid_config()


	def __get_openid_config(self) -> OpenIDConfiguration:
		response = self.http.get('/.well-known/openid-configuration/')

		if response.status_code == 404:
			raise KeycloakError(f'OpenID configuration not found at {response.url}')

		return response.json()


	def get_token(self, credentials: Credentials, access_token: Optional[str]=None) -> KeycloakToken:

		auth_methods_supported = self.openid_config['token_endpoint_auth_methods_supported']

		if 'client_secret_post' in auth_methods_supported:
			request_body = credentials.request_body()
			auth = None
		elif 'client_secret_basic' in auth_methods_supported:
			request_body = credentials.request_body(with_credentials=False)
			auth = credentials.to_basic_auth()
		else:
			raise KeycloakError('No token auth method supported')

		if access_token is not None:
			request_body |= {
				"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
				"subject_token": access_token,
				"subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
			}

		if auth:
			response = self.http.post(self.openid_config['token_endpoint'], data=request_body, auth=auth)
		else:
			response = self.http.post(self.openid_config['token_endpoint'], data=request_body)

		data = response.json()

		if response.is_error:
			raise KeycloakError(f"[{response.status_code}] {data['error']} - {data['error_description']}")

		return KeycloakToken.from_dict(data, emitted_at=self.datetime_provider() - response.elapsed)
