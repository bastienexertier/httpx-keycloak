
import datetime
from typing import TypedDict, Optional

import httpx

from ._interfaces import DatetimeProvider, KeycloakError, TokenRequest
from ._token import KeycloakToken
from ._model import GrantType


class OpenIDConfiguration(TypedDict):
	issuer: str
	authorization_endpoint: str
	token_endpoint: str
	introspection_endpoint: str
	userinfo_endpoint: str
	end_session_endpoint: str
	token_endpoint_auth_methods_supported: list[str]
	grant_types_supported: list[str]


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

	def supports_grant(self, grant: GrantType) -> bool:
		return grant in self.openid_config['grant_types_supported']

	def get_token(self, credentials: TokenRequest) -> KeycloakToken:

		auth_methods_supported = self.openid_config['token_endpoint_auth_methods_supported']

		if 'client_secret_post' in auth_methods_supported:
			request_body = credentials.request_body()
			auth = None
		elif 'client_secret_basic' in auth_methods_supported:
			request_body = credentials.request_body(include_credentials=False)
			auth = credentials.to_basic_auth()
		else:
			raise KeycloakError('No token auth method supported')

		response = self.http.post(
			self.openid_config['token_endpoint'],
			data=request_body,
			auth=auth or httpx.USE_CLIENT_DEFAULT
		)

		data = response.json()

		if response.is_error:
			raise KeycloakError(f"[{response.status_code}] {data['error']} - {data['error_description']}")

		return KeycloakToken.from_dict(data, emitted_at=self.datetime_provider() - response.elapsed)
