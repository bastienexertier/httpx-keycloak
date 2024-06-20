
import datetime
from typing import TypedDict, Optional

import httpx

from ._interfaces import DatetimeProvider, KeycloakError
from ._model import ClientCredentials, ResourceOwnerCredentials, Scopes, KeycloakToken


class OpenIDConfiguration(TypedDict):
	issuer: str
	authorization_endpoint: str
	token_endpoint: str
	introspection_endpoint: str
	userinfo_endpoint: str
	end_session_endpoint: str


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


	def get_token_client_credentials(self, credentials: ClientCredentials) -> KeycloakToken:

		response = self.http.post(self.openid_config['token_endpoint'], data=credentials.request_body())

		data = response.json()

		if response.is_error:
			raise KeycloakError(f"[{response.status_code}] {data['error']} - {data['error_description']}")

		return KeycloakToken.from_dict(data, emitted_at=self.datetime_provider() - response.elapsed)


	def get_token_resource_owner(self, credentials: ResourceOwnerCredentials) -> KeycloakToken:

		response = self.http.post(self.openid_config['token_endpoint'], data=credentials.request_body())

		data = response.json()

		if response.is_error:
			raise KeycloakError(f"[{response.status_code}] {data['error']} - {data['error_description']}")

		return KeycloakToken.from_dict(data, emitted_at=self.datetime_provider() - response.elapsed)


	def exchange_token(self, credentials: ClientCredentials, access_token: str):

		response = self.http.post(
			self.openid_config['token_endpoint'],
			data=credentials.request_body() | {
				"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
				"subject_token": access_token,
				"subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
			}
		)

		data = response.json()

		if response.is_error:
			raise KeycloakError(f"[{response.status_code}] {data['error']} - {data['error_description']}")

		return KeycloakToken.from_dict(data, emitted_at=self.datetime_provider() - response.elapsed)
