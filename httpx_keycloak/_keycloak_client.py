
import datetime
from typing import TypedDict, Optional

import httpx

from ._interfaces import DatetimeProvider, KeycloakError
from ._model import ClientCredentials, Scopes, KeycloakToken


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
		self.open_id_configuration = self.__get_open_id_configuration()

	def __get_open_id_configuration(self) -> OpenIDConfiguration:
		response = self.http.get('/.well-known/openid-configuration/')

		if response.status_code == 404:
			raise KeycloakError(f'OpenID configuration not found at {response.url}')

		return response.json()

	def get_token_client_credentials(self, credentials: ClientCredentials) -> KeycloakToken:

		response = self.http.post(
			self.open_id_configuration['token_endpoint'],
			data={
				"client_id": credentials.client_id,
				"client_secret": credentials.client_secret,
				"grant_type": "client_credentials",
				"scope": str.join(' ', credentials.scopes)
			}
		)

		data = response.json()

		if response.is_error:
			raise KeycloakError(f"[{response.status_code}] {data['error']} - {data['error_description']}")

		return KeycloakToken(
			token_type=data['token_type'],
			access_token=data['access_token'],
			emitted_at=self.datetime_provider() - response.elapsed,
			expires_in=datetime.timedelta(seconds=data['expires_in']),
			scopes=Scopes(data['scope'].split(' '))
		)

	def exchange_token(self, credentials: ClientCredentials, access_token: str):

		response = self.http.post(
			self.open_id_configuration['token_endpoint'],
			data={
				"client_id": credentials.client_id,
				"client_secret": credentials.client_secret,
				"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
				"scope": str.join(' ', credentials.scopes),
				"subject_token": access_token,
				"subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
			}
		)

		data = response.json()

		if response.is_error:
			raise KeycloakError(f"[{response.status_code}] {data['error']} - {data['error_description']}")

		return KeycloakToken(
			token_type=data['token_type'],
			access_token=data['access_token'],
			emitted_at=self.datetime_provider() - response.elapsed,
			expires_in=datetime.timedelta(seconds=data['expires_in']),
			scopes=Scopes(data['scope'].split(' '))
		)
