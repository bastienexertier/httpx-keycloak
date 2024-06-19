
import datetime
from typing import Optional

from ._keycloak_client import KeycloakClient
from ._interfaces import DatetimeProvider, AccessTokenProvider
from ._model import ClientCredentials, KeycloakToken


class ClientCredentialsAccessTokenProvider(AccessTokenProvider):

	def __init__(self, keycloak_client: KeycloakClient, credentials: ClientCredentials, datetime_provider: DatetimeProvider):
		self.keycloak = keycloak_client
		self.credentials = credentials
		self.datetime_provider = datetime_provider

		self.token: KeycloakToken|None = None


	def get_access_token(self) -> KeycloakToken:
		if self.token and not self.token.has_expired(self.datetime_provider()):
			return self.token
		return self.get_new_access_token()


	def get_new_access_token(self) -> KeycloakToken:
		self.token = self.keycloak.get_access_token_client_credentials(self.credentials)
		return self.token



class AccessTokenProviderFactory:

	def __init__(self, keycloak_client: KeycloakClient, datetime_provider: Optional[DatetimeProvider]=None):
		self.keycloak = keycloak_client
		self.datetime_provider = datetime_provider or datetime.datetime.now

	def client_credentials(self, credentials: ClientCredentials) -> AccessTokenProvider:
		return ClientCredentialsAccessTokenProvider(
			self.keycloak,
			credentials,
			self.datetime_provider,
		)
