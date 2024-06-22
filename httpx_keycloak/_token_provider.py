
import datetime
from typing import Optional

from cachelib.simple import SimpleCache

from ._keycloak_client import KeycloakClient
from ._interfaces import DatetimeProvider, AccessTokenProvider, Credentials
from ._model import ClientCredentials, ResourceOwnerCredentials, KeycloakToken



class ClientCredentialsAccessTokenProvider:

	token_cache = SimpleCache(threshold=100)

	def __init__(self, keycloak_client: KeycloakClient, credentials: Credentials, datetime_provider: DatetimeProvider):
		self.datetime_provider = datetime_provider
		self.keycloak = keycloak_client
		self.credentials = credentials

	def get_token(self) -> KeycloakToken:

		token = self.token_cache.get(self.credentials.key)

		if token and not self.token.has_expired(self.datetime_provider()):
			return token

		token = self.get_new_token()

		self.token_cache.add(self.credentials.key, token, timeout=token.expires_in.seconds)

		return token

	def get_new_token(self) -> KeycloakToken:
		self.token = self.keycloak.get_token(self.credentials)
		return self.token


class AccessTokenExchanger:

	def __init__(self, keycloak_client: KeycloakClient, credentials: Credentials, datetime_provider: DatetimeProvider):
		self.keycloak = keycloak_client
		self.credentials = credentials
		self.datetime_provider = datetime_provider

		self.tokens: dict[str, KeycloakToken] = {}

	def exchange_token(self, subject_token: str) -> KeycloakToken:
		token = self.tokens.get(subject_token)
		if token and not token.has_expired(self.datetime_provider()):
			return token
		return self.exchange_new_token(subject_token)

	def exchange_new_token(self, subject_token: str) -> KeycloakToken:
		token = self.keycloak.get_token(self.credentials, subject_token)
		self.tokens[subject_token] = token
		return token


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

	def resource_owner(self, credentials: ResourceOwnerCredentials) -> AccessTokenProvider:
		return ClientCredentialsAccessTokenProvider(
			self.keycloak,
			credentials,
			self.datetime_provider,
		)

	def token_exchange(self, credentials: ClientCredentials) -> AccessTokenExchanger:
		return AccessTokenExchanger(
			self.keycloak,
			credentials,
			self.datetime_provider,
		)
