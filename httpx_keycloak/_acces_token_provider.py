
import datetime
from abc import ABC, abstractmethod
from typing import Optional

from ._keycloak_client import KeycloakClient
from ._interfaces import DatetimeProvider, AccessTokenProvider
from ._model import ClientCredentials, ResourceOwnerCredentials, KeycloakToken


class BaseClientAccessTokenProvider(ABC):

	def __init__(self, datetime_provider: DatetimeProvider):
		self.datetime_provider = datetime_provider
		self.token: KeycloakToken|None = None

	def get_token(self) -> KeycloakToken:
		if self.token and not self.token.has_expired(self.datetime_provider()):
			return self.token
		return self.get_new_token()

	@abstractmethod
	def get_new_token(self) -> KeycloakToken:
		...


class ClientCredentialsAccessTokenProvider(BaseClientAccessTokenProvider):

	def __init__(self, keycloak_client: KeycloakClient, credentials: ClientCredentials, datetime_provider: DatetimeProvider):
		super().__init__(datetime_provider)
		self.keycloak = keycloak_client
		self.credentials = credentials

	def get_new_token(self) -> KeycloakToken:
		self.token = self.keycloak.get_token_client_credentials(self.credentials)
		return self.token


class ResourceOwnerAccessTokenProvider(BaseClientAccessTokenProvider):

	def __init__(self, keycloak_client: KeycloakClient, credentials: ResourceOwnerCredentials, datetime_provider: DatetimeProvider):
		super().__init__(datetime_provider)
		self.keycloak = keycloak_client
		self.credentials = credentials

	def get_new_token(self) -> KeycloakToken:
		self.token = self.keycloak.get_token_resource_owner(self.credentials)
		return self.token


class AccessTokenExchanger:

	def __init__(self, keycloak_client: KeycloakClient, credentials: ClientCredentials, datetime_provider: DatetimeProvider):
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
		token = self.keycloak.exchange_token(self.credentials, subject_token)
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
		return ResourceOwnerAccessTokenProvider(
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
