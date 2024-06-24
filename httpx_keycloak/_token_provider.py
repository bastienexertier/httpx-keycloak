
import datetime
from typing import Optional

from cachelib.simple import SimpleCache

from ._keycloak_client import KeycloakClient
from ._interfaces import DatetimeProvider, AccessTokenProvider, Credentials
from ._model import ClientCredentials, ResourceOwnerCredentials
from ._token import KeycloakToken


def cache_key(credentials: Credentials, token: Optional[str]=None) -> str:

	if isinstance(credentials, ClientCredentials):
		key = f'{credentials.client_id};{credentials.scopes}'
	elif isinstance(credentials, ResourceOwnerCredentials):
		key = f'{credentials.client_id};{credentials.username};{credentials.scopes}'
	else:
		raise TypeError(f'Unkonwn credentials type {credentials.__class__}')

	if token is not None:
		key += f';{token}'

	return key


class ClientCredentialsAccessTokenProvider:

	token_cache = SimpleCache(threshold=100)

	def __init__(self, keycloak_client: KeycloakClient, credentials: Credentials, datetime_provider: DatetimeProvider):
		self.datetime_provider = datetime_provider
		self.keycloak = keycloak_client
		self.credentials = credentials

	def get_token(self) -> KeycloakToken:

		key = cache_key(self.credentials)

		token = self.token_cache.get(key)

		if token and not token.has_expired(self.datetime_provider()):
			return token

		token = self.get_new_token()

		self.token_cache.add(key, token, timeout=token.expires_in.seconds)

		return token

	def get_new_token(self) -> KeycloakToken:

		key = cache_key(self.credentials)

		token = self.keycloak.get_token(self.credentials.request())

		self.token_cache.add(key, token, timeout=token.expires_in.seconds)

		return token


class AccessTokenExchanger:

	exchanged_token_cache = SimpleCache(threshold=100)

	def __init__(self, keycloak_client: KeycloakClient, credentials: Credentials, datetime_provider: DatetimeProvider):
		self.keycloak = keycloak_client
		self.credentials = credentials
		self.datetime_provider = datetime_provider

	def exchange_token(self, subject_token: str) -> KeycloakToken:

		key = cache_key(self.credentials, subject_token)

		token = self.exchanged_token_cache.get(key)

		if token and not token.has_expired(self.datetime_provider()):
			return token

		token = self.exchange_new_token(subject_token)

		self.exchanged_token_cache.add(key, token, timeout=token.expires_in.seconds)

		return token

	def exchange_new_token(self, subject_token: str) -> KeycloakToken:

		key = cache_key(self.credentials, subject_token)

		token = self.keycloak.get_token(self.credentials.exchange(subject_token))

		self.exchanged_token_cache.add(key, token, timeout=token.expires_in.seconds)

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
