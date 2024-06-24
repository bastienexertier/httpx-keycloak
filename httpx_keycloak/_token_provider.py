
import datetime
from typing import Optional, Iterator

from cachelib.simple import SimpleCache

from ._keycloak_client import KeycloakClient
from ._interfaces import DatetimeProvider, AccessTokenProvider, Credentials, SupportsExhange, SupportsRefresh
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

	def get_token(self) -> Iterator[KeycloakToken]:

		key = cache_key(self.credentials)

		token = self.token_cache.get(key)

		if token:
			if not token.has_expired(self.datetime_provider()):
				yield token

			if (
				self.keycloak.supports_grant('refresh_token')
				and isinstance(self.credentials, SupportsRefresh)
				and token.refresh_token
				and not token.refresh_token_has_expired(self.datetime_provider())
			):
				token = self.keycloak.get_token(self.credentials.refresh(token.refresh_token))
				self.token_cache.set(key, token, timeout=token.expires_in.seconds)
				yield token

		token = self.keycloak.get_token(self.credentials.request())
		self.token_cache.set(key, token, timeout=token.expires_in.seconds)

		yield token


class AccessTokenExchanger:

	exchanged_token_cache = SimpleCache(threshold=100)

	def __init__(self, keycloak_client: KeycloakClient, credentials: SupportsExhange, datetime_provider: DatetimeProvider):
		self.keycloak = keycloak_client
		self.credentials = credentials
		self.datetime_provider = datetime_provider

	def exchange_token(self, subject_token: str) -> Iterator[KeycloakToken]:

		key = cache_key(self.credentials, subject_token)

		token = self.exchanged_token_cache.get(key)

		if token:
			if not token.has_expired(self.datetime_provider()):
				yield token

		token = self.keycloak.get_token(self.credentials.exchange(subject_token))
		self.exchanged_token_cache.set(key, token, timeout=token.expires_in.seconds)

		yield token



class AccessTokenProviderFactory:

	def __init__(self, keycloak_client: KeycloakClient, datetime_provider: Optional[DatetimeProvider]=None):
		self.keycloak = keycloak_client
		self.datetime_provider = datetime_provider or datetime.datetime.now

	def client_credentials(self, credentials: Credentials) -> AccessTokenProvider:
		return ClientCredentialsAccessTokenProvider(
			self.keycloak,
			credentials,
			self.datetime_provider,
		)

	def resource_owner(self, credentials: SupportsRefresh) -> AccessTokenProvider:
		return ClientCredentialsAccessTokenProvider(
			self.keycloak,
			credentials,
			self.datetime_provider,
		)

	def token_exchange(self, credentials: SupportsExhange) -> AccessTokenExchanger:
		return AccessTokenExchanger(
			self.keycloak,
			credentials,
			self.datetime_provider,
		)
