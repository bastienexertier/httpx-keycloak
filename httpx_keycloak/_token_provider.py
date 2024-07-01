
import datetime
from typing import Iterator, Optional

from cachelib.simple import SimpleCache

from ._keycloak_client import KeycloakClient
from ._interfaces import DatetimeProvider, SupportsRefresh
from ._model import Credentials
from ._token import KeycloakToken


class TokenProvider:

	token_cache = SimpleCache(threshold=100)

	def __init__(self, keycloak_client: KeycloakClient, datetime_provider: Optional[DatetimeProvider]=None):
		self.keycloak = keycloak_client
		self.now = datetime_provider or datetime.datetime.now

	def get_token(self, credentials: Credentials) -> Iterator[KeycloakToken]:

		key = credentials.key()

		token = self.token_cache.get(key)

		if token:
			if not token.has_expired(self.now()):
				yield token

			if (
				self.keycloak.supports_grant('refresh_token')
				and isinstance(credentials, SupportsRefresh)
				and token.refresh_token
				and not token.refresh_token_has_expired(self.now())
			):
				token = self.keycloak.get_token(credentials.refresh(token.refresh_token))

				self.token_cache.set(key, token, timeout=token.expiration(self.now()))
				yield token

		token = self.keycloak.get_token(credentials)

		self.token_cache.set(key, token, timeout=token.expiration(self.now()))
		yield token
		self.token_cache.delete(key)
