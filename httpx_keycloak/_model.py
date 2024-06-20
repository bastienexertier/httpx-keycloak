
import datetime
from dataclasses import dataclass


Scopes = tuple[str, ...]


@dataclass(frozen=True)
class KeycloakToken:

	token_type: str
	access_token: str
	emitted_at: datetime.datetime
	expires_in: datetime.timedelta
	scopes: Scopes

	def has_expired(self, now: datetime.datetime) -> bool:
		""" Returns True if the token has expired at the given time. """
		print(self.emitted_at)
		print(self.emitted_at + self.expires_in)
		print(now)
		return self.emitted_at + self.expires_in <= now

	def to_bearer_string(self) -> str:
		""" Returns the string to put in the Authorization header. """
		return f'Bearer {self.access_token}'


@dataclass
class ClientCredentials:

	client_id: str
	client_secret: str
	scopes: Scopes = Scopes()

	def with_scopes(self, scopes: Scopes):
		""" Returns a copy of the credentials with the given scopes """
		return self.__class__(self.client_id, self.client_secret, scopes)
