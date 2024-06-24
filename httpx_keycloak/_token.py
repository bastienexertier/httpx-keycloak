
import datetime
from typing import Optional
from dataclasses import dataclass

Scopes = tuple[str, ...]

@dataclass(frozen=True)
class KeycloakToken:

	token_type: str
	emitted_at: datetime.datetime

	access_token: str
	expires_in: datetime.timedelta

	refresh_token: Optional[str]
	refresh_token_expires_in: datetime.timedelta

	scopes: Scopes

	def has_expired(self, now: datetime.datetime) -> bool:
		""" Returns True if the token has expired at the given time. """
		return self.emitted_at + self.expires_in <= now

	def to_bearer_string(self) -> str:
		""" Returns the string to put in the Authorization header. """
		return f'Bearer {self.access_token}'

	@classmethod
	def from_dict(cls, data: dict[str, str], *, emitted_at: datetime.datetime):
		return cls(
			token_type=data['token_type'],
			emitted_at=emitted_at,
			access_token=data['access_token'],
			expires_in=datetime.timedelta(seconds=int(data['expires_in'])),
			refresh_token=data.get('refresh_token'),
			refresh_token_expires_in=datetime.timedelta(seconds=int(data.get('refresh_token_expires_in', 0))),
			scopes=Scopes(data['scope'].split(' '))
		)
