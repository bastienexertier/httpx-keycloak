
import datetime
from typing import Callable, Protocol, Iterator, runtime_checkable

import httpx

from ._token import KeycloakToken


class KeycloakError(Exception):
	...


DatetimeProvider = Callable[[], datetime.datetime]


class TokenRequest(Protocol):

	def request_body(self, *, include_credentials:bool=True) -> dict[str, str]:
		...

	def to_basic_auth(self) -> httpx.BasicAuth:
		...



class Credentials(Protocol):

	def request(self) -> TokenRequest:
		...

@runtime_checkable
class SupportsExhange(Credentials, Protocol):

	def exchange(self, subject_token: str) -> TokenRequest:
		...

@runtime_checkable
class SupportsRefresh(Credentials, Protocol):

	def refresh(self, refresh_token: str) -> TokenRequest:
		...


class TokenProvider(Protocol):

	def get_token(self) -> Iterator[KeycloakToken]:
		...


class TokenExchanger(Protocol):

	def exchange_token(self, subject_token: str) -> Iterator[KeycloakToken]:
		...
