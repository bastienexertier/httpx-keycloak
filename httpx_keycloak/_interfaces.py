
import datetime
from typing import Callable, Optional, Protocol

import httpx

from ._model import KeycloakToken


class KeycloakError(Exception):
	...


DatetimeProvider = Callable[[], datetime.datetime]


class Credentials(Protocol):

	def key(self, other: Optional[str]=None) -> str:
		...

	def request_body(self, *, with_credentials:bool=True) -> dict[str, str]:
		...

	def to_basic_auth(self) -> httpx.BasicAuth:
		...


class AccessTokenProvider(Protocol):

	def get_token(self) -> KeycloakToken:
		...

	def get_new_token(self) -> KeycloakToken:
		...


class AccessTokenExchanger(Protocol):

	def exchange_token(self, subject_token: str) -> KeycloakToken:
		...

	def exchange_new_token(self, subject_token: str) -> KeycloakToken:
		...
