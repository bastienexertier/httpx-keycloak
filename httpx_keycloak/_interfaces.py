
import datetime
from typing import Callable, Protocol

import httpx

from ._token import KeycloakToken


class KeycloakError(Exception):
	...


DatetimeProvider = Callable[[], datetime.datetime]


class TokenRequest(Protocol):

	def request_body(self, *, with_credentials:bool=True) -> dict[str, str]:
		...

	def to_basic_auth(self) -> httpx.BasicAuth:
		...


class Credentials(Protocol):

	def request(self) -> TokenRequest:
		...

	def refresh(self, token: KeycloakToken) -> TokenRequest:
		...

	def exchange(self, subject_token: str) -> TokenRequest:
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
