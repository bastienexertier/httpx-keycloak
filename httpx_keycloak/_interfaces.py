
import datetime
from typing import Callable, Protocol

from ._model import KeycloakToken


class KeycloakError(Exception):
	...


DatetimeProvider = Callable[[], datetime.datetime]


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
