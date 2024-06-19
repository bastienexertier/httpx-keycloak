
import datetime
from typing import Callable, Protocol

from ._model import KeycloakToken


DatetimeProvider = Callable[[], datetime.datetime]

class AccessTokenProvider(Protocol):

	def get_access_token(self) -> KeycloakToken:
		...

	def get_new_access_token(self) -> KeycloakToken:
		...
