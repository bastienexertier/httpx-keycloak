
import datetime
from typing import Union, Optional, Literal, Callable, Protocol, Iterator, runtime_checkable


from ._token import KeycloakToken, Scopes


GrantType = Literal[
	"authorization_code",
	"implicit",
	"refresh_token",
	"password",
	"client_credentials",
	"urn:openid:params:grant-type:ciba",
	"urn:ietf:params:oauth:grant-type:token-exchange",
	"urn:ietf:params:oauth:grant-type:device_code"
]

AuthMethod = Literal[
	"private_key_jwt",
	"client_secret_basic",
	"client_secret_post",
	"tls_client_auth",
	"client_secret_jwt"
]

AuthMethods = Union[AuthMethod, tuple[AuthMethod, ...]]


class KeycloakError(Exception):
	...


DatetimeProvider = Callable[[], datetime.datetime]



class TokenRequest(Protocol):

	auth_methods: AuthMethods

	@property
	def grant_type(self) -> GrantType:
		...

	@property
	def client_id(self) -> str:
		...

	@property
	def client_secret(self) -> Optional[str]:
		...

	@property
	def scopes(self) -> Scopes:
		...

	def to_request_body(self) -> dict[str, str]:
		...


@runtime_checkable
class SupportsExhange(TokenRequest, Protocol):

	def exchange(self, subject_token: str) -> TokenRequest:
		...

@runtime_checkable
class SupportsRefresh(TokenRequest, Protocol):

	def refresh(self, refresh_token: str) -> TokenRequest:
		...


class TokenProvider(Protocol):

	def get_token(self) -> Iterator[KeycloakToken]:
		...


class TokenExchanger(Protocol):

	def exchange_token(self, subject_token: str) -> Iterator[KeycloakToken]:
		...
