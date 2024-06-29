
from typing import Literal, Optional, Union
from dataclasses import dataclass

from ._interfaces import TokenRequest, GrantType
from ._token import Scopes



AuthMethod = Literal[
	"private_key_jwt",
	"client_secret_basic",
	"client_secret_post",
	"tls_client_auth",
	"client_secret_jwt"
]


@dataclass
class ClientCredentials:

	client_id: str
	client_secret: str
	scopes: Scopes = Scopes()

	def with_scopes(self, scopes: Scopes):
		""" Returns a copy of the credentials with the given scopes """
		return self.__class__(self.client_id, self.client_secret, scopes)

	def credentials_as_tuple(self) -> tuple[str, str]:
		return (self.client_id, self.client_secret)

	def credentials_as_dict(self) -> dict[str, str]:
		return {
			'client_id': self.client_id,
			'client_secret': self.client_secret,
		}

	def request(self) -> TokenRequest:
		return ClientCredentialsTokenRequest(self)

	def exchange(self, subject_token: str) -> TokenRequest:
		return TokenExchangeTokenRequest(self, subject_token)

	def refresh(self, refresh_token: str) -> TokenRequest:
		return ClientCredentialsRefreshTokenRequest(self, refresh_token)

@dataclass
class ResourceOwnerCredentials:

	username: str
	password: str

	client_id: str
	scopes: Scopes = Scopes()

	def with_scopes(self, scopes: Scopes):
		""" Returns a copy of the credentials with the given scopes """
		return self.__class__(self.username, self.password, self.client_id, scopes)

	def credentials_as_tuple(self) -> tuple[str, str]:
		return (self.client_id, '')

	def credentials_as_dict(self) -> dict[str, str]:
		return {
			'client_id': self.client_id,
		}

	def request(self) -> TokenRequest:
		return ResourceOwnerTokenRequest(self)

	def refresh(self, refresh_token: str) -> TokenRequest:
		return ResourceOwnerCredentialsRefreshTokenRequest(self, refresh_token)


Credentials = Union[ClientCredentials, ResourceOwnerCredentials]

from typing import Protocol

class TokenRequest(Protocol):

	@property
	def grant_type(self) -> GrantType:
		...

	def client_id(self) -> str:
		...

	def client_secret(self) -> Optional[str]:
		...

	def to_request_body(self) -> dict[str, str]:
		...



@dataclass
class ClientCredentialsTokenRequest:

	credentials: ClientCredentials
	grant_type: GrantType = "client_credentials"

	def client_id(self) -> str:
		return self.credentials.client_id

	def client_secret(self) -> Optional[str]:
		return self.credentials.client_secret

	def to_request_body(self) -> dict[str, str]:
		return {}

@dataclass
class ResourceOwnerTokenRequest:

	credentials: ResourceOwnerCredentials
	grant_type: GrantType = "password"

	def client_id(self) -> str:
		return self.credentials.client_id

	def client_secret(self) -> Optional[str]:
		return None

	def to_request_body(self) -> dict[str, str]:
		return {
			"username": self.credentials.username,
			"password": self.credentials.password,
		}

@dataclass
class TokenExchangeTokenRequest:

	credentials: ClientCredentials
	subject_token: str
	grant_type: GrantType = "urn:ietf:params:oauth:grant-type:token-exchange"

	def client_id(self) -> str:
		return self.credentials.client_id

	def client_secret(self) -> Optional[str]:
		return self.credentials.client_secret

	def to_request_body(self) -> dict[str, str]:
		return {
			"subject_token": self.subject_token,
			"subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
		}

@dataclass
class ClientCredentialsRefreshTokenRequest:

	credentials: ClientCredentials
	refresh_token: str
	grant_type: GrantType = "refresh_token"

	def client_id(self) -> str:
		return self.credentials.client_id

	def client_secret(self) -> Optional[str]:
		return self.credentials.client_secret

	def to_request_body(self) -> dict[str, str]:
		return {
			"refresh_token": self.refresh_token
		}

@dataclass
class ResourceOwnerCredentialsRefreshTokenRequest:

	credentials: ResourceOwnerCredentials
	refresh_token: str
	grant_type: GrantType = "refresh_token"

	def client_id(self) -> str:
		return self.credentials.client_id

	def client_secret(self) -> Optional[str]:
		return None

	def to_request_body(self) -> dict[str, str]:
		return {
			"refresh_token": self.refresh_token
		}
