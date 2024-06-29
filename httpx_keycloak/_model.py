
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

	grant_type: GrantType = "client_credentials"

	def to_request_body(self) -> dict[str, str]:
		return {}

	def with_scopes(self, scopes: Scopes):
		""" Returns a copy of the credentials with the given scopes """
		return self.__class__(self.client_id, self.client_secret, scopes)

	def exchange(self, subject_token: str) -> TokenRequest:
		return TokenExchangeTokenRequest(subject_token, self.client_id, self.client_secret, self.scopes)

	def refresh(self, refresh_token: str) -> TokenRequest:
		return ClientCredentialsRefreshTokenRequest(refresh_token, self.client_id, self.client_secret, self.scopes)

@dataclass
class ResourceOwnerCredentials:

	username: str
	password: str

	client_id: str
	scopes: Scopes = Scopes()

	grant_type: GrantType = "password"

	@property
	def client_secret(self) -> Optional[str]:
		return None

	def to_request_body(self) -> dict[str, str]:
		return {
			"username": self.username,
			"password": self.password,
		}

	def with_scopes(self, scopes: Scopes):
		""" Returns a copy of the credentials with the given scopes """
		return self.__class__(self.username, self.password, self.client_id, scopes)

	def refresh(self, refresh_token: str) -> TokenRequest:
		return ResourceOwnerCredentialsRefreshTokenRequest(refresh_token, self.username, self.password, self.client_id, self.scopes)


Credentials = Union[ClientCredentials, ResourceOwnerCredentials]

@dataclass
class TokenExchangeTokenRequest:

	subject_token: str

	client_id: str
	client_secret: str
	scopes: Scopes = Scopes()

	grant_type: GrantType = "urn:ietf:params:oauth:grant-type:token-exchange"

	def to_request_body(self) -> dict[str, str]:
		return {
			"subject_token": self.subject_token,
			"subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
		}

@dataclass
class ClientCredentialsRefreshTokenRequest:

	refresh_token: str

	client_id: str
	client_secret: str
	scopes: Scopes = Scopes()

	grant_type: GrantType = "refresh_token"

	def to_request_body(self) -> dict[str, str]:
		return {
			"refresh_token": self.refresh_token
		}

@dataclass
class ResourceOwnerCredentialsRefreshTokenRequest:

	refresh_token: str

	username: str
	password: str

	client_id: str
	scopes: Scopes = Scopes()

	grant_type: GrantType = "refresh_token"

	@property
	def client_secret(self) -> Optional[str]:
		return None

	def to_request_body(self) -> dict[str, str]:
		return {
			"refresh_token": self.refresh_token
		}
