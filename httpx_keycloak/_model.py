
from typing import Optional, Union
from dataclasses import dataclass

from ._interfaces import TokenRequest, GrantType, AuthMethods
from ._token import Scopes


@dataclass
class ClientCredentials:

	client_id: str
	client_secret: str
	scopes: Scopes = Scopes()

	auth_methods: AuthMethods = ('client_secret_basic', 'client_secret_post')

	grant_type: GrantType = "client_credentials"

	def to_request_body(self) -> dict[str, str]:
		return {}

	def with_scopes(self, scopes: Scopes):
		""" Returns a copy of the credentials with the given scopes """
		return self.__class__(self.client_id, self.client_secret, scopes)

	def exchange(self, subject_token: str) -> TokenRequest:
		return TokenExchangeTokenRequest(self.auth_methods, subject_token, self.client_id, self.client_secret, self.scopes)

	def refresh(self, refresh_token: str) -> TokenRequest:
		return ClientCredentialsRefreshTokenRequest(self.auth_methods, refresh_token, self.client_id, self.client_secret, self.scopes)

@dataclass
class ResourceOwnerCredentials:

	username: str
	password: str

	client_id: str
	client_secret: Optional[str] = None
	scopes: Scopes = Scopes()

	auth_methods: AuthMethods = ('client_secret_basic', 'client_secret_post')

	grant_type: GrantType = "password"

	def to_request_body(self) -> dict[str, str]:
		return {
			"username": self.username,
			"password": self.password,
		}

	def with_scopes(self, scopes: Scopes):
		""" Returns a copy of the credentials with the given scopes """
		return self.__class__(self.username, self.password, self.client_id, self.client_secret, scopes)

	def refresh(self, refresh_token: str) -> TokenRequest:
		return ResourceOwnerCredentialsRefreshTokenRequest(
			self.auth_methods,
			refresh_token,
			self.username,
			self.password,
			self.client_id,
			self.client_secret,
			self.scopes
		)


Credentials = Union[ClientCredentials, ResourceOwnerCredentials]

@dataclass
class TokenExchangeTokenRequest:

	auth_methods: AuthMethods

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

	auth_methods: AuthMethods

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

	auth_methods: AuthMethods

	refresh_token: str

	username: str
	password: str

	client_id: str
	client_secret: Optional[str] = None
	scopes: Scopes = Scopes()

	grant_type: GrantType = "refresh_token"

	def to_request_body(self) -> dict[str, str]:
		return {
			"refresh_token": self.refresh_token
		}
