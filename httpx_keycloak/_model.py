
from typing import Optional
from dataclasses import dataclass

from ._interfaces import TokenRequest, GrantType, AuthMethods
from ._token import Scopes

DefaultAuthMethods: AuthMethods =  ('client_secret_basic', 'client_secret_post')

@dataclass
class ClientCredentials:

	client_id: str
	client_secret: str
	scopes: Scopes = Scopes()

	auth_methods: AuthMethods = DefaultAuthMethods

	@property
	def grant_type(self) -> GrantType:
		return "client_credentials"

	def to_request_body(self) -> dict[str, str]:
		return {}

	def with_scopes(self, scopes: Scopes):
		""" Returns a copy of the credentials with the given scopes """
		return self.__class__(
			client_id=self.client_id,
			client_secret=self.client_secret,
			scopes=scopes,
			auth_methods=self.auth_methods,
		)

	def exchange(self, subject_token: str) -> TokenRequest:
		return TokenExchangeTokenRequest(
			subject_token=subject_token,
			client_id=self.client_id,
			client_secret=self.client_secret,
			scopes=self.scopes,
			auth_methods=self.auth_methods,
		)

	def refresh(self, refresh_token: str) -> TokenRequest:
		return ClientCredentialsRefreshTokenRequest(
			refresh_token=refresh_token,
			client_id=self.client_id,
			client_secret=self.client_secret,
			scopes=self.scopes,
			auth_methods=self.auth_methods,
		)

@dataclass
class ResourceOwnerCredentials:

	username: str
	password: str

	client_id: str
	client_secret: Optional[str] = None
	scopes: Scopes = Scopes()

	auth_methods: AuthMethods = DefaultAuthMethods

	@property
	def grant_type(self) -> GrantType:
		return "password"

	def to_request_body(self) -> dict[str, str]:
		return {
			"username": self.username,
			"password": self.password,
		}

	def with_scopes(self, scopes: Scopes):
		""" Returns a copy of the credentials with the given scopes """
		return self.__class__(
			username=self.username,
			password=self.password,
			client_id=self.client_id,
			client_secret=self.client_secret,
			scopes=scopes,
			auth_methods=self.auth_methods
		)

	def refresh(self, refresh_token: str) -> TokenRequest:
		return ResourceOwnerCredentialsRefreshTokenRequest(
			refresh_token=refresh_token,
			username=self.username,
			password=self.password,
			client_id=self.client_id,
			client_secret=self.client_secret,
			scopes=self.scopes,
			auth_methods=self.auth_methods,
		)


@dataclass
class TokenExchangeTokenRequest:

	subject_token: str

	client_id: str
	client_secret: str
	scopes: Scopes = Scopes()

	auth_methods: AuthMethods = DefaultAuthMethods

	@property
	def grant_type(self) -> GrantType:
		return "urn:ietf:params:oauth:grant-type:token-exchange"

	def to_request_body(self) -> dict[str, str]:
		return {
			"subject_token": self.subject_token,
			"subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
		}

	def refresh(self, refresh_token: str) -> TokenRequest:
		return ClientCredentialsRefreshTokenRequest(
			refresh_token=refresh_token,
			client_id=self.client_id,
			client_secret=self.client_secret,
			scopes=self.scopes,
			auth_methods=self.auth_methods,
		)

@dataclass
class ClientCredentialsRefreshTokenRequest:

	refresh_token: str

	client_id: str
	client_secret: str
	scopes: Scopes = Scopes()

	auth_methods: AuthMethods = DefaultAuthMethods

	@property
	def grant_type(self) -> GrantType:
		return "refresh_token"

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
	client_secret: Optional[str] = None
	scopes: Scopes = Scopes()

	auth_methods: AuthMethods = DefaultAuthMethods

	@property
	def grant_type(self) -> GrantType:
		return "refresh_token"

	def to_request_body(self) -> dict[str, str]:
		return {
			"refresh_token": self.refresh_token
		}
