
from typing import Optional
from dataclasses import dataclass

from ._interfaces import Credentials, GrantType, AuthMethods
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

	def key(self) -> str:
		return f'{self.client_id}:{self.scopes}'

	def exchange(self, subject_token: str) -> Credentials:
		return TokenExchangeCredentials(
			subject_token=subject_token,
			client_id=self.client_id,
			client_secret=self.client_secret,
			scopes=self.scopes,
			auth_methods=self.auth_methods,
		)

	def refresh(self, refresh_token: str) -> Credentials:
		return ClientCredentialsRefreshCredentials(
			refresh_token=refresh_token,
			client_id=self.client_id,
			client_secret=self.client_secret,
			scopes=self.scopes,
			auth_methods=self.auth_methods,
		)

@dataclass
class ResourceOwnerCredentials:

	client_id: str
	client_secret: Optional[str] = None
	scopes: Scopes = Scopes()

	auth_methods: AuthMethods = DefaultAuthMethods

	def with_username_password(self, username: str, password: str):
		return ResourceOwnerCredentialsWithUser(
			username=username,
			password=password,
			client_id=self.client_id,
			client_secret=self.client_secret,
			scopes=self.scopes,
			auth_methods=self.auth_methods,
		)

@dataclass
class ResourceOwnerCredentialsWithUser:

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

	def key(self) -> str:
		return f'{self.client_id}:{self.username}:{self.scopes}'

	def refresh(self, refresh_token: str) -> Credentials:
		return ResourceOwnerCredentialsRefreshCredentials(
			refresh_token=refresh_token,
			username=self.username,
			password=self.password,
			client_id=self.client_id,
			client_secret=self.client_secret,
			scopes=self.scopes,
			auth_methods=self.auth_methods,
		)


@dataclass
class TokenExchangeCredentials:

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

	def key(self) -> str:
		return f'{self.client_id}:{self.subject_token}:{self.scopes}'

	def refresh(self, refresh_token: str) -> Credentials:
		return ClientCredentialsRefreshCredentials(
			refresh_token=refresh_token,
			client_id=self.client_id,
			client_secret=self.client_secret,
			scopes=self.scopes,
			auth_methods=self.auth_methods,
		)

@dataclass
class ClientCredentialsRefreshCredentials:

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

	def key(self) -> str:
		return f'{self.client_id}:{self.scopes}'

@dataclass
class ResourceOwnerCredentialsRefreshCredentials:

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

	def key(self) -> str:
		return f'{self.client_id}:{self.username}:{self.scopes}'
