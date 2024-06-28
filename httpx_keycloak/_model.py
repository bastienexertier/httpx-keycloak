
from typing import Literal
from dataclasses import dataclass

import httpx

from ._interfaces import TokenRequest
from ._token import Scopes


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


@dataclass
class ClientCredentials:

	client_id: str
	client_secret: str
	scopes: Scopes = Scopes()

	def with_scopes(self, scopes: Scopes):
		""" Returns a copy of the credentials with the given scopes """
		return self.__class__(self.client_id, self.client_secret, scopes)

	def request(self) -> TokenRequest:
		return ClientCredentialsTokenRequest(self)

	def exchange(self, subject_token: str) -> TokenRequest:
		return TokenExchangeTokenRequest(self, subject_token)

@dataclass
class ResourceOwnerCredentials:

	username: str
	password: str

	client_id: str
	scopes: Scopes = Scopes()

	def with_scopes(self, scopes: Scopes):
		""" Returns a copy of the credentials with the given scopes """
		return self.__class__(self.username, self.password, self.client_id, scopes)

	def request(self) -> TokenRequest:
		return ResourceOwnerTokenRequest(self)

	def refresh(self, refresh_token: str) -> TokenRequest:
		return RefreshTokenRequest(self, refresh_token)



@dataclass
class ClientCredentialsTokenRequest:

	credentials: ClientCredentials
	grant_type: GrantType = "client_credentials"

	def to_basic_auth(self) -> httpx.BasicAuth:
		return httpx.BasicAuth(self.credentials.client_id, self.credentials.client_secret)

	def request_body(self, *, include_credentials:bool=True) -> dict[str, str]:

		data: dict[str, str] = {"grant_type": self.grant_type}

		if include_credentials:
			data["client_id"] = self.credentials.client_id
			data["client_secret"] = self.credentials.client_secret

		if self.credentials.scopes:
			data["scope"] = str.join(" ", self.credentials.scopes)

		return data

@dataclass
class ResourceOwnerTokenRequest:

	credentials: ResourceOwnerCredentials
	grant_type: GrantType = "password"

	def to_basic_auth(self) -> httpx.BasicAuth:
		return httpx.BasicAuth(self.credentials.client_id, "")

	def request_body(self, *, include_credentials:bool=True) -> dict[str, str]:

		data = {
				"username": self.credentials.username,
				"password": self.credentials.password,
				"grant_type": "password",
			}

		if include_credentials:
			data["client_id"] = self.credentials.client_id

		if self.credentials.scopes:
			data["scope"] = str.join(" ", self.credentials.scopes)

		return data

@dataclass
class TokenExchangeTokenRequest:

	credentials: ClientCredentials
	subject_token: str
	grant_type: GrantType = "urn:ietf:params:oauth:grant-type:token-exchange"

	def to_basic_auth(self) -> httpx.BasicAuth:
		return httpx.BasicAuth(self.credentials.client_id, self.credentials.client_secret)

	def request_body(self, *, include_credentials:bool=True) -> dict[str, str]:

		data: dict[str, str] = {
			"grant_type": self.grant_type,
			"subject_token": self.subject_token,
			"subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
		}

		if include_credentials:
			data["client_id"] = self.credentials.client_id
			data["client_secret"] = self.credentials.client_secret

		if self.credentials.scopes:
			data["scope"] = str.join(" ", self.credentials.scopes)

		return data

@dataclass
class RefreshTokenRequest:

	credentials: ResourceOwnerCredentials
	refresh_token: str
	grant_type: GrantType = "refresh_token"

	def to_basic_auth(self) -> httpx.BasicAuth:
		return httpx.BasicAuth(self.credentials.client_id, "")

	def request_body(self, *, include_credentials:bool=True) -> dict[str, str]:

		data: dict[str, str] = {
			"username": self.credentials.username,
			"password": self.credentials.password,
			"grant_type": self.grant_type,
			"refresh_token": self.refresh_token
		}

		if include_credentials:
			data["client_id"] = self.credentials.client_id

		return data
