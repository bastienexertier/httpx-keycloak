
import datetime
from typing import Optional, cast
from dataclasses import dataclass

import httpx

from ._interfaces import Credentials, SupportsExhange, KeycloakError, DatetimeProvider
from ._keycloak_client import KeycloakClient
from ._model import ClientCredentials, ResourceOwnerCredentials
from ._token import KeycloakToken
from ._token_provider import TokenProvider


@dataclass(frozen=True)
class AuthenticationTransportSettings:

	retry_on_401: bool = True
	override_existing_auth_header: bool = True


class AuthenticatingTransport(httpx.BaseTransport):

	def __init__(
		self,
		transport: httpx.BaseTransport,
		credentials: Credentials,
		token_provider: TokenProvider,
		settings: Optional[AuthenticationTransportSettings]=None
	):
		self.transport = transport
		self.credentials = credentials
		self.token_provider = token_provider
		self.settings = settings or AuthenticationTransportSettings()

	def build_credentials(self, request: httpx.Request) -> Optional[Credentials]:
		if 'Authorization' in request.headers and not self.settings.override_existing_auth_header:
			return None
		return self.credentials

	def handle_request(self, request: httpx.Request) -> httpx.Response:

		credentials = self.build_credentials(request)

		response = None
		if credentials:

			for token in self.token_provider.get_token(credentials):

				set_auth_header(request, token)

				response = self.transport.handle_request(request)

				if response.status_code != 401 or not self.settings.retry_on_401:
					return response

		return response or self.transport.handle_request(request)


class TokenExchangeAuthenticationTransport(AuthenticatingTransport):

	def build_credentials(self, request: httpx.Request) -> Optional[Credentials]:

		auth_header: str = request.headers.get('Authorization')

		if not auth_header:
			raise KeycloakError('Token to be exchanged not found in Authorization header')

		return cast(SupportsExhange, self.credentials).exchange(auth_header.removeprefix('Bearer '))


def set_auth_header(request: httpx.Request, token: KeycloakToken):
	request.headers['Authorization'] = token.to_bearer_string()



class AuthenticatingTransportFactory:

	def __init__(self, keycloak_client: KeycloakClient, datetime_provider: Optional[DatetimeProvider]=None):
		self.keycloak = keycloak_client
		self.now = datetime_provider or datetime.datetime.now

	def client_credentials_transport(self, transport: httpx.BaseTransport, credentials: ClientCredentials) -> httpx.BaseTransport:
		return AuthenticatingTransport(transport, credentials, TokenProvider(
			self.keycloak,
			self.now,
		))

	def resource_owner_transport(self, transport: httpx.BaseTransport, credentials: ResourceOwnerCredentials) -> httpx.BaseTransport:
		return AuthenticatingTransport(transport, credentials, TokenProvider(
			self.keycloak,
			self.now,
		))

	def token_exchange_transport(self, transport: httpx.BaseTransport, credentials: SupportsExhange) -> httpx.BaseTransport:
		return TokenExchangeAuthenticationTransport(transport, credentials, TokenProvider(
			self.keycloak,
			self.now,
		))
