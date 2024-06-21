
from dataclasses import dataclass

import httpx

from ._interfaces import AccessTokenProvider, AccessTokenExchanger, KeycloakError


@dataclass(frozen=True)
class AuthenticationTransportSettings:

	retry_on_401: bool
	override_existing_auth_header: bool

	@classmethod
	def default(cls):
		return cls(
			retry_on_401=True,
			override_existing_auth_header=False
		)


class ClientAuthenticationTransport(httpx.BaseTransport):

	def __init__(
		self,
		transport: httpx.BaseTransport,
		token_provider: AccessTokenProvider,
		settings: AuthenticationTransportSettings=AuthenticationTransportSettings.default()
	):
		self.transport = transport
		self.token_provider = token_provider
		self.settings = settings

	def handle_request(self, request: httpx.Request) -> httpx.Response:

		if 'Authorization' in request.headers and not self.settings.override_existing_auth_header:
			return self.transport.handle_request(request)

		request.headers['Authorization'] = self.token_provider.get_token().to_bearer_string()

		response = self.transport.handle_request(request)

		if response.status_code != 401 or not self.settings.retry_on_401:
			return response

		request.headers['Authorization'] = self.token_provider.get_new_token().to_bearer_string()

		return self.transport.handle_request(request)


class TokenExchangeAuthenticationTransport(httpx.BaseTransport):

	def __init__(
		self,
		transport: httpx.BaseTransport,
		token_exchanger: AccessTokenExchanger,
		settings: AuthenticationTransportSettings=AuthenticationTransportSettings.default()
	):
		self.transport = transport
		self.token_exchanger = token_exchanger
		self.settings = settings

	def handle_request(self, request: httpx.Request) -> httpx.Response:

		auth_header: str = request.headers.get('Authorization')

		if not auth_header:
			raise KeycloakError('Missing Authorization header')

		subject_token = auth_header.removeprefix('Bearer ')

		request.headers['Authorization'] = self.token_exchanger.exchange_token(subject_token).to_bearer_string()

		response = self.transport.handle_request(request)

		if response.status_code != 401 or not self.settings.retry_on_401:
			return response

		request.headers['Authorization'] = self.token_exchanger.exchange_new_token(subject_token).to_bearer_string()

		return self.transport.handle_request(request)
