
from typing import Optional
from dataclasses import dataclass

import httpx

from ._interfaces import AccessTokenProvider, AccessTokenExchanger, KeycloakError
from ._token import KeycloakToken


@dataclass(frozen=True)
class AuthenticationTransportSettings:

	retry_on_401: bool = True
	override_existing_auth_header: bool = True


class ClientAuthenticationTransport(httpx.BaseTransport):

	def __init__(
		self,
		transport: httpx.BaseTransport,
		token_provider: AccessTokenProvider,
		settings: Optional[AuthenticationTransportSettings]=None
	):
		self.transport = transport
		self.token_provider = token_provider
		self.settings = settings or AuthenticationTransportSettings()

	def handle_request(self, request: httpx.Request) -> httpx.Response:

		if 'Authorization' in request.headers and not self.settings.override_existing_auth_header:
			return self.transport.handle_request(request)

		response = None
		for token in self.token_provider.get_token():

			set_auth_header(request, token)

			response = self.transport.handle_request(request)

			if response.status_code != 401 or not self.settings.retry_on_401:
				return response

		if response:
			return response
		
		return self.transport.handle_request(request)


class TokenExchangeAuthenticationTransport(httpx.BaseTransport):

	def __init__(
		self,
		transport: httpx.BaseTransport,
		token_exchanger: AccessTokenExchanger,
		settings: Optional[AuthenticationTransportSettings]=None
	):
		self.transport = transport
		self.token_exchanger = token_exchanger
		self.settings = settings or AuthenticationTransportSettings()

	def handle_request(self, request: httpx.Request) -> httpx.Response:

		auth_header: str = request.headers.get('Authorization')

		if not auth_header:
			raise KeycloakError('Missing Authorization header')

		subject_token = auth_header.removeprefix('Bearer ')

		response = None
		for token in self.token_exchanger.exchange_token(subject_token):

			set_auth_header(request, token)

			response = self.transport.handle_request(request)

			if response.status_code != 401 or not self.settings.retry_on_401:
				return response

		if response:
			return response
		
		return self.transport.handle_request(request)


def set_auth_header(request: httpx.Request, token: KeycloakToken):
	request.headers['Authorization'] = token.to_bearer_string()
