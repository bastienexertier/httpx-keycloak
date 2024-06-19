
import httpx

from ._interfaces import AccessTokenProvider


class AuthenticationTransportWrapper(httpx.BaseTransport):

	def __init__(self, transport: httpx.BaseTransport, token_provider: AccessTokenProvider):
		self.transport = transport
		self.token_provider = token_provider

	def handle_request(self, request: httpx.Request) -> httpx.Response:

		if 'Authorization' in request.headers:
			return self.transport.handle_request(request)

		request.headers['Authorization'] = self.token_provider.get_access_token().to_bearer_string()

		response = self.transport.handle_request(request)

		if response.status_code == 401:
			request.headers['Authorization'] = self.token_provider.get_new_access_token().to_bearer_string()

		return self.transport.handle_request(request)
