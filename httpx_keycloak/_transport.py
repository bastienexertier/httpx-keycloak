
import httpx

from ._interfaces import AccessTokenProvider


class AuthenticationTransportWrapper(httpx.BaseTransport):

	def __init__(self, transport: httpx.BaseTransport, token_provider: AccessTokenProvider, retry_on_401: bool=True):
		self.transport = transport
		self.token_provider = token_provider
		self.retry_on_401 = retry_on_401

	def handle_request(self, request: httpx.Request) -> httpx.Response:

		if 'Authorization' not in request.headers:

			request.headers['Authorization'] = self.token_provider.get_access_token().to_bearer_string()

			response = self.transport.handle_request(request)

			if response.status_code == 401 and self.retry_on_401:
				request.headers['Authorization'] = self.token_provider.get_new_access_token().to_bearer_string()
			else:
				return response

		return self.transport.handle_request(request)
