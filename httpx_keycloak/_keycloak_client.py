
import datetime
from typing import TypedDict, Optional, Callable

import httpx

from ._interfaces import DatetimeProvider, KeycloakError, TokenRequest
from ._token import KeycloakToken
from ._model import GrantType


class OpenIDConfiguration(TypedDict):
	issuer: str
	authorization_endpoint: str
	token_endpoint: str
	introspection_endpoint: str
	userinfo_endpoint: str
	end_session_endpoint: str
	token_endpoint_auth_methods_supported: list[str]
	grant_types_supported: list[str]


class KeycloakClient:

	def __init__(self, http: httpx.Client, datetime_provider: Optional[DatetimeProvider]=None):
		self.http = http
		self.now = datetime_provider or datetime.datetime.now
		self.__openid_config: Optional[OpenIDConfiguration] = None

		self.__builders: dict[str, Callable[[TokenRequest, dict[str, str]], tuple[Optional[tuple[str, str]], dict[str, str]]]] = {
			'client_secret_basic': self.__build_client_secret_basic,
			'client_secret_post': self.__build_client_secret_post,
			'client_secret_jwt': self.__build_client_secret_jwt,
		}

	def supports_grant(self, grant: GrantType) -> bool:
		return grant in self.openid_config['grant_types_supported']

	def get_token(self, token_request: TokenRequest) -> KeycloakToken:
		"""
		Requests a new token from a TokenRequest.
		A TokenRequest is an object that can provide a Authentication header and request body.
		"""

		openid_config = self.openid_config

		auth_methods_supported = openid_config['token_endpoint_auth_methods_supported']

		if isinstance(token_request.auth_methods, tuple):
			auth_methods = token_request.auth_methods
		elif isinstance(token_request.auth_methods, str):
			auth_methods = (token_request.auth_methods,)
		else:
			auth_methods = ('client_secret_basic', 'client_secret_post')

		auth_method = next((
			self.__builders[method]
			for method in auth_methods
			if method in auth_methods_supported
			and method in self.__builders
		), None)

		if auth_method is None:
			raise KeycloakError(f'None of the requested auth method is supported: {str.join(", ", auth_methods)}')

		request_body: dict[str, str]
		request_body = {'grant_type': token_request.grant_type}
		request_body |= token_request.to_request_body()

		auth, request_body = auth_method(token_request, request_body)

		if token_request.scopes:
			request_body["scope"] = str.join(" ", token_request.scopes)

		response = self.http.post(
			openid_config['token_endpoint'],
			data=request_body,
			auth=auth or httpx.USE_CLIENT_DEFAULT
		)

		data = response.json()

		if response.is_error:
			raise KeycloakError(f"[{response.status_code}] {data['error']} - {data['error_description']}")

		return KeycloakToken.from_dict(data, emitted_at=self.now() - response.elapsed)


	def load_openid_config(self) -> OpenIDConfiguration:
		response = self.http.get('/.well-known/openid-configuration/')

		if response.status_code == 404:
			raise KeycloakError(f'OpenID configuration not found at {response.url}')

		return response.json()

	@property
	def openid_config(self) -> OpenIDConfiguration:
		if not self.__openid_config:
			self.__openid_config = self.load_openid_config()
		return self.__openid_config



	def __build_client_secret_basic(self, request: TokenRequest, data: dict[str, str]) -> tuple[Optional[tuple[str, str]], dict[str, str]]:
		return (request.client_id, request.client_secret or ''), data

	def __build_client_secret_post(self, request: TokenRequest, data: dict[str, str]) -> tuple[Optional[tuple[str, str]], dict[str, str]]:
		data['client_id'] = request.client_id
		if request.client_secret:
			data['client_secret'] = request.client_secret
		return None, data

	def __build_client_secret_jwt(self, request: TokenRequest, data: dict[str, str]) -> tuple[Optional[tuple[str, str]], dict[str, str]]:
		import uuid
		import jwt
		client_assertion = jwt.encode({
			"iss": request.client_id,
			"sub": request.client_id,
			"aud": self.openid_config['token_endpoint'],
			"jti": str(uuid.uuid4()),
			"exp": self.now().timestamp()+1000
		}, request.client_secret, algorithm="HS256")

		data['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
		data['client_assertion'] = client_assertion
		return None, data
