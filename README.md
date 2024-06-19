# HTTPX-Keycloak

My implementation of an httpx.BaseTransport that negotiates an access token and puts it in the request headers.

# Installation

You can't install it yet :(

# Usage

The library only needs to be setup. Once it is done, the authentication will happen behind the usage of httpx.Client, meaning you don't need to change existing code.

```python
import datetime

import httpx
from httpx_keycloak import (
	KeycloakClient,
	AccessTokenProviderFactory,
	AuthenticationTransportWrapper,
	ClientCredentials
)


api_client = httpx.Client(base_url='http://example')

# ============== ADD THIS ==============

access_token_providers = AccessTokenProviderFactory(
	KeycloakClient(httpx.Client(base_url='http://localhost:8080/realms/master'))
)

credentials = ClientCredentials(CLIENT_ID, CLIENT_SECRET, ('scope-1', 'scope-2'))

api_client._transport = AuthenticationTransportWrapper(
	api_client._transport,
	access_token_providers.client_credentials(credentials)
)

# ===== JUST THIS, NOW USE A USUAL =====

api_client.get('/users')

```