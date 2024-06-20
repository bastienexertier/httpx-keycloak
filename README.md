# HTTPX-Keycloak

My implementation of an httpx.BaseTransport that negotiates an access token and puts it in the request headers.

# Installation

You can't install it yet :(

# Usage

The library only needs to be setup. Once it is done, the authentication will happen behind the usage of httpx.Client, meaning you don't need to change existing code.

## Client Credentials

```python
import httpx
from httpx_keycloak import (
	KeycloakClient,
	AccessTokenProviderFactory,
	ClientCredentialsAuthenticationTransport,
	ClientCredentials
)


api_client = httpx.Client(base_url='http://example')

# ============== ADD THIS ==============

access_token_providers = AccessTokenProviderFactory(
	KeycloakClient(httpx.Client(base_url='http://localhost:8080/realms/master'))
)

credentials = ClientCredentials(CLIENT_ID, CLIENT_SECRET, ('scope-1', 'scope-2'))

api_client._transport = ClientCredentialsAuthenticationTransport(
	api_client._transport,
	access_token_providers.client_credentials(credentials)
)

# ===== JUST THIS. NOW USE A USUAL =====

api_client.get('/users')

```

## Resource Owner

```python
import httpx
from httpx_keycloak import (
	KeycloakClient,
	AccessTokenProviderFactory,
	ClientCredentialsAuthenticationTransport,
	ClientCredentials
)


api_client = httpx.Client(base_url='http://example')

# ============== ADD THIS ==============

access_token_providers = AccessTokenProviderFactory(
	KeycloakClient(httpx.Client(base_url='http://localhost:8080/realms/master'))
)

credentials = ResourceOwnerCredentials(USERNAME, PASSWORD, CLIENT_ID, ('scope-1', 'scope-2')) # <<<

api_client._transport = ClientCredentialsAuthenticationTransport(
	api_client._transport,
	access_token_providers.resource_owner(credentials) # <<<
)

# ===== JUST THIS. NOW USE A USUAL =====

api_client.get('/users')

```

## Token Exchange

```python
import httpx
from httpx_keycloak import (
	KeycloakClient,
	AccessTokenProviderFactory,
	TokenExchangeAuthenticationTransport,
	ClientCredentials
)

api_client = httpx.Client(base_url='http://example')

# ============== ADD THIS ==============

access_token_providers = AccessTokenProviderFactory(
	KeycloakClient(httpx.Client(base_url='http://localhost:8080/realms/master'))
)

credentials = ClientCredentials(CLIENT_ID, CLIENT_SECRET, ('scope-1', 'scope-2'))

api_client._transport = TokenExchangeAuthenticationTransport( # <<<
	api_client._transport,
	access_token_providers.token_exchange(credentials) # <<<
)

# ===== JUST THIS. NOW USE A USUAL =====

# * Put the token to be exchanged in the authorization headers

api_client.get('/users', headers={'Authorization': 'token_to_be_exchanged'})

```
