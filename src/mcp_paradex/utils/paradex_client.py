"""
Paradex API client utilities.
"""

import asyncio
import ipaddress
import logging
import time
import urllib.request
from contextvars import ContextVar
from typing import Any, cast

import httpx
from paradex_py.account.account import ParadexAccount
from paradex_py.account.subkey_account import SubkeyAccount
from paradex_py.api.api_client import ParadexApiClient
from paradex_py.api.protocols import DefaultRetryStrategy

from mcp_paradex.utils.config import config
from mcp_paradex.utils.errors import ParadexApiError

logger = logging.getLogger(__name__)

# Singleton instance of the Paradex client
_paradex_client: ParadexApiClient | None = None
_client_lock = asyncio.Lock()

# Set by BearerAuthMiddleware for each HTTP request; None means no Bearer token present.
_request_bearer_token: ContextVar[str | None] = ContextVar("bearer_token", default=None)


def _proxy_mounts() -> dict[str, httpx.BaseTransport | None]:
    """The proxy mounts httpx builds from HTTP(S)_PROXY, ALL_PROXY and NO_PROXY with trust_env."""
    env = urllib.request.getproxies()
    no_proxy = [host.strip() for host in env.get("no", "").split(",") if host.strip()]
    if "*" in no_proxy:
        return {}
    mounts: dict[str, httpx.BaseTransport | None] = {}
    for scheme in ("http", "https", "all"):
        if url := env.get(scheme):
            proxy = url if "://" in url else f"http://{url}"
            mounts[f"{scheme}://"] = httpx.HTTPTransport(proxy=proxy, retries=1)
    for host in no_proxy:
        mounts[_no_proxy_pattern(host)] = None
    return mounts


def _no_proxy_pattern(host: str) -> str:
    if "://" in host:
        return host
    address = host.split("/")[0]
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return f"all://{host}" if host.lower() == "localhost" else f"all://*{host}"
    return f"all://[{host}]" if ip.version == 6 else f"all://{host}"


def _http_client() -> httpx.Client:
    """An httpx client whose connections retry once, so a stale pooled connection reconnects.

    A client given its own transport skips proxy env vars, so the proxies are mounted here.
    httpx still reads SSL_CERT_FILE and SSL_CERT_DIR for every transport.
    """
    return httpx.Client(
        transport=httpx.HTTPTransport(retries=1),
        mounts=_proxy_mounts(),
        timeout=httpx.Timeout(30.0),
    )


def _make_jwt_client(jwt: str) -> ParadexApiClient:
    """Create a Paradex client authenticated with a JWT token (no private key needed)."""
    client = ParadexApiClient(
        env=cast(Any, config.ENVIRONMENT),
        logger=logger,
        http_client=cast(Any, _http_client()),
        auto_auth=False,
        retry_strategy=DefaultRetryStrategy(),
        auth_params={"token_usage": "interactive"},
    )
    client.set_token(jwt)
    return client


def _signer_account(client: ParadexApiClient) -> ParadexAccount:
    try:
        from paradex_py.account.external_signer import ExternalSignerAccount, HeaderSigner
    except ImportError as e:
        raise ValueError(
            "Signer mode (PARADEX_SIGNER_HEADER) needs a paradex-py with ExternalSignerAccount"
        ) from e
    return ExternalSignerAccount(
        config=client.fetch_system_config(),
        l2_address=cast(str, config.PARADEX_ACCOUNT_ADDRESS),
        l2_public_key=cast(str, config.PARADEX_ACCOUNT_PUBLIC_KEY),
        signer=HeaderSigner(
            header=cast(str, config.PARADEX_SIGNER_HEADER),
            signature=cast(str, config.PARADEX_SIGNER_SIGNATURE),
        ),
    )


async def get_paradex_client() -> ParadexApiClient:
    """
    Get or initialize the Paradex client.

    Returns:
        Paradex: The initialized Paradex client.

    Raises:
        ValueError: If the required configuration is not set.
    """
    # Per-request Bearer token takes precedence over the singleton.
    bearer_token = _request_bearer_token.get()
    if bearer_token:
        return _make_jwt_client(bearer_token)

    global _paradex_client

    if _paradex_client is not None:
        return _paradex_client

    async with _client_lock:
        # Double-check in case another task initialized it while waiting
        if _paradex_client is not None:
            return _paradex_client

        if signer_error := config.signer_config_error():
            raise ValueError(signer_error)
        if config.PARADEX_SIGNER_HEADER and config.PARADEX_ACCOUNT_PRIVATE_KEY:
            logger.warning(
                "PARADEX_SIGNER_HEADER and PARADEX_ACCOUNT_PRIVATE_KEY are both set; "
                "using the signer and ignoring the private key"
            )

        logger.info("Initializing Paradex client env=%s", config.ENVIRONMENT)
        client = ParadexApiClient(
            env=cast(Any, config.ENVIRONMENT),
            logger=logger,
            http_client=cast(Any, _http_client()),
            retry_strategy=DefaultRetryStrategy(),
            auth_params={"token_usage": "interactive"},
        )
        logger.info("Paradex client api_url=%s", client.api_url)

        if config.PARADEX_SIGNER_HEADER:
            logger.info("Authenticating Paradex client via external signer")
            client.init_account(_signer_account(client))
            logger.info("Paradex client authenticated account=%s", client.account)
        elif config.PARADEX_ACCOUNT_PRIVATE_KEY:
            response = client.fetch_system_config()
            if config.PARADEX_ACCOUNT_ADDRESS:
                # Use SubkeyAccount for any L2 key + address pair.
                # Works for both main account keys and registered subkeys
                # (same pattern as the SDK's ParadexL2 high-level client).
                logger.info("Authenticating Paradex client via L2 key + address")
                acc: ParadexAccount = SubkeyAccount(
                    config=response,
                    l2_private_key=config.PARADEX_ACCOUNT_PRIVATE_KEY,
                    l2_address=config.PARADEX_ACCOUNT_ADDRESS,
                )
            else:
                logger.info("Authenticating Paradex client via private key")
                acc = ParadexAccount(
                    config=response,
                    l1_address="0x0000000000000000000000000000000000000000",
                    l2_private_key=config.PARADEX_ACCOUNT_PRIVATE_KEY,
                )
            client.init_account(acc)
            logger.info("Paradex client authenticated account=%s", client.account)
        elif config.PARADEX_JWT_TOKEN:
            logger.info("Authenticating Paradex client via JWT token")
            client.auto_auth = False  # no account to re-sign with
            client.set_token(config.PARADEX_JWT_TOKEN)

        _paradex_client = client
        return client


async def get_authenticated_paradex_client() -> ParadexApiClient:
    """
    Get or initialize the authenticated Paradex client.

    Returns:
        Paradex: The initialized Paradex client.

    Raises:
        ValueError: If the required configuration is not set.
    """
    # Per-request Bearer token always yields an authenticated client.
    bearer_token = _request_bearer_token.get()
    if bearer_token:
        return _make_jwt_client(bearer_token)

    client = await get_paradex_client()
    # For JWT-token singleton mode, set_token was called but account is None — that's OK.
    # We detect authentication by checking either account or the JWT token config.
    if client.account is None and not config.PARADEX_JWT_TOKEN:
        raise ValueError("Paradex client is not authenticated")
    return client


async def api_call(
    client: ParadexApiClient, path: str, params: dict[str, Any] | None = None
) -> dict[str, Any]:
    """
    Make a direct API call to Paradex.

    Args:
        client: The Paradex client instance.
        path: The API path to call.
        params: Optional parameters for the API call.

    Returns:
        Dict[str, Any]: The response from the API call.
    """
    from mcp_paradex.utils.telemetry import SpanKind, get_tracer

    url = f"{client.api_url}/{path}"
    tracer = get_tracer()
    with tracer.start_as_current_span(
        f"paradex.api {path}",
        kind=SpanKind.CLIENT,
        attributes={"http.url": url, "peer.service": "paradex-api"},
    ):
        logger.info("API call url=%s params=%s", url, params)
        t0 = time.monotonic()
        try:
            # Refresh token if needed before the call.  Skip for clients with no
            # credentials at all (public-only access: no account and no manual token).
            if client.account is not None or client._manual_token is not None:
                client._validate_auth()
            response = client.get(client.api_url, path, params)
            logger.info("API call url=%s completed ms=%.0f", url, (time.monotonic() - t0) * 1000)
            return response  # type: ignore[no-any-return]
        except ParadexApiError:
            raise
        except httpx.HTTPStatusError as exc:
            logger.error(
                "API call url=%s failed ms=%.0f status=%d error=%s",
                url,
                (time.monotonic() - t0) * 1000,
                exc.response.status_code,
                exc,
            )
            raise ParadexApiError(str(exc), path=path, status=exc.response.status_code) from exc
        except Exception as exc:
            logger.error(
                "API call url=%s failed ms=%.0f error=%s: %s",
                url,
                (time.monotonic() - t0) * 1000,
                type(exc).__name__,
                exc,
            )
            raise ParadexApiError(str(exc), path=path) from exc
