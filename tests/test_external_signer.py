"""The external-signer mode: no private key in the server, a signing proxy holds it."""

import logging
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import httpx
import pytest
from mcp.server.fastmcp.exceptions import ToolError
from paradex_py.account.account import ParadexAccount

import mcp_paradex.utils.paradex_client as client_module
from mcp_paradex.server.server import server

config = client_module.config

try:
    from paradex_py.account.external_signer import ExternalSignerAccount, HeaderSigner
except ImportError:
    ExternalSignerAccount = HeaderSigner = None

needs_external_signer = pytest.mark.skipif(
    ExternalSignerAccount is None, reason="paradex-py has no ExternalSignerAccount"
)

SIGNER_ENV = {
    "PARADEX_SIGNER_HEADER": "X-Signer-Header",
    "PARADEX_SIGNER_SIGNATURE": "stand-in",
    "PARADEX_ACCOUNT_ADDRESS": "0x129c135ed63df9353885e292be4426b8ed6122b13c6c0e1bb787288a1f5adfa",
    "PARADEX_ACCOUNT_PUBLIC_KEY": "0x2c144d2f2d4fc61b6f8967f3ba0012a87d90140bcfe5a3e92e8df83258c960f",
    "PARADEX_ACCOUNT_PRIVATE_KEY": None,
    "PARADEX_JWT_TOKEN": None,
    "PARADEX_API_KEY": None,
    "PARADEX_AUTH_SERVER_URL": None,
}

PROXY_ENV = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")


def _set_config(monkeypatch, **overrides):
    for key, value in {**SIGNER_ENV, **overrides}.items():
        monkeypatch.setattr(config, key, value)


@pytest.fixture
def fake_api_client(monkeypatch):
    monkeypatch.setattr(client_module, "_paradex_client", None)
    api = MagicMock()
    api.fetch_system_config.return_value = SimpleNamespace(
        starknet_chain_id="PRIVATE_SN_PARACLEAR_MAINNET"
    )
    with patch.object(client_module, "ParadexApiClient", return_value=api):
        yield api


@needs_external_signer
@pytest.mark.asyncio
async def test_signer_env_builds_an_account_with_no_private_key(fake_api_client, monkeypatch):
    _set_config(monkeypatch)

    await client_module.get_paradex_client()

    (account,), _ = fake_api_client.init_account.call_args
    assert isinstance(account, ExternalSignerAccount)
    assert isinstance(account.signer, HeaderSigner)
    assert account.signer.header == "X-Signer-Header"
    assert account.signer.signature == "stand-in"
    assert hex(account.l2_address) == SIGNER_ENV["PARADEX_ACCOUNT_ADDRESS"]
    assert hex(account.l2_public_key) == SIGNER_ENV["PARADEX_ACCOUNT_PUBLIC_KEY"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "missing",
    ["PARADEX_ACCOUNT_PUBLIC_KEY", "PARADEX_ACCOUNT_ADDRESS", "PARADEX_SIGNER_SIGNATURE"],
)
async def test_signer_env_missing_a_value_is_refused_on_every_call(
    fake_api_client, monkeypatch, missing
):
    _set_config(monkeypatch, **{missing: None})

    for _ in range(2):
        with pytest.raises(ValueError, match=missing):
            await client_module.get_paradex_client()
    assert client_module._paradex_client is None


@needs_external_signer
@pytest.mark.asyncio
async def test_a_failed_signer_setup_is_retried_on_the_next_call(fake_api_client, monkeypatch):
    _set_config(monkeypatch)
    fake_api_client.init_account.side_effect = httpx.ConnectError("signer down")

    with pytest.raises(httpx.ConnectError):
        await client_module.get_paradex_client()
    assert client_module._paradex_client is None

    fake_api_client.init_account.side_effect = None
    assert await client_module.get_paradex_client() is fake_api_client


@pytest.mark.asyncio
@pytest.mark.parametrize("stray", ["PARADEX_ACCOUNT_PUBLIC_KEY", "PARADEX_SIGNER_SIGNATURE"])
async def test_signer_value_without_the_header_is_refused(fake_api_client, monkeypatch, stray):
    unset = {"PARADEX_SIGNER_SIGNATURE": None, "PARADEX_ACCOUNT_PUBLIC_KEY": None}
    _set_config(
        monkeypatch,
        PARADEX_SIGNER_HEADER=None,
        PARADEX_ACCOUNT_PRIVATE_KEY="0x1",
        **{**unset, stray: "set"},
    )

    with pytest.raises(ValueError, match=f"{stray} need PARADEX_SIGNER_HEADER"):
        await client_module.get_paradex_client()


@needs_external_signer
@pytest.mark.asyncio
async def test_signer_wins_over_a_private_key_and_warns(fake_api_client, monkeypatch, caplog):
    _set_config(monkeypatch, PARADEX_ACCOUNT_PRIVATE_KEY="0x1")

    with caplog.at_level(logging.WARNING, logger=client_module.logger.name):
        await client_module.get_paradex_client()

    (account,), _ = fake_api_client.init_account.call_args
    assert isinstance(account, ExternalSignerAccount)
    assert "ignoring the private key" in caplog.text


@pytest.mark.parametrize(
    ("overrides", "configured"),
    [
        ({}, True),
        ({"PARADEX_ACCOUNT_PUBLIC_KEY": None}, False),
        ({"PARADEX_ACCOUNT_ADDRESS": None}, False),
        ({"PARADEX_SIGNER_SIGNATURE": None}, False),
        ({"PARADEX_SIGNER_HEADER": None}, False),
    ],
)
def test_is_configured_needs_every_signer_value(monkeypatch, overrides, configured):
    _set_config(monkeypatch, **overrides)
    assert config.is_configured() is configured


@pytest.fixture
def proxy_env(monkeypatch):
    for name in PROXY_ENV:
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(name.lower(), raising=False)
    return monkeypatch


def _transport_for(client: httpx.Client, url: str) -> httpx.BaseTransport:
    return client._transport_for_url(httpx.URL(url))


def test_http_client_routes_through_the_env_proxy(proxy_env):
    proxy_env.setenv("HTTPS_PROXY", "http://proxy.internal:8080")

    client = client_module._http_client()

    transport = _transport_for(client, "https://api.prod.paradex.trade/v1/system/config")
    assert transport is not client._transport
    assert isinstance(transport, httpx.HTTPTransport)
    assert transport._pool._proxy_url.host == b"proxy.internal"  # type: ignore[attr-defined]


def _proxy_for(client: httpx.Client, url: str) -> str | None:
    pool = _transport_for(client, url)._pool  # type: ignore[attr-defined]
    proxy = getattr(pool, "_proxy_url", None)
    return None if proxy is None else str(proxy)


@pytest.mark.parametrize(
    "env",
    [
        {"HTTPS_PROXY": "proxy.internal:8080"},
        {"ALL_PROXY": "http://proxy.internal:8080", "NO_PROXY": "::1,10.0.0.1"},
        {"ALL_PROXY": "http://proxy.internal:8080", "NO_PROXY": "http://foo,localhost"},
        {"ALL_PROXY": "http://proxy.internal:8080", "NO_PROXY": ".paradex.trade"},
        {"ALL_PROXY": "http://proxy.internal:8080", "NO_PROXY": "foo,*"},
    ],
)
def test_http_client_routes_like_an_httpx_default_client(proxy_env, env):
    for name, value in env.items():
        proxy_env.setenv(name, value)

    ours, httpx_default = client_module._http_client(), httpx.Client()

    for url in (
        "https://api.prod.paradex.trade/v1",
        "https://paradex.trade/",
        "https://[::1]/",
        "https://10.0.0.1/",
        "http://foo/",
        "https://foo/",
        "https://localhost/",
        "https://sub.localhost/",
    ):
        assert _proxy_for(ours, url) == _proxy_for(httpx_default, url), url


def test_jwt_client_routes_through_the_env_proxy(proxy_env):
    proxy_env.setenv("HTTPS_PROXY", "http://proxy.internal:8080")

    http = client_module._make_jwt_client("jwt").client

    assert _transport_for(http, "https://api.prod.paradex.trade/v1") is not http._transport


@pytest.fixture
def signer_client(monkeypatch):
    api = MagicMock()
    api.account = MagicMock(spec=ParadexAccount)
    monkeypatch.setattr(client_module, "_paradex_client", api)
    monkeypatch.setattr(client_module.config, "PARADEX_SIGNER_HEADER", "X-Signer-Header")
    return api


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tool", "args"),
    [
        (
            "paradex_block_trade_create_offer_based",
            {
                "market_id": "BTC-USD-PERP",
                "min_price": "1",
                "max_price": "2",
                "min_size": "1",
                "max_size": "2",
                "counterparty_accounts": [],
            },
        ),
        (
            "paradex_block_trade_submit_offer",
            {
                "block_trade_id": "b1",
                "market_id": "BTC-USD-PERP",
                "side": "BUY",
                "price": "1",
                "size": "1",
            },
        ),
        ("paradex_block_trade_execute", {"block_trade_id": "b1", "offer_ids": []}),
    ],
)
async def test_block_trade_signing_is_refused_in_signer_mode(signer_client, tool, args):
    with pytest.raises(ToolError, match="not available in signer mode"):
        await server.call_tool(tool, args)

    signer_client.account.build_block_trade_signature.assert_not_called()
    signer_client.account.build_block_trade_offer_signature.assert_not_called()
    signer_client.create_block_trade.assert_not_called()
    signer_client.create_block_trade_offer.assert_not_called()
    signer_client.execute_block_trade.assert_not_called()


def test_signer_mode_without_the_sdk_support_says_so(monkeypatch):
    monkeypatch.setitem(sys.modules, "paradex_py.account.external_signer", None)
    with pytest.raises(ValueError, match="needs a paradex-py with ExternalSignerAccount"):
        client_module._signer_account(MagicMock())
