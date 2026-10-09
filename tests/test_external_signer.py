"""The external-signer mode: no private key in the server, a signing proxy holds it."""

import logging
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import httpx
import pytest
from mcp.server.fastmcp.exceptions import ToolError
from paradex_py.account.external_signer import ExternalSignerAccount, HeaderSigner

import mcp_paradex.utils.paradex_client as client_module
from mcp_paradex.server.server import server

config = client_module.config

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


def test_http_client_skips_the_proxy_for_no_proxy_hosts(proxy_env):
    proxy_env.setenv("HTTPS_PROXY", "http://proxy.internal:8080")
    proxy_env.setenv("NO_PROXY", "paradex.trade,10.0.0.1,localhost")

    client = client_module._http_client()

    for url in ("https://api.prod.paradex.trade/v1", "https://10.0.0.1/", "https://localhost/"):
        assert _transport_for(client, url) is client._transport
    assert _transport_for(client, "https://example.com/") is not client._transport


def test_http_client_with_no_proxy_star_uses_no_proxy(proxy_env):
    proxy_env.setenv("ALL_PROXY", "http://proxy.internal:8080")
    proxy_env.setenv("NO_PROXY", "*")

    client = client_module._http_client()

    assert _transport_for(client, "https://api.prod.paradex.trade/v1") is client._transport


@pytest.fixture
def signer_client(monkeypatch):
    api = MagicMock()
    api.account = MagicMock(spec=ExternalSignerAccount)
    monkeypatch.setattr(client_module, "_paradex_client", api)
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
