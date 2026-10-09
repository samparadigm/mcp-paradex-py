"""
Configuration utilities for the MCP Paradex server.
"""

import os
from enum import Enum

from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


def _sanitize_env(value: str | None) -> str | None:
    """Return None for unsubstituted MCPB template variables like ${user_config.foo}."""
    if value and value.startswith("${") and value.endswith("}"):
        return None
    return value or None


class Environment(str, Enum):
    """Trading environment options."""

    TESTNET = "testnet"
    PROD = "prod"


class Config:
    """Configuration settings for the MCP Paradex server."""

    # Server configuration
    SERVER_NAME: str = os.getenv("SERVER_NAME", "Paradex Trading")
    SERVER_PORT: int = int(os.getenv("SERVER_PORT", "3000"))

    # Paradex configuration
    ENVIRONMENT: str = os.getenv("PARADEX_ENVIRONMENT", "prod")

    PARADEX_ACCOUNT_ADDRESS: str | None = _sanitize_env(os.getenv("PARADEX_ACCOUNT_ADDRESS"))
    PARADEX_ACCOUNT_PRIVATE_KEY: str | None = _sanitize_env(
        os.getenv("PARADEX_ACCOUNT_PRIVATE_KEY")
    )

    # External signer: the key is held by a signing proxy. Each message hash goes in the
    # PARADEX_SIGNER_HEADER header, and PARADEX_SIGNER_SIGNATURE goes where the signature
    # belongs for the proxy to replace. Needs the account address and the key's public key.
    PARADEX_ACCOUNT_PUBLIC_KEY: str | None = _sanitize_env(os.getenv("PARADEX_ACCOUNT_PUBLIC_KEY"))
    PARADEX_SIGNER_HEADER: str | None = _sanitize_env(os.getenv("PARADEX_SIGNER_HEADER"))
    PARADEX_SIGNER_SIGNATURE: str | None = _sanitize_env(os.getenv("PARADEX_SIGNER_SIGNATURE"))

    # JWT-based auth (alternative to private key)
    PARADEX_JWT_TOKEN: str | None = _sanitize_env(os.getenv("PARADEX_JWT_TOKEN"))
    # Long-term API key (JWT) — exposed as user_config.paradex_api_key in the MCPB manifest.
    # Account address is auto-extracted from the token payload at startup.
    PARADEX_API_KEY: str | None = _sanitize_env(os.getenv("PARADEX_API_KEY"))
    # OAuth Resource Server config (for HTTP mode)
    MCP_SERVER_URL: str | None = os.getenv("MCP_SERVER_URL")
    PARADEX_AUTH_SERVER_URL: str | None = os.getenv("PARADEX_AUTH_SERVER_URL")

    def signer_config_error(self) -> str | None:
        """What is missing or stray in the signer settings, or None when they are complete or unset."""
        if self.PARADEX_SIGNER_HEADER:
            missing = [name for name in _SIGNER_NEEDS if not getattr(self, name)]
            return f"PARADEX_SIGNER_HEADER also needs {', '.join(missing)}" if missing else None
        stray = [name for name in _SIGNER_ONLY if getattr(self, name)]
        return f"{' and '.join(stray)} need PARADEX_SIGNER_HEADER" if stray else None

    def is_configured(self) -> bool:
        """Check if all required configuration is set."""
        signer_ready = self.PARADEX_SIGNER_HEADER is not None and not self.signer_config_error()
        return any(
            [
                self.PARADEX_ACCOUNT_PRIVATE_KEY is not None,
                signer_ready,
                self.PARADEX_JWT_TOKEN is not None,
                self.PARADEX_API_KEY is not None,
                self.PARADEX_AUTH_SERVER_URL is not None,
            ]
        )


_SIGNER_ONLY = ("PARADEX_SIGNER_SIGNATURE", "PARADEX_ACCOUNT_PUBLIC_KEY")
_SIGNER_NEEDS = (*_SIGNER_ONLY, "PARADEX_ACCOUNT_ADDRESS")


config = Config()


def _decode_jwt_payload(token: str) -> dict:
    """Decode the payload segment of a JWT without verifying the signature."""
    import base64
    import json as _json

    payload_b64 = token.split(".")[1]
    padded = payload_b64 + "=" * (-len(payload_b64) % 4)
    return _json.loads(base64.urlsafe_b64decode(padded))  # type: ignore[no-any-return]


def _extract_account_from_jwt(token: str) -> str | None:
    """Return the account address embedded in a Paradex JWT payload, or None."""
    try:
        payload = _decode_jwt_payload(token)
    except Exception:
        return None
    for key in ("account", "account_address", "sub"):
        value = payload.get(key)
        if value and isinstance(value, str):
            return str(value)
    return None


# Map PARADEX_API_KEY → PARADEX_JWT_TOKEN so the rest of the implementation is unchanged.
if config.PARADEX_API_KEY and not config.PARADEX_JWT_TOKEN:
    config.PARADEX_JWT_TOKEN = config.PARADEX_API_KEY

# Auto-populate account address from API key JWT when not explicitly configured.
if config.PARADEX_API_KEY and not config.PARADEX_ACCOUNT_ADDRESS:
    _addr = _extract_account_from_jwt(config.PARADEX_API_KEY)
    if _addr:
        config.PARADEX_ACCOUNT_ADDRESS = _addr
