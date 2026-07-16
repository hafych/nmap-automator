"""Authentication and API-key scopes (lazy re-export from server)."""

from __future__ import annotations

from typing import Any

_EXPORTS = frozenset(
    {
        "API_AUTH_KEYS",
        "API_AUTH_TOKEN",
        "API_AUTH_TOKENS",
        "API_KEY_SCOPES",
        "current_api_key_id",
        "current_owner_id",
        "current_scopes",
        "owner_id_from_token",
        "require_api_auth",
        "scopes_allow",
        "_expand_scopes",
        "_load_api_auth_keys",
        "_load_api_auth_tokens",
        "_resolve_api_key",
        "_token_is_authorized",
    }
)


def __getattr__(name: str) -> Any:
    if name in _EXPORTS:
        from recon_operator import server as _server

        return getattr(_server, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
