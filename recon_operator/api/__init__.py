"""HTTP API surface (lazy re-export from server)."""

from __future__ import annotations

from typing import Any

_EXPORTS = frozenset({"app", "build_openapi_spec", "main"})


def __getattr__(name: str) -> Any:
    if name in _EXPORTS:
        from recon_operator import server as _server

        return getattr(_server, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
