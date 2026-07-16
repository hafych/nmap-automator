"""HTTP API surface (lazy re-export from server)."""

from __future__ import annotations

from importlib import import_module
from typing import Any

_EXPORTS = frozenset({"app", "build_openapi_spec", "main"})


def __getattr__(name: str) -> Any:
    if name in _EXPORTS:
        _server = import_module("recon_operator.server")

        return getattr(_server, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
