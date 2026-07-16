"""Recon Operator application package.

Implementation: :mod:`recon_operator.server`
Compatibility entrypoint: top-level ``autonmap`` / ``python -m recon_operator``
"""

from __future__ import annotations

from typing import Any


def __getattr__(name: str) -> Any:
    if name == "VERSION":
        from recon_operator.server import VERSION as _version

        return _version
    if name == "create_app":
        from recon_operator.server import app as _app

        return lambda: _app
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
