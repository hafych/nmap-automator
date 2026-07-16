"""Allow ``python -m recon_operator`` to start the API server."""

from __future__ import annotations

import asyncio

from recon_operator.server import log_event, main


def run() -> None:
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log_event("KeyboardInterrupt received")
    except Exception as exc:  # pragma: no cover - process entry
        log_event(f"Critical error: {exc}")


if __name__ == "__main__":
    run()
