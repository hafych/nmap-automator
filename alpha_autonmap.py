"""Backward-compatible entrypoint for the legacy filename."""

import asyncio

from autonmap import main

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    except Exception as e:
        raise SystemExit(f"Critical error: {e}") from e
