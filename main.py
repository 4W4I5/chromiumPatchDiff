"""Web entrypoint for chromiumPatchDiff."""

from __future__ import annotations

import os

import uvicorn

from web.app import app


def main() -> int:
    host = os.getenv("WEB_HOST", "127.0.0.1").strip() or "127.0.0.1"
    try:
        port = int(os.getenv("WEB_PORT", "8000"))
    except ValueError:
        port = 8000

    uvicorn.run(
        "main:app",
        host=host,
        port=max(1, min(port, 65535)),
        reload=False,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
