"""Web entrypoint for chromiumPatchDiff."""

import os
import uvicorn

from web.app import app


def main() -> int:
    # Force 0.0.0.0 so it's accessible from outside the VM
    host = "0.0.0.0"
    
    # Get port from environment variable (default 8000)
    try:
        port = int(os.getenv("WEB_PORT", "8080"))
    except ValueError:
        port = 8080

    # Production-friendly settings
    uvicorn.run(
        app,                    # Pass the app object directly (better than string)
        host=host,
        port=max(1, min(port, 65535)),
        log_level="info",
        access_log=True,
        workers=1,              # Increase only if you have enough CPU/RAM
        # reload=False is default in production, but you can control via env
        reload=os.getenv("UVICORN_RELOAD", "false").lower() == "true",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())