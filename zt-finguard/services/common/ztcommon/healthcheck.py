"""Container HEALTHCHECK: call this service's own /healthz over mTLS.

Usage: python -m ztcommon.healthcheck
"""
import sys

import httpx

from . import config, mtls


def main() -> int:
    try:
        with httpx.Client(verify=mtls.client_ssl_context(), timeout=3) as c:
            r = c.get(f"https://{config.SERVICE_NAME}:{config.PORT}/healthz")
        return 0 if r.status_code == 200 else 1
    except Exception as exc:  # noqa: BLE001
        print(f"unhealthy: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
