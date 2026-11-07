"""Private loopback monitoring sink; no release or training authority."""

import sys

from mlsecops import monitoring_config
from mlsecops.private_cli import Arguments
from mlsecops.process_privacy import enforce as enforce_privacy
from mlsecops.serving_http import run_server


def main():
    try:
        enforce_privacy()
        parser = Arguments(prog="monitoring-sink", description="Signed loopback alert receipts")
        parser.add_argument("--config", required=True)
        options = parser.parse_args()
        app, port = monitoring_config.sink(options.config)
        run_server(
            app,
            host="127.0.0.1",
            port=port,
            access_log=False,
            proxy_headers=False,
            server_header=False,
            timeout_keep_alive=2,
            limit_concurrency=16,
            log_level="warning",
        )
        if getattr(app, "startup_failed", False) is True:
            raise ValueError("monitor_sink_startup_failed")
        return 0
    except (Exception, KeyboardInterrupt) as error:
        print("monitoring_sink_rejected", file=sys.stderr)
        return 130 if isinstance(error, KeyboardInterrupt) else 1


if __name__ == "__main__":
    raise SystemExit(main())
