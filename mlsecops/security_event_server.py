"""Explicit Linux collector: loopback v1 or mandatory mTLS v2; no implicit state init."""

import sys
import time
from pathlib import Path

from mlsecops import (
    key_files,
    security_event_config,
    security_event_http,
    security_event_runtime,
    security_event_store,
    security_event_tls,
    security_events,
)
from mlsecops.contracts import Rejected, bounded_read, decode
from mlsecops.private_cli import Arguments
from mlsecops.process_privacy import enforce as enforce_privacy
from mlsecops.serving_http import run_server

FIELDS = (
    "schema_version",
    "registry_file",
    "registry_root",
    "registry_sha256",
    "state_directory",
    "state_sha256",
    "receipt_key_file",
    "collector_key_file",
    "ingress_token_file",
    "operator_token_file",
    "port",
)


def absolute(value):
    if type(value) is not str or not Path(value).is_absolute():
        raise Rejected("security_server_path")
    return Path(value)


def configured(path):
    value = decode(bounded_read(absolute(path), 16384), 16384)
    version = value.get("schema_version") if type(value) is dict else None
    security_events.shape(value, (*FIELDS, "tls") if version == 2 else FIELDS)
    if type(version) is not int or version not in (1, 2):
        raise Rejected("security_server_schema")
    tls = security_event_tls.server_context(value["tls"]) if version == 2 else None
    port = security_events.integer(value["port"], 1024)
    if port > 65535:
        raise Rejected("security_server_port")
    registry = security_event_config.Registry(
        decode(bounded_read(absolute(value["registry_file"]), 32768), 32768),
        trusted_root=value["registry_root"],
        expected_sha256=value["registry_sha256"],
        clock_ms=time.time_ns() // 1_000_000,
    )
    store = security_event_store.Store(value["state_directory"], value["state_sha256"], registry)
    collector = security_event_runtime.Collector(
        store,
        absolute(value["receipt_key_file"]),
        absolute(value["collector_key_file"]),
    )
    tokens = [
        security_events.hexadecimal(key_files.read(absolute(value[name])).decode("ascii"))
        for name in ("ingress_token_file", "operator_token_file")
    ]
    app = security_event_http.App(collector, *tokens)
    app.tls_context = tls
    return app, port


def main():
    try:
        enforce_privacy()
        parser = Arguments(prog="security-event-collector")
        parser.add_argument("--config", required=True)
        options = parser.parse_args()
        app, port = configured(options.config)
        tls = app.tls_context
        run_server(
            app,
            host="127.0.0.1" if tls is None else "0.0.0.0",
            port=port,
            access_log=False,
            proxy_headers=False,
            server_header=False,
            timeout_keep_alive=2,
            limit_concurrency=16,
            log_level="warning",
            **({"ssl_context_factory": lambda *_: tls} if tls is not None else {}),
        )
        if app.startup_failed:
            raise Rejected("security_server_startup")
        return 0
    except (Exception, KeyboardInterrupt, SystemExit) as error:
        print("security_collector_rejected", file=sys.stderr)
        return 130 if isinstance(error, KeyboardInterrupt) else 1


if __name__ == "__main__":
    raise SystemExit(main())
