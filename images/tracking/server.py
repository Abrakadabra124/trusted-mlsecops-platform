import json
import os
from pathlib import Path

CONFIG = Path("/config")


def database_uri(role):
    return (
        f"postgresql+psycopg://{role}@tracking-pg:5432/{role}"
        f"?sslmode=verify-full&sslrootcert={CONFIG}/ca.crt"
        f"&sslcert={CONFIG}/{role}.crt&sslkey={CONFIG}/{role}.key"
    )


def main():
    os.umask(0o077)
    credentials = json.loads((CONFIG / "bootstrap.json").read_text())
    auth = Path("/tmp/auth.ini")
    auth.write_text(
        "[mlflow]\ndefault_permission = NO_PERMISSIONS\nadmin_username = admin\n"
        f"database_uri = {database_uri('tracking_auth')}\n"
        "authorization_function = mlflow.server.auth:authenticate_request_basic_auth\n"
    )
    environment = {
        **os.environ,
        "MLFLOW_AUTH_CONFIG_PATH": str(auth),
        "MLFLOW_AUTH_ADMIN_PASSWORD": credentials["admin"],
        "MLFLOW_FLASK_SERVER_SECRET_KEY": credentials["csrf"],
        "MLFLOW_DISABLE_TELEMETRY": "true",
        "MLFLOW_ENABLE_REMOTE_ASSISTANT": "false",
        "MLFLOW_ENABLE_ASSISTANT_SANDBOX": "false",
        "MLFLOW_SERVER_ENABLE_JOB_EXECUTION": "false",
    }
    os.execvpe(
        "mlflow",
        [
            "mlflow",
            "server",
            "--app-name",
            "basic-auth",
            "--backend-store-uri",
            database_uri("tracking_metadata"),
            "--artifacts-destination",
            "/artifacts",
            "--host",
            "0.0.0.0",
            "--port",
            "5000",
            "--workers",
            "1",
            "--allowed-hosts",
            "localhost:*,127.0.0.1:*",
            "--uvicorn-opts",
            "--ssl-keyfile /config/server.key --ssl-certfile /config/server.crt",
        ],
        environment,
    )


if __name__ == "__main__":
    main()
