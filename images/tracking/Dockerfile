FROM ghcr.io/astral-sh/uv:0.12.23-python3.12-trixie-slim@sha256:28d570c06d150303b39adfa731ada20956c63fc86b1277d7ff2ad63185974092 AS builder
WORKDIR /app
COPY images/tracking/requirements.lock /app/requirements.lock
RUN uv venv /app/.venv && uv pip sync --python /app/.venv/bin/python --require-hashes --only-binary :all: /app/requirements.lock

FROM python:3.12.15-slim-trixie@sha256:2b4f19dae3a777dfc3b76730bda1e82e1f66ab2a2686fa93ca78edbfb4f04ffe
COPY --from=builder /app/.venv /app/.venv
COPY images/tracking/probe.py /app/probe.py
COPY images/tracking/server.py /app/server.py
ARG MATERIALS_DIGEST
LABEL org.trusted-mlsecops.tracking-materials=$MATERIALS_DIGEST
ENV PATH="/app/.venv/bin:$PATH" PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/tmp OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 NUMEXPR_NUM_THREADS=1 MLFLOW_DISABLE_TELEMETRY=true
USER 65532:65532
WORKDIR /tmp
ENTRYPOINT ["python"]
