FROM ghcr.io/astral-sh/uv:0.12.23-python3.12-trixie-slim@sha256:28d570c06d150303b39adfa731ada20956c63fc86b1277d7ff2ad63185974092 AS tooling
FROM cgr.dev/chainguard/wolfi-base@sha256:81211e15a86ea1d5357f284482af45730c51de45eaf10ad9ce205d6bfc2df323 AS runtime
RUN apk add --no-cache 'python-3.12=3.12.15-r4' 'glibc-2.44=2.44-r8' 'libstdc++=16.2.0-r1' \
    && test "$(python3 --version)" = 'Python 3.12.15'

FROM runtime AS dependencies
COPY --from=tooling /usr/local/bin/uv /usr/local/bin/uv
WORKDIR /app
ENV UV_LINK_MODE=copy UV_NO_CACHE=1 UV_PYTHON_DOWNLOADS=never UV_PYTHON=/usr/bin/python3.12
COPY pyproject.toml uv.lock .python-version ./
RUN uv sync --locked --no-dev --no-install-project

FROM runtime
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    OMP_NUM_THREADS=1 \
    OPENBLAS_NUM_THREADS=1 \
    MKL_NUM_THREADS=1 \
    ORT_DISABLE_TELEMETRY=1 \
    PATH="/app/.venv/bin:${PATH}"
COPY --from=dependencies /app/.venv /app/.venv
COPY pyproject.toml uv.lock .python-version Dockerfile ./
COPY mlsecops ./mlsecops
COPY policies ./policies
USER 65532:65532
CMD ["python", "-m", "mlsecops.worker", "--help"]
