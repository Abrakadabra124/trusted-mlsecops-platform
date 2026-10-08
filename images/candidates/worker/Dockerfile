FROM ghcr.io/astral-sh/uv:0.12.23-python3.12-trixie-slim@sha256:28d570c06d150303b39adfa731ada20956c63fc86b1277d7ff2ad63185974092 AS dependencies
WORKDIR /app
ENV UV_LINK_MODE=copy UV_NO_CACHE=1
COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-dev --no-install-project

FROM python:3.12.15-slim-trixie@sha256:2b4f19dae3a777dfc3b76730bda1e82e1f66ab2a2686fa93ca78edbfb4f04ffe
WORKDIR /app
RUN sed -i 's#http://deb.debian.org#https://deb.debian.org#g' /etc/apt/sources.list.d/debian.sources \
    && apt-get -o Acquire::Retries=1 -o Acquire::https::Timeout=30 update \
    && apt-get -o Acquire::Retries=1 -o Acquire::https::Timeout=30 install -y --no-install-recommends 'libpcre2-8-0=10.46-1~deb13u3' \
    && test "$(dpkg-query -W -f='${Version}' libpcre2-8-0)" = '10.46-1~deb13u3' \
    && rm -rf /var/lib/apt/lists/*
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    OMP_NUM_THREADS=1 \
    OPENBLAS_NUM_THREADS=1 \
    MKL_NUM_THREADS=1 \
    ORT_DISABLE_TELEMETRY=1 \
    PATH="/app/.venv/bin:${PATH}"
COPY --from=dependencies /app/.venv /app/.venv
COPY pyproject.toml uv.lock Dockerfile ./
COPY mlsecops ./mlsecops
COPY policies ./policies
USER 65532:65532
CMD ["python", "-m", "mlsecops.worker", "--help"]
