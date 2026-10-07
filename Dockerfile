FROM ghcr.io/astral-sh/uv:0.12.23-python3.12-trixie-slim@sha256:28d570c06d150303b39adfa731ada20956c63fc86b1277d7ff2ad63185974092
WORKDIR /app
ENV UV_LINK_MODE=copy \
    UV_NO_CACHE=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    OMP_NUM_THREADS=1 \
    OPENBLAS_NUM_THREADS=1 \
    MKL_NUM_THREADS=1 \
    PATH="/app/.venv/bin:${PATH}"
COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-dev --no-install-project
COPY mlsecops ./mlsecops
COPY policies ./policies
USER 65532:65532
CMD ["python", "-m", "mlsecops.worker", "--help"]
