FROM ghcr.io/astral-sh/uv:0.12.23-python3.12-trixie-slim@sha256:28d570c06d150303b39adfa731ada20956c63fc86b1277d7ff2ad63185974092 AS tooling
FROM cgr.dev/chainguard/wolfi-base@sha256:81211e15a86ea1d5357f284482af45730c51de45eaf10ad9ce205d6bfc2df323 AS runtime
RUN apk add --no-cache \
        'apk-tools=2.14.10-r17' \
        'busybox=1.38.0-r3' \
        'ca-certificates-bundle=20260909-r3' \
        'gdbm=1.26-r7' \
        'glibc-2.44=2.44-r8' \
        'glibc-2.44-locale-posix=2.44-r8' \
        'ld-linux-2.44=2.44-r8' \
        'libbrotlicommon1=1.2.1-r2' \
        'libbrotlidec1=1.2.1-r2' \
        'libbrotlienc1=1.2.1-r2' \
        'libbz2-1=1.0.8-r25' \
        'libcrypt1-2.44=2.44-r8' \
        'libexpat1=2.9.0-r0' \
        'libffi=3.8.0-r2' \
        'libgcc=16.2.0-r1' \
        'libstdc++=16.2.0-r1' \
        'libuuid=2.42.4-r1' \
        'libxcrypt=4.5.2-r6' \
        'mpdecimal=4.0.1-r4' \
        'ncurses=6.6.20261017-r0' \
        'ncurses-terminfo-base=6.6.20261017-r0' \
        'openssl-4.0-libcrypto=4.0.3-r8' \
        'openssl-4.0-libssl=4.0.3-r8' \
        'openssl-provider-legacy-allowed=4.0.3-r1' \
        'py3-pip-wheel=26.2.1-r4' \
        'python-3.12=3.12.15-r4' \
        'python-3.12-base=3.12.15-r4' \
        'readline=8.3-r3' \
        'sqlite-libs=3.54.1-r0' \
        'wolfi-base=1-r7' \
        'wolfi-baselayout=20230201-r30' \
        'wolfi-keys=1-r13' \
        'xz=5.8.4-r0' \
        'zlib=1.3.2.1_rc20260921-r0' \
    && test "$(apk info | wc -l)" -eq 34 \
    && test "$(python3 --version)" = 'Python 3.12.15'

FROM runtime AS builder
COPY --from=tooling /usr/local/bin/uv /usr/local/bin/uv
WORKDIR /app
ENV UV_LINK_MODE=copy UV_NO_CACHE=1 UV_PYTHON_DOWNLOADS=never UV_PYTHON=/usr/bin/python3.12
COPY images/tracking/requirements.lock /app/requirements.lock
RUN uv venv /app/.venv && uv pip sync --python /app/.venv/bin/python --require-hashes --only-binary :all: /app/requirements.lock

FROM runtime
COPY --from=builder /app/.venv /app/.venv
COPY images/tracking/probe.py /app/probe.py
COPY images/tracking/server.py /app/server.py
ARG MATERIALS_DIGEST
LABEL org.trusted-mlsecops.tracking-materials=$MATERIALS_DIGEST
ENV PATH="/app/.venv/bin:$PATH" PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/tmp OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 NUMEXPR_NUM_THREADS=1 MLFLOW_DISABLE_TELEMETRY=true
USER 65532:65532
WORKDIR /tmp
ENTRYPOINT ["python"]
