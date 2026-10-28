FROM cgr.dev/chainguard/wolfi-base@sha256:81211e15a86ea1d5357f284482af45730c51de45eaf10ad9ce205d6bfc2df323
LABEL org.opencontainers.image.source="https://github.com/Abrakadabra124/trusted-mlsecops-platform"
RUN apk add --no-cache \
        'apk-tools=2.14.10-r17' \
        'bash=5.3-r14' \
        'busybox=1.38.0-r3' \
        'ca-certificates-bundle=20260909-r3' \
        'coreutils=9.12-r4' \
        'cyrus-sasl-heimdal-libs=2.1.28-r58' \
        'ecpg-18=18.6-r5' \
        'gdbm=1.26-r7' \
        'glibc-2.44=2.44-r8' \
        'glibc-2.44-locale-posix=2.44-r8' \
        'heimdal-libs=7.8.0-r54' \
        'icu78-data-full=78.3-r4' \
        'keyutils-libs=1.6.3-r41' \
        'krb5-conf=1.0-r10' \
        'krb5-libs=1.22.2-r5' \
        'ld-linux-2.44=2.44-r8' \
        'libacl1=2.4.0-r4' \
        'libattr1=2.6.0-r4' \
        'libLLVM=19.1.7-r8' \
        'libbrotlicommon1=1.2.1-r2' \
        'libbrotlidec1=1.2.1-r2' \
        'libbrotlienc1=1.2.1-r2' \
        'libcom_err=1.47.4-r3' \
        'libcrypt1-2.44=2.44-r8' \
        'libcrypto3=3.6.5-r5' \
        'libedit=3.1-r20' \
        'libffi=3.8.0-r2' \
        'libgcc=16.2.0-r1' \
        'libicu78=78.3-r4' \
        'libldap-2.6=2.6.14-r0' \
        'liblz4-1=1.10.0-r11' \
        'libpcre2-8-0=10.49-r1' \
        'libpq-18=18.6-r5' \
        'libselinux=3.11-r2' \
        'libsepol=3.11-r3' \
        'libssl3=3.6.5-r5' \
        'libstdc++=16.2.0-r1' \
        'libverto=0.3.2-r9' \
        'libxcrypt=4.5.2-r6' \
        'libxml2=2.15.0-r0' \
        'libxml2-2.13-2=2.13.9-r1' \
        'libzstd1=1.5.7-r10' \
        'linux-pam=1.7.3-r0' \
        'ncurses=6.6.20261017-r0' \
        'ncurses-terminfo-base=6.6.20261017-r0' \
        'openssl-4.0-libcrypto=4.0.3-r8' \
        'openssl-4.0-libssl=4.0.3-r8' \
        'openssl-provider-legacy-allowed=4.0.3-r1' \
        'postgresql-18=18.6-r5' \
        'postgresql-18-base=18.6-r5' \
        'postgresql-18-client=18.6-r5' \
        'postgresql-18-client-base=18.6-r5' \
        'readline=8.3-r3' \
        'sqlite-libs=3.54.1-r0' \
        'tzdata=2026e-r0' \
        'wolfi-base=1-r7' \
        'wolfi-baselayout=20230201-r30' \
        'wolfi-keys=1-r13' \
        'xz=5.8.4-r0' \
        'zlib=1.3.2.1_rc20260921-r0' \
    && test "$(apk info | wc -l)" -eq 60 \
    && command -v bash >/dev/null \
    && test "$(timeout --version | head -n 1)" = 'timeout (GNU coreutils) 9.12' \
    && (timeout 1 bash -c 'sleep 5'; test "$?" -eq 124) \
    && addgroup -g 999 postgres \
    && adduser -D -H -u 999 -G postgres postgres \
    && test "$(postgres --version)" = 'postgres (PostgreSQL) 18.6' \
    && test "$(psql --version)" = 'psql (PostgreSQL) 18.6'
ENV PATH="/usr/libexec/postgresql18:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    LANG=C.UTF-8 \
    PG_MAJOR=18 \
    PG_VERSION=18.6 \
    PGDATA=/var/lib/postgresql/18/docker
USER 999:999
ENTRYPOINT ["postgres"]
