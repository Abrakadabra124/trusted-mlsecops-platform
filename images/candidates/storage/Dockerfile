FROM cgr.dev/chainguard/wolfi-base@sha256:81211e15a86ea1d5357f284482af45730c51de45eaf10ad9ce205d6bfc2df323
RUN apk add --no-cache 'postgresql-18=18.6-r5' 'postgresql-18-client=18.6-r5' 'glibc-2.44=2.44-r8' \
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
