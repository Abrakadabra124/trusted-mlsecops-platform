FROM postgres:18.6-trixie@sha256:885953109528ad3dfc90362b1a6f50a78620b5315be19f187753d267e484dc5b AS prepared
RUN rm /usr/local/bin/gosu /usr/local/bin/docker-entrypoint.sh

FROM scratch
COPY --from=prepared / /
ENV PATH="/usr/lib/postgresql/18/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    LANG=en_US.utf8 \
    PG_MAJOR=18 \
    PG_VERSION=18.6-1.pgdg13+2 \
    PGDATA=/var/lib/postgresql/18/docker
ENTRYPOINT ["postgres"]
