FROM docker.io/library/golang:1.26.11-bookworm@sha256:79ecd0a7157c7a4cf3b281ced8465350591bf54fedab540e75374a003e1fde7e AS build
ENV GOENV=off GOTOOLCHAIN=local GOWORK=off GOFLAGS=-mod=readonly \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 \
    GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org LC_ALL=C
WORKDIR /src
RUN <<'SH'
set -eu
test "$(go env GOVERSION)" = go1.26.11
curl -fsSL --retry 3 https://codeload.github.com/etcd-io/etcd/tar.gz/0689586e360e2c6b46f95ad5634c25d5fa1683db -o /tmp/etcd.tar.gz
echo 'a06073d4041092c4892bcf56a810d69d59a29232d1050dfb3fe97ad69bc3bb71  /tmp/etcd.tar.gz' | sha256sum -c -
tar -xzf /tmp/etcd.tar.gz --strip-components=1
test "$(cat .go-version)" = 1.26.11
# Import upstream metadata for Go's native main-module and VCS stamps.
# The build inputs remain the files extracted from the verified archive.
git clone -q --depth=1 --no-checkout --branch v3.6.17 https://github.com/etcd-io/etcd.git /tmp/etcd-history
mv /tmp/etcd-history/.git .git
git read-tree HEAD
revision=0689586e360e2c6b46f95ad5634c25d5fa1683db
test "$(git rev-parse HEAD)" = "$revision"
for dir in server etcdctl etcdutl; do
    ref="refs/tags/$dir/v3.6.17"
    git fetch -q --depth=1 --no-tags origin "$ref:$ref"
    test "$(git rev-parse "$ref^{commit}")" = "$revision"
done
state=$(git status --porcelain)
test -z "$state"
SH

# The patch applies to the three command roots and their in-tree replacements.
# Versions and sums outside this overlay come from the verified source archive.
RUN <<'SH'
set -eu
cat >/tmp/patch.sum <<'SUM'
golang.org/x/crypto v0.59.0 h1:xS2jhqYbzNrpvkWP2YTDf4TJwBy3ykR03i8vFDxEc7c=
golang.org/x/crypto v0.59.0/go.mod h1:veDyUwATGs3c+vN3VfTbzViMGXeTBk3WyhBOkn+F/4U=
golang.org/x/sys v0.50.0 h1:dkKZEFTEKaLr1sjhs0WiKqoi8Jj5nHbS3Njmx1UoMJs=
golang.org/x/sys v0.50.0/go.mod h1:hNLxWAXmnKAxqDtdwIYC4bM9oQPEecfsnNMuSxOs3og=
golang.org/x/term v0.48.0 h1:G6UU1eiSB8nl3DzeUGt7Mg+2SctI8tPS6Z5/mBt6cOk=
golang.org/x/term v0.48.0/go.mod h1:BRDLHCZr2SUjIeBHHpRyQeC9xzSAVbzY2rvKgafnHf4=
golang.org/x/text v0.44.0 h1:YItdp/mQNGnsmrgpcdA5yQ3bnRxCfo/Tj/iByGW9GGo=
golang.org/x/text v0.44.0/go.mod h1:S4FR1waQ9LbjQTls97SyRjDaUUVkaM+cXwwuG/G+MwY=
golang.org/x/sync v0.25.0 h1:dJnifr0nMV8/SBnBvdo4eSGGnrc3O4FFx6IqvtLcmRs=
golang.org/x/sync v0.25.0/go.mod h1:sUUOizhqBxiL6pEWpqNLUiaJn1ShEbZ6BBqskPbjZm0=
golang.org/x/tools v0.52.0 h1:ryxg4U63oaUYk7uOLTF37n43f4qgtGvqV4Ioit1BaEs=
golang.org/x/tools v0.52.0/go.mod h1:ItcP5UNaVGG+Yc4eIYmaFLNJ4soEopkx5Y2d4lcEurs=
golang.org/x/mod v0.42.0 h1:ICeL3t2L30ljSPHHxDnR4fqVcBt/zR2zJAb9juavmQg=
golang.org/x/mod v0.42.0/go.mod h1:u5fzIrRInkL8MaO1cbRkUHT64v303YIT5KEqpNr7jRs=
SUM
for dir in . api client/pkg client/v3 pkg server etcdctl etcdutl; do
    sed -i -e 's|golang.org/x/crypto v0\.58\.0\b|golang.org/x/crypto v0.59.0|' \
           -e 's|golang.org/x/sys v0\.49\.0\b|golang.org/x/sys v0.50.0|' \
           -e 's|golang.org/x/text v0\.43\.0\b|golang.org/x/text v0.44.0|' "$dir/go.mod"
    cat /tmp/patch.sum >> "$dir/go.sum"
done
# etcdctl's original executable has no linked x/crypto package. Freeze its
# graph selection as well, without adding any import to the command.
sed -i '/golang.org\/x\/net v0\.62\.0/i\	golang.org/x/crypto v0.59.0 // indirect' etcdctl/go.mod
find . \( -name go.mod -o -name go.sum \) -type f -print0 | sort -z | xargs -0 sha256sum >/tmp/manifests.sha256
cat >/tmp/expected-versions <<'VERSIONS'
golang.org/x/crypto v0.59.0
golang.org/x/net v0.62.0
golang.org/x/sys v0.50.0
golang.org/x/term v0.48.0
golang.org/x/text v0.44.0
VERSIONS
for dir in server etcdctl etcdutl; do
    (
        cd "$dir"
        go list -m -f '{{.Path}} {{.Version}}' golang.org/x/crypto golang.org/x/net \
            golang.org/x/sys golang.org/x/term golang.org/x/text >/tmp/versions
        diff -u /tmp/expected-versions /tmp/versions
        go list -deps . >"/tmp/$dir.packages"
        if grep -Eq '^golang\.org/x/crypto/openpgp(/|$)' "/tmp/$dir.packages"; then exit 1; fi
    )
done
sha256sum --check --status /tmp/manifests.sha256
SH

RUN --network=none <<'SH'
set -eu
export GOPROXY=off
mkdir /out
for dir in server etcdctl etcdutl; do
    name="$dir"
    if [ "$dir" = server ]; then name=etcd; fi
    (cd "$dir" && go build -mod=readonly -buildvcs=true -trimpath -installsuffix=cgo \
        -ldflags='-X=go.etcd.io/etcd/api/v3/version.GitSHA=0689586e360e2c6b46f95ad5634c25d5fa1683db' \
        -o "/out/$name" .)
    (cd "$dir" && go list -deps -f '{{.Dir}}' .) >>/tmp/linked-dirs
done
sha256sum --check --status /tmp/manifests.sha256
# Preserve notices from the directories containing linked Go packages and their parents.
sort -u /tmp/linked-dirs >/tmp/package-dirs
while IFS= read -r dir; do
    case "$dir" in
        /src/*) root=/src; prefix=etcd ;;
        /usr/local/go/src/*) root=/usr/local/go; prefix=go ;;
        /go/pkg/mod/*) root=/go/pkg/mod; prefix=modules ;;
        *) echo "unexpected Go package directory: $dir" >&2; exit 1 ;;
    esac
    while [ "$dir" != "$root" ]; do
        printf '%s\t%s/%s\n' "$dir" "$prefix" "${dir#"$root"/}" >>/tmp/notice-dirs
        dir=$(dirname "$dir")
    done
done </tmp/package-dirs
sort -u /tmp/notice-dirs >/tmp/unique-notice-dirs
while IFS="$(printf '\t')" read -r dir relative; do
    for notice in "$dir"/LICENSE* "$dir"/LICENCE* "$dir"/COPYING* "$dir"/NOTICE* "$dir"/PATENTS; do
        if [ -f "$notice" ]; then
            install -D -m 0644 "$notice" "/notices/$relative/$(basename "$notice")"
        fi
    done
done </tmp/unique-notice-dirs
test -s /notices/modules/golang.org/x/crypto@v0.59.0/LICENSE
SH

FROM gcr.io/distroless/static-debian13@sha256:d03c145fad326bff275ec4106475ed8310426caf709decd9f8cbc494af59bc18
LABEL org.opencontainers.image.version="3.6.17" \
      org.trusted-mlsecops-platform.etcd.upstream-revision="0689586e360e2c6b46f95ad5634c25d5fa1683db" \
      org.opencontainers.image.source="https://github.com/Abrakadabra124/trusted-mlsecops-platform" \
      org.opencontainers.image.url="https://github.com/etcd-io/etcd/releases/tag/v3.6.17" \
      org.trusted-mlsecops-platform.etcd.patch="x-crypto-v0.59.0-r1"
COPY --from=build /out/ /usr/local/bin/
COPY --from=build /notices/ /usr/share/licenses/
COPY --from=build /src/LICENSE /usr/share/licenses/etcd/LICENSE
COPY --from=build /usr/local/go/LICENSE /usr/share/licenses/go/LICENSE
WORKDIR /var/etcd/
WORKDIR /var/lib/etcd/
EXPOSE 2379 2380
CMD ["/usr/local/bin/etcd"]
