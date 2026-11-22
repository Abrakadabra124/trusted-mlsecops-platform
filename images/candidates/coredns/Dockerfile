FROM registry.k8s.io/coredns/coredns@sha256:3429e3bbffb1e839470c4a3541d4d78aca84a1394c75a539d0200c58c63196ac AS baseline
FROM docker.io/library/golang@sha256:fb7cceb528b47141eccd9b60bf3cbd27d5ef5f8cf5b7d338bec866da495b50dc AS build
ENV GOENV=off GOTOOLCHAIN=local GOWORK=off GOFLAGS=-mod=readonly \
    GOOS=linux GOARCH=amd64 GOAMD64=v1 CGO_ENABLED=0 \
    GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org
WORKDIR /src
RUN <<'SH'
set -eu
test "$(go env GOVERSION)" = go1.27.4
rev=a6fde3fe339c6ec848447e11cc9796be8c97b4e0
curl -fsSL --retry 3 "https://codeload.github.com/coredns/coredns/tar.gz/$rev" -o /tmp/src.tgz
echo '94c2c332ce7cdd724da9caead82e145b322e0d0590f77984c252dd659bf335c0  /tmp/src.tgz' | sha256sum -c -
tar -xzf /tmp/src.tgz --strip-components=1
git init -q .
git fetch -q --depth=1 https://github.com/coredns/coredns.git refs/tags/v1.15.0:refs/tags/v1.15.0
test "$(git rev-parse 'v1.15.0^{commit}')" = "$rev"
git reset --mixed -q "$rev"
test -z "$(git status --porcelain)"
test "$(cat .go-version)" = 1.27.3
SH

RUN <<'SH'
set -eu
go mod edit -require=github.com/klauspost/compress@v1.20.2 \
  -require=golang.org/x/crypto@v0.59.0 -require=golang.org/x/net@v0.62.0 \
  -require=golang.org/x/sys@v0.50.0 -require=golang.org/x/term@v0.48.0 \
  -require=golang.org/x/text@v0.44.0 -require=golang.org/x/mod@v0.42.0 -require=golang.org/x/sync@v0.25.0
cat >>go.sum <<'SUM'
github.com/klauspost/compress v1.20.2 h1:v5tiZvm1KGLyg5d5oXdXe3lsSPrbEUiKoXGia//I7Qo=
github.com/klauspost/compress v1.20.2/go.mod h1:LUdAzn7YLVvxLpc7y3V1m40wESHTgc1422pwwBSKYuI=
golang.org/x/crypto v0.59.0 h1:xS2jhqYbzNrpvkWP2YTDf4TJwBy3ykR03i8vFDxEc7c=
golang.org/x/crypto v0.59.0/go.mod h1:veDyUwATGs3c+vN3VfTbzViMGXeTBk3WyhBOkn+F/4U=
golang.org/x/mod v0.42.0 h1:ICeL3t2L30ljSPHHxDnR4fqVcBt/zR2zJAb9juavmQg=
golang.org/x/mod v0.42.0/go.mod h1:u5fzIrRInkL8MaO1cbRkUHT64v303YIT5KEqpNr7jRs=
golang.org/x/net v0.62.0 h1:18ELalfM5+XNRwzM2nYqXsZQ9ByS1uhj2O/U7+5jqRY=
golang.org/x/net v0.62.0/go.mod h1:WgDCOTH8iwtB66T4/GfI94AHo/hhdb7Hah9NDseQfiI=
golang.org/x/sync v0.25.0 h1:dJnifr0nMV8/SBnBvdo4eSGGnrc3O4FFx6IqvtLcmRs=
golang.org/x/sync v0.25.0/go.mod h1:sUUOizhqBxiL6pEWpqNLUiaJn1ShEbZ6BBqskPbjZm0=
golang.org/x/sys v0.50.0 h1:dkKZEFTEKaLr1sjhs0WiKqoi8Jj5nHbS3Njmx1UoMJs=
golang.org/x/sys v0.50.0/go.mod h1:hNLxWAXmnKAxqDtdwIYC4bM9oQPEecfsnNMuSxOs3og=
golang.org/x/term v0.48.0 h1:G6UU1eiSB8nl3DzeUGt7Mg+2SctI8tPS6Z5/mBt6cOk=
golang.org/x/term v0.48.0/go.mod h1:BRDLHCZr2SUjIeBHHpRyQeC9xzSAVbzY2rvKgafnHf4=
golang.org/x/text v0.44.0 h1:YItdp/mQNGnsmrgpcdA5yQ3bnRxCfo/Tj/iByGW9GGo=
golang.org/x/text v0.44.0/go.mod h1:S4FR1waQ9LbjQTls97SyRjDaUUVkaM+cXwwuG/G+MwY=
golang.org/x/tools v0.52.0 h1:ryxg4U63oaUYk7uOLTF37n43f4qgtGvqV4Ioit1BaEs=
golang.org/x/tools v0.52.0/go.mod h1:ItcP5UNaVGG+Yc4eIYmaFLNJ4soEopkx5Y2d4lcEurs=
SUM
cat >/tmp/manifest-pins <<'PINS'
e3df235366f4da30e9cd885cc749362b3a99cad56735a645102e81facdbbdc05  go.mod
5cde768da02a5de3775066ac090eb019f2ab16765d32e74d5ee627d049d76d6a  go.sum
PINS
sha256sum -c /tmp/manifest-pins
go list -tags=grpcnotrace -deps . >/tmp/linked-packages
if grep -Eq '^golang\.org/x/crypto/openpgp(/|$)' /tmp/linked-packages; then exit 1; fi
go mod verify
sha256sum -c /tmp/manifest-pins
SH

COPY --from=baseline /coredns /tmp/official-coredns
RUN --network=none <<'SH'
set -eu
export GOPROXY=off
mkdir /out
for attempt in first second; do
  GOCACHE="/tmp/cache-$attempt" go build -mod=readonly -buildvcs=true -trimpath \
    -tags=grpcnotrace -ldflags='-s -w -X github.com/coredns/coredns/coremain.GitCommit=a6fde3f-patched' \
    -o "/tmp/$attempt" .
  GOCACHE="/tmp/cache-$attempt" go clean -cache
done
cmp /tmp/first /tmp/second
install -m0755 /tmp/first /out/coredns
cp --attributes-only --preserve=xattr /tmp/official-coredns /out/coredns
cmp /tmp/first /out/coredns
go version -m /out/coredns >/tmp/buildinfo
test "$(head -n1 /tmp/buildinfo)" = '/out/coredns: go1.27.4'
go list -mod=readonly -tags=grpcnotrace -deps . >/tmp/offline-imports
LC_ALL=C sort /tmp/offline-imports >/tmp/sorted-imports
echo '1b075628aba0c1e1d53b377a635bac2e48d19e30a4ffe5a0569baf1620bd23a5  /tmp/sorted-imports' | sha256sum -c -
awk '$1=="dep" {print $2, $3, $4}' /tmp/buildinfo | LC_ALL=C sort >/tmp/deps
echo 'ba442d8830f85812d71ec981d11d5fbd6b80f917603578802b7bf0ee98cfef88  /tmp/deps' | sha256sum -c -
if grep -Eq '^[[:space:]]*=>' /tmp/buildinfo; then exit 1; fi
awk '$1=="mod" {n++; if ($2!="github.com/coredns/coredns" || $3!="v1.15.0+dirty") exit 1}
     END {if (n!=1) exit 1}' /tmp/buildinfo
for pair in 'github.com/klauspost/compress v1.20.2' 'golang.org/x/net v0.62.0' 'golang.org/x/crypto v0.59.0'; do
  awk -v pair="$pair" '$1=="dep" && $2 " " $3 == pair {n++} END {exit n!=1}' /tmp/buildinfo
done
grep -Fqx "$(printf '\tbuild\tvcs.revision=a6fde3fe339c6ec848447e11cc9796be8c97b4e0')" /tmp/buildinfo
grep -Fqx "$(printf '\tbuild\tvcs.modified=true')" /tmp/buildinfo
sha256sum -c /tmp/manifest-pins
sha256sum /out/coredns | tee /tmp/coredns.sha256
cat /tmp/buildinfo
SH

FROM scratch AS evidence
COPY --from=build /tmp/coredns.sha256 /coredns.sha256

FROM baseline
COPY --from=build /out/coredns /coredns
