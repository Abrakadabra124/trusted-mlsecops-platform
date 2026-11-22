ARG SOURCE_DATE_EPOCH=1785898268
FROM docker.io/kindest/local-path-provisioner@sha256:77ab4466418c90f8a651cdec58ef864977eeb755c3ec83791c1d4b0d9259c938 AS stock
FROM docker.io/library/golang@sha256:fb7cceb528b47141eccd9b60bf3cbd27d5ef5f8cf5b7d338bec866da495b50dc AS build
ARG SOURCE_DATE_EPOCH
ENV GOENV=off GOTOOLCHAIN=local GOWORK=off GOFLAGS=-mod=readonly \
    GOOS=linux GOARCH=amd64 GOAMD64=v1 CGO_ENABLED=0 \
    GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org LC_ALL=C
WORKDIR /src
RUN <<'SOURCE'
set -eu
test "$(go env GOVERSION)" = go1.27.4
rev=49b2be8e26d6d34c9afaa21fa33108d2e82f8955
curl -fsSL --retry 3 "https://codeload.github.com/rancher/local-path-provisioner/tar.gz/$rev" -o /tmp/upstream.tgz
echo '2b95efae90cd01de97dd9809739d24b0ad2ccaded6e86e308f71733b690b3de8  /tmp/upstream.tgz' | sha256sum -c -
tar -xzf /tmp/upstream.tgz --strip-components=1
git init -q .
git fetch -q --depth=1 https://github.com/rancher/local-path-provisioner.git refs/tags/v0.0.37:refs/tags/v0.0.37
test "$(git rev-parse 'v0.0.37^{commit}')" = "$rev"
git reset -q --mixed "$rev"
test "$(git show -s --format=%ct HEAD)" = "$SOURCE_DATE_EPOCH"
test -z "$(git status --porcelain)"
SOURCE

# Select only the three updated modules and their required indirect version increases.
# The unchanged modules retain the sums in the exact upstream tree.
RUN <<'ACQUIRE'
set -eu
go mod edit -require=github.com/klauspost/compress@v1.20.2 \
    -require=golang.org/x/net@v0.62.0 -require=golang.org/x/text@v0.43.0 \
    -require=golang.org/x/mod@v0.41.0 -require=golang.org/x/sync@v0.24.0 \
    -require=golang.org/x/sys@v0.49.0 -require=golang.org/x/term@v0.47.0 \
    -require=golang.org/x/tools@v0.51.0
cat >>go.sum <<'SUM'
github.com/klauspost/compress v1.20.2 h1:v5tiZvm1KGLyg5d5oXdXe3lsSPrbEUiKoXGia//I7Qo=
github.com/klauspost/compress v1.20.2/go.mod h1:LUdAzn7YLVvxLpc7y3V1m40wESHTgc1422pwwBSKYuI=
golang.org/x/mod v0.41.0 h1:qJmnOUb4YB+FsEuM3HcWucdZASCPGhsX6uljO6pog0c=
golang.org/x/mod v0.41.0/go.mod h1:Ek9pY8RKWXwsWvd3rQiHYtMqkjSUV+s1Rj7j4H5Ur6o=
golang.org/x/net v0.62.0 h1:18ELalfM5+XNRwzM2nYqXsZQ9ByS1uhj2O/U7+5jqRY=
golang.org/x/net v0.62.0/go.mod h1:WgDCOTH8iwtB66T4/GfI94AHo/hhdb7Hah9NDseQfiI=
golang.org/x/sync v0.24.0 h1:iqiDrGoDgyuvAKrhLQthUEzU/R378N78gXbBjxed7oA=
golang.org/x/sync v0.24.0/go.mod h1:sUUOizhqBxiL6pEWpqNLUiaJn1ShEbZ6BBqskPbjZm0=
golang.org/x/sys v0.49.0 h1:XbzkgYJHdqh/8m2Uu0W/dQv8nktxx4BFHp1M0gROTXA=
golang.org/x/sys v0.49.0/go.mod h1:hNLxWAXmnKAxqDtdwIYC4bM9oQPEecfsnNMuSxOs3og=
golang.org/x/term v0.47.0 h1:cpyOwQkr2Nzxe2p6KnrTG7Ei2wtzjsuSjhpXXepZ/BM=
golang.org/x/term v0.47.0/go.mod h1:efAfAuG6RKABvg1ArGebRkvX6LXul14SM67o2e4mUCY=
golang.org/x/text v0.43.0 h1:1QivrlhwAsnMOcqgOdl9my7s9OyZl8O5/UGUTJVXoWc=
golang.org/x/text v0.43.0/go.mod h1:hbSIYA/amXcRXTFSZqh8tWHEoqRvvbKPJ2uz/KU+a+s=
golang.org/x/tools v0.51.0 h1:k4Xc/1Om9jwkBJBo4NVLMSARBoWtK10mx+W5BnXCeAI=
golang.org/x/tools v0.51.0/go.mod h1:9eEncMayCV6zRMGhR5eZEC2iBx98qWcF1HZ9Z7wJOoA=
SUM
cat >/tmp/manifests.sha256 <<'PINS'
48fb11764cdc0254b9da0431cc7986b58ac9394b0f4c703c293566b0bb080ae8  go.mod
4ab8f4d4cc50083be729230da4ea0ccb64db55f46fabf2b02bc5d747d6138189  go.sum
PINS
sha256sum -c /tmp/manifests.sha256
go list -mod=readonly -deps . >/tmp/packages
go mod verify
sha256sum -c /tmp/manifests.sha256
ACQUIRE

RUN --network=none <<'BUILD'
#!/bin/bash
set -euo pipefail
export GOPROXY=off
mkdir /out /evidence
go mod verify
go list -mod=readonly -deps . | sort >/evidence/imports
echo '8905aad3703d96eb5fa727cd06fdb9d69510ff6ef4e9be44a83052ddfdd32719  /evidence/imports' | sha256sum -c -
for attempt in first second; do
    GOCACHE="/tmp/cache-$attempt" go build -mod=readonly -trimpath -buildvcs=true \
        -ldflags='-s -w -buildid= -X main.VERSION=v0.0.37+deps.r1' -o "/tmp/$attempt" .
    GOCACHE="/tmp/cache-$attempt" go clean -cache
done
cmp /tmp/first /tmp/second
install -m0755 /tmp/first /out/local-path-provisioner
cd /out
sha256sum local-path-provisioner | tee /evidence/binary.sha256
go version -m local-path-provisioner >/evidence/buildinfo
info=/evidence/buildinfo
test "$(head -n1 "$info")" = 'local-path-provisioner: go1.27.4'
awk -F '\t' '$2=="mod" { n++; if ($3!="github.com/rancher/local-path-provisioner" || $4!="v0.0.37+dirty") bad=1 }
             END { exit (n!=1 || bad) }' "$info"
grep -Fxq $'\tpath\tgithub.com/rancher/local-path-provisioner' "$info"
grep -Fxq $'\tbuild\tvcs.revision=49b2be8e26d6d34c9afaa21fa33108d2e82f8955' "$info"
grep -Fxq $'\tbuild\tvcs.modified=true' "$info"
grep -Fxq $'\tbuild\tCGO_ENABLED=0' "$info"
if grep -q '^[[:space:]]*=>' "$info"; then exit 1; fi
awk '$1=="dep" { print $2, $3, $4 }' "$info" | sort >/evidence/modules
echo '0c46948e3d47ceda67b8df46140e6b088e00e55eb6e06f38fa1e4bbd51d9624b  /evidence/modules' | sha256sum -c -
readelf -lW local-path-provisioner >/tmp/segments
if grep -Eq '^[[:space:]]*(INTERP|DYNAMIC)[[:space:]]' /tmp/segments; then exit 1; fi
grep -aFq 'v0.0.37+deps.r1' local-path-provisioner
cd /src
sha256sum -c /tmp/manifests.sha256
test "$(git status --porcelain)" = "$(printf ' M go.mod\n M go.sum')"
BUILD

# Walk the directories of compiled packages up to their module roots. Keep
# original notice paths and contents, including package-specific licenses.
RUN --network=none <<'LICENSES'
#!/bin/bash
set -euo pipefail
export GOPROXY=off
goroot="$(go env GOROOT)"
go list -deps -f '{{.Dir}}|{{with .Module}}{{.Dir}}{{end}}' . >/tmp/package-dirs
while IFS='|' read -r dir root; do
    case "$root" in
        '') root="$goroot"; prefix=go ;;
        /src) prefix=local-path-provisioner ;;
        /go/pkg/mod/*) prefix="modules/${root#/go/pkg/mod/}" ;;
        *) exit 1 ;;
    esac
    while [[ "$dir" == "$root" || "$dir" == "$root/"* ]]; do
        printf '%s|%s%s\n' "$dir" "$prefix" "${dir#"$root"}"
        [[ "$dir" != "$root" ]] || break
        dir="$(dirname "$dir")"
    done
done </tmp/package-dirs | sort -u >/tmp/notice-dirs
shopt -s nullglob nocaseglob
while IFS='|' read -r dir relative; do
    for f in "$dir"/{license*,licence*,copying*,copyright*,notice*,patents,patents.*}; do
        [[ ! -L "$f" ]] || exit 1
        name="$(basename "$f")"
        dest="/notices/$relative/$name"
        if [[ -f "$f" && "$name" != *.go ]]; then
            install -D -m0644 "$f" "$dest"
        elif [[ -d "$f" ]]; then
            case "${name,,}" in
                licenses|licences|notices) mkdir -p "$dest"; cp -R "$f/." "$dest/" ;;
            esac
        fi
    done
done </tmp/notice-dirs
cd /notices
test -z "$(find . ! -type f ! -type d -print -quit)"
find . -type f -print0 | sort -z | xargs -0 sha256sum >/evidence/licenses.sha256
echo '87aef4cec3568c3bbb8cd3a84ce7a00d8a3c68beec887625e5e0ea90512f5abe  /evidence/licenses.sha256' | sha256sum -c -
find . -type f -exec chmod 0644 {} +
find . -type d -exec chmod 0755 {} +
find . /out -exec touch -d "@$SOURCE_DATE_EPOCH" {} +
LICENSES

FROM scratch AS evidence
COPY --from=build /evidence/ /

FROM stock
COPY --from=build --chown=0:0 --chmod=0755 /out/local-path-provisioner /usr/local/bin/local-path-provisioner
COPY --from=build --chown=0:0 /notices/ /usr/share/licenses/local-path-provisioner-r1/
