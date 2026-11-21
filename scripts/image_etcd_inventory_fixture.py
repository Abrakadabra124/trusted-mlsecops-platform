"""Independent package inputs from the pinned etcd linux/amd64 filesystem.

Go rows retain the mod/dep record, declared version and any following local
replacement, in ELF order. The final column of a replace is its embedded version.
The six Debian records come from /var/lib/dpkg/status.d. Each corresponding
md5sums and copyright path exists in the checked layers. Qualification only.
"""

from scripts.image_audit_contract import SYFT_VERSION, observe_packages

_CONFIG = "sha256:be2dd319600bac16f542b8e46e1b78511c35a31e46829ee9acc82a83c94aa377"
_DEB = (
    ("base-files", "13.8+deb13u7"),
    ("ca-certificates", "20250419+deb13u1"),
    ("media-types", "13.0.0"),
    ("netbase", "6.5"),
    ("tzdata", "2026f-0+deb13u1"),
    ("tzdata-legacy", "2026f-0+deb13u1"),
)
_BUILDINFO = {
    "/usr/local/bin/etcd": """\
go1.26.11
mod go.etcd.io/etcd/server/v3 v3.6.17
dep github.com/beorn7/perks v1.0.1
dep github.com/cenkalti/backoff/v5 v5.0.3
dep github.com/cespare/xxhash/v2 v2.3.0
dep github.com/coreos/go-semver v0.3.1
dep github.com/coreos/go-systemd/v22 v22.5.0
dep github.com/dustin/go-humanize v1.0.1
dep github.com/go-logr/logr v1.4.4
dep github.com/go-logr/stdr v1.2.2
dep github.com/gogo/protobuf v1.3.2
dep github.com/golang-jwt/jwt/v5 v5.2.2
dep github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da
dep github.com/golang/protobuf v1.5.4
dep github.com/google/btree v1.1.3
dep github.com/google/go-cmp v0.7.0
dep github.com/google/uuid v1.6.0
dep github.com/gorilla/websocket v1.5.3
dep github.com/grpc-ecosystem/go-grpc-middleware v1.3.0
dep github.com/grpc-ecosystem/go-grpc-middleware/providers/prometheus v1.0.1
dep github.com/grpc-ecosystem/go-grpc-middleware/v2 v2.1.0
dep github.com/grpc-ecosystem/grpc-gateway/v2 v2.29.0
dep github.com/jonboulle/clockwork v0.5.0
dep github.com/klauspost/compress v1.20.2
dep github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822
dep github.com/prometheus/client_golang v1.20.5
dep github.com/prometheus/client_model v0.6.1
dep github.com/prometheus/common v0.62.0
dep github.com/prometheus/procfs v0.15.1
dep github.com/sirupsen/logrus v1.9.4
dep github.com/soheilhy/cmux v0.1.5
dep github.com/spf13/cobra v1.10.2
dep github.com/spf13/pflag v1.0.10
dep github.com/tmc/grpc-websocket-proxy v0.0.0-20201229170055-e5319fda7802
dep github.com/xiang90/probing v0.0.0-20190116061207-43a291ad63a2
dep go.etcd.io/bbolt v1.4.3
dep go.etcd.io/etcd/api/v3 v3.6.17 => ../api (devel)
dep go.etcd.io/etcd/client/pkg/v3 v3.6.17 => ../client/pkg (devel)
dep go.etcd.io/etcd/client/v3 v3.6.17 => ../client/v3 (devel)
dep go.etcd.io/etcd/pkg/v3 v3.6.17 => ../pkg (devel)
dep go.etcd.io/raft/v3 v3.6.0
dep go.opentelemetry.io/auto/sdk v1.2.1
dep go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.59.0
dep go.opentelemetry.io/otel v1.45.0
dep go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.45.0
dep go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.45.0
dep go.opentelemetry.io/otel/metric v1.45.0
dep go.opentelemetry.io/otel/sdk v1.45.0
dep go.opentelemetry.io/otel/trace v1.45.0
dep go.opentelemetry.io/proto/otlp v1.11.0
dep go.uber.org/multierr v1.11.0
dep go.uber.org/zap v1.27.0
dep golang.org/x/crypto v0.58.0
dep golang.org/x/net v0.62.0
dep golang.org/x/sys v0.49.0
dep golang.org/x/text v0.43.0
dep golang.org/x/time v0.9.0
dep google.golang.org/genproto/googleapis/api v0.0.0-20260803160001-6ac0973c030d
dep google.golang.org/genproto/googleapis/rpc v0.0.0-20260803160001-6ac0973c030d
dep google.golang.org/grpc v1.83.2
dep google.golang.org/protobuf v1.36.11
dep gopkg.in/natefinch/lumberjack.v2 v2.2.1
dep sigs.k8s.io/json v0.0.0-20211020170558-c049b76a60c6
dep sigs.k8s.io/yaml v1.4.0
""",
    "/usr/local/bin/etcdctl": """\
go1.26.11
mod go.etcd.io/etcd/etcdctl/v3 v3.6.17
dep github.com/VividCortex/ewma v1.2.0
dep github.com/bgentry/speakeasy v0.2.0
dep github.com/cheggaaa/pb/v3 v3.1.6
dep github.com/coreos/go-semver v0.3.1
dep github.com/coreos/go-systemd/v22 v22.5.0
dep github.com/dustin/go-humanize v1.0.1
dep github.com/fatih/color v1.18.0
dep github.com/gogo/protobuf v1.3.2
dep github.com/golang/protobuf v1.5.4
dep github.com/grpc-ecosystem/grpc-gateway/v2 v2.29.0
dep github.com/mattn/go-colorable v0.1.14
dep github.com/mattn/go-isatty v0.0.20
dep github.com/mattn/go-runewidth v0.0.16
dep github.com/olekukonko/tablewriter v0.0.5
dep github.com/rivo/uniseg v0.4.7
dep github.com/spf13/cobra v1.10.2
dep github.com/spf13/pflag v1.0.10
dep go.etcd.io/etcd/api/v3 v3.6.17 => ../api (devel)
dep go.etcd.io/etcd/client/pkg/v3 v3.6.17 => ../client/pkg (devel)
dep go.etcd.io/etcd/client/v3 v3.6.17 => ../client/v3 (devel)
dep go.etcd.io/etcd/pkg/v3 v3.6.17 => ../pkg (devel)
dep go.uber.org/multierr v1.11.0
dep go.uber.org/zap v1.27.0
dep golang.org/x/net v0.62.0
dep golang.org/x/sys v0.49.0
dep golang.org/x/text v0.43.0
dep golang.org/x/time v0.9.0
dep google.golang.org/genproto/googleapis/api v0.0.0-20260803160001-6ac0973c030d
dep google.golang.org/genproto/googleapis/rpc v0.0.0-20260803160001-6ac0973c030d
dep google.golang.org/grpc v1.83.2
dep google.golang.org/protobuf v1.36.11
""",
    "/usr/local/bin/etcdutl": """\
go1.26.11
mod go.etcd.io/etcd/etcdutl/v3 v3.6.17
dep github.com/beorn7/perks v1.0.1
dep github.com/cespare/xxhash/v2 v2.3.0
dep github.com/coreos/go-semver v0.3.1
dep github.com/coreos/go-systemd/v22 v22.5.0
dep github.com/dustin/go-humanize v1.0.1
dep github.com/go-logr/logr v1.4.4
dep github.com/go-logr/stdr v1.2.2
dep github.com/gogo/protobuf v1.3.2
dep github.com/golang-jwt/jwt/v5 v5.2.2
dep github.com/golang/protobuf v1.5.4
dep github.com/google/btree v1.1.3
dep github.com/google/go-cmp v0.7.0
dep github.com/grpc-ecosystem/grpc-gateway/v2 v2.29.0
dep github.com/jonboulle/clockwork v0.5.0
dep github.com/mattn/go-runewidth v0.0.16
dep github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822
dep github.com/olekukonko/tablewriter v0.0.5
dep github.com/prometheus/client_golang v1.20.5
dep github.com/prometheus/client_model v0.6.1
dep github.com/prometheus/common v0.62.0
dep github.com/prometheus/procfs v0.15.1
dep github.com/rivo/uniseg v0.4.7
dep github.com/spf13/cobra v1.10.2
dep github.com/spf13/pflag v1.0.10
dep github.com/xiang90/probing v0.0.0-20190116061207-43a291ad63a2
dep go.etcd.io/bbolt v1.4.3
dep go.etcd.io/etcd/api/v3 v3.6.17 => ../api (devel)
dep go.etcd.io/etcd/client/pkg/v3 v3.6.17 => ../client/pkg (devel)
dep go.etcd.io/etcd/client/v3 v3.6.17 => ../client/v3 (devel)
dep go.etcd.io/etcd/pkg/v3 v3.6.17 => ../pkg (devel)
dep go.etcd.io/etcd/server/v3 v3.6.17 => ../server (devel)
dep go.etcd.io/raft/v3 v3.6.0
dep go.opentelemetry.io/auto/sdk v1.2.1
dep go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.59.0
dep go.opentelemetry.io/otel v1.45.0
dep go.opentelemetry.io/otel/metric v1.45.0
dep go.opentelemetry.io/otel/trace v1.45.0
dep go.uber.org/multierr v1.11.0
dep go.uber.org/zap v1.27.0
dep golang.org/x/crypto v0.58.0
dep golang.org/x/net v0.62.0
dep golang.org/x/sys v0.49.0
dep golang.org/x/text v0.43.0
dep golang.org/x/time v0.9.0
dep google.golang.org/genproto/googleapis/api v0.0.0-20260803160001-6ac0973c030d
dep google.golang.org/genproto/googleapis/rpc v0.0.0-20260803160001-6ac0973c030d
dep google.golang.org/grpc v1.83.2
dep google.golang.org/protobuf v1.36.11
dep sigs.k8s.io/json v0.0.0-20211020170558-c049b76a60c6
""",
}


def sbom():
    """Return a fresh Syft input with artifact IDs and locations for join qualification."""
    artifacts = []

    def add(kind, name, version, cataloger, paths):
        artifacts.append(
            {
                "id": str(len(artifacts)),
                "name": name,
                "type": kind,
                "version": version,
                "foundBy": cataloger,
                "locations": [{"path": p} for p in paths],
            }
        )

    for path, records in _BUILDINFO.items():
        go_version, *modules = records.splitlines()
        add("go-module", "stdlib", go_version, "go-module-binary-cataloger", [path])
        for line in modules:
            kind, name, version, *replace = line.split()
            assert kind in ("mod", "dep")
            if replace:
                arrow, target, embedded = replace
                assert (
                    kind == "dep"
                    and arrow == "=>"
                    and target.startswith("../")
                    and embedded == "(devel)"
                )
                version = "UNKNOWN"
            add("go-module", name, version, "go-module-binary-cataloger", [path])
    for name, version in _DEB:
        status = f"/var/lib/dpkg/status.d/{name}"
        add(
            "deb",
            name,
            version,
            "dpkg-db-cataloger",
            [
                status,
                status + ".md5sums",
                f"/usr/share/doc/{name}/copyright",
            ],
        )
    return {
        "descriptor": {"name": "syft", "version": SYFT_VERSION},
        "source": {"type": "image", "metadata": {"imageID": _CONFIG}},
        "distro": {"id": "debian", "versionID": "13.7"},
        "artifacts": artifacts,
    }


def observation():
    return observe_packages(sbom(), _CONFIG)
