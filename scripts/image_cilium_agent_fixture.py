"""Normalized native runtime-005 package observation from run 44959047516, in original row order.

Each row contains package type, name, version and every catalogued path.
Only the two repeated cataloger names are expanded on read. Qualification data.
"""

_ROWS = """\
deb apt 3.2.1ubuntu0.1 /usr/share/doc/apt/copyright /var/lib/dpkg/info/apt.conffiles /var/lib/dpkg/info/apt.list /var/lib/dpkg/info/apt.md5sums /var/lib/dpkg/info/apt.postinst /var/lib/dpkg/info/apt.postrm /var/lib/dpkg/info/apt.preinst /var/lib/dpkg/info/apt.prerm /var/lib/dpkg/info/apt.shlibs /var/lib/dpkg/info/apt.triggers /var/lib/dpkg/status
deb base-files 14ubuntu6.3 /usr/share/doc/base-files/copyright /var/lib/dpkg/info/base-files.conffiles /var/lib/dpkg/info/base-files.list /var/lib/dpkg/info/base-files.md5sums /var/lib/dpkg/info/base-files.postinst /var/lib/dpkg/info/base-files.postrm /var/lib/dpkg/info/base-files.preinst /var/lib/dpkg/info/base-files.prerm /var/lib/dpkg/info/base-files.triggers /var/lib/dpkg/status
deb base-passwd 3.6.8 /usr/share/doc/base-passwd/copyright /var/lib/dpkg/info/base-passwd.list /var/lib/dpkg/info/base-passwd.md5sums /var/lib/dpkg/info/base-passwd.postinst /var/lib/dpkg/info/base-passwd.postrm /var/lib/dpkg/info/base-passwd.preinst /var/lib/dpkg/info/base-passwd.templates /var/lib/dpkg/status
deb bash 5.3-2ubuntu1 /usr/share/doc/bash/copyright /var/lib/dpkg/info/bash.conffiles /var/lib/dpkg/info/bash.list /var/lib/dpkg/info/bash.md5sums /var/lib/dpkg/info/bash.postinst /var/lib/dpkg/info/bash.postrm /var/lib/dpkg/info/bash.prerm /var/lib/dpkg/status
deb bash-completion 1:2.16.0-8build1 /usr/share/doc/bash-completion/copyright /var/lib/dpkg/info/bash-completion.conffiles /var/lib/dpkg/info/bash-completion.list /var/lib/dpkg/info/bash-completion.md5sums /var/lib/dpkg/status
deb bsdutils 1:2.41.3-3ubuntu2.2 /usr/share/doc/bsdutils/copyright /var/lib/dpkg/info/bsdutils.list /var/lib/dpkg/info/bsdutils.md5sums /var/lib/dpkg/status
deb ca-certificates 20260816ubuntu0.26.04.2 /usr/share/doc/ca-certificates/copyright /var/lib/dpkg/info/ca-certificates.config /var/lib/dpkg/info/ca-certificates.list /var/lib/dpkg/info/ca-certificates.md5sums /var/lib/dpkg/info/ca-certificates.postinst /var/lib/dpkg/info/ca-certificates.postrm /var/lib/dpkg/info/ca-certificates.prerm /var/lib/dpkg/info/ca-certificates.templates /var/lib/dpkg/info/ca-certificates.triggers /var/lib/dpkg/status
go-module cel.dev/expr v0.25.2 /usr/bin/cilium-agent
go-module cel.dev/expr v0.25.2 /usr/bin/cilium-dbg
go-module cel.dev/expr v0.25.2 /usr/bin/hubble
deb coreutils 9.5-1ubuntu2+0.0.0~ubuntu25 /usr/share/doc/coreutils/copyright /var/lib/dpkg/info/coreutils.list /var/lib/dpkg/info/coreutils.md5sums /var/lib/dpkg/status
deb coreutils-from-uutils 0.0.0~ubuntu25 /usr/share/doc/coreutils-from-uutils/copyright /var/lib/dpkg/info/coreutils-from-uutils.list /var/lib/dpkg/info/coreutils-from-uutils.md5sums /var/lib/dpkg/info/coreutils-from-uutils.postinst /var/lib/dpkg/info/coreutils-from-uutils.preinst /var/lib/dpkg/info/coreutils-from-uutils.prerm /var/lib/dpkg/status
deb dash 0.5.12-12ubuntu3 /usr/share/doc/dash/copyright /var/lib/dpkg/info/dash.list /var/lib/dpkg/info/dash.md5sums /var/lib/dpkg/info/dash.postinst /var/lib/dpkg/info/dash.postrm /var/lib/dpkg/info/dash.preinst /var/lib/dpkg/info/dash.prerm /var/lib/dpkg/info/dash.templates /var/lib/dpkg/status
deb debconf 1.5.92 /usr/share/doc/debconf/copyright /var/lib/dpkg/info/debconf.conffiles /var/lib/dpkg/info/debconf.config /var/lib/dpkg/info/debconf.list /var/lib/dpkg/info/debconf.md5sums /var/lib/dpkg/info/debconf.postinst /var/lib/dpkg/info/debconf.templates /var/lib/dpkg/status
deb debianutils 5.23.2build1 /usr/share/doc/debianutils/copyright /var/lib/dpkg/info/debianutils.list /var/lib/dpkg/info/debianutils.md5sums /var/lib/dpkg/info/debianutils.postinst /var/lib/dpkg/info/debianutils.postrm /var/lib/dpkg/info/debianutils.prerm /var/lib/dpkg/info/debianutils.triggers /var/lib/dpkg/status
deb diffutils 1:3.12-1ubuntu0.1 /usr/share/doc/diffutils/copyright /var/lib/dpkg/info/diffutils.list /var/lib/dpkg/info/diffutils.md5sums /var/lib/dpkg/status
deb dpkg 1.23.7ubuntu1 /usr/share/doc/dpkg/copyright /var/lib/dpkg/info/dpkg.conffiles /var/lib/dpkg/info/dpkg.list /var/lib/dpkg/info/dpkg.md5sums /var/lib/dpkg/info/dpkg.postinst /var/lib/dpkg/info/dpkg.postrm /var/lib/dpkg/info/dpkg.prerm /var/lib/dpkg/status
deb e2fsprogs 1.47.2-3ubuntu4 /usr/share/doc/e2fsprogs/copyright /var/lib/dpkg/info/e2fsprogs.conffiles /var/lib/dpkg/info/e2fsprogs.list /var/lib/dpkg/info/e2fsprogs.md5sums /var/lib/dpkg/info/e2fsprogs.postinst /var/lib/dpkg/info/e2fsprogs.postrm /var/lib/dpkg/info/e2fsprogs.preinst /var/lib/dpkg/info/e2fsprogs.prerm /var/lib/dpkg/status
deb findutils 4.10.0-3build2 /usr/share/doc/findutils/copyright /var/lib/dpkg/info/findutils.list /var/lib/dpkg/info/findutils.md5sums /var/lib/dpkg/status
deb gcc-16-base 16-20260322-1ubuntu1 /usr/share/doc/gcc-16-base/copyright /var/lib/dpkg/info/gcc-16-base:amd64.md5sums /var/lib/dpkg/status
go-module github.com/antlr4-go/antlr/v4 v4.13.1 /usr/bin/cilium-agent
go-module github.com/antlr4-go/antlr/v4 v4.13.1 /usr/bin/cilium-dbg
go-module github.com/antlr4-go/antlr/v4 v4.13.1 /usr/bin/hubble
go-module github.com/aws/aws-sdk-go-v2 v1.42.0 /usr/bin/cilium-agent
go-module github.com/aws/aws-sdk-go-v2/config v1.32.25 /usr/bin/cilium-agent
go-module github.com/aws/aws-sdk-go-v2/credentials v1.19.24 /usr/bin/cilium-agent
go-module github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.29 /usr/bin/cilium-agent
go-module github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.29 /usr/bin/cilium-agent
go-module github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.29 /usr/bin/cilium-agent
go-module github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.30 /usr/bin/cilium-agent
go-module github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.12 /usr/bin/cilium-agent
go-module github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.29 /usr/bin/cilium-agent
go-module github.com/aws/aws-sdk-go-v2/service/signin v1.2.0 /usr/bin/cilium-agent
go-module github.com/aws/aws-sdk-go-v2/service/sso v1.31.3 /usr/bin/cilium-agent
go-module github.com/aws/aws-sdk-go-v2/service/ssooidc v1.36.6 /usr/bin/cilium-agent
go-module github.com/aws/aws-sdk-go-v2/service/sts v1.43.3 /usr/bin/cilium-agent
go-module github.com/aws/smithy-go v1.27.2 /usr/bin/cilium-agent
go-module github.com/beorn7/perks v1.0.1 /usr/bin/cilium-agent
go-module github.com/beorn7/perks v1.0.1 /usr/bin/cilium-dbg
go-module github.com/beorn7/perks v1.0.1 /usr/bin/hubble
go-module github.com/blang/semver/v4 v4.0.0 /opt/cni/bin/cilium-cni
go-module github.com/blang/semver/v4 v4.0.0 /usr/bin/cilium-agent
go-module github.com/blang/semver/v4 v4.0.0 /usr/bin/cilium-bugtool
go-module github.com/blang/semver/v4 v4.0.0 /usr/bin/cilium-dbg
go-module github.com/blang/semver/v4 v4.0.0 /usr/bin/cilium-health
go-module github.com/blang/semver/v4 v4.0.0 /usr/bin/hubble
go-module github.com/cespare/xxhash/v2 v2.3.0 /opt/cni/bin/cilium-cni
go-module github.com/cespare/xxhash/v2 v2.3.0 /usr/bin/cilium-agent
go-module github.com/cespare/xxhash/v2 v2.3.0 /usr/bin/cilium-dbg
go-module github.com/cespare/xxhash/v2 v2.3.0 /usr/bin/cilium-health
go-module github.com/cespare/xxhash/v2 v2.3.0 /usr/bin/hubble
go-module github.com/cilium/cilium v1.20.5 /usr/bin/cilium-agent
go-module github.com/cilium/cilium v1.20.5 /usr/bin/cilium-bugtool
go-module github.com/cilium/cilium v1.20.5 /usr/bin/cilium-dbg
go-module github.com/cilium/cilium v1.20.5 /usr/bin/cilium-envoy-bootstrap-locality
go-module github.com/cilium/cilium v1.20.5 /usr/bin/cilium-health
go-module github.com/cilium/cilium v1.20.5 /usr/bin/cilium-health-responder
go-module github.com/cilium/cilium v1.20.5 /usr/bin/cilium-mount
go-module github.com/cilium/cilium v1.20.5 /usr/bin/cilium-sysctlfix
go-module github.com/cilium/cilium v1.20.5+dirty /opt/cni/bin/cilium-cni
go-module github.com/cilium/cilium v1.20.5+dirty /usr/bin/hubble
go-module github.com/cilium/dns v1.1.51-0.20240603182237-af788769786a /usr/bin/cilium-agent
go-module github.com/cilium/dns v1.1.51-0.20240603182237-af788769786a /usr/bin/cilium-dbg
go-module github.com/cilium/ebpf v0.22.0 /opt/cni/bin/cilium-cni
go-module github.com/cilium/ebpf v0.22.0 /usr/bin/cilium-agent
go-module github.com/cilium/ebpf v0.22.0 /usr/bin/cilium-bugtool
go-module github.com/cilium/ebpf v0.22.0 /usr/bin/cilium-dbg
go-module github.com/cilium/ebpf v0.22.0 /usr/bin/cilium-health
go-module github.com/cilium/ebpf v0.22.0 /usr/bin/hubble
go-module github.com/cilium/hive v1.0.4 /opt/cni/bin/cilium-cni
go-module github.com/cilium/hive v1.0.4 /usr/bin/cilium-agent
go-module github.com/cilium/hive v1.0.4 /usr/bin/cilium-bugtool
go-module github.com/cilium/hive v1.0.4 /usr/bin/cilium-dbg
go-module github.com/cilium/hive v1.0.4 /usr/bin/cilium-health
go-module github.com/cilium/hive v1.0.4 /usr/bin/hubble
go-module github.com/cilium/lumberjack/v2 v2.4.2 /opt/cni/bin/cilium-cni
go-module github.com/cilium/lumberjack/v2 v2.4.2 /usr/bin/cilium-agent
go-module github.com/cilium/lumberjack/v2 v2.4.2 /usr/bin/cilium-dbg
go-module github.com/cilium/lumberjack/v2 v2.4.2 /usr/bin/hubble
go-module github.com/cilium/proxy v0.0.0-20260701124752-9c14fdc485a1 /usr/bin/cilium-agent
go-module github.com/cilium/proxy v0.0.0-20260701124752-9c14fdc485a1 /usr/bin/cilium-dbg
go-module github.com/cilium/statedb v0.8.5 /opt/cni/bin/cilium-cni
go-module github.com/cilium/statedb v0.8.5 /usr/bin/cilium-agent
go-module github.com/cilium/statedb v0.8.5 /usr/bin/cilium-dbg
go-module github.com/cilium/statedb v0.8.5 /usr/bin/hubble
go-module github.com/cilium/stream v0.0.1 /opt/cni/bin/cilium-cni
go-module github.com/cilium/stream v0.0.1 /usr/bin/cilium-agent
go-module github.com/cilium/stream v0.0.1 /usr/bin/cilium-dbg
go-module github.com/cilium/stream v0.0.1 /usr/bin/hubble
go-module github.com/cilium/workerpool v1.4.0 /usr/bin/cilium-agent
go-module github.com/cilium/workerpool v1.4.0 /usr/bin/cilium-bugtool
go-module github.com/cilium/workerpool v1.4.0 /usr/bin/cilium-dbg
go-module github.com/cloudflare/cfssl v1.6.5 /usr/bin/cilium-agent
go-module github.com/cloudflare/cfssl v1.6.5 /usr/bin/cilium-dbg
go-module github.com/cloudflare/cfssl v1.6.5 /usr/bin/hubble
go-module github.com/cncf/xds/go v0.0.0-20260202195803-dba9d589def2 /usr/bin/cilium-agent
go-module github.com/cncf/xds/go v0.0.0-20260202195803-dba9d589def2 /usr/bin/cilium-dbg
go-module github.com/containernetworking/cni v1.3.0 /opt/cni/bin/cilium-cni
go-module github.com/containernetworking/cni v1.3.0 /usr/bin/cilium-agent
go-module github.com/containernetworking/cni v1.3.0 /usr/bin/cilium-dbg
go-module github.com/containernetworking/cni v1.3.1 /cni/loopback
go-module github.com/containernetworking/plugins v1.10.0 /cni/loopback
go-module github.com/coreos/go-iptables v0.8.0 /usr/bin/cilium-agent
go-module github.com/coreos/go-semver v0.3.1 /usr/bin/cilium-agent
go-module github.com/coreos/go-semver v0.3.1 /usr/bin/cilium-dbg
go-module github.com/coreos/go-semver v0.3.1 /usr/bin/hubble
go-module github.com/coreos/go-systemd/v22 v22.7.0 /usr/bin/cilium-agent
go-module github.com/coreos/go-systemd/v22 v22.7.0 /usr/bin/cilium-dbg
go-module github.com/coreos/go-systemd/v22 v22.7.0 /usr/bin/cilium-sysctlfix
go-module github.com/coreos/go-systemd/v22 v22.7.0 /usr/bin/hubble
go-module github.com/cpuguy83/go-md2man/v2 v2.0.6 /usr/bin/cilium-agent
go-module github.com/cpuguy83/go-md2man/v2 v2.0.6 /usr/bin/cilium-bugtool
go-module github.com/cpuguy83/go-md2man/v2 v2.0.6 /usr/bin/cilium-dbg
go-module github.com/cpuguy83/go-md2man/v2 v2.0.6 /usr/bin/cilium-health
go-module github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc /opt/cni/bin/cilium-cni
go-module github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc /usr/bin/cilium-agent
go-module github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc /usr/bin/cilium-bugtool
go-module github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc /usr/bin/cilium-dbg
go-module github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc /usr/bin/cilium-envoy-bootstrap-locality
go-module github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc /usr/bin/cilium-health
go-module github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc /usr/bin/hubble
go-module github.com/dgryski/go-farm v0.0.0-20240924180020-3414d57e47da /usr/bin/cilium-agent
go-module github.com/eapache/channels v1.1.0 /usr/bin/cilium-agent
go-module github.com/eapache/queue v1.1.0 /usr/bin/cilium-agent
go-module github.com/emicklei/go-restful/v3 v3.13.0 /usr/bin/cilium-agent
go-module github.com/emicklei/go-restful/v3 v3.13.0 /usr/bin/cilium-dbg
go-module github.com/emicklei/go-restful/v3 v3.13.0 /usr/bin/cilium-envoy-bootstrap-locality
go-module github.com/emicklei/go-restful/v3 v3.13.0 /usr/bin/hubble
go-module github.com/envoyproxy/go-control-plane v0.14.0 /usr/bin/cilium-agent
go-module github.com/envoyproxy/go-control-plane/envoy v1.39.0 /usr/bin/cilium-agent
go-module github.com/envoyproxy/go-control-plane/envoy v1.39.0 /usr/bin/cilium-dbg
go-module github.com/envoyproxy/go-control-plane/ratelimit v0.1.0 /usr/bin/cilium-agent
go-module github.com/envoyproxy/protoc-gen-validate v1.3.3 /usr/bin/cilium-agent
go-module github.com/envoyproxy/protoc-gen-validate v1.3.3 /usr/bin/cilium-dbg
go-module github.com/fatih/color v1.19.0 /usr/bin/cilium-agent
go-module github.com/fatih/color v1.19.0 /usr/bin/cilium-dbg
go-module github.com/fatih/color v1.19.0 /usr/bin/hubble
go-module github.com/fsnotify/fsnotify v1.10.1 /opt/cni/bin/cilium-cni
go-module github.com/fsnotify/fsnotify v1.10.1 /usr/bin/cilium-agent
go-module github.com/fsnotify/fsnotify v1.10.1 /usr/bin/cilium-bugtool
go-module github.com/fsnotify/fsnotify v1.10.1 /usr/bin/cilium-dbg
go-module github.com/fsnotify/fsnotify v1.10.1 /usr/bin/cilium-health
go-module github.com/fsnotify/fsnotify v1.10.1 /usr/bin/hubble
go-module github.com/fxamacker/cbor/v2 v2.9.1 /opt/cni/bin/cilium-cni
go-module github.com/fxamacker/cbor/v2 v2.9.1 /usr/bin/cilium-agent
go-module github.com/fxamacker/cbor/v2 v2.9.1 /usr/bin/cilium-bugtool
go-module github.com/fxamacker/cbor/v2 v2.9.1 /usr/bin/cilium-dbg
go-module github.com/fxamacker/cbor/v2 v2.9.1 /usr/bin/cilium-envoy-bootstrap-locality
go-module github.com/fxamacker/cbor/v2 v2.9.1 /usr/bin/cilium-health
go-module github.com/fxamacker/cbor/v2 v2.9.1 /usr/bin/cilium-mount
go-module github.com/fxamacker/cbor/v2 v2.9.1 /usr/bin/hubble
go-module github.com/gaissmai/bart v0.26.1 /usr/bin/cilium-agent
go-module github.com/go-errors/errors v1.5.1 /usr/bin/hubble
go-module github.com/go-logr/logr v1.4.4 /opt/cni/bin/cilium-cni
go-module github.com/go-logr/logr v1.4.4 /usr/bin/cilium-agent
go-module github.com/go-logr/logr v1.4.4 /usr/bin/cilium-bugtool
go-module github.com/go-logr/logr v1.4.4 /usr/bin/cilium-dbg
go-module github.com/go-logr/logr v1.4.4 /usr/bin/cilium-envoy-bootstrap-locality
go-module github.com/go-logr/logr v1.4.4 /usr/bin/cilium-health
go-module github.com/go-logr/logr v1.4.4 /usr/bin/cilium-mount
go-module github.com/go-logr/logr v1.4.4 /usr/bin/hubble
go-module github.com/go-logr/stdr v1.2.2 /opt/cni/bin/cilium-cni
go-module github.com/go-logr/stdr v1.2.2 /usr/bin/cilium-agent
go-module github.com/go-logr/stdr v1.2.2 /usr/bin/cilium-dbg
go-module github.com/go-logr/stdr v1.2.2 /usr/bin/cilium-health
go-module github.com/go-logr/stdr v1.2.2 /usr/bin/hubble
go-module github.com/go-openapi/analysis v0.25.2 /opt/cni/bin/cilium-cni
go-module github.com/go-openapi/analysis v0.25.2 /usr/bin/cilium-agent
go-module github.com/go-openapi/analysis v0.25.2 /usr/bin/cilium-bugtool
go-module github.com/go-openapi/analysis v0.25.2 /usr/bin/cilium-dbg
go-module github.com/go-openapi/analysis v0.25.2 /usr/bin/cilium-health
go-module github.com/go-openapi/analysis v0.25.2 /usr/bin/hubble
go-module github.com/go-openapi/errors v0.22.8 /opt/cni/bin/cilium-cni
go-module github.com/go-openapi/errors v0.22.8 /usr/bin/cilium-agent
go-module github.com/go-openapi/errors v0.22.8 /usr/bin/cilium-bugtool
go-module github.com/go-openapi/errors v0.22.8 /usr/bin/cilium-dbg
go-module github.com/go-openapi/errors v0.22.8 /usr/bin/cilium-health
go-module github.com/go-openapi/errors v0.22.8 /usr/bin/hubble
go-module github.com/go-openapi/jsonpointer v0.23.1 /opt/cni/bin/cilium-cni
go-module github.com/go-openapi/jsonpointer v0.23.1 /usr/bin/cilium-agent
go-module github.com/go-openapi/jsonpointer v0.23.1 /usr/bin/cilium-bugtool
go-module github.com/go-openapi/jsonpointer v0.23.1 /usr/bin/cilium-dbg
go-module github.com/go-openapi/jsonpointer v0.23.1 /usr/bin/cilium-envoy-bootstrap-locality
go-module github.com/go-openapi/jsonpointer v0.23.1 /usr/bin/cilium-health
go-module github.com/go-openapi/jsonpointer v0.23.1 /usr/bin/hubble
go-module github.com/go-openapi/jsonreference v0.21.6 /opt/cni/bin/cilium-cni
go-module github.com/go-openapi/jsonreference v0.21.6 /usr/bin/cilium-agent
go-module github.com/go-openapi/jsonreference v0.21.6 /usr/bin/cilium-bugtool
go-module github.com/go-openapi/jsonreference v0.21.6 /usr/bin/cilium-dbg
go-module github.com/go-openapi/jsonreference v0.21.6 /usr/bin/cilium-envoy-bootstrap-locality
go-module github.com/go-openapi/jsonreference v0.21.6 /usr/bin/cilium-health
go-module github.com/go-openapi/jsonreference v0.21.6 /usr/bin/hubble
go-module github.com/go-openapi/loads v0.24.0 /opt/cni/bin/cilium-cni
go-module github.com/go-openapi/loads v0.24.0 /usr/bin/cilium-agent
go-module github.com/go-openapi/loads v0.24.0 /usr/bin/cilium-bugtool
go-module github.com/go-openapi/loads v0.24.0 /usr/bin/cilium-dbg
go-module github.com/go-openapi/loads v0.24.0 /usr/bin/cilium-health
go-module github.com/go-openapi/loads v0.24.0 /usr/bin/hubble
go-module github.com/go-openapi/runtime v0.32.4 /opt/cni/bin/cilium-cni
go-module github.com/go-openapi/runtime v0.32.4 /usr/bin/cilium-agent
go-module github.com/go-openapi/runtime v0.32.4 /usr/bin/cilium-dbg
go-module github.com/go-openapi/runtime v0.32.4 /usr/bin/cilium-health
go-module github.com/go-openapi/runtime v0.32.4 /usr/bin/hubble
go-module github.com/go-openapi/runtime/server-middleware v0.30.0 /opt/cni/bin/cilium-cni
go-module github.com/go-openapi/runtime/server-middleware v0.30.0 /usr/bin/cilium-agent
go-module github.com/go-openapi/runtime/server-middleware v0.30.0 /usr/bin/cilium-dbg
go-module github.com/go-openapi/runtime/server-middleware v0.30.0 /usr/bin/cilium-health
go-module github.com/go-openapi/runtime/server-middleware v0.30.0 /usr/bin/hubble
go-module github.com/go-openapi/spec v0.22.6 /opt/cni/bin/cilium-cni
go-module github.com/go-openapi/spec v0.22.6 /usr/bin/cilium-agent
go-module github.com/go-openapi/spec v0.22.6 /usr/bin/cilium-bugtool
go-module github.com/go-openapi/spec v0.22.6 /usr/bin/cilium-dbg
go-module github.com/go-openapi/spec v0.22.6 /usr/bin/cilium-health
go-module github.com/go-openapi/spec v0.22.6 /usr/bin/hubble
go-module github.com/go-openapi/strfmt v0.26.3 /opt/cni/bin/cilium-cni
go-module github.com/go-openapi/strfmt v0.26.3 /usr/bin/cilium-agent
go-module github.com/go-openapi/strfmt v0.26.3 /usr/bin/cilium-bugtool
go-module github.com/go-openapi/strfmt v0.26.3 /usr/bin/cilium-dbg
go-module github.com/go-openapi/strfmt v0.26.3 /usr/bin/cilium-health
go-module github.com/go-openapi/strfmt v0.26.3 /usr/bin/hubble
go-module github.com/go-openapi/swag v0.26.1 /usr/bin/cilium-agent
go-module github.com/go-openapi/swag v0.26.1 /usr/bin/cilium-dbg
go-module github.com/go-openapi/swag v0.26.1 /usr/bin/cilium-envoy-bootstrap-locality
go-module github.com/go-openapi/swag v0.26.1 /usr/bin/hubble
go-module github.com/go-openapi/swag/cmdutils v0.26.1 /usr/bin/cilium-agent
go-module github.com/go-openapi/swag/cmdutils v0.26.1 /usr/bin/cilium-dbg
go-module github.com/go-openapi/swag/cmdutils v0.26.1 /usr/bin/cilium-envoy-bootstrap-locality
go-module github.com/go-openapi/swag/cmdutils v0.26.1 /usr/bin/hubble
go-module github.com/go-openapi/swag/conv v0.26.1 /opt/cni/bin/cilium-cni
go-module github.com/go-openapi/swag/conv v0.26.1 /usr/bin/cilium-agent
go-module github.com/go-openapi/swag/conv v0.26.1 /usr/bin/cilium-bugtool
go-module github.com/go-openapi/swag/conv v0.26.1 /usr/bin/cilium-dbg
go-module github.com/go-openapi/swag/conv v0.26.1 /usr/bin/cilium-envoy-bootstrap-locality
go-module github.com/go-openapi/swag/conv v0.26.1 /usr/bin/cilium-health
go-module github.com/go-openapi/swag/conv v0.26.1 /usr/bin/hubble
go-module github.com/go-openapi/swag/fileutils v0.26.1 /opt/cni/bin/cilium-cni
go-module github.com/go-openapi/swag/fileutils v0.26.1 /usr/bin/cilium-agent
go-module github.com/go-openapi/swag/fileutils v0.26.1 /usr/bin/cilium-bugtool
go-module github.com/go-openapi/swag/fileutils v0.26.1 /usr/bin/cilium-dbg
go-module github.com/go-openapi/swag/fileutils v0.26.1 /usr/bin/cilium-envoy-bootstrap-locality
go-module github.com/go-openapi/swag/fileutils v0.26.1 /usr/bin/cilium-health
go-module github.com/go-openapi/swag/fileutils v0.26.1 /usr/bin/hubble
go-module github.com/go-openapi/swag/jsonname v0.26.1 /opt/cni/bin/cilium-cni
go-module github.com/go-openapi/swag/jsonname v0.26.1 /usr/bin/cilium-agent
go-module github.com/go-openapi/swag/jsonname v0.26.1 /usr/bin/cilium-bugtool
go-module github.com/go-openapi/swag/jsonname v0.26.1 /usr/bin/cilium-dbg
go-module github.com/go-openapi/swag/jsonname v0.26.1 /usr/bin/cilium-envoy-bootstrap-locality
go-module github.com/go-openapi/swag/jsonname v0.26.1 /usr/bin/cilium-health
go-module github.com/go-openapi/swag/jsonname v0.26.1 /usr/bin/hubble
go-module github.com/go-openapi/swag/jsonutils v0.26.1 /opt/cni/bin/cilium-cni
go-module github.com/go-openapi/swag/jsonutils v0.26.1 /usr/bin/cilium-agent
go-module github.com/go-openapi/swag/jsonutils v0.26.1 /usr/bin/cilium-bugtool
go-module github.com/go-openapi/swag/jsonutils v0.26.1 /usr/bin/cilium-dbg
go-module github.com/go-openapi/swag/jsonutils v0.26.1 /usr/bin/cilium-envoy-bootstrap-locality
go-module github.com/go-openapi/swag/jsonutils v0.26.1 /usr/bin/cilium-health
go-module github.com/go-openapi/swag/jsonutils v0.26.1 /usr/bin/hubble
go-module github.com/go-openapi/swag/loading v0.26.1 /opt/cni/bin/cilium-cni
go-module github.com/go-openapi/swag/loading v0.26.1 /usr/bin/cilium-agent
go-module github.com/go-openapi/swag/loading v0.26.1 /usr/bin/cilium-bugtool
go-module github.com/go-openapi/swag/loading v0.26.1 /usr/bin/cilium-dbg
go-module github.com/go-openapi/swag/loading v0.26.1 /usr/bin/cilium-envoy-bootstrap-locality
go-module github.com/go-openapi/swag/loading v0.26.1 /usr/bin/cilium-health
go-module github.com/go-openapi/swag/loading v0.26.1 /usr/bin/hubble
go-module github.com/go-openapi/swag/mangling v0.26.1 /opt/cni/bin/cilium-cni
go-module github.com/go-openapi/swag/mangling v0.26.1 /usr/bin/cilium-agent
go-module github.com/go-openapi/swag/mangling v0.26.1 /usr/bin/cilium-bugtool
go-module github.com/go-openapi/swag/mangling v0.26.1 /usr/bin/cilium-dbg
go-module github.com/go-openapi/swag/mangling v0.26.1 /usr/bin/cilium-envoy-bootstrap-locality
go-module github.com/go-openapi/swag/mangling v0.26.1 /usr/bin/cilium-health
go-module github.com/go-openapi/swag/mangling v0.26.1 /usr/bin/hubble
go-module github.com/go-openapi/swag/netutils v0.26.1 /usr/bin/cilium-agent
go-module github.com/go-openapi/swag/netutils v0.26.1 /usr/bin/cilium-dbg
go-module github.com/go-openapi/swag/netutils v0.26.1 /usr/bin/cilium-envoy-bootstrap-locality
go-module github.com/go-openapi/swag/netutils v0.26.1 /usr/bin/hubble
go-module github.com/go-openapi/swag/stringutils v0.26.1 /opt/cni/bin/cilium-cni
go-module github.com/go-openapi/swag/stringutils v0.26.1 /usr/bin/cilium-agent
go-module github.com/go-openapi/swag/stringutils v0.26.1 /usr/bin/cilium-bugtool
go-module github.com/go-openapi/swag/stringutils v0.26.1 /usr/bin/cilium-dbg
go-module github.com/go-openapi/swag/stringutils v0.26.1 /usr/bin/cilium-envoy-bootstrap-locality
go-module github.com/go-openapi/swag/stringutils v0.26.1 /usr/bin/cilium-health
go-module github.com/go-openapi/swag/stringutils v0.26.1 /usr/bin/hubble
go-module github.com/go-openapi/swag/typeutils v0.26.1 /opt/cni/bin/cilium-cni
go-module github.com/go-openapi/swag/typeutils v0.26.1 /usr/bin/cilium-agent
go-module github.com/go-openapi/swag/typeutils v0.26.1 /usr/bin/cilium-bugtool
go-module github.com/go-openapi/swag/typeutils v0.26.1 /usr/bin/cilium-dbg
go-module github.com/go-openapi/swag/typeutils v0.26.1 /usr/bin/cilium-envoy-bootstrap-locality
go-module github.com/go-openapi/swag/typeutils v0.26.1 /usr/bin/cilium-health
go-module github.com/go-openapi/swag/typeutils v0.26.1 /usr/bin/hubble
go-module github.com/go-openapi/swag/yamlutils v0.26.1 /opt/cni/bin/cilium-cni
go-module github.com/go-openapi/swag/yamlutils v0.26.1 /usr/bin/cilium-agent
go-module github.com/go-openapi/swag/yamlutils v0.26.1 /usr/bin/cilium-bugtool
go-module github.com/go-openapi/swag/yamlutils v0.26.1 /usr/bin/cilium-dbg
go-module github.com/go-openapi/swag/yamlutils v0.26.1 /usr/bin/cilium-envoy-bootstrap-locality
go-module github.com/go-openapi/swag/yamlutils v0.26.1 /usr/bin/cilium-health
go-module github.com/go-openapi/swag/yamlutils v0.26.1 /usr/bin/hubble
go-module github.com/go-openapi/validate v0.26.0 /opt/cni/bin/cilium-cni
go-module github.com/go-openapi/validate v0.26.0 /usr/bin/cilium-agent
go-module github.com/go-openapi/validate v0.26.0 /usr/bin/cilium-bugtool
go-module github.com/go-openapi/validate v0.26.0 /usr/bin/cilium-dbg
go-module github.com/go-openapi/validate v0.26.0 /usr/bin/cilium-health
go-module github.com/go-openapi/validate v0.26.0 /usr/bin/hubble
go-module github.com/go-viper/mapstructure/v2 v2.5.0 /opt/cni/bin/cilium-cni
go-module github.com/go-viper/mapstructure/v2 v2.5.0 /usr/bin/cilium-agent
go-module github.com/go-viper/mapstructure/v2 v2.5.0 /usr/bin/cilium-bugtool
go-module github.com/go-viper/mapstructure/v2 v2.5.0 /usr/bin/cilium-dbg
go-module github.com/go-viper/mapstructure/v2 v2.5.0 /usr/bin/cilium-health
go-module github.com/go-viper/mapstructure/v2 v2.5.0 /usr/bin/hubble
go-module github.com/godbus/dbus/v5 v5.2.0 /usr/bin/cilium-sysctlfix
go-module github.com/gogo/protobuf v1.3.2 /usr/bin/cilium-agent
go-module github.com/gogo/protobuf v1.3.2 /usr/bin/cilium-dbg
go-module github.com/gogo/protobuf v1.3.2 /usr/bin/hubble
go-module github.com/golang/protobuf v1.5.4 /usr/bin/cilium-agent
go-module github.com/golang/protobuf v1.5.4 /usr/bin/cilium-dbg
go-module github.com/golang/protobuf v1.5.4 /usr/bin/hubble
go-module github.com/google/btree v1.1.3 /usr/bin/hubble
go-module github.com/google/cel-go v0.30.0 /usr/bin/cilium-agent
go-module github.com/google/cel-go v0.30.0 /usr/bin/cilium-dbg
go-module github.com/google/cel-go v0.30.0 /usr/bin/hubble
go-module github.com/google/gnostic-models v0.7.1 /usr/bin/cilium-agent
go-module github.com/google/gnostic-models v0.7.1 /usr/bin/cilium-dbg
go-module github.com/google/gnostic-models v0.7.1 /usr/bin/cilium-envoy-bootstrap-locality
go-module github.com/google/gnostic-models v0.7.1 /usr/bin/hubble
go-module github.com/google/go-cmp v0.7.0 /opt/cni/bin/cilium-cni
go-module github.com/google/go-cmp v0.7.0 /usr/bin/cilium-agent
go-module github.com/google/go-cmp v0.7.0 /usr/bin/cilium-bugtool
go-module github.com/google/go-cmp v0.7.0 /usr/bin/cilium-dbg
go-module github.com/google/go-cmp v0.7.0 /usr/bin/cilium-health
go-module github.com/google/go-cmp v0.7.0 /usr/bin/hubble
go-module github.com/google/gops UNKNOWN /usr/bin/gops
go-module github.com/google/gops v0.3.28 /opt/cni/bin/cilium-cni
go-module github.com/google/gops v0.3.28 /usr/bin/cilium-agent
go-module github.com/google/renameio/v2 v2.0.2 /usr/bin/cilium-agent
go-module github.com/google/renameio/v2 v2.0.2 /usr/bin/cilium-dbg
go-module github.com/google/renameio/v2 v2.0.2 /usr/bin/hubble
go-module github.com/google/uuid v1.6.0 /opt/cni/bin/cilium-cni
go-module github.com/google/uuid v1.6.0 /usr/bin/cilium-agent
go-module github.com/google/uuid v1.6.0 /usr/bin/cilium-bugtool
go-module github.com/google/uuid v1.6.0 /usr/bin/cilium-dbg
go-module github.com/google/uuid v1.6.0 /usr/bin/cilium-envoy-bootstrap-locality
go-module github.com/google/uuid v1.6.0 /usr/bin/cilium-health
go-module github.com/google/uuid v1.6.0 /usr/bin/hubble
go-module github.com/gopacket/gopacket v1.7.2 /opt/cni/bin/cilium-cni
go-module github.com/gopacket/gopacket v1.7.2 /usr/bin/cilium-agent
go-module github.com/gopacket/gopacket v1.7.2 /usr/bin/cilium-dbg
go-module github.com/gorilla/websocket v1.5.4-0.20250319132907-e064f32e3674 /usr/bin/hubble
go-module github.com/grpc-ecosystem/go-grpc-middleware/v2 v2.3.3 /usr/bin/hubble
go-module github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0 /usr/bin/cilium-agent
go-module github.com/grpc-ecosystem/grpc-gateway/v2 v2.29.0 /usr/bin/cilium-agent
go-module github.com/grpc-ecosystem/grpc-gateway/v2 v2.29.0 /usr/bin/cilium-dbg
go-module github.com/grpc-ecosystem/grpc-gateway/v2 v2.29.0 /usr/bin/hubble
go-module github.com/hashicorp/go-hclog v1.6.3 /usr/bin/cilium-agent
go-module github.com/hashicorp/go-hclog v1.6.3 /usr/bin/cilium-dbg
go-module github.com/hashicorp/golang-lru/v2 v2.0.7 /usr/bin/cilium-agent
go-module github.com/hashicorp/golang-lru/v2 v2.0.7 /usr/bin/cilium-dbg
go-module github.com/hashicorp/golang-lru/v2 v2.0.7 /usr/bin/hubble
go-module github.com/jeremywohl/flatten v1.0.1 /usr/bin/cilium-dbg
go-module github.com/josharian/native v1.1.0 /usr/bin/cilium-agent
go-module github.com/josharian/native v1.1.0 /usr/bin/cilium-dbg
go-module github.com/json-iterator/go v1.1.12 /opt/cni/bin/cilium-cni
go-module github.com/json-iterator/go v1.1.12 /usr/bin/cilium-agent
go-module github.com/json-iterator/go v1.1.12 /usr/bin/cilium-bugtool
go-module github.com/json-iterator/go v1.1.12 /usr/bin/cilium-dbg
go-module github.com/json-iterator/go v1.1.12 /usr/bin/cilium-envoy-bootstrap-locality
go-module github.com/json-iterator/go v1.1.12 /usr/bin/cilium-health
go-module github.com/json-iterator/go v1.1.12 /usr/bin/cilium-mount
go-module github.com/json-iterator/go v1.1.12 /usr/bin/hubble
go-module github.com/k-sone/critbitgo v1.4.0 /usr/bin/cilium-agent
go-module github.com/klauspost/compress v1.20.2 /usr/bin/cilium-agent
go-module github.com/klauspost/compress v1.20.2 /usr/bin/cilium-dbg
go-module github.com/kubernetes-sigs/iptables-wrappers UNKNOWN /usr/sbin/iptables-wrapper
go-module github.com/liggitt/tabwriter v0.0.0-20181228230101-89fcab3d43de /opt/cni/bin/cilium-cni
go-module github.com/liggitt/tabwriter v0.0.0-20181228230101-89fcab3d43de /usr/bin/cilium-agent
go-module github.com/liggitt/tabwriter v0.0.0-20181228230101-89fcab3d43de /usr/bin/cilium-dbg
go-module github.com/liggitt/tabwriter v0.0.0-20181228230101-89fcab3d43de /usr/bin/hubble
go-module github.com/lthibault/jitterbug/v2 v2.2.2 /usr/bin/cilium-agent
go-module github.com/mackerelio/go-osstat v0.2.7 /opt/cni/bin/cilium-cni
go-module github.com/mackerelio/go-osstat v0.2.7 /usr/bin/cilium-agent
go-module github.com/mackerelio/go-osstat v0.2.7 /usr/bin/cilium-bugtool
go-module github.com/mackerelio/go-osstat v0.2.7 /usr/bin/cilium-dbg
go-module github.com/mackerelio/go-osstat v0.2.7 /usr/bin/cilium-health
go-module github.com/mackerelio/go-osstat v0.2.7 /usr/bin/hubble
go-module github.com/mattn/go-colorable v0.1.14 /usr/bin/cilium-agent
go-module github.com/mattn/go-colorable v0.1.14 /usr/bin/cilium-dbg
go-module github.com/mattn/go-colorable v0.1.14 /usr/bin/hubble
go-module github.com/mattn/go-isatty v0.0.20 /usr/bin/cilium-agent
go-module github.com/mattn/go-isatty v0.0.20 /usr/bin/cilium-dbg
go-module github.com/mattn/go-isatty v0.0.20 /usr/bin/hubble
go-module github.com/mattn/go-shellwords v1.0.13 /usr/bin/cilium-agent
go-module github.com/mattn/go-shellwords v1.0.13 /usr/bin/cilium-dbg
go-module github.com/mdlayher/arp v0.0.0-20260528070854-93566ba168e9 /usr/bin/cilium-agent
go-module github.com/mdlayher/ethernet v0.0.0-20220221185849-529eae5b6118 /usr/bin/cilium-agent
go-module github.com/mdlayher/genetlink v1.3.2 /usr/bin/cilium-agent
go-module github.com/mdlayher/genetlink v1.3.2 /usr/bin/cilium-dbg
go-module github.com/mdlayher/ndp v1.1.0 /usr/bin/cilium-agent
go-module github.com/mdlayher/netlink v1.7.2 /usr/bin/cilium-agent
go-module github.com/mdlayher/netlink v1.7.2 /usr/bin/cilium-dbg
go-module github.com/mdlayher/packet v1.1.2 /usr/bin/cilium-agent
go-module github.com/mdlayher/socket v0.5.1 /usr/bin/cilium-agent
go-module github.com/mdlayher/socket v0.5.1 /usr/bin/cilium-dbg
go-module github.com/mitchellh/go-wordwrap v1.0.1 /usr/bin/cilium-agent
go-module github.com/mitchellh/go-wordwrap v1.0.1 /usr/bin/cilium-dbg
go-module github.com/mitchellh/go-wordwrap v1.0.1 /usr/bin/hubble
go-module github.com/mitchellh/mapstructure v1.5.0 /opt/cni/bin/cilium-cni
go-module github.com/mitchellh/mapstructure v1.5.0 /usr/bin/cilium-agent
go-module github.com/mitchellh/mapstructure v1.5.0 /usr/bin/cilium-bugtool
go-module github.com/mitchellh/mapstructure v1.5.0 /usr/bin/cilium-dbg
go-module github.com/mitchellh/mapstructure v1.5.0 /usr/bin/cilium-health
go-module github.com/mitchellh/mapstructure v1.5.0 /usr/bin/hubble
go-module github.com/moby/spdystream v0.5.1 /usr/bin/hubble
go-module github.com/moby/term v0.5.2 /usr/bin/hubble
go-module github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd /opt/cni/bin/cilium-cni
go-module github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd /usr/bin/cilium-agent
go-module github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd /usr/bin/cilium-bugtool
go-module github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd /usr/bin/cilium-dbg
go-module github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd /usr/bin/cilium-envoy-bootstrap-locality
go-module github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd /usr/bin/cilium-health
go-module github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd /usr/bin/cilium-mount
go-module github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd /usr/bin/hubble
go-module github.com/modern-go/reflect2 v1.0.3-0.20250322232337-35a7c28c31ee /opt/cni/bin/cilium-cni
go-module github.com/modern-go/reflect2 v1.0.3-0.20250322232337-35a7c28c31ee /usr/bin/cilium-agent
go-module github.com/modern-go/reflect2 v1.0.3-0.20250322232337-35a7c28c31ee /usr/bin/cilium-bugtool
go-module github.com/modern-go/reflect2 v1.0.3-0.20250322232337-35a7c28c31ee /usr/bin/cilium-dbg
go-module github.com/modern-go/reflect2 v1.0.3-0.20250322232337-35a7c28c31ee /usr/bin/cilium-envoy-bootstrap-locality
go-module github.com/modern-go/reflect2 v1.0.3-0.20250322232337-35a7c28c31ee /usr/bin/cilium-health
go-module github.com/modern-go/reflect2 v1.0.3-0.20250322232337-35a7c28c31ee /usr/bin/cilium-mount
go-module github.com/modern-go/reflect2 v1.0.3-0.20250322232337-35a7c28c31ee /usr/bin/hubble
go-module github.com/monochromegane/go-gitignore v0.0.0-20200626010858-205db1a8cc00 /usr/bin/hubble
go-module github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 /usr/bin/cilium-agent
go-module github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 /usr/bin/cilium-dbg
go-module github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 /usr/bin/cilium-envoy-bootstrap-locality
go-module github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 /usr/bin/hubble
go-module github.com/oklog/ulid/v2 v2.1.1 /opt/cni/bin/cilium-cni
go-module github.com/oklog/ulid/v2 v2.1.1 /usr/bin/cilium-agent
go-module github.com/oklog/ulid/v2 v2.1.1 /usr/bin/cilium-bugtool
go-module github.com/oklog/ulid/v2 v2.1.1 /usr/bin/cilium-dbg
go-module github.com/oklog/ulid/v2 v2.1.1 /usr/bin/cilium-health
go-module github.com/oklog/ulid/v2 v2.1.1 /usr/bin/hubble
go-module github.com/orcaman/concurrent-map/v2 v2.0.1 /usr/bin/cilium-agent
go-module github.com/osrg/gobgp/v4 v4.7.0 /usr/bin/cilium-agent
go-module github.com/osrg/gobgp/v4 v4.7.0 /usr/bin/cilium-dbg
go-module github.com/pelletier/go-toml/v2 v2.2.4 /opt/cni/bin/cilium-cni
go-module github.com/pelletier/go-toml/v2 v2.2.4 /usr/bin/cilium-agent
go-module github.com/pelletier/go-toml/v2 v2.2.4 /usr/bin/cilium-bugtool
go-module github.com/pelletier/go-toml/v2 v2.2.4 /usr/bin/cilium-dbg
go-module github.com/pelletier/go-toml/v2 v2.2.4 /usr/bin/cilium-health
go-module github.com/pelletier/go-toml/v2 v2.2.4 /usr/bin/hubble
go-module github.com/peterbourgon/diskv v2.0.1+incompatible /usr/bin/hubble
go-module github.com/petermattis/goid v0.0.0-20250813065127-a731cc31b4fe /opt/cni/bin/cilium-cni
go-module github.com/petermattis/goid v0.0.0-20250813065127-a731cc31b4fe /usr/bin/cilium-agent
go-module github.com/petermattis/goid v0.0.0-20250813065127-a731cc31b4fe /usr/bin/cilium-bugtool
go-module github.com/petermattis/goid v0.0.0-20250813065127-a731cc31b4fe /usr/bin/cilium-dbg
go-module github.com/petermattis/goid v0.0.0-20250813065127-a731cc31b4fe /usr/bin/cilium-health
go-module github.com/petermattis/goid v0.0.0-20250813065127-a731cc31b4fe /usr/bin/cilium-mount
go-module github.com/petermattis/goid v0.0.0-20250813065127-a731cc31b4fe /usr/bin/hubble
go-module github.com/pkg/errors v0.9.1 /cni/loopback
go-module github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 /usr/bin/cilium-agent
go-module github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 /usr/bin/cilium-dbg
go-module github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 /usr/bin/hubble
go-module github.com/prometheus-community/pro-bing v0.9.0 /usr/bin/cilium-agent
go-module github.com/prometheus/client_golang v1.23.2 /usr/bin/cilium-agent
go-module github.com/prometheus/client_golang v1.23.2 /usr/bin/cilium-dbg
go-module github.com/prometheus/client_golang v1.23.2 /usr/bin/hubble
go-module github.com/prometheus/client_model v0.6.2 /usr/bin/cilium-agent
go-module github.com/prometheus/client_model v0.6.2 /usr/bin/cilium-dbg
go-module github.com/prometheus/client_model v0.6.2 /usr/bin/hubble
go-module github.com/prometheus/common v0.69.0 /usr/bin/cilium-agent
go-module github.com/prometheus/common v0.69.0 /usr/bin/cilium-dbg
go-module github.com/prometheus/common v0.69.0 /usr/bin/hubble
go-module github.com/prometheus/procfs v0.20.1 /usr/bin/cilium-agent
go-module github.com/prometheus/procfs v0.20.1 /usr/bin/cilium-dbg
go-module github.com/prometheus/procfs v0.20.1 /usr/bin/hubble
go-module github.com/russross/blackfriday/v2 v2.1.0 /usr/bin/cilium-agent
go-module github.com/russross/blackfriday/v2 v2.1.0 /usr/bin/cilium-bugtool
go-module github.com/russross/blackfriday/v2 v2.1.0 /usr/bin/cilium-dbg
go-module github.com/russross/blackfriday/v2 v2.1.0 /usr/bin/cilium-health
go-module github.com/sagikazarmark/locafero v0.11.0 /opt/cni/bin/cilium-cni
go-module github.com/sagikazarmark/locafero v0.11.0 /usr/bin/cilium-agent
go-module github.com/sagikazarmark/locafero v0.11.0 /usr/bin/cilium-bugtool
go-module github.com/sagikazarmark/locafero v0.11.0 /usr/bin/cilium-dbg
go-module github.com/sagikazarmark/locafero v0.11.0 /usr/bin/cilium-health
go-module github.com/sagikazarmark/locafero v0.11.0 /usr/bin/hubble
go-module github.com/sasha-s/go-deadlock v0.3.9 /opt/cni/bin/cilium-cni
go-module github.com/sasha-s/go-deadlock v0.3.9 /usr/bin/cilium-agent
go-module github.com/sasha-s/go-deadlock v0.3.9 /usr/bin/cilium-bugtool
go-module github.com/sasha-s/go-deadlock v0.3.9 /usr/bin/cilium-dbg
go-module github.com/sasha-s/go-deadlock v0.3.9 /usr/bin/cilium-health
go-module github.com/sasha-s/go-deadlock v0.3.9 /usr/bin/cilium-mount
go-module github.com/sasha-s/go-deadlock v0.3.9 /usr/bin/hubble
go-module github.com/segmentio/fasthash v1.0.3 /usr/bin/cilium-agent
go-module github.com/shirou/gopsutil/v3 v3.24.5 /usr/bin/gops
go-module github.com/sourcegraph/conc v0.3.1-0.20240121214520-5f936abd7ae8 /opt/cni/bin/cilium-cni
go-module github.com/sourcegraph/conc v0.3.1-0.20240121214520-5f936abd7ae8 /usr/bin/cilium-agent
go-module github.com/sourcegraph/conc v0.3.1-0.20240121214520-5f936abd7ae8 /usr/bin/cilium-bugtool
go-module github.com/sourcegraph/conc v0.3.1-0.20240121214520-5f936abd7ae8 /usr/bin/cilium-dbg
go-module github.com/sourcegraph/conc v0.3.1-0.20240121214520-5f936abd7ae8 /usr/bin/cilium-health
go-module github.com/sourcegraph/conc v0.3.1-0.20240121214520-5f936abd7ae8 /usr/bin/hubble
go-module github.com/spf13/afero v1.15.0 /opt/cni/bin/cilium-cni
go-module github.com/spf13/afero v1.15.0 /usr/bin/cilium-agent
go-module github.com/spf13/afero v1.15.0 /usr/bin/cilium-bugtool
go-module github.com/spf13/afero v1.15.0 /usr/bin/cilium-dbg
go-module github.com/spf13/afero v1.15.0 /usr/bin/cilium-health
go-module github.com/spf13/afero v1.15.0 /usr/bin/hubble
go-module github.com/spf13/cast v1.10.0 /opt/cni/bin/cilium-cni
go-module github.com/spf13/cast v1.10.0 /usr/bin/cilium-agent
go-module github.com/spf13/cast v1.10.0 /usr/bin/cilium-bugtool
go-module github.com/spf13/cast v1.10.0 /usr/bin/cilium-dbg
go-module github.com/spf13/cast v1.10.0 /usr/bin/cilium-health
go-module github.com/spf13/cast v1.10.0 /usr/bin/hubble
go-module github.com/spf13/cobra v1.10.2 /opt/cni/bin/cilium-cni
go-module github.com/spf13/cobra v1.10.2 /usr/bin/cilium-agent
go-module github.com/spf13/cobra v1.10.2 /usr/bin/cilium-bugtool
go-module github.com/spf13/cobra v1.10.2 /usr/bin/cilium-dbg
go-module github.com/spf13/cobra v1.10.2 /usr/bin/cilium-health
go-module github.com/spf13/cobra v1.10.2 /usr/bin/hubble
go-module github.com/spf13/cobra v1.9.1 /usr/bin/gops
go-module github.com/spf13/pflag v1.0.10 /opt/cni/bin/cilium-cni
go-module github.com/spf13/pflag v1.0.10 /usr/bin/cilium-agent
go-module github.com/spf13/pflag v1.0.10 /usr/bin/cilium-bugtool
go-module github.com/spf13/pflag v1.0.10 /usr/bin/cilium-dbg
go-module github.com/spf13/pflag v1.0.10 /usr/bin/cilium-health
go-module github.com/spf13/pflag v1.0.10 /usr/bin/cilium-health-responder
go-module github.com/spf13/pflag v1.0.10 /usr/bin/cilium-sysctlfix
go-module github.com/spf13/pflag v1.0.10 /usr/bin/hubble
go-module github.com/spf13/pflag v1.0.6 /usr/bin/gops
go-module github.com/spf13/viper v1.21.0 /opt/cni/bin/cilium-cni
go-module github.com/spf13/viper v1.21.0 /usr/bin/cilium-agent
go-module github.com/spf13/viper v1.21.0 /usr/bin/cilium-bugtool
go-module github.com/spf13/viper v1.21.0 /usr/bin/cilium-dbg
go-module github.com/spf13/viper v1.21.0 /usr/bin/cilium-health
go-module github.com/spf13/viper v1.21.0 /usr/bin/hubble
go-module github.com/spiffe/spire-api-sdk v1.15.1 /usr/bin/cilium-agent
go-module github.com/subosito/gotenv v1.6.0 /opt/cni/bin/cilium-cni
go-module github.com/subosito/gotenv v1.6.0 /usr/bin/cilium-agent
go-module github.com/subosito/gotenv v1.6.0 /usr/bin/cilium-bugtool
go-module github.com/subosito/gotenv v1.6.0 /usr/bin/cilium-dbg
go-module github.com/subosito/gotenv v1.6.0 /usr/bin/cilium-health
go-module github.com/subosito/gotenv v1.6.0 /usr/bin/hubble
go-module github.com/tidwall/gjson v1.19.0 /usr/bin/cilium-agent
go-module github.com/tidwall/gjson v1.19.0 /usr/bin/cilium-dbg
go-module github.com/tidwall/match v1.1.1 /usr/bin/cilium-agent
go-module github.com/tidwall/match v1.1.1 /usr/bin/cilium-dbg
go-module github.com/tidwall/pretty v1.2.1 /usr/bin/cilium-agent
go-module github.com/tidwall/pretty v1.2.1 /usr/bin/cilium-dbg
go-module github.com/tidwall/sjson v1.2.5 /usr/bin/cilium-agent
go-module github.com/tidwall/sjson v1.2.5 /usr/bin/cilium-dbg
go-module github.com/tklauser/go-sysconf v0.3.12 /usr/bin/gops
go-module github.com/tklauser/numcpus v0.6.1 /usr/bin/gops
go-module github.com/vishvananda/netlink v1.3.1 /cni/loopback
go-module github.com/vishvananda/netlink v1.3.2-0.20260624190457-bab08b3566fc /opt/cni/bin/cilium-cni
go-module github.com/vishvananda/netlink v1.3.2-0.20260624190457-bab08b3566fc /usr/bin/cilium-agent
go-module github.com/vishvananda/netlink v1.3.2-0.20260624190457-bab08b3566fc /usr/bin/cilium-bugtool
go-module github.com/vishvananda/netlink v1.3.2-0.20260624190457-bab08b3566fc /usr/bin/cilium-dbg
go-module github.com/vishvananda/netlink v1.3.2-0.20260624190457-bab08b3566fc /usr/bin/cilium-health
go-module github.com/vishvananda/netlink v1.3.2-0.20260624190457-bab08b3566fc /usr/bin/cilium-health-responder
go-module github.com/vishvananda/netlink v1.3.2-0.20260624190457-bab08b3566fc /usr/bin/cilium-mount
go-module github.com/vishvananda/netlink v1.3.2-0.20260624190457-bab08b3566fc /usr/bin/hubble
go-module github.com/vishvananda/netns v0.0.5 /cni/loopback
go-module github.com/vishvananda/netns v0.0.5 /opt/cni/bin/cilium-cni
go-module github.com/vishvananda/netns v0.0.5 /usr/bin/cilium-agent
go-module github.com/vishvananda/netns v0.0.5 /usr/bin/cilium-bugtool
go-module github.com/vishvananda/netns v0.0.5 /usr/bin/cilium-dbg
go-module github.com/vishvananda/netns v0.0.5 /usr/bin/cilium-health
go-module github.com/vishvananda/netns v0.0.5 /usr/bin/cilium-health-responder
go-module github.com/vishvananda/netns v0.0.5 /usr/bin/cilium-mount
go-module github.com/vishvananda/netns v0.0.5 /usr/bin/hubble
go-module github.com/x448/float16 v0.8.4 /opt/cni/bin/cilium-cni
go-module github.com/x448/float16 v0.8.4 /usr/bin/cilium-agent
go-module github.com/x448/float16 v0.8.4 /usr/bin/cilium-bugtool
go-module github.com/x448/float16 v0.8.4 /usr/bin/cilium-dbg
go-module github.com/x448/float16 v0.8.4 /usr/bin/cilium-envoy-bootstrap-locality
go-module github.com/x448/float16 v0.8.4 /usr/bin/cilium-health
go-module github.com/x448/float16 v0.8.4 /usr/bin/cilium-mount
go-module github.com/x448/float16 v0.8.4 /usr/bin/hubble
go-module github.com/xlab/treeprint v1.2.0 /usr/bin/gops
go-module github.com/xlab/treeprint v1.2.0 /usr/bin/hubble
deb gnu-coreutils 9.7-3ubuntu2.1 /usr/share/doc/gnu-coreutils/copyright /var/lib/dpkg/info/gnu-coreutils.list /var/lib/dpkg/info/gnu-coreutils.md5sums /var/lib/dpkg/status
go-module go.etcd.io/etcd/api/v3 v3.6.12 /usr/bin/cilium-agent
go-module go.etcd.io/etcd/api/v3 v3.6.12 /usr/bin/cilium-dbg
go-module go.etcd.io/etcd/api/v3 v3.6.12 /usr/bin/hubble
go-module go.etcd.io/etcd/client/pkg/v3 v3.6.14 /usr/bin/cilium-agent
go-module go.etcd.io/etcd/client/pkg/v3 v3.6.14 /usr/bin/cilium-dbg
go-module go.etcd.io/etcd/client/pkg/v3 v3.6.14 /usr/bin/hubble
go-module go.etcd.io/etcd/client/v3 v3.6.12 /usr/bin/cilium-agent
go-module go.etcd.io/etcd/client/v3 v3.6.12 /usr/bin/cilium-dbg
go-module go.etcd.io/etcd/client/v3 v3.6.12 /usr/bin/hubble
go-module go.opentelemetry.io/auto/sdk v1.2.1 /opt/cni/bin/cilium-cni
go-module go.opentelemetry.io/auto/sdk v1.2.1 /usr/bin/cilium-agent
go-module go.opentelemetry.io/auto/sdk v1.2.1 /usr/bin/cilium-dbg
go-module go.opentelemetry.io/auto/sdk v1.2.1 /usr/bin/cilium-health
go-module go.opentelemetry.io/auto/sdk v1.2.1 /usr/bin/hubble
go-module go.opentelemetry.io/otel v1.47.0 /opt/cni/bin/cilium-cni
go-module go.opentelemetry.io/otel v1.47.0 /usr/bin/cilium-agent
go-module go.opentelemetry.io/otel v1.47.0 /usr/bin/cilium-dbg
go-module go.opentelemetry.io/otel v1.47.0 /usr/bin/cilium-health
go-module go.opentelemetry.io/otel v1.47.0 /usr/bin/hubble
go-module go.opentelemetry.io/otel/log v1.47.0 /opt/cni/bin/cilium-cni
go-module go.opentelemetry.io/otel/log v1.47.0 /usr/bin/cilium-agent
go-module go.opentelemetry.io/otel/log v1.47.0 /usr/bin/cilium-dbg
go-module go.opentelemetry.io/otel/log v1.47.0 /usr/bin/cilium-health
go-module go.opentelemetry.io/otel/log v1.47.0 /usr/bin/hubble
go-module go.opentelemetry.io/otel/metric v1.47.0 /opt/cni/bin/cilium-cni
go-module go.opentelemetry.io/otel/metric v1.47.0 /usr/bin/cilium-agent
go-module go.opentelemetry.io/otel/metric v1.47.0 /usr/bin/cilium-dbg
go-module go.opentelemetry.io/otel/metric v1.47.0 /usr/bin/cilium-health
go-module go.opentelemetry.io/otel/metric v1.47.0 /usr/bin/hubble
go-module go.opentelemetry.io/otel/trace v1.47.0 /opt/cni/bin/cilium-cni
go-module go.opentelemetry.io/otel/trace v1.47.0 /usr/bin/cilium-agent
go-module go.opentelemetry.io/otel/trace v1.47.0 /usr/bin/cilium-dbg
go-module go.opentelemetry.io/otel/trace v1.47.0 /usr/bin/cilium-health
go-module go.opentelemetry.io/otel/trace v1.47.0 /usr/bin/hubble
go-module go.opentelemetry.io/proto/otlp v1.11.0 /usr/bin/cilium-agent
go-module go.uber.org/dig v1.17.1 /opt/cni/bin/cilium-cni
go-module go.uber.org/dig v1.17.1 /usr/bin/cilium-agent
go-module go.uber.org/dig v1.17.1 /usr/bin/cilium-bugtool
go-module go.uber.org/dig v1.17.1 /usr/bin/cilium-dbg
go-module go.uber.org/dig v1.17.1 /usr/bin/cilium-health
go-module go.uber.org/dig v1.17.1 /usr/bin/hubble
go-module go.uber.org/goleak v1.3.0 /usr/bin/cilium-agent
go-module go.uber.org/goleak v1.3.0 /usr/bin/cilium-dbg
go-module go.uber.org/multierr v1.11.0 /usr/bin/cilium-agent
go-module go.uber.org/multierr v1.11.0 /usr/bin/cilium-dbg
go-module go.uber.org/multierr v1.11.0 /usr/bin/hubble
go-module go.uber.org/zap v1.28.0 /usr/bin/cilium-agent
go-module go.uber.org/zap v1.28.0 /usr/bin/cilium-dbg
go-module go.uber.org/zap v1.28.0 /usr/bin/hubble
go-module go.yaml.in/yaml/v2 v2.4.4 /opt/cni/bin/cilium-cni
go-module go.yaml.in/yaml/v2 v2.4.4 /usr/bin/cilium-agent
go-module go.yaml.in/yaml/v2 v2.4.4 /usr/bin/cilium-bugtool
go-module go.yaml.in/yaml/v2 v2.4.4 /usr/bin/cilium-dbg
go-module go.yaml.in/yaml/v2 v2.4.4 /usr/bin/cilium-envoy-bootstrap-locality
go-module go.yaml.in/yaml/v2 v2.4.4 /usr/bin/cilium-health
go-module go.yaml.in/yaml/v2 v2.4.4 /usr/bin/cilium-mount
go-module go.yaml.in/yaml/v2 v2.4.4 /usr/bin/hubble
go-module go.yaml.in/yaml/v3 v3.0.5 /opt/cni/bin/cilium-cni
go-module go.yaml.in/yaml/v3 v3.0.5 /usr/bin/cilium-agent
go-module go.yaml.in/yaml/v3 v3.0.5 /usr/bin/cilium-bugtool
go-module go.yaml.in/yaml/v3 v3.0.5 /usr/bin/cilium-dbg
go-module go.yaml.in/yaml/v3 v3.0.5 /usr/bin/cilium-envoy-bootstrap-locality
go-module go.yaml.in/yaml/v3 v3.0.5 /usr/bin/cilium-health
go-module go.yaml.in/yaml/v3 v3.0.5 /usr/bin/hubble
go-module go4.org/netipx v0.0.0-20231129151722-fdeea329fbba /opt/cni/bin/cilium-cni
go-module go4.org/netipx v0.0.0-20231129151722-fdeea329fbba /usr/bin/cilium-agent
go-module go4.org/netipx v0.0.0-20231129151722-fdeea329fbba /usr/bin/cilium-bugtool
go-module go4.org/netipx v0.0.0-20231129151722-fdeea329fbba /usr/bin/cilium-dbg
go-module go4.org/netipx v0.0.0-20231129151722-fdeea329fbba /usr/bin/cilium-health
go-module go4.org/netipx v0.0.0-20231129151722-fdeea329fbba /usr/bin/hubble
go-module golang.org/x/crypto v0.59.0 /usr/bin/cilium-agent
go-module golang.org/x/crypto v0.59.0 /usr/bin/cilium-dbg
go-module golang.org/x/exp v0.0.0-20260611194520-c48552f49976 /usr/bin/cilium-agent
go-module golang.org/x/exp v0.0.0-20260611194520-c48552f49976 /usr/bin/cilium-dbg
go-module golang.org/x/exp v0.0.0-20260611194520-c48552f49976 /usr/bin/hubble
go-module golang.org/x/net v0.62.0 /opt/cni/bin/cilium-cni
go-module golang.org/x/net v0.62.0 /usr/bin/cilium-agent
go-module golang.org/x/net v0.62.0 /usr/bin/cilium-bugtool
go-module golang.org/x/net v0.62.0 /usr/bin/cilium-dbg
go-module golang.org/x/net v0.62.0 /usr/bin/cilium-envoy-bootstrap-locality
go-module golang.org/x/net v0.62.0 /usr/bin/cilium-health
go-module golang.org/x/net v0.62.0 /usr/bin/cilium-mount
go-module golang.org/x/net v0.62.0 /usr/bin/hubble
go-module golang.org/x/oauth2 v0.36.0 /usr/bin/cilium-agent
go-module golang.org/x/oauth2 v0.36.0 /usr/bin/cilium-dbg
go-module golang.org/x/oauth2 v0.36.0 /usr/bin/cilium-envoy-bootstrap-locality
go-module golang.org/x/oauth2 v0.36.0 /usr/bin/hubble
go-module golang.org/x/sync v0.25.0 /opt/cni/bin/cilium-cni
go-module golang.org/x/sync v0.25.0 /usr/bin/cilium-agent
go-module golang.org/x/sync v0.25.0 /usr/bin/cilium-bugtool
go-module golang.org/x/sync v0.25.0 /usr/bin/cilium-dbg
go-module golang.org/x/sync v0.25.0 /usr/bin/cilium-health
go-module golang.org/x/sync v0.25.0 /usr/bin/cilium-mount
go-module golang.org/x/sync v0.25.0 /usr/bin/hubble
go-module golang.org/x/sys v0.30.0 /usr/bin/gops
go-module golang.org/x/sys v0.49.0 /cni/loopback
go-module golang.org/x/sys v0.50.0 /opt/cni/bin/cilium-cni
go-module golang.org/x/sys v0.50.0 /usr/bin/cilium-agent
go-module golang.org/x/sys v0.50.0 /usr/bin/cilium-bugtool
go-module golang.org/x/sys v0.50.0 /usr/bin/cilium-dbg
go-module golang.org/x/sys v0.50.0 /usr/bin/cilium-envoy-bootstrap-locality
go-module golang.org/x/sys v0.50.0 /usr/bin/cilium-health
go-module golang.org/x/sys v0.50.0 /usr/bin/cilium-health-responder
go-module golang.org/x/sys v0.50.0 /usr/bin/cilium-mount
go-module golang.org/x/sys v0.50.0 /usr/bin/hubble
go-module golang.org/x/term v0.48.0 /opt/cni/bin/cilium-cni
go-module golang.org/x/term v0.48.0 /usr/bin/cilium-agent
go-module golang.org/x/term v0.48.0 /usr/bin/cilium-bugtool
go-module golang.org/x/term v0.48.0 /usr/bin/cilium-dbg
go-module golang.org/x/term v0.48.0 /usr/bin/cilium-envoy-bootstrap-locality
go-module golang.org/x/term v0.48.0 /usr/bin/cilium-health
go-module golang.org/x/term v0.48.0 /usr/bin/hubble
go-module golang.org/x/text v0.44.0 /opt/cni/bin/cilium-cni
go-module golang.org/x/text v0.44.0 /usr/bin/cilium-agent
go-module golang.org/x/text v0.44.0 /usr/bin/cilium-bugtool
go-module golang.org/x/text v0.44.0 /usr/bin/cilium-dbg
go-module golang.org/x/text v0.44.0 /usr/bin/cilium-envoy-bootstrap-locality
go-module golang.org/x/text v0.44.0 /usr/bin/cilium-health
go-module golang.org/x/text v0.44.0 /usr/bin/cilium-mount
go-module golang.org/x/text v0.44.0 /usr/bin/hubble
go-module golang.org/x/time v0.15.0 /opt/cni/bin/cilium-cni
go-module golang.org/x/time v0.15.0 /usr/bin/cilium-agent
go-module golang.org/x/time v0.15.0 /usr/bin/cilium-bugtool
go-module golang.org/x/time v0.15.0 /usr/bin/cilium-dbg
go-module golang.org/x/time v0.15.0 /usr/bin/cilium-envoy-bootstrap-locality
go-module golang.org/x/time v0.15.0 /usr/bin/cilium-health
go-module golang.org/x/time v0.15.0 /usr/bin/cilium-mount
go-module golang.org/x/time v0.15.0 /usr/bin/hubble
go-module golang.org/x/tools v0.52.0 /opt/cni/bin/cilium-cni
go-module golang.org/x/tools v0.52.0 /usr/bin/cilium-agent
go-module golang.org/x/tools v0.52.0 /usr/bin/cilium-bugtool
go-module golang.org/x/tools v0.52.0 /usr/bin/cilium-dbg
go-module golang.org/x/tools v0.52.0 /usr/bin/cilium-health
go-module golang.org/x/tools v0.52.0 /usr/bin/hubble
go-module golang.zx2c4.com/wireguard/wgctrl v0.0.0-20241231184526-a9ab2273dd10 /usr/bin/cilium-agent
go-module golang.zx2c4.com/wireguard/wgctrl v0.0.0-20241231184526-a9ab2273dd10 /usr/bin/cilium-dbg
go-module google.golang.org/genproto/googleapis/api v0.0.0-20260803160001-6ac0973c030d /usr/bin/cilium-agent
go-module google.golang.org/genproto/googleapis/api v0.0.0-20260803160001-6ac0973c030d /usr/bin/cilium-dbg
go-module google.golang.org/genproto/googleapis/api v0.0.0-20260803160001-6ac0973c030d /usr/bin/hubble
go-module google.golang.org/genproto/googleapis/rpc v0.0.0-20260803160001-6ac0973c030d /usr/bin/cilium-agent
go-module google.golang.org/genproto/googleapis/rpc v0.0.0-20260803160001-6ac0973c030d /usr/bin/cilium-dbg
go-module google.golang.org/genproto/googleapis/rpc v0.0.0-20260803160001-6ac0973c030d /usr/bin/hubble
go-module google.golang.org/grpc v1.83.2 /usr/bin/cilium-agent
go-module google.golang.org/grpc v1.83.2 /usr/bin/cilium-dbg
go-module google.golang.org/grpc v1.83.2 /usr/bin/hubble
go-module google.golang.org/protobuf v1.36.12-0.20260120151049-f2248ac996af /usr/bin/cilium-agent
go-module google.golang.org/protobuf v1.36.12-0.20260120151049-f2248ac996af /usr/bin/cilium-dbg
go-module google.golang.org/protobuf v1.36.12-0.20260120151049-f2248ac996af /usr/bin/cilium-envoy-bootstrap-locality
go-module google.golang.org/protobuf v1.36.12-0.20260120151049-f2248ac996af /usr/bin/hubble
go-module gopkg.in/evanphx/json-patch.v4 v4.13.0 /usr/bin/cilium-agent
go-module gopkg.in/evanphx/json-patch.v4 v4.13.0 /usr/bin/cilium-dbg
go-module gopkg.in/evanphx/json-patch.v4 v4.13.0 /usr/bin/cilium-envoy-bootstrap-locality
go-module gopkg.in/evanphx/json-patch.v4 v4.13.0 /usr/bin/hubble
go-module gopkg.in/inf.v0 v0.9.1 /opt/cni/bin/cilium-cni
go-module gopkg.in/inf.v0 v0.9.1 /usr/bin/cilium-agent
go-module gopkg.in/inf.v0 v0.9.1 /usr/bin/cilium-bugtool
go-module gopkg.in/inf.v0 v0.9.1 /usr/bin/cilium-dbg
go-module gopkg.in/inf.v0 v0.9.1 /usr/bin/cilium-envoy-bootstrap-locality
go-module gopkg.in/inf.v0 v0.9.1 /usr/bin/cilium-health
go-module gopkg.in/inf.v0 v0.9.1 /usr/bin/cilium-mount
go-module gopkg.in/inf.v0 v0.9.1 /usr/bin/hubble
deb gpgv 2.4.8-4ubuntu3.1 /usr/share/doc/gpgv/copyright /var/lib/dpkg/info/gpgv.list /var/lib/dpkg/info/gpgv.md5sums /var/lib/dpkg/status
deb grep 3.12-1 /usr/share/doc/grep/copyright /var/lib/dpkg/info/grep.list /var/lib/dpkg/info/grep.md5sums /var/lib/dpkg/status
deb gzip 1.14-1~exp2ubuntu1.1 /usr/share/doc/gzip/copyright /var/lib/dpkg/info/gzip.list /var/lib/dpkg/info/gzip.md5sums /var/lib/dpkg/info/gzip.postinst /var/lib/dpkg/info/gzip.preinst /var/lib/dpkg/status
deb hostname 3.25build1 /usr/share/doc/hostname/copyright /var/lib/dpkg/info/hostname.list /var/lib/dpkg/info/hostname.md5sums /var/lib/dpkg/status
deb init-system-helpers 1.69 /usr/share/doc/init-system-helpers/copyright /var/lib/dpkg/info/init-system-helpers.list /var/lib/dpkg/info/init-system-helpers.md5sums /var/lib/dpkg/info/init-system-helpers.postinst /var/lib/dpkg/status
deb iproute2 6.19.0-1ubuntu1.1 /usr/share/doc/iproute2/copyright /var/lib/dpkg/info/iproute2.config /var/lib/dpkg/info/iproute2.list /var/lib/dpkg/info/iproute2.md5sums /var/lib/dpkg/info/iproute2.postinst /var/lib/dpkg/info/iproute2.postrm /var/lib/dpkg/info/iproute2.preinst /var/lib/dpkg/info/iproute2.prerm /var/lib/dpkg/info/iproute2.templates /var/lib/dpkg/status
deb ipset 7.19-1ubuntu3 /usr/share/doc/ipset/copyright /var/lib/dpkg/info/ipset.list /var/lib/dpkg/info/ipset.md5sums /var/lib/dpkg/status
deb iptables 1.8.8-1 /usr/share/doc/iptables/copyright /var/lib/dpkg/info/iptables.list /var/lib/dpkg/info/iptables.md5sums /var/lib/dpkg/info/iptables.postinst /var/lib/dpkg/info/iptables.prerm /var/lib/dpkg/status
deb jq 1.8.1-4ubuntu2 /usr/share/doc/jq/copyright /var/lib/dpkg/info/jq.list /var/lib/dpkg/info/jq.md5sums /var/lib/dpkg/status
go-module k8s.io/api v0.36.6 /usr/bin/cilium-agent
go-module k8s.io/api v0.36.6 /usr/bin/cilium-dbg
go-module k8s.io/api v0.36.6 /usr/bin/cilium-envoy-bootstrap-locality
go-module k8s.io/api v0.36.6 /usr/bin/hubble
go-module k8s.io/apiextensions-apiserver v0.36.6 /usr/bin/cilium-agent
go-module k8s.io/apiextensions-apiserver v0.36.6 /usr/bin/cilium-dbg
go-module k8s.io/apiextensions-apiserver v0.36.6 /usr/bin/hubble
go-module k8s.io/apimachinery v0.36.6 /opt/cni/bin/cilium-cni
go-module k8s.io/apimachinery v0.36.6 /usr/bin/cilium-agent
go-module k8s.io/apimachinery v0.36.6 /usr/bin/cilium-bugtool
go-module k8s.io/apimachinery v0.36.6 /usr/bin/cilium-dbg
go-module k8s.io/apimachinery v0.36.6 /usr/bin/cilium-envoy-bootstrap-locality
go-module k8s.io/apimachinery v0.36.6 /usr/bin/cilium-health
go-module k8s.io/apimachinery v0.36.6 /usr/bin/cilium-mount
go-module k8s.io/apimachinery v0.36.6 /usr/bin/hubble
go-module k8s.io/apiserver v0.36.6 /usr/bin/cilium-dbg
go-module k8s.io/cli-runtime v0.36.6 /usr/bin/hubble
go-module k8s.io/client-go v0.36.6 /opt/cni/bin/cilium-cni
go-module k8s.io/client-go v0.36.6 /usr/bin/cilium-agent
go-module k8s.io/client-go v0.36.6 /usr/bin/cilium-bugtool
go-module k8s.io/client-go v0.36.6 /usr/bin/cilium-dbg
go-module k8s.io/client-go v0.36.6 /usr/bin/cilium-envoy-bootstrap-locality
go-module k8s.io/client-go v0.36.6 /usr/bin/cilium-health
go-module k8s.io/client-go v0.36.6 /usr/bin/hubble
go-module k8s.io/component-base v0.36.6 /usr/bin/cilium-dbg
go-module k8s.io/klog/v2 v2.140.0 /opt/cni/bin/cilium-cni
go-module k8s.io/klog/v2 v2.140.0 /usr/bin/cilium-agent
go-module k8s.io/klog/v2 v2.140.0 /usr/bin/cilium-bugtool
go-module k8s.io/klog/v2 v2.140.0 /usr/bin/cilium-dbg
go-module k8s.io/klog/v2 v2.140.0 /usr/bin/cilium-envoy-bootstrap-locality
go-module k8s.io/klog/v2 v2.140.0 /usr/bin/cilium-health
go-module k8s.io/klog/v2 v2.140.0 /usr/bin/cilium-mount
go-module k8s.io/klog/v2 v2.140.0 /usr/bin/hubble
go-module k8s.io/kube-openapi v0.0.0-20260501160325-927ab1f70cd6 /opt/cni/bin/cilium-cni
go-module k8s.io/kube-openapi v0.0.0-20260501160325-927ab1f70cd6 /usr/bin/cilium-agent
go-module k8s.io/kube-openapi v0.0.0-20260501160325-927ab1f70cd6 /usr/bin/cilium-bugtool
go-module k8s.io/kube-openapi v0.0.0-20260501160325-927ab1f70cd6 /usr/bin/cilium-dbg
go-module k8s.io/kube-openapi v0.0.0-20260501160325-927ab1f70cd6 /usr/bin/cilium-envoy-bootstrap-locality
go-module k8s.io/kube-openapi v0.0.0-20260501160325-927ab1f70cd6 /usr/bin/cilium-health
go-module k8s.io/kube-openapi v0.0.0-20260501160325-927ab1f70cd6 /usr/bin/cilium-mount
go-module k8s.io/kube-openapi v0.0.0-20260501160325-927ab1f70cd6 /usr/bin/hubble
go-module k8s.io/kubectl v0.36.6 /usr/bin/hubble
go-module k8s.io/streaming v0.36.6 /usr/bin/hubble
go-module k8s.io/utils v0.0.0-20261023123148-ca04ba58ecab /opt/cni/bin/cilium-cni
go-module k8s.io/utils v0.0.0-20261023123148-ca04ba58ecab /usr/bin/cilium-agent
go-module k8s.io/utils v0.0.0-20261023123148-ca04ba58ecab /usr/bin/cilium-bugtool
go-module k8s.io/utils v0.0.0-20261023123148-ca04ba58ecab /usr/bin/cilium-dbg
go-module k8s.io/utils v0.0.0-20261023123148-ca04ba58ecab /usr/bin/cilium-envoy-bootstrap-locality
go-module k8s.io/utils v0.0.0-20261023123148-ca04ba58ecab /usr/bin/cilium-health
go-module k8s.io/utils v0.0.0-20261023123148-ca04ba58ecab /usr/bin/cilium-mount
go-module k8s.io/utils v0.0.0-20261023123148-ca04ba58ecab /usr/bin/hubble
deb kmod 34.2-2ubuntu2 /usr/share/doc/kmod/copyright /usr/share/doc/libkmod2/copyright /var/lib/dpkg/info/kmod.conffiles /var/lib/dpkg/info/kmod.list /var/lib/dpkg/info/kmod.md5sums /var/lib/dpkg/info/kmod.postinst /var/lib/dpkg/info/kmod.postrm /var/lib/dpkg/info/kmod.preinst /var/lib/dpkg/info/kmod.prerm /var/lib/dpkg/info/kmod.triggers /var/lib/dpkg/status
deb libacl1 2.3.2-2 /usr/share/doc/libacl1/copyright /var/lib/dpkg/info/libacl1:amd64.md5sums /var/lib/dpkg/status
deb libapt-pkg7.0 3.2.1ubuntu0.1 /usr/share/doc/libapt-pkg7.0/copyright /var/lib/dpkg/info/libapt-pkg7.0:amd64.md5sums /var/lib/dpkg/status
deb libatomic1 16-20260322-1ubuntu1 /usr/share/doc/gcc-16-base/copyright /usr/share/doc/libatomic1/copyright /var/lib/dpkg/info/libatomic1:amd64.md5sums /var/lib/dpkg/status
deb libattr1 1:2.5.2-4ubuntu0.1 /usr/share/doc/libattr1/copyright /var/lib/dpkg/info/libattr1:amd64.conffiles /var/lib/dpkg/info/libattr1:amd64.md5sums /var/lib/dpkg/status
deb libaudit-common 1:4.1.2-1ubuntu0.1 /usr/share/doc/libaudit-common/copyright /var/lib/dpkg/info/libaudit-common.conffiles /var/lib/dpkg/info/libaudit-common.list /var/lib/dpkg/info/libaudit-common.md5sums /var/lib/dpkg/status
deb libaudit1 1:4.1.2-1ubuntu0.1 /usr/share/doc/libaudit1/copyright /var/lib/dpkg/info/libaudit1:amd64.md5sums /var/lib/dpkg/status
deb libblkid1 2.41.3-3ubuntu2.2 /usr/share/doc/libblkid1/copyright /var/lib/dpkg/info/libblkid1:amd64.md5sums /var/lib/dpkg/status
deb libbpf1 1:1.6.3-1ubuntu1 /usr/share/doc/libbpf1/copyright /var/lib/dpkg/info/libbpf1:amd64.md5sums /var/lib/dpkg/status
deb libbsd0 0.12.2-2build2 /usr/share/doc/libbsd0/copyright /var/lib/dpkg/info/libbsd0:amd64.md5sums /var/lib/dpkg/status
deb libbz2-1.0 1.0.8-6ubuntu0.1 /usr/share/doc/libbz2-1.0/copyright /var/lib/dpkg/info/libbz2-1.0:amd64.md5sums /var/lib/dpkg/status
deb libc-bin 2.43-2ubuntu2.7 /usr/share/doc/libc-bin/copyright /var/lib/dpkg/info/libc-bin.conffiles /var/lib/dpkg/info/libc-bin.list /var/lib/dpkg/info/libc-bin.md5sums /var/lib/dpkg/info/libc-bin.postinst /var/lib/dpkg/info/libc-bin.triggers /var/lib/dpkg/status
deb libc-gconv-modules-extra 2.43-2ubuntu2.7 /usr/share/doc/libc-gconv-modules-extra/copyright /var/lib/dpkg/info/libc-gconv-modules-extra:amd64.md5sums /var/lib/dpkg/status
deb libc6 2.43-2ubuntu2.7 /usr/share/doc/libc6/copyright /var/lib/dpkg/info/libc6:amd64.conffiles /var/lib/dpkg/info/libc6:amd64.md5sums /var/lib/dpkg/status
deb libcap-ng0 0.8.5-4build5 /usr/share/doc/libcap-ng0/copyright /var/lib/dpkg/info/libcap-ng0:amd64.md5sums /var/lib/dpkg/status
deb libcap2 1:2.75-10ubuntu2 /usr/share/doc/libcap2/copyright /var/lib/dpkg/info/libcap2:amd64.md5sums /var/lib/dpkg/status
deb libcap2-bin 1:2.75-10ubuntu2 /usr/share/doc/libcap2-bin/copyright /var/lib/dpkg/info/libcap2-bin.list /var/lib/dpkg/info/libcap2-bin.md5sums /var/lib/dpkg/status
deb libcom-err2 1.47.2-3ubuntu4 /usr/share/doc/libcom-err2/copyright /var/lib/dpkg/info/libcom-err2:amd64.md5sums /var/lib/dpkg/status
deb libcrypt1 1:4.5.1-1 /usr/share/doc/libcrypt1/copyright /var/lib/dpkg/info/libcrypt1:amd64.md5sums /var/lib/dpkg/status
deb libdb5.3t64 5.3.28+dfsg2-10ubuntu1 /usr/share/doc/libdb5.3t64/copyright /var/lib/dpkg/info/libdb5.3t64:amd64.md5sums /var/lib/dpkg/status
deb libdebconfclient0 0.280ubuntu1 /usr/share/doc/libdebconfclient0/copyright /var/lib/dpkg/info/libdebconfclient0:amd64.md5sums /var/lib/dpkg/status
deb libelf1t64 0.194-4 /usr/share/doc/libelf1t64/copyright /var/lib/dpkg/info/libelf1t64:amd64.md5sums /var/lib/dpkg/status
deb libext2fs2t64 1.47.2-3ubuntu4 /usr/share/doc/libext2fs2t64/copyright /var/lib/dpkg/info/libext2fs2t64:amd64.md5sums /var/lib/dpkg/status
deb libgcc-s1 16-20260322-1ubuntu1 /usr/share/doc/gcc-16-base/copyright /usr/share/doc/libgcc-s1/copyright /var/lib/dpkg/info/libgcc-s1:amd64.md5sums /var/lib/dpkg/status
deb libgcrypt20 1.12.0-2ubuntu1.1 /usr/share/doc/libgcrypt20/copyright /var/lib/dpkg/info/libgcrypt20:amd64.md5sums /var/lib/dpkg/status
deb libgmp10 2:6.3.0+dfsg-5ubuntu2 /usr/share/doc/libgmp10/copyright /var/lib/dpkg/info/libgmp10:amd64.md5sums /var/lib/dpkg/status
deb libgpg-error0 1.58-2 /usr/share/doc/libgpg-error0/copyright /var/lib/dpkg/info/libgpg-error0:amd64.md5sums /var/lib/dpkg/status
deb libgssapi-krb5-2 1.22.1-2ubuntu4.1 /usr/share/doc/libgssapi-krb5-2/copyright /var/lib/dpkg/info/libgssapi-krb5-2:amd64.md5sums /var/lib/dpkg/status
deb libip4tc-dev 1.8.8-1 /usr/share/doc/libip4tc-dev/copyright /var/lib/dpkg/info/libip4tc-dev:amd64.md5sums /var/lib/dpkg/status
deb libip4tc2 1.8.8-1 /usr/share/doc/libip4tc2/copyright /var/lib/dpkg/info/libip4tc2:amd64.md5sums /var/lib/dpkg/status
deb libip6tc-dev 1.8.8-1 /usr/share/doc/libip6tc-dev/copyright /var/lib/dpkg/info/libip6tc-dev:amd64.md5sums /var/lib/dpkg/status
deb libip6tc2 1.8.8-1 /usr/share/doc/libip6tc2/copyright /var/lib/dpkg/info/libip6tc2:amd64.md5sums /var/lib/dpkg/status
deb libipset13 7.19-1ubuntu3 /usr/share/doc/libipset13/copyright /var/lib/dpkg/info/libipset13:amd64.md5sums /var/lib/dpkg/status
deb libiptc-dev 1.8.8-1 /usr/share/doc/libiptc-dev/copyright /var/lib/dpkg/info/libiptc-dev:amd64.md5sums /var/lib/dpkg/status
deb libiptc0 1.8.8-1 /usr/share/doc/libiptc0/copyright /var/lib/dpkg/info/libiptc0:amd64.md5sums /var/lib/dpkg/status
deb libjq1 1.8.1-4ubuntu2 /usr/share/doc/libjq1/copyright /var/lib/dpkg/info/libjq1:amd64.md5sums /var/lib/dpkg/status
deb libk5crypto3 1.22.1-2ubuntu4.1 /usr/share/doc/libk5crypto3/copyright /var/lib/dpkg/info/libk5crypto3:amd64.md5sums /var/lib/dpkg/status
deb libkeyutils1 1.6.3-6ubuntu3 /usr/share/doc/libkeyutils1/copyright /var/lib/dpkg/info/libkeyutils1:amd64.md5sums /var/lib/dpkg/status
deb libkmod2 34.2-2ubuntu2 /usr/share/doc/libkmod2/copyright /var/lib/dpkg/info/libkmod2:amd64.md5sums /var/lib/dpkg/status
deb libkrb5-3 1.22.1-2ubuntu4.1 /usr/share/doc/libkrb5-3/copyright /var/lib/dpkg/info/libkrb5-3:amd64.md5sums /var/lib/dpkg/status
deb libkrb5support0 1.22.1-2ubuntu4.1 /usr/share/doc/libkrb5support0/copyright /var/lib/dpkg/info/libkrb5support0:amd64.md5sums /var/lib/dpkg/status
deb liblz4-1 1.10.0-8 /usr/share/doc/liblz4-1/copyright /var/lib/dpkg/info/liblz4-1:amd64.md5sums /var/lib/dpkg/status
deb liblzma5 5.8.3-1ubuntu0.1 /usr/share/doc/liblzma5/copyright /var/lib/dpkg/info/liblzma5:amd64.md5sums /var/lib/dpkg/status
deb libmd0 1.1.0-2build4 /usr/share/doc/libmd0/copyright /var/lib/dpkg/info/libmd0:amd64.md5sums /var/lib/dpkg/status
deb libmnl0 1.0.5-3build1 /usr/share/doc/libmnl0/copyright /var/lib/dpkg/info/libmnl0:amd64.md5sums /var/lib/dpkg/status
deb libmount1 2.41.3-3ubuntu2.2 /usr/share/doc/libmount1/copyright /var/lib/dpkg/info/libmount1:amd64.md5sums /var/lib/dpkg/status
deb libncursesw6 6.6+20251231-1 /usr/share/doc/libncursesw6/copyright /usr/share/doc/libtinfo6/copyright /var/lib/dpkg/info/libncursesw6:amd64.md5sums /var/lib/dpkg/status
deb libnetfilter-conntrack3 1.1.1-1 /usr/share/doc/libnetfilter-conntrack3/copyright /var/lib/dpkg/info/libnetfilter-conntrack3:amd64.md5sums /var/lib/dpkg/status
deb libnfnetlink0 1.0.2-3build1 /usr/share/doc/libnfnetlink0/copyright /var/lib/dpkg/info/libnfnetlink0:amd64.md5sums /var/lib/dpkg/status
deb libnftnl11 1.3.1-1 /usr/share/doc/libnftnl11/copyright /var/lib/dpkg/info/libnftnl11:amd64.md5sums /var/lib/dpkg/status
deb libonig5 6.9.10-1build1 /usr/share/doc/libonig5/copyright /var/lib/dpkg/info/libonig5:amd64.md5sums /var/lib/dpkg/status
deb libpam-modules 1.7.0-5ubuntu3.2 /usr/share/doc/libpam-modules/copyright /var/lib/dpkg/info/libpam-modules:amd64.conffiles /var/lib/dpkg/info/libpam-modules:amd64.md5sums /var/lib/dpkg/status
deb libpam-modules-bin 1.7.0-5ubuntu3.2 /usr/share/doc/libpam-modules-bin/copyright /var/lib/dpkg/info/libpam-modules-bin.list /var/lib/dpkg/info/libpam-modules-bin.md5sums /var/lib/dpkg/info/libpam-modules-bin.postinst /var/lib/dpkg/info/libpam-modules-bin.postrm /var/lib/dpkg/info/libpam-modules-bin.prerm /var/lib/dpkg/status
deb libpam-runtime 1.7.0-5ubuntu3.2 /usr/share/doc/libpam-runtime/copyright /var/lib/dpkg/info/libpam-runtime.conffiles /var/lib/dpkg/info/libpam-runtime.list /var/lib/dpkg/info/libpam-runtime.md5sums /var/lib/dpkg/info/libpam-runtime.postinst /var/lib/dpkg/info/libpam-runtime.postrm /var/lib/dpkg/info/libpam-runtime.prerm /var/lib/dpkg/info/libpam-runtime.templates /var/lib/dpkg/status
deb libpam0g 1.7.0-5ubuntu3.2 /usr/share/doc/libpam0g/copyright /var/lib/dpkg/info/libpam0g:amd64.md5sums /var/lib/dpkg/status
deb libpcre2-8-0 10.46-1ubuntu0.1 /usr/share/doc/libpcre2-8-0/copyright /var/lib/dpkg/info/libpcre2-8-0:amd64.md5sums /var/lib/dpkg/status
deb libproc2-0 2:4.0.4-9ubuntu1 /usr/share/doc/libproc2-0/copyright /var/lib/dpkg/info/libproc2-0:amd64.md5sums /var/lib/dpkg/status
deb libseccomp2 2.6.0-2ubuntu5 /usr/share/doc/libseccomp2/copyright /var/lib/dpkg/info/libseccomp2:amd64.md5sums /var/lib/dpkg/status
deb libselinux1 3.9-4build1 /usr/share/doc/libselinux1/copyright /var/lib/dpkg/info/libselinux1:amd64.md5sums /var/lib/dpkg/status
deb libsemanage-common 3.9-1build1 /usr/share/doc/libsemanage-common/copyright /var/lib/dpkg/info/libsemanage-common.conffiles /var/lib/dpkg/info/libsemanage-common.list /var/lib/dpkg/info/libsemanage-common.md5sums /var/lib/dpkg/status
deb libsemanage2 3.9-1build1 /usr/share/doc/libsemanage2/copyright /var/lib/dpkg/info/libsemanage2:amd64.md5sums /var/lib/dpkg/status
deb libsepol2 3.9-2 /usr/share/doc/libsepol2/copyright /var/lib/dpkg/info/libsepol2:amd64.md5sums /var/lib/dpkg/status
deb libsmartcols1 2.41.3-3ubuntu2.2 /usr/share/doc/libsmartcols1/copyright /var/lib/dpkg/info/libsmartcols1:amd64.md5sums /var/lib/dpkg/status
deb libss2 1.47.2-3ubuntu4 /usr/share/doc/libss2/copyright /var/lib/dpkg/info/libss2:amd64.md5sums /var/lib/dpkg/status
deb libssl3t64 3.5.5-1ubuntu3.7 /usr/share/doc/libssl3t64/copyright /var/lib/dpkg/info/libssl3t64:amd64.md5sums /var/lib/dpkg/status
deb libstdc++6 16-20260322-1ubuntu1 /usr/share/doc/gcc-16-base/copyright /usr/share/doc/libstdc++6/copyright /var/lib/dpkg/info/libstdc++6:amd64.md5sums /var/lib/dpkg/status
deb libsystemd0 259.9-0ubuntu0.1 /usr/share/doc/libsystemd0/copyright /var/lib/dpkg/info/libsystemd0:amd64.md5sums /var/lib/dpkg/status
deb libtinfo6 6.6+20251231-1 /usr/share/doc/libtinfo6/copyright /var/lib/dpkg/info/libtinfo6:amd64.md5sums /var/lib/dpkg/status
deb libtirpc-common 1.3.7-0.1 /usr/share/doc/libtirpc-common/copyright /var/lib/dpkg/info/libtirpc-common.conffiles /var/lib/dpkg/info/libtirpc-common.list /var/lib/dpkg/info/libtirpc-common.md5sums /var/lib/dpkg/status
deb libtirpc3t64 1.3.7-0.1 /usr/share/doc/libtirpc3t64/copyright /var/lib/dpkg/info/libtirpc3t64:amd64.md5sums /var/lib/dpkg/status
deb libudev1 259.9-0ubuntu0.1 /usr/share/doc/libudev1/copyright /var/lib/dpkg/info/libudev1:amd64.md5sums /var/lib/dpkg/status
deb libuuid1 2.41.3-3ubuntu2.2 /usr/share/doc/libuuid1/copyright /var/lib/dpkg/info/libuuid1:amd64.md5sums /var/lib/dpkg/status
deb libxtables-dev 1.8.8-1 /usr/share/doc/libxtables-dev/copyright /var/lib/dpkg/info/libxtables-dev:amd64.md5sums /var/lib/dpkg/status
deb libxtables12 1.8.8-1 /usr/share/doc/libxtables12/copyright /var/lib/dpkg/info/libxtables12:amd64.md5sums /var/lib/dpkg/status
deb libxxhash0 0.8.3-2build1 /usr/share/doc/libxxhash0/copyright /var/lib/dpkg/info/libxxhash0:amd64.md5sums /var/lib/dpkg/status
deb libzstd1 1.5.7+dfsg-3 /usr/share/doc/libzstd1/copyright /var/lib/dpkg/info/libzstd1:amd64.md5sums /var/lib/dpkg/status
deb login 1:4.16.0-2+really2.41.3-3ubuntu2.2 /usr/share/doc/login/copyright /var/lib/dpkg/info/login.conffiles /var/lib/dpkg/info/login.defs.conffiles /var/lib/dpkg/info/login.defs.list /var/lib/dpkg/info/login.defs.md5sums /var/lib/dpkg/info/login.defs.postinst /var/lib/dpkg/info/login.list /var/lib/dpkg/info/login.md5sums /var/lib/dpkg/info/login.postinst /var/lib/dpkg/info/login.postrm /var/lib/dpkg/info/login.preinst /var/lib/dpkg/info/login.prerm /var/lib/dpkg/status
deb login.defs 1:4.17.4-2ubuntu3 /usr/share/doc/login.defs/copyright /var/lib/dpkg/info/login.defs.conffiles /var/lib/dpkg/info/login.defs.list /var/lib/dpkg/info/login.defs.md5sums /var/lib/dpkg/info/login.defs.postinst /var/lib/dpkg/status
deb logsave 1.47.2-3ubuntu4 /usr/share/doc/logsave/copyright /var/lib/dpkg/info/logsave.list /var/lib/dpkg/info/logsave.md5sums /var/lib/dpkg/status
deb mawk 1.3.4.20260129-1 /usr/share/doc/mawk/copyright /var/lib/dpkg/info/mawk.list /var/lib/dpkg/info/mawk.md5sums /var/lib/dpkg/info/mawk.postinst /var/lib/dpkg/info/mawk.prerm /var/lib/dpkg/status
deb mount 2.41.3-3ubuntu2.2 /usr/share/doc/mount/copyright /var/lib/dpkg/info/mount.list /var/lib/dpkg/info/mount.md5sums /var/lib/dpkg/status
deb ncurses-base 6.6+20251231-1 /usr/share/doc/ncurses-base/copyright /var/lib/dpkg/info/ncurses-base.conffiles /var/lib/dpkg/info/ncurses-base.list /var/lib/dpkg/info/ncurses-base.md5sums /var/lib/dpkg/status
deb ncurses-bin 6.6+20251231-1 /usr/share/doc/ncurses-bin/copyright /var/lib/dpkg/info/ncurses-bin.list /var/lib/dpkg/info/ncurses-bin.md5sums /var/lib/dpkg/status
deb netbase 6.5build1 /usr/share/doc/netbase/copyright /var/lib/dpkg/info/netbase.conffiles /var/lib/dpkg/info/netbase.list /var/lib/dpkg/info/netbase.md5sums /var/lib/dpkg/info/netbase.postinst /var/lib/dpkg/info/netbase.postrm /var/lib/dpkg/status
deb openssl 3.5.5-1ubuntu3.7 /usr/share/doc/libssl3t64/copyright /usr/share/doc/openssl/copyright /var/lib/dpkg/info/openssl.conffiles /var/lib/dpkg/info/openssl.list /var/lib/dpkg/info/openssl.md5sums /var/lib/dpkg/info/openssl.postinst /var/lib/dpkg/status
deb openssl-provider-legacy 3.5.5-1ubuntu3.7 /usr/share/doc/openssl-provider-legacy/copyright /var/lib/dpkg/info/openssl-provider-legacy.list /var/lib/dpkg/info/openssl-provider-legacy.md5sums /var/lib/dpkg/status
deb passwd 1:4.17.4-2ubuntu3 /usr/share/doc/passwd/copyright /var/lib/dpkg/info/passwd.conffiles /var/lib/dpkg/info/passwd.list /var/lib/dpkg/info/passwd.md5sums /var/lib/dpkg/info/passwd.postinst /var/lib/dpkg/info/passwd.postrm /var/lib/dpkg/info/passwd.preinst /var/lib/dpkg/info/passwd.prerm /var/lib/dpkg/status
deb perl-base 5.40.1-7ubuntu0.4 /usr/share/doc/perl-base/copyright /var/lib/dpkg/info/perl-base.list /var/lib/dpkg/info/perl-base.md5sums /var/lib/dpkg/status
deb procps 2:4.0.4-9ubuntu1 /usr/share/doc/procps/copyright /var/lib/dpkg/info/procps.conffiles /var/lib/dpkg/info/procps.list /var/lib/dpkg/info/procps.md5sums /var/lib/dpkg/info/procps.postinst /var/lib/dpkg/info/procps.postrm /var/lib/dpkg/info/procps.preinst /var/lib/dpkg/info/procps.prerm /var/lib/dpkg/info/procps.triggers /var/lib/dpkg/status
deb rust-coreutils 0.10.0-1ubuntu2~26.04.1 /usr/share/doc/rust-coreutils/copyright /var/lib/dpkg/info/rust-coreutils.list /var/lib/dpkg/info/rust-coreutils.md5sums /var/lib/dpkg/status
deb sed 4.9-2ubuntu1 /usr/share/doc/sed/copyright /var/lib/dpkg/info/sed.list /var/lib/dpkg/info/sed.md5sums /var/lib/dpkg/status
deb sensible-utils 0.0.26build1 /usr/share/doc/sensible-utils/copyright /var/lib/dpkg/info/sensible-utils.list /var/lib/dpkg/info/sensible-utils.md5sums /var/lib/dpkg/status
go-module sigs.k8s.io/controller-runtime v0.24.1 /usr/bin/cilium-agent
go-module sigs.k8s.io/controller-runtime v0.24.1 /usr/bin/cilium-dbg
go-module sigs.k8s.io/gateway-api v1.6.3 /usr/bin/cilium-agent
go-module sigs.k8s.io/gateway-api v1.6.3 /usr/bin/cilium-dbg
go-module sigs.k8s.io/json v0.0.0-20250730193827-2d320260d730 /opt/cni/bin/cilium-cni
go-module sigs.k8s.io/json v0.0.0-20250730193827-2d320260d730 /usr/bin/cilium-agent
go-module sigs.k8s.io/json v0.0.0-20250730193827-2d320260d730 /usr/bin/cilium-bugtool
go-module sigs.k8s.io/json v0.0.0-20250730193827-2d320260d730 /usr/bin/cilium-dbg
go-module sigs.k8s.io/json v0.0.0-20250730193827-2d320260d730 /usr/bin/cilium-envoy-bootstrap-locality
go-module sigs.k8s.io/json v0.0.0-20250730193827-2d320260d730 /usr/bin/cilium-health
go-module sigs.k8s.io/json v0.0.0-20250730193827-2d320260d730 /usr/bin/cilium-mount
go-module sigs.k8s.io/json v0.0.0-20250730193827-2d320260d730 /usr/bin/hubble
go-module sigs.k8s.io/kustomize/api v0.21.1 /usr/bin/hubble
go-module sigs.k8s.io/kustomize/kyaml v0.21.1 /usr/bin/hubble
go-module sigs.k8s.io/mcs-api v0.5.2 /usr/bin/cilium-agent
go-module sigs.k8s.io/mcs-api v0.5.2 /usr/bin/cilium-dbg
go-module sigs.k8s.io/mcs-api v0.5.2 /usr/bin/hubble
go-module sigs.k8s.io/network-policy-api v0.2.1 /usr/bin/cilium-agent
go-module sigs.k8s.io/network-policy-api v0.2.1 /usr/bin/cilium-dbg
go-module sigs.k8s.io/network-policy-api v0.2.1 /usr/bin/hubble
go-module sigs.k8s.io/randfill v1.0.0 /opt/cni/bin/cilium-cni
go-module sigs.k8s.io/randfill v1.0.0 /usr/bin/cilium-agent
go-module sigs.k8s.io/randfill v1.0.0 /usr/bin/cilium-bugtool
go-module sigs.k8s.io/randfill v1.0.0 /usr/bin/cilium-dbg
go-module sigs.k8s.io/randfill v1.0.0 /usr/bin/cilium-envoy-bootstrap-locality
go-module sigs.k8s.io/randfill v1.0.0 /usr/bin/cilium-health
go-module sigs.k8s.io/randfill v1.0.0 /usr/bin/cilium-mount
go-module sigs.k8s.io/randfill v1.0.0 /usr/bin/hubble
go-module sigs.k8s.io/structured-merge-diff/v6 v6.4.0 /opt/cni/bin/cilium-cni
go-module sigs.k8s.io/structured-merge-diff/v6 v6.4.0 /usr/bin/cilium-agent
go-module sigs.k8s.io/structured-merge-diff/v6 v6.4.0 /usr/bin/cilium-bugtool
go-module sigs.k8s.io/structured-merge-diff/v6 v6.4.0 /usr/bin/cilium-dbg
go-module sigs.k8s.io/structured-merge-diff/v6 v6.4.0 /usr/bin/cilium-envoy-bootstrap-locality
go-module sigs.k8s.io/structured-merge-diff/v6 v6.4.0 /usr/bin/cilium-health
go-module sigs.k8s.io/structured-merge-diff/v6 v6.4.0 /usr/bin/cilium-mount
go-module sigs.k8s.io/structured-merge-diff/v6 v6.4.0 /usr/bin/hubble
go-module sigs.k8s.io/yaml v1.6.0 /usr/bin/cilium-agent
go-module sigs.k8s.io/yaml v1.6.0 /usr/bin/cilium-dbg
go-module sigs.k8s.io/yaml v1.6.0 /usr/bin/cilium-envoy-bootstrap-locality
go-module sigs.k8s.io/yaml v1.6.0 /usr/bin/hubble
go-module stdlib go1.26.11 /cni/loopback
go-module stdlib go1.26.11 /opt/cni/bin/cilium-cni
go-module stdlib go1.26.11 /usr/bin/cilium-agent
go-module stdlib go1.26.11 /usr/bin/cilium-bugtool
go-module stdlib go1.26.11 /usr/bin/cilium-dbg
go-module stdlib go1.26.11 /usr/bin/cilium-envoy-bootstrap-locality
go-module stdlib go1.26.11 /usr/bin/cilium-health
go-module stdlib go1.26.11 /usr/bin/cilium-health-responder
go-module stdlib go1.26.11 /usr/bin/cilium-mount
go-module stdlib go1.26.11 /usr/bin/cilium-sysctlfix
go-module stdlib go1.26.11 /usr/bin/gops
go-module stdlib go1.26.11 /usr/bin/hubble
go-module stdlib go1.26.11 /usr/sbin/iptables-wrapper
deb sysvinit-utils 3.15-5ubuntu1 /usr/share/doc/sysvinit-utils/copyright /var/lib/dpkg/info/sysvinit-utils.list /var/lib/dpkg/info/sysvinit-utils.md5sums /var/lib/dpkg/status
deb tar 1.35+dfsg-4ubuntu0.4 /usr/share/doc/tar/copyright /var/lib/dpkg/info/tar.list /var/lib/dpkg/info/tar.md5sums /var/lib/dpkg/info/tar.postinst /var/lib/dpkg/info/tar.prerm /var/lib/dpkg/status
deb ubuntu-keyring 2023.11.28.1build1 /usr/share/doc/ubuntu-keyring/copyright /var/lib/dpkg/info/ubuntu-keyring.list /var/lib/dpkg/info/ubuntu-keyring.md5sums /var/lib/dpkg/info/ubuntu-keyring.postinst /var/lib/dpkg/status
deb util-linux 2.41.3-3ubuntu2.2 /usr/share/doc/util-linux/copyright /var/lib/dpkg/info/util-linux.conffiles /var/lib/dpkg/info/util-linux.list /var/lib/dpkg/info/util-linux.md5sums /var/lib/dpkg/info/util-linux.postinst /var/lib/dpkg/info/util-linux.postrm /var/lib/dpkg/info/util-linux.prerm /var/lib/dpkg/status
deb zlib1g 1:1.3.dfsg+really1.3.1-1ubuntu3.2 /usr/share/doc/zlib1g/copyright /var/lib/dpkg/info/zlib1g:amd64.md5sums /var/lib/dpkg/status
"""


def observation():
    packages = []
    catalogers = {"deb": "dpkg-db-cataloger", "go-module": "go-module-binary-cataloger"}
    for line in _ROWS.splitlines():
        kind, name, version, *paths = line.split()
        packages.append(
            {
                "type": kind,
                "name": name,
                "version": version,
                "paths": paths,
                "foundBy": catalogers[kind],
            }
        )
    return {
        "image_id": "sha256:33f1b95a921dd4ed3acfb9a7fbaa003f51bd221295e6715c7904682d11525264",
        "scope": "package-observation-not-application-coverage",
        "status": "inconclusive",
        "distro": {"id": "ubuntu", "versionID": "26.04"},
        "package_count": 947,
        "package_types": {"deb": 124, "go-module": 823},
        "packages": packages,
    }
