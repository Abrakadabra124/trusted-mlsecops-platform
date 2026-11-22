FROM kindest/node@sha256:597367624b4748b74b98e4fe2d661cd78063d02ecdaca702fd90572375b83e67
RUN --network=none --mount=type=bind,target=/inputs <<'SH'
set -eu
set -- libssl3t64 openssl openssl-provider-legacy
for package do
    test "$(dpkg-query -W -f='${Status} ${Version} ${Architecture}' "$package")" = "install ok installed 3.5.6-1~deb13u2 amd64"
    file="/inputs/${package}_3.5.9-1~deb13u1_amd64.deb"
    test "$(dpkg-deb -f "$file" Package)" = "$package"
    test "$(dpkg-deb -f "$file" Version)" = '3.5.9-1~deb13u1'
    test "$(dpkg-deb -f "$file" Architecture)" = amd64
done
DEBIAN_FRONTEND=noninteractive dpkg --force-confold -i /inputs/*.deb
for package do
    test "$(dpkg-query -W -f='${Status} ${Version} ${Architecture}' "$package")" = "install ok installed 3.5.9-1~deb13u1 amd64"
done
problems=$(dpkg --audit "$@")
test -z "$problems"
# Read back all ELF payloads from the three signed amd64 packages after dpkg triggers.
sha256sum --check <<'SUMS'
238d03b1d3a7f5aa3c9cf8171d483a32c227df0f5a606a55ab31f154c8aa60be  /usr/bin/openssl
a4e00ad0bb09d820ba5c41672567e965d4ca03153f7842751ef243355a569805  /usr/lib/x86_64-linux-gnu/libcrypto.so.3
a890bcf10b78b752135a035809a10792330ff9b9c2ae3bb2239d7a08a5a6610b  /usr/lib/x86_64-linux-gnu/libssl.so.3
47af7436924d44b49719792780eaee3c472df720908cb969f00c940c219cba45  /usr/lib/x86_64-linux-gnu/ossl-modules/legacy.so
98bbe2dc4f1ba3af6302a168abe1ee326fd30961f73adcd2dc40f0063ef702b1  /usr/lib/x86_64-linux-gnu/engines-3/afalg.so
6f3f7a2b43f973bb6ef86f4e52fbecffd36702bd7c8938e86f8e55edde88050c  /usr/lib/x86_64-linux-gnu/engines-3/loader_attic.so
72102fc277f866a8fa3e98eb727d5fd5064fe2a2d2231117eb8d0eaf8d9a6fef  /usr/lib/x86_64-linux-gnu/engines-3/padlock.so
SUMS
SH
