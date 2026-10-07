import hashlib
import io
import platform
import tarfile
import urllib.request
from pathlib import Path

TOOLS = {
    "kind": (
        "https://github.com/kubernetes-sigs/kind/releases/download/v0.33.0/kind-linux-amd64",
        "aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d",
        None,
    ),
    "helm": (
        "https://get.helm.sh/helm-v4.2.4-linux-amd64.tar.gz",
        "c306b46f719b0a4da32d0f78ee21bf90ce8d602f15b22ab753f0674d1670a7f3",
        "linux-amd64/helm",
    ),
    "kubectl": (
        "https://dl.k8s.io/release/v1.36.4/bin/linux/amd64/kubectl",
        "8b8f088da2dab964f853b38464033b1be15ede2839eca751482357c45abdd05a",
        None,
    ),
}


def main():
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise SystemExit("This installer targets disposable Linux x86_64 CI runners only")
    target = Path(".runtime/bin").resolve()
    if target.parent != Path(".runtime").resolve() or target.is_symlink():
        raise SystemExit("Unsafe local tool directory")
    target.mkdir(parents=True, exist_ok=True)
    for name, (url, expected, member_name) in TOOLS.items():
        with urllib.request.urlopen(url, timeout=90) as response:
            content = response.read(128 * 1024**2 + 1)
        if len(content) > 128 * 1024**2 or hashlib.sha256(content).hexdigest() != expected:
            raise SystemExit(f"Digest or size mismatch: {name}")
        if member_name:
            with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as archive:
                member = archive.getmember(member_name)
                if not member.isfile() or member.size > 128 * 1024**2:
                    raise SystemExit("Invalid archive member")
                content = archive.extractfile(member).read()
        path = target / name
        if path.is_symlink():
            raise SystemExit("Refusing symlink tool target")
        path.write_bytes(content)
        path.chmod(0o755)
        print(name, hashlib.sha256(content).hexdigest())


if __name__ == "__main__":
    main()
