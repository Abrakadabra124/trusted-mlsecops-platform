"""Publish the qualified etcd archive from the fixed delivery authority."""

from scripts.qualified_publication import REPOSITORY, QualifiedPublisher


class EtcdPublisher(QualifiedPublisher):
    COMPONENT = "etcd"
    TAG_PREFIX = "3.6.17-xcrypto-v0.59.0-r1-"
    WORKFLOW = ".github/workflows/etcd-candidate.yml"
    BRANCH = "qualify/r1-etcd-delivery"
    EXPECTED_SOURCE = "13ef78c65cf212706b1bbb4495a33ef6437d1fc2"
    WORKFLOW_SHA256 = "d17df170a0e8f7e39b8444c0bb4b5b4a04082355e25904be403ec55441e6ec6e"
    RECIPE = "2c2ef58b4f8eeb484d24c0bb1d55b91d9d26fd2e49a1185153bbe8511a2f5f2d"
    STEPS = (
        "Build twice and compare files extracted from both final images",
        "Scan both Docker archives and the three extracted candidate executables",
        "Check native versions and run a disposable single-member server",
        "Apply the candidate gates to the unmodified reports",
        "Prepare project workspace and pinned kind tools",
        "Replace and roll back the etcd static Pod on the owned kind node",
        "Remove and verify the disposable kind cluster and node",
        "Bind the original scanned archive to the verified running config",
        "Upload the qualified archive and its receipt",
    )

    def verify_image(self, details):
        labels = details["Config"]["Labels"]
        self.require(
            labels.get("org.opencontainers.image.source") == "https://github.com/" + REPOSITORY
            and labels.get("org.opencontainers.image.version") == "3.6.17"
            and labels.get("org.trusted-mlsecops-platform.etcd.patch") == "x-crypto-v0.59.0-r1"
            and labels.get("org.trusted-mlsecops-platform.etcd.upstream-revision")
            == "0689586e360e2c6b46f95ad5634c25d5fa1683db",
            "image_labels_invalid",
        )


PUBLISHER = EtcdPublisher()
main = PUBLISHER.main


if __name__ == "__main__":
    raise SystemExit(main())
