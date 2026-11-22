"""Publish only the reviewed CoreDNS kind qualification from the public project."""

import re

from scripts.qualified_publication import QualifiedPublisher, positive


class CoreDNSPublisher(QualifiedPublisher):
    COMPONENT = "coredns"
    TAG_PREFIX = "1.15.0-deps-r1-"
    WORKFLOW = ".github/workflows/coredns-dependency-candidate.yml"
    BRANCH = "qualify/r1-coredns-kind-candidate"
    REQUIRE_PUBLIC = True

    EXPECTED_SOURCE = "75ed1469660bb69bf0fc2157b9b3e4ed38993910"
    WORKFLOW_SHA256 = "5a3637fcd3e64f49eb76d077d33b1a2ca57c640c0f0eea98fd79f2f3c6fdb15e"
    RECIPE = "1d7bde1eaa8639468a9e6ed2d7a71033e6536e7f0b1ae2915b58770ddeb61b3a"
    RUN_ID = 45027909018
    JOB_ID = 137224861240
    JOB_NAME = "qualify"
    ARTIFACT_ID = 14756383824
    ZIP_DIGEST = "sha256:7199a842682c7579a444429efd67fe9bd5fa347eec888a46c77e0727cd7dd988"
    ZIP_SIZE = 159623877
    STEPS = (
        "Set up job",
        "Read exact public source and check the recipe pin",
        "Run astral-sh/setup-uv@c18668ad3cf93ea998bef934396af7bb5c839dc7",
        "Test the inventory, capability and finding gates",
        "Build twice offline and export the agreed executable hash",
        "Compare the original findings and inspect the archived executables",
        "Query the candidate on UDP port 53 in its own network namespace",
        "Prepare the project workspace and pinned kind tools",
        "Verify both running CoreDNS replicas, switch and roll back",
        "Delete the owned disposable cluster and verify absence",
        "Bind the scanned archive to the verified running CoreDNS config",
        "Upload the scanned CoreDNS archive and its receipt",
        "Post Run astral-sh/setup-uv@c18668ad3cf93ea998bef934396af7bb5c839dc7",
        "Complete job",
    )

    def preflight(self, env):
        run_id = self.dispatch(env, env.get("QUALIFIED_RUN_ID", ""))
        # The fixed public repository exposes job and artifact metadata without a grant.
        return self.evidence(run_id, None)

    def verify_pins(self, run_id):
        pins = ((self.EXPECTED_SOURCE, 40), (self.WORKFLOW_SHA256, 64), (self.RECIPE, 64))
        self.require(
            all(
                isinstance(v, str) and re.fullmatch(f"[0-9a-f]{{{size}}}", v) and v != "0" * size
                for v, size in pins
            )
            and positive(self.RUN_ID)
            and positive(self.JOB_ID)
            and isinstance(self.JOB_NAME, str)
            and self.JOB_NAME.strip()
            and isinstance(self.STEPS, tuple)
            and self.STEPS
            and all(isinstance(name, str) and name.strip() for name in self.STEPS),
            "producer_pins_unset",
        )
        self.require(positive(run_id) and run_id == self.RUN_ID, "run_id_invalid")

    def job_matches(self, job):
        return (
            super().job_matches(job)
            and positive(job.get("id"))
            and job["id"] == self.JOB_ID
            and tuple(step["name"] for step in job["steps"]) == self.STEPS
        )

    def select_artifact(self, document, run_id):
        self.require(document["total_count"] == 1, "artifact_count")
        artifact = super().select_artifact(document, run_id)
        self.require(
            artifact["id"] == self.ARTIFACT_ID
            and artifact["digest"] == self.ZIP_DIGEST
            and artifact["size_in_bytes"] == self.ZIP_SIZE,
            "artifact_pin_mismatch",
        )
        return artifact

    def verify_image(self, details):
        config = details["Config"]
        self.require(
            config.get("User") == "65532:65532" and config.get("Entrypoint") == ["/coredns"],
            "image_config_invalid",
        )


PUBLISHER = CoreDNSPublisher()


if __name__ == "__main__":
    raise SystemExit(PUBLISHER.main())
