"""Publish only the reviewed CoreDNS kind qualification from the public project."""

import re

from scripts.qualified_publication import QualifiedPublisher, positive


class CoreDNSPublisher(QualifiedPublisher):
    COMPONENT = "coredns"
    TAG_PREFIX = "1.15.0-deps-r1-"
    WORKFLOW = ".github/workflows/coredns-dependency-candidate.yml"
    BRANCH = "qualify/r1-coredns-kind-candidate"
    REQUIRE_PUBLIC = True

    # Set together after review of a successful replacement producer and its archive.
    EXPECTED_SOURCE = None
    WORKFLOW_SHA256 = None
    RECIPE = None
    RUN_ID = None
    JOB_ID = None
    JOB_NAME = None
    STEPS = ()

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

    def verify_image(self, details):
        config = details["Config"]
        self.require(
            config.get("User") == "65532:65532" and config.get("Entrypoint") == ["/coredns"],
            "image_config_invalid",
        )


PUBLISHER = CoreDNSPublisher()


if __name__ == "__main__":
    raise SystemExit(PUBLISHER.main())
