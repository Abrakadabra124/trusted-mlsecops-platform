"""Finite operator-selected trust destinations; never an automatic fallback."""

from enum import StrEnum

from mlsecops.contracts import Rejected


class Target(StrEnum):
    PRIMARY = "primary"
    MODEL_REVOCATION = "model-revocation"

    @property
    def namespace(self):
        return "ml-trust" if self is Target.PRIMARY else "ml-trust-model"

    @property
    def host(self):
        return "postgres." + self.namespace + ".svc.cluster.local"

    @property
    def secret(self):
        return "trust-client" if self is Target.PRIMARY else "trust-client-model"

    @property
    def directory(self):
        return "kubernetes-trust" if self is Target.PRIMARY else "kubernetes-trust-model"


def select(value):
    if isinstance(value, Target):
        return value
    if type(value) is str:
        try:
            return Target(value)
        except ValueError:
            pass
    raise Rejected("trust_target_invalid")


HOSTS = tuple(target.host for target in Target)
