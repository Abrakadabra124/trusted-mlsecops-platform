"""Public, immutable observer configuration backed by a complete dual-signed root history."""

import copy

from mlsecops import kube_security_resources as resources
from mlsecops import security_events as events
from mlsecops import security_trust_events as source
from mlsecops import trust_rotation
from mlsecops.contracts import Rejected, canonical, digest

MAX_CONFIG_BYTES = 128 * 1024


def verify(profile, context):
    events.shape(profile, ("schema_version", "history", "rotations"))
    events.version(profile["schema_version"])
    rotations = profile["rotations"]
    if type(rotations) is not list or not 1 <= len(rotations) <= source.MAX_ROTATIONS:
        raise Rejected("kube_observer_rotation_count")
    source.project(
        profile["history"],
        environment=context["environment"],
        initial_root=context["initial_root"],
        rotations=rotations,
    )
    versions = [item["version"] for item in rotations]
    if versions != sorted(versions):
        raise Rejected("kube_observer_rotation_order")
    if sum(len(canonical(item["package"])) for item in rotations) > MAX_CONFIG_BYTES // 2:
        raise Rejected("kube_observer_configuration_limit")
    return profile


def current_root(profile, context):
    if profile is None:
        return events.public_key(context["initial_root"])
    return verify(profile, context)["history"]["root_public"]


def authorized_roots(profile, context):
    # Continuity only. The model/promotion reader still checks the CURRENT SQL root;
    # a historically configured HTTP reader must be able to report its actual refusal.
    if profile is None:
        return (events.public_key(context["initial_root"]),)
    verify(profile, context)
    return (context["initial_root"], *(item["next_root"] for item in profile["rotations"]))


def advance(profile, context, history, package, *, next_root):
    root = current_root(profile, context)
    events.public_key(next_root)
    rotations = [] if profile is None else profile["rotations"]
    if profile is not None:
        prior = profile["history"]
        if (
            history.get("documents", [])[: prior["head_version"]] != prior["documents"]
            or type(history.get("clock")) is not int
            or history["clock"] < prior["clock"]
        ):
            raise Rejected("kube_observer_history_changed")
        if root == next_root:
            if canonical(package) != canonical(rotations[-1]["package"]):
                raise Rejected("kube_observer_retry_changed")
            verify({**profile, "history": history}, context)
            return copy.deepcopy(profile)
    intent = trust_rotation.authorization(package, root)
    if intent["next_root"] != next_root or intent["environment"] != context["environment"]:
        raise Rejected("kube_observer_rotation_target")
    candidate = dict(
        schema_version=1,
        history=history,
        rotations=[
            *rotations,
            dict(version=intent["next_version"], next_root=next_root, package=package),
        ],
    )
    verify(candidate, context)
    if candidate["history"]["root_public"] != next_root:
        raise Rejected("kube_observer_rotation_head")
    return copy.deepcopy(candidate)


def mapping(workspace, profile, context):
    verify(profile, context)
    config = dict(
        schema_version=1,
        trust_client="/client",
        environment=context["environment"],
        initial_root=context["initial_root"],
        producer_config="/security/producer.json",
        rotations=[],
    )
    data = {}
    for item in profile["rotations"]:
        name = "rotation-" + str(item["version"]) + ".json"
        data[name] = canonical(item["package"]).decode()
        config["rotations"].append(
            dict(
                version=item["version"],
                next_root=item["next_root"],
                package_file="/observer/" + name,
            )
        )
    data["observer.json"] = canonical(config).decode()
    content = canonical(data)
    if len(content) > MAX_CONFIG_BYTES:
        raise Rejected("kube_observer_configuration_limit")
    name = "trust-observer-" + digest(content)[:40]
    return resources.resource("ConfigMap", name, workspace, "ml-serving", immutable=True, data=data)


def deployment(workspace, image, profile, context):
    document = resources.deployment(workspace, image, "trust")
    config = mapping(workspace, profile, context)
    spec = document["spec"]["template"]["spec"]
    resources.private_files(
        spec,
        config["metadata"]["name"],
        tuple(sorted(config["data"])),
        public=True,
        area="observer",
    )
    spec["containers"][0]["command"][-1] = "/observer/observer.json"
    return document
