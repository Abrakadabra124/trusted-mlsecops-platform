"""Fresh named-resource inventory read; callers retain UID and specification checks."""

from mlsecops.cluster import kubectl
from mlsecops.contracts import Rejected, decode


def identity(document):
    if not isinstance(document, dict) or not isinstance(document.get("metadata"), dict):
        raise Rejected("kube_resource_readback_identity")
    metadata = document["metadata"]
    fields = document.get("apiVersion"), document.get("kind"), metadata.get("name")
    if any(not isinstance(value, str) or not value for value in fields):
        raise Rejected("kube_resource_readback_identity")
    namespace = metadata.get("namespace", "")
    if not isinstance(namespace, str):
        raise Rejected("kube_resource_readback_identity")
    return fields[0], fields[1], namespace, fields[2]


def read(state, documents):
    expected = {}
    for document in documents:
        key = identity(document)
        if key in expected:
            raise Rejected("kube_resource_readback_duplicate_request")
        api_version, kind, namespace, name = key
        metadata = {"name": name}
        if namespace:
            metadata["namespace"] = namespace
        expected[key] = {"apiVersion": api_version, "kind": kind, "metadata": metadata}
    if not expected:
        return []
    response = decode(
        kubectl(
            state,
            ["get", "-f", "-", "-o", "json"],
            {"apiVersion": "v1", "kind": "List", "items": list(expected.values())},
        ).stdout
    )
    if isinstance(response, dict) and response.get("kind") == "List":
        if response.get("apiVersion") != "v1" or not isinstance(response.get("items"), list):
            raise Rejected("kube_resource_readback_list")
        items = response["items"]
    else:
        items = [response]
    observed = {}
    for item in items:
        key = identity(item)
        if key not in expected or key in observed:
            raise Rejected("kube_resource_readback_inventory")
        observed[key] = item
    if observed.keys() != expected.keys():
        raise Rejected("kube_resource_readback_inventory")
    return [observed[key] for key in expected]
