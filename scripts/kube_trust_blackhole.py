"""Hosted test fault: drop only serving-to-trust traffic, with owned cleanup."""

import uuid

from mlsecops import kube_storage, kube_trust
from mlsecops.boundary_qualification import delete_options
from mlsecops.cluster import kubectl
from mlsecops.contracts import Rejected, decode
from mlsecops.kube_storage_resources import ACCOUNT, POD_NAMESPACE, resource
from mlsecops.storage_pki import workspace_id


class Blackhole:
    def __init__(self, state):
        self.state = state
        self.marker = None
        self.attempted = False
        self.uid = None
        self.document = resource(
            "CiliumNetworkPolicy",
            "serving-trust-blackhole-" + uuid.uuid4().hex,
            workspace_id(state),
            kube_trust.NAMESPACE,
            spec={
                "endpointSelector": {"matchLabels": {"k8s:app": "postgres"}},
                "ingressDeny": [
                    {
                        "fromEndpoints": [
                            {
                                "matchLabels": {
                                    POD_NAMESPACE: "ml-serving",
                                    ACCOUNT: "serving",
                                }
                            }
                        ]
                    }
                ],
            },
        )

    def start(self):
        self.marker = kube_trust.validate(self.state)
        if self.attempted or kube_storage.get(self.state, self.document) is not None:
            raise Rejected("trust_blackhole_collision")
        self.attempted = True
        observed = decode(
            kubectl(self.state, ["create", "-f", "-", "-o", "json"], self.document).stdout
        )
        self.uid = observed["metadata"]["uid"]
        kube_storage.verify_resource(self.document, observed, self.uid)

    def close(self):
        if not self.attempted:
            return
        observed = kube_storage.get(self.state, self.document)
        if observed is not None:
            # An uncertain create is resolved by exact random-name/spec/labels
            # readback. Never adopt a resource with a different observed UID.
            uid = self.uid or observed.get("metadata", {}).get("uid")
            if not isinstance(uid, str) or not uid:
                raise Rejected("trust_blackhole_identity")
            kube_storage.verify_resource(self.document, observed, uid)
            name = self.document["metadata"]["name"]
            endpoint = (
                f"/apis/cilium.io/v2/namespaces/{kube_trust.NAMESPACE}/ciliumnetworkpolicies/{name}"
            )
            kubectl(self.state, ["delete", f"--raw={endpoint}", "-f", "-"], delete_options(uid))
            if kube_storage.get(self.state, self.document) is not None:
                raise Rejected("trust_blackhole_cleanup_incomplete")
        restored = kube_trust.validate(self.state)
        if any(restored[key] != self.marker[key] for key in ("volume_uid", "pod_uid")):
            raise Rejected("trust_blackhole_authority_changed")
        self.attempted = False
