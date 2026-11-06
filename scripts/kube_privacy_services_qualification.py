"""Controlled contracts for the service-log observer. Never starts local services."""

import copy
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from mlsecops.contracts import Rejected, canonical
from scripts import kube_privacy_services as services
from scripts.kube_privacy_logs_qualification import pod


class ServiceWindowContracts(unittest.TestCase):
    def setUp(self):
        self.start = b"tml-privacy-start-" + b"a" * 32
        self.end = b"tml-privacy-end-" + b"b" * 32
        self.before = b"startup\nWARNING: " + self.start + b"\n"
        self.after = self.before + b"WARNING: " + self.end + b"\n"
        self.needles = tuple(f"private-input-{i}".encode() for i in range(9))

    def test_complete_window_requires_exact_prefix_and_both_unique_boundaries(self):
        services.verify_window(self.before, self.after, self.start, self.end, self.needles)
        for before, after in (
            (b"", self.after),
            (self.before, self.after[1:]),
            (self.before, self.before),
            (self.before, self.after + self.end),
            (self.before + self.start, self.after),
            (self.after, self.after),
            (self.before, self.after + self.needles[0]),
            (self.before, b"x" * (services.logs.MAX_BYTES + 1)),
            ("text", self.after),
            (self.before, "text"),
        ):
            with self.subTest(before=type(before).__name__), self.assertRaises(Rejected):
                services.verify_window(before, after, self.start, self.end, self.needles)

    def test_marker_and_canary_inventory_cannot_be_missing_malformed_or_reused(self):
        for start, end, needles in (
            (b"", self.end, self.needles),
            (self.start, self.start, self.needles),
            (self.start, b"x", self.needles),
            (self.start, self.end, ()),
            (self.start, self.end, list(self.needles)),
            (self.start, self.end, (b"",) * 9),
            (self.start, self.end, (b"x",) * 9),
            (self.start, self.end, (b"x" * 4097,) + self.needles[1:]),
            (self.start, self.end, ("text",) + self.needles[1:]),
        ):
            with self.subTest(start=start[:20]), self.assertRaises(Rejected):
                services.verify_window(self.before, self.after, start, end, needles)

    def test_settings_readback_is_exact_and_role_database_overrides_are_rejected(self):
        module = Mock()
        module.admin.side_effect = [canonical(services.SETTINGS).decode(), "0"]
        self.assertEqual(services.settings(Path("owned"), module), services.SETTINGS)
        for value in (
            None,
            {},
            {**services.SETTINGS, "log_destination": "syslog"},
            {**services.SETTINGS, "unexpected": "value"},
        ):
            module.admin.side_effect = [canonical(value).decode(), "0"]
            with self.subTest(value=value), self.assertRaises(Rejected):
                services.settings(Path("owned"), module)
        module.admin.side_effect = [canonical(services.SETTINGS).decode(), "1"]
        with self.assertRaisesRegex(Rejected, "privacy_service_settings"):
            services.settings(Path("owned"), module)

    def test_marker_injection_uses_only_generated_literal_and_session_local_client_filter(self):
        module = Mock()
        services.mark(Path("owned"), module, self.start)
        statement = module.admin.call_args.args[1]
        self.assertIn("SET LOCAL client_min_messages=error", statement)
        self.assertIn("RAISE WARNING", statement)
        self.assertIn(self.start.decode(), statement)
        self.assertNotIn("ALTER", statement)
        self.assertNotIn("INSERT", statement)
        for marker in (b"';DROP", "text", b"tml-privacy-start-" + b"0" * 31):
            with self.assertRaises(Rejected):
                services.mark(Path("owned"), module, marker)

    def test_hosted_boundary_precedes_all_cluster_operations(self):
        with (
            patch.object(services, "hosted", side_effect=Rejected("hosted")),
            patch.object(services, "inspect") as inspect,
            self.assertRaisesRegex(Rejected, "^hosted$"),
        ):
            services.Windows(Path("owned"), Path("private"))
        inspect.assert_not_called()

    def test_destination_cannot_escape_owned_state_or_replace_existing_private_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            for target in (Path("relative"), root, root.parent / "foreign", root / ".." / "escape"):
                with (
                    self.subTest(target=str(target)),
                    patch.object(services, "hosted"),
                    patch.object(services, "inspect") as inspect,
                    self.assertRaisesRegex(Rejected, "privacy_service_destination"),
                ):
                    services.Windows(root, target)
                inspect.assert_not_called()
            target = root / "private"
            target.mkdir()
            (target / "original").write_bytes(b"preserve")
            with (
                patch.object(services, "hosted"),
                patch.object(services, "inspect", return_value={}),
                patch.object(services, "mark") as mark,
                self.assertRaises(FileExistsError),
            ):
                services.Windows(root, target)
            mark.assert_not_called()
            self.assertEqual((target / "original").read_bytes(), b"preserve")

    def test_wait_allows_bounded_cri_delay_but_rejects_duplicated_marker(self):
        observer = object.__new__(services.Windows)
        observer.state = Path("unused")
        observed = {"pod": {}, "owner": "owned"}
        with (
            patch.object(
                services.logs, "capture", side_effect=[({}, b"pending"), ({}, self.start)]
            ),
            patch.object(services.time, "monotonic", side_effect=[0, 1]),
            patch.object(services.time, "sleep") as sleep,
        ):
            self.assertEqual(observer.wait(observed, self.start, self.needles), ({}, self.start))
        sleep.assert_called_once_with(0.1)
        with (
            patch.object(services.logs, "capture", return_value=({}, self.start * 2)),
            self.assertRaisesRegex(Rejected, "privacy_service_marker_unobserved"),
        ):
            observer.wait(observed, self.start, self.needles)

    def test_live_identity_rejects_wrong_spec_digest_namespace_or_extra_containers(self):
        value = pod(terminal=False)
        value["metadata"].update(namespace="ml-storage", name="postgres-0")
        value["spec"]["containers"][0]["name"] = "postgres"
        value["status"]["containerStatuses"][0]["name"] = "postgres"
        document = {
            "kind": "StatefulSet",
            "metadata": {"name": "postgres", "namespace": "ml-storage"},
            "spec": {"template": {"spec": copy.deepcopy(value["spec"])}},
        }
        module = Mock()
        module.validate.return_value = {"resources": {"StatefulSet/ml-storage/postgres": "job-uid"}}
        module.desired.return_value = [document]
        for fault in (None, "spec", "image", "init", "ephemeral", "namespace"):
            changed = copy.deepcopy(value)
            if fault == "spec":
                changed["spec"]["containers"][0]["name"] = "other"
            if fault == "image":
                document["spec"]["template"]["spec"]["containers"][0]["image"] = "mutable:latest"
            if fault in {"init", "ephemeral"}:
                changed["spec"][fault + "Containers"] = [{"name": "foreign"}]
            if fault == "namespace":
                changed["metadata"]["namespace"] = "foreign"
            with (
                self.subTest(fault=fault),
                patch.object(
                    services, "kubectl", return_value=SimpleNamespace(stdout=canonical(changed))
                ),
                patch.object(services, "settings", return_value=services.SETTINGS),
                patch.object(services, "verify_running_image"),
            ):
                if fault is None:
                    result = services.inspect(Path("owned"), module)
                    self.assertEqual(result["identity"]["namespace"], "ml-storage")
                else:
                    with self.assertRaises(Rejected):
                        services.inspect(Path("owned"), module)
            document["spec"]["template"]["spec"] = copy.deepcopy(value["spec"])

    def lifecycle(self, fault=None):
        streams, calls, packets = {}, [], {}
        identities = {}
        for namespace, module in (
            ("ml-storage", services.kube_storage),
            ("ml-trust", services.kube_trust),
        ):
            streams[id(module)] = b"startup\n"
            identities[id(module)] = {
                "pod": {"namespace": namespace},
                "owner": "owner",
                "identity": {"namespace": namespace, "pod_uid": namespace + "-uid"},
                "settings": dict(services.SETTINGS),
            }

        def inspect(state, module):
            calls.append(("inspect", module))
            return copy.deepcopy(identities[id(module)])

        def mark(state, module, marker):
            calls.append(("mark", marker))
            if fault != "missing-marker":
                streams[id(module)] += b"WARNING: " + marker + b"\n"

        def capture(state, pod, *, needles, **kwargs):
            calls.append(("capture", needles))
            if fault == "control-error" and needles[0].startswith(b"tml-privacy-control-"):
                raise Rejected("privacy_log_identity_changed")
            namespace = pod["namespace"]
            module = services.kube_storage if namespace == "ml-storage" else services.kube_trust
            raw = streams[id(module)]
            if any(needle in raw for needle in needles) and fault != "blind-control":
                raise Rejected("privacy_log_canary")
            return {"bytes": len(raw), **identities[id(module)]["identity"]}, raw

        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(services, "hosted"),
            patch.object(services, "inspect", side_effect=inspect),
            patch.object(services, "mark", side_effect=mark),
            patch.object(services.logs, "capture", side_effect=capture),
            patch.object(services.time, "sleep"),
            patch.object(services.time, "monotonic", side_effect=range(0, 10000, 10)),
            patch.object(
                services.audit_snapshot,
                "store_packet",
                side_effect=lambda path, data: packets.__setitem__(path, data),
            ),
            patch.object(
                services.audit_snapshot,
                "load_packet",
                side_effect=lambda path: b"changed" if fault == "retained" else packets[path],
            ),
        ):
            root = Path(temporary).resolve()
            observer = services.Windows(root, root / "private")
            if fault == "identity":
                identities[id(services.kube_storage)]["identity"]["pod_uid"] = "changed"
            if fault == "prefix":
                streams[id(services.kube_storage)] = b"rotated\n"
            if fault == "canary":
                streams[id(services.kube_storage)] += self.needles[0]
            if fault == "settings":
                identities[id(services.kube_storage)]["settings"]["log_destination"] = "syslog"
            result = observer.close(self.needles)
            self.assertTrue(observer.reverify(self.needles, result))
            with self.assertRaisesRegex(Rejected, "privacy_service_retained_inventory"):
                observer.reverify(self.needles, {})
            changed = copy.deepcopy(result)
            changed["ml-storage"]["sha256"] = "0" * 64
            with self.assertRaisesRegex(Rejected, "privacy_service_retained_changed"):
                observer.reverify(self.needles, changed)
            with self.assertRaisesRegex(Rejected, "privacy_service_already_closed"):
                observer.close(self.needles)
            for namespace in ("ml-storage", "ml-trust"):
                packet = services.audit_snapshot.load_packet(root / "private" / namespace)
                self.assertNotIn(self.needles[0], packet)
            return result, calls

    def test_closed_window_is_retained_reread_and_both_live_sinks_detect_control(self):
        result, calls = self.lifecycle()
        self.assertEqual(set(result), {"ml-storage", "ml-trust"})
        for value in result.values():
            self.assertTrue(value["closed_window"])
            self.assertTrue(value["leak_control_detected"])
            self.assertTrue(value["retained_reverified"])
            self.assertFalse(value["release_ready"])
        self.assertEqual(sum(kind == "mark" for kind, _ in calls), 6)

    def test_changed_identity_prefix_settings_canary_missing_boundary_or_blind_capture_never_pass(
        self,
    ):
        for fault in (
            "identity",
            "prefix",
            "settings",
            "canary",
            "missing-marker",
            "blind-control",
            "retained",
            "control-error",
        ):
            with self.subTest(fault=fault), self.assertRaises(Rejected):
                self.lifecycle(fault)


if __name__ == "__main__":
    unittest.main()
