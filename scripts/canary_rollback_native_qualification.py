"""Controlled recovery contracts; no container, SQL server or listener is started."""

import copy
import subprocess
import time
import unittest
from contextlib import ExitStack, nullcontext
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from mlsecops import release_authorization, security_events, signing
from mlsecops.contracts import Rejected, canonical, decode, digest
from scripts import audit_correlation_probe
from scripts import canary_rollback_native as recovery
from scripts import security_events_qualification as event_fixtures


class Recovery(unittest.TestCase):
    def test_real_configured_app_uses_owned_clients_and_correct_credential(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            args = dict(
                context={"policy": {"environment": "local-cpu"}},
                trusted_root="root",
                expected_policy="f" * 64,
                expected_serving_image="sha256:" + "a" * 64,
            )
            with patch.object(recovery, "listen", return_value=nullcontext(12345)):
                with recovery.endpoint(
                    root, root, args, signing.encode64(bytes(range(32))), 3
                ) as target:
                    port, token, path = target
                    self.assertEqual((port, path.read_text()), (12345, token))
                    config = decode((path.parent / "config.json").read_bytes())
                    self.assertEqual(config["minimum_sequence"], 3)
                    self.assertEqual(
                        Path(config["storage_client"]), root / "storage-clients/serving"
                    )
                    self.assertTrue(Path(config["audit_directory"]).is_dir())
                    self.assertNotIn("kubernetes_worker", config)
                    with patch.object(
                        recovery.load_measurement, "request", new_callable=AsyncMock
                    ) as send:
                        send.return_value = (503, {"error": {"code": "model_unavailable"}})
                        result = recovery.predict(target, b"payload", "f" * 64)
                    send.assert_awaited_once_with(port, token, b"payload")
                    self.assertEqual(result["payload_sha256"], digest(b"payload"))
                    self.assertNotIn(token, str(result))

    def test_manual_uses_cli_stdin_private_token_file_and_durable_queue_readback(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            case = "c" * 64
            item = {"case_sha256": case, "status": "pending human review"}
            results = [
                subprocess.CompletedProcess([], 0, canonical(x), b"") for x in ([], item, [item])
            ]
            with patch.object(recovery.subprocess, "run", side_effect=results) as run:
                target = (1234, "a" * 64, root / "secret")
                report = recovery.manual(root, root, target, case, b"payload")
            commands = [call.args[0] for call in run.call_args_list]
            self.assertEqual([cmd[5] for cmd in commands], ["list", "submit", "list"])
            self.assertTrue(all(cmd[1:3] == ["-m", "mlsecops.manual_review"] for cmd in commands))
            self.assertEqual(commands[1][-2:], ["--token-file", str(target[2])])
            self.assertEqual(run.call_args_list[1].kwargs["input"], b"payload")
            self.assertEqual(report["after"], [item])
            self.assertNotIn(target[1], str(commands) + str(report))
            with (
                patch.object(
                    recovery.subprocess,
                    "run",
                    return_value=subprocess.CompletedProcess([], 1, b"", b"private"),
                ),
                self.assertRaisesRegex(Rejected, "^canary_rollback_manual_cli$"),
            ):
                recovery.manual(root, root, target, case, b"payload")

    def test_trust_update_is_compared_to_independent_serving_sql_read(self):
        authority = Path("trust-store")
        fixture = SimpleNamespace(trust_fixture=SimpleNamespace(key="key", public="public"))
        envelope = {"signed": "sample"}
        with (
            patch.object(
                recovery.trust_authority,
                "update",
                return_value={"document_sha256": recovery.sha(envelope)},
            ) as write,
            patch.object(recovery.trust_authority, "read", return_value=(envelope, 123)) as read,
        ):
            self.assertEqual(
                recovery.publish_trust(authority, fixture, "policy", ["b"]),
                {"envelope": envelope, "sql_second": 123},
            )
            write.assert_called_once_with(authority, "policy", "key", revoked_artifacts=["b"])
            read.assert_called_once_with(
                authority / "storage-clients/serving", "local-cpu", "public"
            )
            read.return_value = ({"signed": "old"}, 123)
            with self.assertRaises(Rejected):
                recovery.publish_trust(authority, fixture, "policy", ["b"])

    def test_host_guard_precedes_images_credentials_and_storage(self):
        with (
            patch.object(recovery.promoter, "hosted", side_effect=Rejected("hosted")),
            patch.object(recovery, "resolve_image") as image,
            patch.object(recovery, "disposable") as stores,
            self.assertRaisesRegex(Rejected, "^hosted$"),
        ):
            recovery.drill(".", ".runtime", "image", "a" * 32, [[0.5] * 6])
        image.assert_not_called()
        stores.assert_not_called()

    def test_summary_only_record_cannot_establish_recovery(self):
        with self.assertRaises(Rejected):
            recovery.replay({"status": "pass", "rollback_seconds": 1, "manual_review": True})

    def test_120_second_boundary_includes_publication_and_entire_http_read(self):
        for elapsed in (120 * recovery.NS, 120 * recovery.NS + 1):
            with self.subTest(elapsed=elapsed):
                events = {
                    "revoke_b": {"start": {"mono_ns": 11}},
                    "restored_a": {"end": {"mono_ns": 11 + elapsed}},
                }
                if elapsed == 120 * recovery.NS:
                    self.assertEqual(recovery.recovery_ns(events), elapsed)
                else:
                    with self.assertRaises(Rejected):
                        recovery.recovery_ns(events)


class SignedDrill(unittest.TestCase):
    dataset_mode = False

    @classmethod
    def setUpClass(cls):
        # The owner/orchestrator and cryptographic paths are real. Replace the external
        # SQL, Docker, HTTP and subprocess boundaries before calling the hosted wrapper.
        with ExitStack() as stack:
            root = Path(stack.enter_context(TemporaryDirectory()))
            fx = event_fixtures.EventContracts("runTest")
            fx.setUp()
            stack.callback(fx.doCleanups)
            ns = recovery.NS
            base = int(time.time())
            ticks = 0
            history = []
            args_by_seq = {}
            denied_counts = {}
            trust_states = []
            pending = []
            server_rows = {seq: [] for seq in (1, 2, 3)}
            proofs = {}

            def stamp():
                nonlocal ticks
                ticks += 1
                return {"mono_ns": ns + ticks * 1_000_000, "wall_ns": base * ns + ticks * 1_000_000}

            def trust_update(authority, fixture, policy, revoked):
                revoked_set = sorted(
                    set(revoked)
                    | set(trust_states[-1][0]["revoked_artifacts"] if trust_states else [])
                )
                payload = dict(
                    schema_version=1,
                    environment="local-cpu",
                    version=len(trust_states) + 1,
                    promotion_policy_sha256=policy,
                    issued_at=base,
                    expires_at=base + 600,
                    revoked_artifacts=revoked_set,
                    revoked_keys=[],
                )
                envelope = signing.sign(payload, "trust-policy", fixture.trust_fixture.key)
                trust_states.append((payload, envelope))
                return {"envelope": envelope, "sql_second": base}

            def select(root, models, authority, args, public):
                seq = len(history) + 1
                args_by_seq[seq] = args
                decision = release_authorization.verify(**args, clock=base)
                proof = dict(
                    schema_version=1,
                    policy_envelope=args["policy_envelope"],
                    assurance_envelope=args["assurance_envelope"],
                    approval_envelope=args["approval_envelope"],
                    reports={k: digest(v) for k, v in args["reports"].items()},
                    decision=decision,
                )
                approval = decode(signing.decode64(args["approval_envelope"]["payload"]))
                selection = dict(
                    schema_version=1,
                    kind="promotion-selection",
                    environment="local-cpu",
                    sequence=seq,
                    subject_sha256=decision["subject_sha256"],
                    policy_sha256=args["expected_policy"],
                    proposal_reference=recovery.sha(args["package"]["envelope"]),
                    authorization_reference=recovery.sha(proof),
                    issued_at=approval["issued_at"],
                    expires_at=approval["expires_at"],
                )
                reference = recovery.sha(selection)
                head = dict(
                    sequence=seq,
                    environment="local-cpu",
                    request_sha256=reference,
                    release_ready=False,
                )
                receipt = {
                    **head,
                    "state": "recorded-not-activated",
                    "subject_sha256": selection["subject_sha256"],
                    "proposal_reference": selection["proposal_reference"],
                    "trust": {
                        "version": len(trust_states),
                        "document_sha256": recovery.sha(trust_states[-1][1]),
                    },
                }
                event = dict(
                    request_sha256=reference,
                    previous_sha256=history[-1]["request_sha256"] if history else None,
                    sql_second=base,
                )
                history.append(head)
                proofs[seq] = (selection["authorization_reference"], decision["approval_sha256"])
                return dict(
                    receipt=receipt,
                    selection=selection,
                    authorization=proof,
                    head=head,
                    event=event,
                )

            def predict(target, body, reference):
                seq = target
                args = args_by_seq[seq]
                doc = decode(signing.decode64(args["package"]["envelope"]["payload"]))
                model = doc["materials"]["model"]
                count = denied_counts.get(seq, 0)
                if set((model, doc["materials"]["split_manifest"])).intersection(
                    trust_states[-1][0]["revoked_artifacts"]
                ):
                    denied_counts[seq] = count + 1
                if denied_counts.get(seq, 0) > 1:
                    status, reply = (
                        503,
                        {
                            "schema_version": 1,
                            "request_id": f"{ticks:032x}",
                            "error": {"code": "model_unavailable"},
                        },
                    )
                else:
                    from mlsecops import model as onnx_model

                    runtime, _ = onnx_model.session(
                        args["package"]["capsule"]["objects"][("candidates", model)]
                    )
                    score = float(onnx_model.predict(runtime, [[0.5] * 6])[0])
                    status, reply = (
                        200,
                        dict(
                            schema_version=1,
                            request_id=f"{ticks:032x}",
                            model_sha256=model,
                            bundle_sha256=recovery.sha(doc),
                            predictions=[dict(decision="score", reason=None, score=score)],
                        ),
                    )
                if status == 200:
                    server_rows[seq].append(
                        dict(
                            request_id=reply["request_id"],
                            selection_sha256=reference,
                            bundle_sha256=reply["bundle_sha256"],
                            model_sha256=reply["model_sha256"],
                            authorization_sha256=proofs[seq][0],
                            approval_sha256=proofs[seq][1],
                        )
                    )
                return dict(
                    path="/v1/predict",
                    payload_sha256=digest(body),
                    selection_sha256=reference,
                    status=status,
                    response=reply,
                )

            def rejected(root, models, authority, public, args):
                # Validate the signed seq4 proposal before issuing the signed trust denial.
                verified = release_authorization.verify(**args, clock=base)
                if verified["sequence"] != 4:
                    raise AssertionError("expected a fourth signed selection attempt")
                prior = history[-1]
                req = dict(
                    schema_version=1,
                    proposal_reference=recovery.sha(args["package"]["envelope"]),
                    policy_reference=recovery.sha(args["policy_envelope"]),
                    assurance_reference=recovery.sha(args["assurance_envelope"]),
                    approval_reference=recovery.sha(args["approval_envelope"]),
                )
                start = stamp()
                ms = start["wall_ns"] // 1_000_000
                fx.document.update(issued_at_ms=ms - 500, expires_at_ms=ms + 180000)
                registry = fx.registry_for(clock=ms)
                event = fx.event(
                    "promotion.denied",
                    "promoter",
                    reason="trust",
                    sequence=2,
                    occurred_at_ms=ms,
                    observed_at_ms=ms,
                    asset_sha256=req["proposal_reference"],
                    bundle_sha256=req["proposal_reference"],
                )
                envelope = signing.sign(event, "security-event", fx.keys["promoter"])
                checked = registry.verify(envelope, clock_ms=ms)
                receipt = security_events.delivered(
                    checked, registry.sha256, ingested_at_ms=ms, routed_at_ms=ms, late=False
                )
                return dict(
                    before=prior,
                    after=prior,
                    request=req,
                    refusal_code="trust_artifact_revoked",
                    approval=args["approval_envelope"],
                    start=start,
                    end=stamp(),
                    outcome={"status": "rejected", "release_ready": False},
                    incident=dict(
                        envelope=envelope,
                        receipt=signing.sign(receipt, "security-event-receipt", fx.keys["receipt"]),
                        ingested_at_ms=ms,
                        late=False,
                    ),
                    registry=dict(
                        root=fx.publics["root"],
                        pin=registry.sha256,
                        envelope=signing.sign(
                            fx.document, "security-event-config", fx.keys["root"]
                        ),
                    ),
                )

            def manual(root, state, target, case, body):
                item = {"case_sha256": case, "status": "pending human review"}
                pending.append(item)
                return dict(
                    before=[], submitted=item, after=list(pending), payload_sha256=digest(body)
                )

            def stub(obj, name, **kwargs):
                return stack.enter_context(patch.object(obj, name, **kwargs))

            stub(recovery.promoter, "hosted")
            stub(recovery, "resolve_image", return_value="sha256:" + "a" * 64)
            stub(
                recovery,
                "disposable",
                side_effect=lambda r, s, c, name, p: nullcontext(root / name),
            )
            for obj, name in (
                (recovery.promotion_state, "install"),
                (recovery.promotion_state, "configure"),
                (recovery.trust_authority, "install"),
            ):
                stub(obj, name)
            stub(recovery, "stamp", side_effect=stamp)
            stub(recovery.time, "time", return_value=base)
            stub(recovery.time, "sleep")
            stub(recovery, "publish_trust", side_effect=trust_update)
            stub(recovery, "select", side_effect=select)
            stub(recovery, "endpoint", side_effect=lambda *args: nullcontext(args[-1]))
            stub(recovery, "predict", side_effect=predict)
            stub(recovery, "reject_rollback", side_effect=rejected)
            stub(recovery, "manual", side_effect=manual)
            stub(recovery, "completed", side_effect=lambda models, seq: server_rows[seq])
            stub(recovery.promotion_state, "state", side_effect=lambda *_: history[-1])
            cls.packet = recovery.drill(
                root,
                root,
                "image",
                "a" * 32,
                [[0.5] * 6],
                **(
                    {"revoke_datasets": True, "check_inventory_head": cls.inventory_head}
                    if cls.dataset_mode
                    else {}
                ),
            )
            restored = cls.packet["events"]["rollback_a"]["value"]
            args = args_by_seq[3]
            cls.restored_context = audit_correlation_probe.release(
                args["package"],
                args["context"],
                restored["selection"],
                restored["authorization"],
                args["trusted_root"],
            )

    def test_closed_server_journal_projects_only_completed_predictions_for_restored_a(self):
        sample = self.packet["completed_http"][2][0]
        event = dict(
            schema_version=2,
            principal_id="f" * 32,
            request_id=sample["request_id"],
            stage="response_completed",
            status=200,
            route="predict",
            context=self.restored_context,
        )
        started = dict(event, stage="request_started", status=None, context=None)
        denied = dict(event, status=503, context=None, request_id="e" * 32)
        journal = b"\n".join(canonical({"event": e}) for e in (started, event, denied))
        with patch.object(recovery.audit_snapshot, "read_closed", return_value=[journal]) as read:
            self.assertEqual(recovery.completed(Path("models"), 3), [sample])
            read.assert_called_once_with(Path("models/serving-3/audit"))
        ready = canonical({"event": dict(event, route="ready")})
        with patch.object(recovery.audit_snapshot, "read_closed", return_value=[ready]):
            with self.assertRaises(Rejected):
                recovery.completed(Path("models"), 3)

    def test_normal_signed_sequence_has_two_actual_models_and_cache_hit_before_each_denial(self):
        result = recovery.replay(self.packet)
        self.assertEqual(result["refusal_statuses"], [503, 503])
        self.assertEqual(result["refusal_attempts"], [2, 2])
        self.assertGreater(result["recovery_ns"], 0)
        self.assertNotEqual(result["from_request_sha256"], result["target_request_sha256"])
        self.assertNotEqual(result["restored_request_sha256"], result["target_request_sha256"])

    def test_promotion_receipt_reloads_selection_proof_event_and_head_with_serving_client(self):
        expected = self.packet["events"]["rollback_a"]["value"]
        root = Path("model-store")
        client = root / "storage-clients/serving"
        db = Mock()
        row = expected["event"]
        db.execute.return_value.fetchone.return_value = (
            row["request_sha256"],
            row["previous_sha256"],
            row["sql_second"],
        )
        objects = {
            recovery.sha(expected[k]): canonical(expected[k])
            for k in ("authorization", "selection")
        }

        def get(who, table, reference):
            self.assertEqual((who, table), (client, "releases"))
            return objects[reference]

        with (
            patch.object(recovery.promoter, "controlled", return_value=expected["receipt"]),
            patch.object(
                recovery.storage,
                "connect",
                side_effect=lambda who: (
                    nullcontext(db) if who == client else self.fail("wrong role")
                ),
            ),
            patch.object(recovery.storage, "get", side_effect=get),
            patch.object(recovery.promotion_state, "state", return_value=expected["head"]),
        ):
            self.assertEqual(recovery.select(root, root, root, {}, "public"), expected)
            self.assertEqual(db.execute.call_args.args[1], ("local-cpu", 3))
            db.execute.return_value.fetchone.return_value = None
            with self.assertRaises(Rejected):
                recovery.select(root, root, root, {}, "public")

    def reject(self, change):
        doc = copy.deepcopy(self.packet)
        change(doc["events"])
        raw = canonical(doc)
        self.assertNotEqual(digest(raw), recovery.sha(self.packet))
        with self.assertRaises(Rejected):
            recovery.replay(decode(raw))

    def test_real_negative_request_construction_and_signed_collector_readback(self):
        record = self.packet
        events = record["events"]
        expected = events["reject_rollback_b"]["value"]
        source = events["select_b"]["value"]
        proof = source["authorization"]
        args = {
            "package": {"envelope": record["proposals"]["b"]},
            "approval_envelope": expected["approval"],
            "policy_envelope": proof["policy_envelope"],
            "assurance_envelope": proof["assurance_envelope"],
        }
        with TemporaryDirectory() as tmp, ExitStack() as stack:
            root = Path(tmp)
            reg = expected["registry"]
            registry = root / "registry.json"
            recovery.write_json(registry, reg["envelope"])
            recovery.write_json(
                root / "collector.json",
                dict(
                    registry_root=reg["root"],
                    registry_sha256=reg["pin"],
                    registry_file=str(registry),
                ),
            )
            first = {"opaque": "first refusal"}
            exchange = Mock(
                side_effect=[
                    (200, {"incidents": [first]}),
                    (200, {"incidents": [first, expected["incident"]]}),
                ]
            )
            fixture = SimpleNamespace(
                directory=root, audit_config=root / "audit", exchange=exchange
            )
            stack.enter_context(
                patch.object(
                    recovery.security_event_audit_fixture, "live", return_value=nullcontext(fixture)
                )
            )
            stack.enter_context(
                patch.object(
                    recovery.storage, "put", side_effect=lambda c, t, content: digest(content)
                )
            )
            stack.enter_context(
                patch.object(recovery.promoter, "configuration", return_value={"controlled": True})
            )
            submit = stack.enter_context(
                patch.object(
                    recovery.promoter.promotion_controller,
                    "submit",
                    side_effect=Rejected("trust_artifact_revoked"),
                )
            )
            cli = stack.enter_context(
                patch.object(recovery.promoter, "invoke", return_value=expected["outcome"])
            )
            stack.enter_context(
                patch.object(recovery.promotion_state, "state", return_value=expected["before"])
            )
            stack.enter_context(
                patch.object(recovery, "stamp", side_effect=[expected["start"], expected["end"]])
            )
            value = recovery.reject_rollback(root, root, root, record["trust_root"], args)
            self.assertEqual(canonical(value), canonical(expected))
            self.assertEqual(cli.call_args.args[3], submit.call_args.args[1])
            self.assertEqual(cli.call_args.kwargs, {"denied": True})
            submit.side_effect = Rejected("trust_lease_expired")
            with self.assertRaises(Rejected):
                recovery.reject_rollback(root, root, root, record["trust_root"], args)
            self.assertEqual(cli.call_count, 1)

    def test_closed_http_completion_from_previous_selection_cannot_establish_recovery(self):
        doc = copy.deepcopy(self.packet)
        doc["completed_http"][2][0]["selection_sha256"] = doc["events"]["select_a"]["value"][
            "receipt"
        ]["request_sha256"]
        with self.assertRaises(Rejected):
            recovery.replay(decode(canonical(doc)))

    def test_tampered_trust_update_and_ledger_time_reject_after_rehash(self):
        self.reject(
            lambda e: e["revoke_a"]["value"].update(envelope=e["revoke_b"]["value"]["envelope"])
        )
        self.reject(lambda e: e["rollback_a"]["value"]["event"].update(sql_second=1))
        self.reject(
            lambda e: e["reject_rollback_b"]["value"].update(refusal_code="trust_lease_expired")
        )
        self.reject(
            lambda e: e["reject_rollback_b"]["value"]["incident"]["receipt"]["signatures"][
                0
            ].update(sig="AAAA")
        )

    def test_rehashed_healthy_and_denial_swaps_and_early_receipt_reject(self):
        for label, change in (
            (
                "wrong restored model",
                lambda e: e["restored_a"]["value"].update(
                    response=e["healthy_b"]["value"]["response"]
                ),
            ),
            ("cached success only", lambda e: e["denied_b"]["value"].pop()),
            (
                "false refusal",
                lambda e: e["denied_a"]["value"][-1]["value"]["response"]["error"].update(
                    code="not_ready"
                ),
            ),
            (
                "request replay",
                lambda e: e["denied_a"]["value"][-1]["value"]["response"].update(
                    request_id=e["healthy_a"]["value"]["response"]["request_id"]
                ),
            ),
            (
                "foreign clock",
                lambda e: e["restored_a"]["end"].update(mono_ns=e["revoke_b"]["start"]["mono_ns"]),
            ),
            (
                "forged previous link",
                lambda e: e["rollback_a"]["value"]["event"].update(previous_sha256="f" * 64),
            ),
            (
                "wrong negative target",
                lambda e: e["reject_rollback_b"]["value"]["request"].update(
                    proposal_reference="e" * 64
                ),
            ),
            (
                "wrong approval",
                lambda e: e["reject_rollback_b"]["value"].update(
                    approval=e["rollback_a"]["value"]["authorization"]["approval_envelope"]
                ),
            ),
            (
                "wrong incident time",
                lambda e: e["reject_rollback_b"]["value"].update(
                    start=e["reject_rollback_b"]["value"]["end"]
                ),
            ),
            (
                "different queue",
                lambda e: e["manual"]["value"]["after"][0].update(case_sha256="b" * 64),
            ),
            (
                "negative mutated head",
                lambda e: e["reject_rollback_b"]["value"].update(
                    after=e["select_b"]["value"]["head"]
                ),
            ),
            (
                "head after fallback",
                lambda e: e["final_head"].update(value=e["select_b"]["value"]["head"]),
            ),
        ):
            with self.subTest(label=label):
                self.reject(change)
