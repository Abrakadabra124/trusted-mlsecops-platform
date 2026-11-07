"""Reconcile private HTTP observations, closed windows, signed labels and receipts."""

from mlsecops import monitoring, monitoring_alerts, monitoring_labels, monitoring_stream
from mlsecops.contracts import Rejected, canonical, digest, require_fields
from mlsecops.release_policy import checked


def verify(packet, *, reference, reference_sha256, context, sink_public, label_public, epoch):
    monitoring.schema(packet, ("windows", "http", "labels", "receipts"))
    if (
        type(packet["windows"]) is not list
        or len(packet["windows"]) != 12
        or type(packet["http"]) is not list
        or len(packet["http"]) != 120
        or type(packet["labels"]) is not list
        or len(packet["labels"]) != 2
        or type(packet["receipts"]) is not list
        or len(packet["receipts"]) != 3
    ):
        raise Rejected("monitor_packet_inventory")
    evaluator = monitoring.Evaluator(reference, reference_sha256)
    cursor, requests, windows, evidence = 0, set(), {}, {}
    for index, item in enumerate(packet["windows"]):
        require_fields(item, ("document", "predictions"))
        document = item["document"]
        accumulator = monitoring_stream.Accumulator(
            reference, reference_sha256, started_at_ms=document["started_at_ms"]
        )
        for _ in range(10):
            record = packet["http"][cursor]
            cursor += 1
            require_fields(record, ("features", "response"))
            response = record["response"]
            monitoring.schema(
                response, ("request_id", "bundle_sha256", "model_sha256", "predictions")
            )
            if (
                response["request_id"] in requests
                or len(record["features"]) != 100
                or response["bundle_sha256"] != context.bundle_sha256
                or response["model_sha256"] != context.model_sha256
            ):
                raise Rejected("monitor_packet_http_binding")
            requests.add(response["request_id"])
            accumulator.add(
                context, record["features"], response["predictions"], response["request_id"]
            )
        closed = accumulator.close(
            sequence=document["sequence"], ended_at_ms=document["ended_at_ms"]
        )
        if closed.content != canonical(document) or canonical(closed.predictions) != canonical(
            item["predictions"]
        ):
            raise Rejected("monitor_packet_window_changed")
        report = evaluator.evaluate(document)
        expected = [] if index < 11 else ["data_drift", "prediction_drift"]
        if report["status"] != "observed" or report["alerts"] != expected:
            raise Rejected("monitor_packet_drift_profile")
        for kind in report["alerts"]:
            evidence[(closed.sha256, kind)] = digest(canonical(report))
        windows[closed.sha256] = monitoring_labels.Labels(
            reference, reference_sha256, closed, closed.sha256, label_public
        )
    seen = set()
    for index, item in enumerate(packet["labels"]):
        require_fields(item, ("envelope", "response", "accepted_at_ms"))
        document = checked(item["envelope"], "monitor-labels", label_public)
        if type(document) is not dict or document.get("window_sha256") not in windows:
            raise Rejected("monitor_packet_label_window")
        key = document["window_sha256"]
        report = windows[key].accept(item["envelope"], clock_ms=item["accepted_at_ms"])
        if (
            report != item["response"]
            or report["accepted_labels"] != (200 if index == 0 else 0)
            or report["alert"] != "quality_degradation"
            or report["positives"] != 200
        ):
            raise Rejected("monitor_packet_quality_profile")
        if key not in seen:
            evidence[(key, "quality_degradation")] = digest(canonical(report))
            seen.add(key)
    receipts = set()
    elapsed = []
    for sequence, item in enumerate(packet["receipts"], 1):
        require_fields(
            item,
            (
                "kind",
                "window_sha256",
                "event_sha256",
                "received_at_ms",
                "delivery_seconds",
                "envelope",
                "event",
                "admitted_ns",
                "finished_ns",
            ),
        )
        event = item["event"]
        acknowledgement = monitoring_alerts.receipt(item["envelope"], event, sink_public)
        key = event["window_sha256"], event["kind"]
        start = monitoring.integer(item["admitted_ns"], 0, 2**63 - 1)
        end = monitoring.integer(item["finished_ns"], start, 2**63 - 1)
        delta = (end - start) / 1000000000
        if (
            key not in evidence
            or key in receipts
            or event["evidence_sha256"] != evidence[key]
            or event["reference_sha256"] != reference_sha256
            or event["epoch"] != epoch
            or event["sequence"] != sequence
            or delta >= 120
            or item["delivery_seconds"] != delta
            or item["event_sha256"] != acknowledgement["event_sha256"]
            or item["received_at_ms"] != acknowledgement["received_at_ms"]
            or item["kind"] != key[1]
            or item["window_sha256"] != key[0]
        ):
            raise Rejected("monitor_packet_receipt_binding")
        receipts.add(key)
        elapsed.append(delta)
    if receipts != set(evidence):
        raise Rejected("monitor_packet_delivery_incomplete")
    return {
        "schema_version": 1,
        "status": "pass",
        "reference_sha256": reference_sha256,
        "observations": 12000,
        "clean_windows": 10,
        "shift_windows": 2,
        "delivered_alerts": 3,
        "max_delivery_seconds": max(elapsed),
        "packet_sha256": digest(canonical(packet)),
        "release_ready": False,
        "full_M15": "inconclusive",
    }
