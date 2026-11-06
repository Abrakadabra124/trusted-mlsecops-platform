"""Authenticated delayed labels joined to one closed private prediction ledger.

The pinned key belongs to the verified label authority, never to feedback
submitters. Authenticity does not prove that the authority's labels are correct.
"""

import threading

from mlsecops import monitoring, monitoring_stream, signing
from mlsecops.contracts import Rejected, canonical, digest, require_fields
from mlsecops.release_policy import checked


class Labels:
    def __init__(self, reference, reference_sha256, closed, window_sha256, public):
        evaluator = monitoring.Evaluator(reference, reference_sha256)
        if type(closed) is not monitoring_stream.ClosedWindow:
            raise Rejected("monitor_closed_window_type")
        document = closed.document()
        evaluator.evaluate(document)
        if (
            closed.sha256 != monitoring.sha256(window_sha256)
            or canonical(document) != closed.content
        ):
            raise Rejected("monitor_closed_window_binding")
        predictions = closed.predictions
        if type(predictions) is not tuple or len(predictions) != document["observations"]:
            raise Rejected("monitor_prediction_ledger_shape")
        observed = {}
        for item in predictions:
            if type(item) is not tuple or len(item) != 2:
                raise Rejected("monitor_prediction_ledger_shape")
            identifier = monitoring.sha256(item[0])
            if type(item[1]) is not bool or identifier in observed:
                raise Rejected("monitor_prediction_ledger_shape")
            observed[identifier] = item[1]
        if digest(canonical(predictions)) != document["prediction_ledger_sha256"] or sum(
            observed.values()
        ) != sum(document["histograms"]["prediction"][6:11]):
            raise Rejected("monitor_prediction_ledger_binding")
        raw_public = signing.decode64(public)
        if len(raw_public) != 32 or signing.encode64(raw_public) != public:
            raise Rejected("monitor_label_key")
        self._reference_sha256, self._window_sha256 = reference_sha256, window_sha256
        self._baseline = reference["true_positives"], reference["positive_labels"]
        self._ended, self._public = document["ended_at_ms"], public
        self._predictions, self._labels = observed, {}
        self._lock = threading.Lock()

    def accept(self, envelope, *, clock_ms):
        document = checked(envelope, "monitor-labels", self._public)
        monitoring.schema(
            document,
            ("reference_sha256", "window_sha256", "issued_at_ms", "expires_at_ms", "labels"),
        )
        if (document["reference_sha256"], document["window_sha256"]) != (
            self._reference_sha256,
            self._window_sha256,
        ):
            raise Rejected("monitor_labels_binding")
        issued, expires, clock = (
            monitoring.integer(value, 1, 2**53 - 1)
            for value in (document["issued_at_ms"], document["expires_at_ms"], clock_ms)
        )
        if not self._ended <= issued <= clock < expires or expires - issued > 86400000:
            raise Rejected("monitor_labels_lifetime")
        labels = document["labels"]
        if type(labels) is not list or not 1 <= len(labels) <= 1000:
            raise Rejected("monitor_labels_shape")
        batch = {}
        for item in labels:
            require_fields(item, ("observation_id", "label"))
            identifier = monitoring.sha256(item["observation_id"])
            label = monitoring.integer(item["label"], 0, 1)
            if identifier in batch:
                raise Rejected("monitor_labels_duplicate")
            if identifier not in self._predictions:
                raise Rejected("monitor_label_unmatched")
            batch[identifier] = label
        with self._lock:
            if any(
                identifier in self._labels and self._labels[identifier] != value
                for identifier, value in batch.items()
            ):
                raise Rejected("monitor_label_conflict")
            accepted = sum(identifier not in self._labels for identifier in batch)
            self._labels.update(batch)
            positives = sum(self._labels.values())
            true_positives = sum(
                self._predictions[identifier] and label == 1
                for identifier, label in self._labels.items()
            )
            degraded = monitoring.quality(*self._baseline, true_positives, positives)
            return {
                "schema_version": 1,
                "reference_sha256": self._reference_sha256,
                "window_sha256": self._window_sha256,
                "status": "insufficient" if degraded is None else "observed",
                "accepted_labels": accepted,
                "labelled_observations": len(self._labels),
                "positives": positives,
                "true_positives": true_positives,
                "alert": "quality_degradation" if degraded else None,
                "release_ready": False,
            }
