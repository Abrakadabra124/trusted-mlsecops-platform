"""Explicit local files and pinned monitoring identities; no startup side effects."""

from pathlib import Path

from mlsecops import (
    monitoring,
    monitoring_alerts,
    monitoring_delivery,
    monitoring_runtime,
    monitoring_state,
)
from mlsecops.contracts import Rejected, bounded_read, canonical, decode, digest
from mlsecops.release_policy import checked


def absolute(value):
    if type(value) is not str or not Path(value).is_absolute():
        raise Rejected("monitor_config_path")
    return Path(value)


def document(path):
    return decode(bounded_read(absolute(path), 16384), 16384)


def producer(path):
    config = document(path)
    monitoring.schema(
        config,
        (
            "reference_file",
            "reference_sha256",
            "reference_public",
            "producer_key_file",
            "label_public",
            "sink_public",
            "sink_port",
            "epoch",
            "state_directory",
            "state_sha256",
        ),
    )
    public = monitoring_alerts.public_key(config["reference_public"])
    reference = checked(document(config["reference_file"]), "monitor-reference", public)
    monitoring.validate_reference(reference)
    reference_sha256 = monitoring.sha256(config["reference_sha256"])
    if digest(canonical(reference)) != reference_sha256:
        raise Rejected("monitor_reference_binding")
    client = monitoring_delivery.Client(
        absolute(config["producer_key_file"]),
        config["sink_public"],
        port=config["sink_port"],
        reference_sha256=reference_sha256,
        epoch=config["epoch"],
    )
    if public in (client.producer_public, client.sink_public, config["label_public"]):
        raise Rejected("monitor_reference_roles")
    guard = monitoring_state.Guard(
        config["state_directory"],
        config["state_sha256"],
        "producer",
        config["epoch"],
        reference_sha256,
    )
    return monitoring_runtime.Runtime(
        reference, reference_sha256, config["label_public"], client, epoch_guard=guard
    )


def sink(path):
    config = document(path)
    monitoring.schema(
        config,
        (
            "reference_sha256",
            "producer_public",
            "receipt_key_file",
            "port",
            "epoch",
            "state_directory",
            "state_sha256",
        ),
    )
    port = monitoring_delivery.port_number(config["port"])
    receiver = monitoring_alerts.Sink(
        config["producer_public"],
        absolute(config["receipt_key_file"]),
        reference_sha256=config["reference_sha256"],
        epoch=config["epoch"],
    )
    guard = monitoring_state.Guard(
        config["state_directory"],
        config["state_sha256"],
        "sink",
        config["epoch"],
        config["reference_sha256"],
    )
    return monitoring_delivery.App(receiver, epoch_guard=guard), port
