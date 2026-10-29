"""Trusted Linux worker initialization, before any model or request is read."""

import importlib
import importlib.metadata
import os
import re
import sys
from contextlib import ExitStack

from mlsecops.contracts import Rejected

LIMIT = 4096
PCI_WARNING = re.compile(
    rb"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{1,9} "
    rb"\[W:onnxruntime:Default, device_discovery\.cc:\d{1,4} GetPciBusId\] "
    rb'Skipping pci_bus_id for PCI path at "/sys/devices/[a-zA-Z0-9_./:-]{1,768}" '
    rb'because filename "[a-zA-Z0-9_.:-]{1,128}" did not match expected pattern of '
    + re.escape(b"[0-9a-f]+:[0-9a-f]+:[0-9a-f]+[.][0-9a-f]+")
)


def validate_diagnostics(content):
    if len(content) >= LIMIT or (content and not content.endswith(b"\n")):
        raise Rejected("runtime_bootstrap_rejected")
    for line in content.splitlines():
        if line.startswith(b"\x1b[0;93m") and line.endswith(b"\x1b[m"):
            line = line[7:-3]
        if PCI_WARNING.fullmatch(line) is None:
            raise Rejected("runtime_bootstrap_rejected")


def initialize():
    try:
        if (
            sys.platform != "linux"
            or "onnxruntime" in sys.modules
            or importlib.metadata.version("onnxruntime") != "1.30.0"
        ):
            raise Rejected("runtime_bootstrap_rejected")
        resource = importlib.import_module("resource")
        limits = resource.getrlimit(resource.RLIMIT_FSIZE)
        if limits[0] != resource.RLIM_INFINITY and limits[0] < LIMIT:
            raise Rejected("runtime_bootstrap_rejected")
        sys.stderr.flush()
        with ExitStack() as cleanup:
            capture = os.memfd_create("runtime-init", os.MFD_CLOEXEC)
            cleanup.callback(os.close, capture)
            saved = os.dup(2)
            cleanup.callback(os.close, saved)
            resource.setrlimit(resource.RLIMIT_FSIZE, (LIMIT, limits[1]))
            cleanup.callback(resource.setrlimit, resource.RLIMIT_FSIZE, limits)
            os.dup2(capture, 2)
            cleanup.callback(os.dup2, saved, 2)
            runtime = importlib.import_module("onnxruntime")
            runtime.set_default_logger_severity(3)
            # A full capture might be truncated. It must never be accepted.
            os.lseek(capture, 0, os.SEEK_SET)
            validate_diagnostics(os.read(capture, LIMIT))
    except Exception:
        raise Rejected("runtime_bootstrap_rejected") from None
