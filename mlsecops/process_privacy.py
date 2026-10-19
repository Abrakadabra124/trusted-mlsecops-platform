import importlib
import sys

from mlsecops.contracts import Rejected


def enforce():
    try:
        if sys.platform != "linux":
            raise Rejected("worker_privacy_unavailable")
        import ctypes

        resource = importlib.import_module("resource")
        prctl = ctypes.CDLL(None, use_errno=True).prctl
        prctl.restype = ctypes.c_int
        prctl.argtypes = [ctypes.c_int, *([ctypes.c_ulong] * 4)]
        if prctl(4, 0, 0, 0, 0) != 0:
            raise Rejected("worker_privacy_unavailable")
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        if prctl(3, 0, 0, 0, 0) != 0 or resource.getrlimit(resource.RLIMIT_CORE) != (0, 0):
            raise Rejected("worker_privacy_unavailable")
    except Exception:
        raise Rejected("worker_privacy_unavailable") from None


def readback():
    try:
        if sys.platform != "linux":
            raise Rejected("process_privacy_readback_unavailable")
        import ctypes

        resource = importlib.import_module("resource")
        prctl = ctypes.CDLL(None, use_errno=True).prctl
        prctl.restype = ctypes.c_int
        prctl.argtypes = [ctypes.c_int, *([ctypes.c_ulong] * 4)]
        dumpable = prctl(3, 0, 0, 0, 0)
        if dumpable < 0:
            raise Rejected("process_privacy_readback_unavailable")
        return {"dumpable": dumpable, "core_limits": list(resource.getrlimit(resource.RLIMIT_CORE))}
    except Exception:
        raise Rejected("process_privacy_readback_unavailable") from None
