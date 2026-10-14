import threading
from contextlib import contextmanager, suppress

from mlsecops import advisory
from mlsecops.contracts import Rejected, canonical, decode, digest
from mlsecops.serving_runtime import Worker


class Engine:
    def __init__(self, reader):
        self.reader = reader
        self.loaded = None
        self.worker = None
        self.lock = threading.Lock()
        self.stopped = threading.Event()
        self.heartbeat = None

    @contextmanager
    def exclusive(self):
        if not self.lock.acquire(timeout=1):
            raise Rejected("serving_busy")
        try:
            if self.stopped.is_set():
                raise Rejected("serving_closed")
            yield
        finally:
            self.lock.release()

    def clear(self):
        self.loaded = None
        if self.worker is not None:
            try:
                self.worker.close()
            except Exception:
                raise Rejected("serving_cleanup_unconfirmed") from None
            self.worker = None

    def activate(self):
        with self.exclusive():
            try:
                self.clear()
                loaded = self.reader.load()
                self.worker = Worker(loaded.model, self.reader.image)
                self.worker.start()
                if (
                    self.worker.image != self.reader.image
                    or self.worker.binding["model_sha256"] != loaded.model_sha256
                    or digest(loaded.model) != loaded.model_sha256
                ):
                    raise Rejected("serving_loaded_identity")
                self.worker.ping()
                self.reader.check(loaded)
                self.loaded = loaded
                if self.heartbeat is None:
                    heartbeat = threading.Thread(target=self.maintain, daemon=True)
                    heartbeat.start()
                    self.heartbeat = heartbeat
                return self.identity()
            except Exception:
                self.clear()
                raise Rejected("serving_activation_rejected") from None

    def identity(self):
        return {
            "ready": True,
            "bundle_sha256": self.loaded.subject_sha256,
            "model_sha256": self.loaded.model_sha256,
        }

    def require_current(self):
        if self.loaded is None or self.worker is None:
            raise Rejected("serving_not_ready")
        self.reader.check(self.loaded)
        self.worker.ping()

    def check(self):
        with self.exclusive():
            if self.loaded is None:
                raise Rejected("serving_not_ready")
            try:
                self.require_current()
                self.reader.check(self.loaded)
                return self.identity()
            except Exception:
                self.clear()
                raise Rejected("serving_readiness_rejected") from None

    def predict(self, features):
        advisory.validate(features)
        features = decode(canonical(features))
        with self.exclusive():
            if self.loaded is None:
                raise Rejected("serving_not_ready")
            try:
                self.require_current()
                predictions = advisory.decide(features, self.worker.predict)
                self.reader.check(self.loaded)
                identity = self.identity()
                return {
                    "schema_version": 1,
                    "bundle_sha256": identity["bundle_sha256"],
                    "model_sha256": identity["model_sha256"],
                    "predictions": predictions,
                }
            except Exception:
                self.clear()
                raise Rejected("serving_prediction_rejected") from None

    def maintain(self):
        while not self.stopped.wait(30):
            with suppress(Rejected):
                self.check()

    def close(self):
        self.stopped.set()
        with self.lock:
            self.clear()
        if self.heartbeat is not None and self.heartbeat is not threading.current_thread():
            self.heartbeat.join(timeout=2)
