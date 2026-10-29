import math
import threading
import time
from contextlib import contextmanager, suppress
from dataclasses import dataclass

from mlsecops import advisory, serving_context
from mlsecops.contracts import Rejected, canonical, decode, digest
from mlsecops.serving_runtime import Worker


@dataclass(frozen=True)
class ResponseBudget:
    generation: threading.Event
    deadline: float

    def remaining(self):
        if type(self.deadline) not in (int, float) or not math.isfinite(self.deadline):
            raise Rejected("serving_response_deadline_invalid")
        remaining = self.deadline - time.monotonic()
        if self.generation.is_set() or remaining <= 0:
            raise Rejected("serving_response_deadline")
        return remaining


@dataclass(frozen=True, slots=True, repr=False)
class ServingResult:
    payload: dict
    audit_context: serving_context.ReleaseContext | serving_context.QualificationContext
    generation: threading.Event


class Engine:
    def __init__(self, reader, *, worker_factory=None):
        self.reader = reader
        self.worker_factory = worker_factory
        self.loaded = None
        self.audit_context = None
        self.worker = None
        self.retiring = None
        self.cleanup = None
        self.lock = threading.Lock()
        self.stopped = threading.Event()
        self.heartbeat = None
        generation = threading.Event()
        generation.set()
        self.admission = ResponseBudget(generation, 0)

    @property
    def generation(self):
        return self.admission.generation

    def require_generation(self):
        if self.generation.is_set() or self.stopped.is_set():
            raise Rejected("serving_generation_fenced")

    def response_budget(self):
        admission = self.admission
        if admission.generation.is_set() or self.stopped.is_set():
            raise Rejected("serving_generation_fenced")
        if self.loaded is None or self.worker is None:
            raise Rejected("serving_not_ready")
        deadline = self.reader.trust.deadline
        if type(deadline) not in (int, float) or not math.isfinite(deadline):
            raise Rejected("serving_response_deadline_invalid")
        return ResponseBudget(
            admission.generation,
            min(time.monotonic() + 10, deadline - 0.25, admission.deadline - 0.25),
        )

    def expire(self, generation):
        generation.set()
        if self.lock.acquire(blocking=False):
            try:
                if self.generation is generation:
                    self.invalidate()
            finally:
                self.lock.release()

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
        self.generation.set()
        self.loaded = None
        self.audit_context = None
        self.reap()
        if self.worker is not None:
            try:
                self.worker.close()
            except Exception:
                raise Rejected("serving_cleanup_unconfirmed") from None
            self.worker = None

    def reap(self):
        if self.cleanup is not None and self.cleanup.is_alive():
            raise Rejected("serving_cleanup_pending")
        if self.retiring is not None:
            try:
                self.retiring.close()
            except Exception:
                raise Rejected("serving_cleanup_unconfirmed") from None
            self.retiring = None
        self.cleanup = None

    def invalidate(self):
        self.generation.set()
        self.loaded = None
        self.audit_context = None
        if self.worker is None:
            return
        if self.retiring is not None:
            raise Rejected("serving_cleanup_unconfirmed")
        worker = self.worker
        self.retiring, self.worker = worker, None

        def retire():
            try:
                worker.close()
            except Exception:
                return
            with self.lock:
                if self.retiring is worker:
                    self.retiring = None

        try:
            self.cleanup = threading.Thread(target=retire, daemon=True)
            self.cleanup.start()
        except Exception:
            raise Rejected("serving_cleanup_unconfirmed") from None

    def drain(self):
        with self.lock:
            cleanup = self.cleanup
        if (
            cleanup is not None
            and cleanup.ident is not None
            and cleanup is not threading.current_thread()
        ):
            cleanup.join(timeout=45)
        with self.lock:
            self.reap()

    def activate(self):
        with self.exclusive():
            try:
                self.clear()
                loaded = self.reader.load()
                self.worker = (self.worker_factory or Worker)(loaded.model, self.reader.image)
                self.worker.start()
                if (
                    self.worker.image != self.reader.image
                    or self.worker.binding["model_sha256"] != loaded.model_sha256
                    or digest(loaded.model) != loaded.model_sha256
                ):
                    raise Rejected("serving_loaded_identity")
                self.worker.ping()
                self.reader.check(loaded)
                context = serving_context.bind(
                    loaded.audit_context,
                    bundle_sha256=loaded.subject_sha256,
                    model_sha256=loaded.model_sha256,
                )
                self.loaded = loaded
                self.audit_context = context
                if self.heartbeat is None:
                    heartbeat = threading.Thread(target=self.maintain, daemon=True)
                    heartbeat.start()
                    self.heartbeat = heartbeat
                monotonic = time.monotonic()
                wall = time.time()
                if type(loaded.expires_at) is not int or loaded.expires_at <= wall:
                    raise Rejected("serving_release_expired")
                self.admission = ResponseBudget(
                    threading.Event(), monotonic + loaded.expires_at - wall
                )
                return self.identity()
            except Exception:
                self.clear()
                raise Rejected("serving_activation_rejected") from None

    def identity(self):
        self.require_generation()
        return {
            "ready": True,
            "bundle_sha256": self.loaded.subject_sha256,
            "model_sha256": self.loaded.model_sha256,
        }

    def require_current(self):
        self.require_generation()
        if self.loaded is None or self.worker is None:
            raise Rejected("serving_not_ready")
        self.reader.check(self.loaded)
        self.require_generation()
        self.worker.ping()
        self.require_generation()

    def check(self, *, generation=None):
        return self.check_result(generation=generation).payload

    def result(self, payload):
        self.require_generation()
        context = serving_context.bind(
            self.audit_context,
            bundle_sha256=payload["bundle_sha256"],
            model_sha256=payload["model_sha256"],
        )
        return ServingResult(payload, context, self.generation)

    def check_result(self, *, generation=None):
        with self.exclusive():
            if generation is not None and generation is not self.generation:
                raise Rejected("serving_generation_changed")
            if self.loaded is None:
                raise Rejected("serving_not_ready")
            try:
                self.require_current()
                self.reader.check(self.loaded)
                self.require_generation()
                return self.result(self.identity())
            except Exception:
                self.invalidate()
                raise Rejected("serving_readiness_rejected") from None

    def predict(self, features, *, generation=None):
        return self.predict_result(features, generation=generation).payload

    def predict_result(self, features, *, generation=None):
        advisory.validate(features)
        features = decode(canonical(features))
        with self.exclusive():
            if generation is not None and generation is not self.generation:
                raise Rejected("serving_generation_changed")
            if self.loaded is None:
                raise Rejected("serving_not_ready")
            try:
                self.require_current()
                predictions = advisory.decide(features, self.worker.predict)
                self.require_generation()
                self.reader.check(self.loaded)
                self.require_generation()
                identity = self.identity()
                return self.result(
                    {
                        "schema_version": 1,
                        "bundle_sha256": identity["bundle_sha256"],
                        "model_sha256": identity["model_sha256"],
                        "predictions": predictions,
                    }
                )
            except Exception:
                self.invalidate()
                raise Rejected("serving_prediction_rejected") from None

    def maintain(self):
        while not self.stopped.wait(30):
            with suppress(Rejected):
                self.check()

    def close(self):
        self.stopped.set()
        self.generation.set()
        self.drain()
        with self.lock:
            self.clear()
        if self.heartbeat is not None and self.heartbeat is not threading.current_thread():
            self.heartbeat.join(timeout=2)
