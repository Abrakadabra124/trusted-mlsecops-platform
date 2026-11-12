"""Serial source checks; only a verified child may publish a producer heartbeat."""

import signal
import subprocess
import sys
import threading
import time
from contextlib import suppress
from pathlib import Path

from mlsecops import security_event_store as journal
from mlsecops import security_trust_events as source
from mlsecops.contracts import Rejected, canonical
from mlsecops.private_cli import Arguments
from mlsecops.process_privacy import enforce

PERIOD_SECONDS = 30
CHILD_SECONDS = 10
STOP_SECONDS = 1


class Observer:
    def __init__(self, path):
        self.path = journal.path(path)
        _, self.pin = source.configuration(self.path)
        self.stopped = threading.Event()
        self.child = None
        self.first_success = False

    def close(self):
        process = self.child
        if process is None:
            return
        try:
            if process.poll() is None:
                with suppress(ProcessLookupError):
                    process.terminate()
                try:
                    process.wait(timeout=STOP_SECONDS)
                except subprocess.TimeoutExpired:
                    with suppress(ProcessLookupError):
                        process.kill()
                    process.wait(timeout=STOP_SECONDS)
            else:
                process.wait(timeout=STOP_SECONDS)
        except Exception:
            raise Rejected("trust_observer_cleanup_unconfirmed") from None
        self.child = None

    def once(self):
        if self.stopped.is_set() or self.child is not None:
            raise Rejected("trust_observer_lifecycle")
        deadline = time.monotonic() + CHILD_SECONDS
        try:
            self.child = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "mlsecops.security_trust_events",
                    "--config",
                    self.path,
                    "--config-sha256",
                    self.pin,
                    "--heartbeat",
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                cwd=Path(__file__).resolve().parents[1],
            )
            while not self.stopped.is_set():
                code = self.child.poll()
                if code is not None:
                    return code == 0
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self.stopped.wait(min(0.05, remaining))
            return False
        finally:
            self.close()

    def run(self):
        try:
            while not self.stopped.is_set():
                started = time.monotonic()
                try:
                    ok = self.once()
                except Exception:
                    # A failed reap is fatal: never lose the child handle and
                    # launch a second process over a possibly live operation.
                    if self.child is not None:
                        raise
                    ok = False
                if not ok and not self.stopped.is_set():
                    print("trust_observer_check_failed", file=sys.stderr, flush=True)
                if ok and not self.first_success:
                    # One bounded public signal per process. Child output stays private;
                    # the operator must separately verify collector state and Pod identity.
                    print(
                        canonical(
                            dict(
                                state="trust_observer_first_success",
                                config_sha256=self.pin,
                                release_ready=False,
                            )
                        ).decode(),
                        flush=True,
                    )
                    self.first_success = True
                self.stopped.wait(max(0, PERIOD_SECONDS - (time.monotonic() - started)))
        finally:
            self.close()


def main(arguments=None):
    parser = Arguments()
    parser.add_argument("--config", required=True)
    previous = {}
    try:
        options = parser.parse_args(arguments)
        enforce()
        observer = Observer(options.config)
        for number in (signal.SIGTERM, signal.SIGINT):
            previous[number] = signal.signal(number, lambda *_: observer.stopped.set())
        # Separate private configuration directory; never hold the outbox lock
        # here because the owned child must acquire it for durable writes.
        with journal.locked(str(Path(observer.path).parent)):
            observer.run()
        print(canonical(dict(state="stopped", release_ready=False)).decode())
        return 0
    except (Exception, KeyboardInterrupt) as error:
        print("trust_observer_rejected", file=sys.stderr)
        return 130 if isinstance(error, KeyboardInterrupt) else 1
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


if __name__ == "__main__":
    raise SystemExit(main())
