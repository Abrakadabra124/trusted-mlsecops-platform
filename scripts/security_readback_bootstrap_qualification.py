"""Cold subprocess regression for bounded journal bootstrap. Synthetic private state only."""

import json
import subprocess
import sys
import unittest

from mlsecops.contracts import canonical, decode, digest
from scripts import security_event_live_qualification as fixtures

DEPENDENCIES = ("mlsecops.serving_http", "numpy", "sklearn", "psycopg", "fastapi", "uvicorn")

IMPORT = """
import importlib, json, sys, time
started = time.monotonic()
importlib.import_module(sys.argv[1])
print(json.dumps(dict(seconds=round(time.monotonic() - started, 6),
                     loaded=[name for name in json.loads(sys.argv[2]) if name in sys.modules])))
"""

# Simulate one slow unrelated HTTP/model import in a fresh interpreter. The
# fixed readback code, real configuration, journal and three-second budget run unchanged.
COLD = """
import importlib.abc, json, sys, time
from mlsecops.contracts import Rejected, decode
from mlsecops.process_privacy import enforce
enforce()
class SlowHTTP(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'mlsecops.serving_http':
            time.sleep(3.1)
        return None
sys.meta_path.insert(0, SlowHTTP())
started = time.monotonic()
try:
    exec(sys.stdin.read(), {})
except Rejected as error:
    category = 'readback_deadline' if str(error) == 'security_readback_deadline' else 'other'
    print(json.dumps(dict(status='rejected', category=category)))
    raise SystemExit(1)
"""


def child(code, *args, source=None):
    return subprocess.run(
        [sys.executable, "-B", "-W", "error", "-c", code, *args],
        input=source,
        capture_output=True,
        timeout=20,
        check=False,
    )


class ColdImports(unittest.TestCase):
    def test_readback_setup_imports_only_its_security_dependencies(self):
        for module in (
            "security_event_server",
            "security_event_delivery",
            "security_event_admission",
        ):
            result = child(IMPORT, "mlsecops." + module, json.dumps(DEPENDENCIES))
            self.assertEqual(result.returncode, 0, "cold import failed")
            report = decode(result.stdout, 4096)
            print(canonical({"module": module, **report}).decode(), flush=True)
            self.assertEqual(report["loaded"], [], module)


@unittest.skipUnless(sys.platform == "linux", "private journal requires Linux")
class ColdCollector(unittest.TestCase):
    def setUp(self):
        self.fx = fixtures.LiveCollector("runTest")
        self.fx.setUp()
        self.addCleanup(lambda: self.assertTrue(self.fx.doCleanups()))
        # Provisioning alone. No listener or HTTP worker has started.
        self.path = str(self.fx.directory / "collector.json")
        self.state = self.fx.directory / "state"
        self.before = {p.name: digest(p.read_bytes()) for p in self.state.iterdir()}

    def test_slow_unrelated_http_import_cannot_exhaust_journal_deadline(self):
        from mlsecops import kube_observer_readback as observer
        from scripts import kube_security_native as native

        setup = (
            "from mlsecops.security_event_server import configured\n"
            "store = configured(" + repr(self.path) + ")[0].collector.store"
        )
        programs = {
            "public": native.READ.replace("SETUP", setup),
            "private": native.PRIVATE_READ.replace("SETUP", setup),
            "observer": observer.SNAPSHOT.replace("SETUP", setup).replace(
                "BODY", "print(canonical(dict(pin=store.pin)).decode())"
            ),
        }
        for kind, program in programs.items():
            with self.subTest(kind=kind):
                result = child(COLD, source=program.encode())
                category = "complete" if result.returncode == 0 else "other"
                lines = result.stdout.splitlines()
                if result.returncode and len(lines) == 1:
                    report = decode(lines[0], 4096)
                    if report == {"status": "rejected", "category": "readback_deadline"}:
                        category = "readback_deadline"
                print(canonical({"reader": kind, "status": category}).decode(), flush=True)
                self.assertEqual(result.returncode, 0, category)
                report = decode(result.stdout, native.PRIVATE_READBACK_BYTES)
                self.assertEqual(
                    report["pin"],
                    decode((self.fx.directory / "collector.json").read_bytes())["state_sha256"],
                )
                self.assertEqual(
                    {p.name: digest(p.read_bytes()) for p in self.state.iterdir()}, self.before
                )


if __name__ == "__main__":
    unittest.main()
