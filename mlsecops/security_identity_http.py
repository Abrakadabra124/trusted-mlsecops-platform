"""One owned child at a time; cancellation never abandons an audit operation."""

import asyncio
import secrets
import sys
from contextlib import suppress
from pathlib import Path

from mlsecops import security_event_store as journal
from mlsecops import security_events as events
from mlsecops import security_identity_events as source
from mlsecops.contracts import Rejected

CHILD_SECONDS = 3
WAIT_SECONDS = 6
STOP_SECONDS = 1


async def stop(process):
    if process.returncode is None:
        with suppress(ProcessLookupError):
            process.terminate()
        try:
            await asyncio.wait_for(process.wait(), STOP_SECONDS)
        except TimeoutError:
            with suppress(ProcessLookupError):
                process.kill()
            await asyncio.wait_for(process.wait(), STOP_SECONDS)
    if process.returncode is None:
        raise Rejected("identity_security_child_cleanup_unconfirmed")


class Observer:
    def __init__(self, path):
        self.path = journal.path(path)
        config, self.pin = source.configuration(self.path)
        self.service = config["service_sha256"]
        self.pending = self.child = self.loop = None
        self.started = self.closed = False
        self.stop_requested = False

    def finished(self, task):
        with suppress(Exception, asyncio.CancelledError):
            task.result()
        if self.pending is task:
            self.pending = None

    async def run(self, action, correlation):
        # No pipes: child output cannot enter memory/logs/HTTP. Exit zero is
        # produced only after the trusted child validates role and receipt.
        spawn = asyncio.create_task(
            asyncio.create_subprocess_exec(
                sys.executable,
                "-m",
                "mlsecops.security_identity_events",
                "--config",
                self.path,
                "--config-sha256",
                self.pin,
                "--action",
                action,
                "--correlation",
                correlation,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
                cwd=Path(__file__).resolve().parents[1],
            )
        )
        process = None
        try:
            process = await asyncio.shield(spawn)
            self.child = process
            code = await asyncio.wait_for(process.wait(), CHILD_SECONDS)
            if code != 0:
                raise Rejected("identity_security_child_rejected")
        finally:
            if process is None:
                try:
                    process = await asyncio.shield(spawn)
                    self.child = process
                except Exception:
                    process = None
            if process is not None:
                await stop(process)
                self.child = None

    async def invoke(self, action, correlation):
        if self.closed or self.loop is not asyncio.get_running_loop():
            raise Rejected("identity_security_lifecycle")
        if self.pending is not None or self.child is not None:
            raise Rejected("identity_security_busy")
        task = asyncio.create_task(self.run(action, correlation))
        self.pending = task
        task.add_done_callback(self.finished)
        try:
            await asyncio.wait_for(asyncio.shield(task), WAIT_SECONDS)
        except Exception:
            raise Rejected("identity_security_unavailable") from None

    async def start(self):
        if self.started or self.closed:
            raise Rejected("identity_security_lifecycle")
        self.loop = asyncio.get_running_loop()
        await self.invoke("probe", secrets.token_hex(16))
        self.started = True

    async def report(self, correlation, reason):
        if not self.started or reason not in ("credential", "role"):
            raise Rejected("identity_security_request")
        events.hexadecimal(correlation, 32)
        await self.invoke(reason, correlation)

    async def close(self):
        if self.loop is not None and self.loop is not asyncio.get_running_loop():
            raise Rejected("identity_security_lifecycle")
        self.closed = True
        task = self.pending
        if task is not None:
            if not self.stop_requested:
                self.stop_requested = True
                task.cancel()
            try:
                await asyncio.wait_for(asyncio.shield(task), WAIT_SECONDS)
            except (Exception, asyncio.CancelledError):
                if not task.done():
                    raise Rejected("identity_security_child_cleanup_unconfirmed") from None
        if self.child is not None:
            await stop(self.child)
            self.child = None


def configured(path):
    return Observer(path)
