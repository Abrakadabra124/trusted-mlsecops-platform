import os
import sys

MAX_RECORDS = 65536
MAX_REQUESTS = 16384
RANKS = {
    "request_started": 0,
    "response_intended": 1,
    "response_started": 2,
    "response_completed": 3,
    "aborted": 3,
}


def project(chunks):
    from mlsecops import audit_event, audit_retention
    from mlsecops.contracts import Rejected, decode

    if (
        type(chunks) not in (list, tuple)
        or not 1 <= len(chunks) <= 64
        or any(type(content) is not bytes or not content for content in chunks)
        or sum(map(len, chunks)) > audit_retention.MAX_BYTES
    ):
        raise Rejected("audit_export_source_invalid")
    requests = {}
    records = 0
    previous = None
    retained_prefix = None
    for content in chunks:
        first, last = audit_retention.sequences(content)
        if retained_prefix is None:
            retained_prefix = first > 1
        if previous is not None and first != previous + 1:
            raise Rejected("audit_export_sequence_invalid")
        previous = last
        for line in content.split(b"\n")[:-1]:
            records += 1
            if records > MAX_RECORDS:
                raise Rejected("audit_export_capacity")
            event = audit_event.checked(decode(line)["event"])
            identifier, stage = event["request_id"], event["stage"]
            state = requests.get(identifier)
            if state is None:
                if stage != "request_started" and not retained_prefix:
                    raise Rejected("audit_export_missing_start")
                if len(requests) >= MAX_REQUESTS:
                    raise Rejected("audit_export_capacity")
                state = {
                    "principal": event["principal_id"],
                    "route": event["route"],
                    "rank": -1,
                    "context": None,
                    "status": None,
                    "unresolved": stage != "request_started",
                    "terminal": None,
                }
                requests[identifier] = state
            rank = RANKS[stage]
            if (
                state["principal"] != event["principal_id"]
                or state["route"] != event["route"]
                or rank <= state["rank"]
            ):
                raise Rejected("audit_export_request_invalid")
            if state["rank"] >= 0 and rank != state["rank"] + 1 and stage != "aborted":
                raise Rejected("audit_export_missing_stage")
            if (
                state["rank"] == 2
                and event["status"] != state["status"]
                or state["rank"] == 1
                and stage == "response_started"
                and event["status"] != state["status"]
                and (state["status"], event["status"]) != (200, 503)
                or state["rank"] in (0, 1)
                and stage == "aborted"
                and event["status"] is not None
            ):
                raise Rejected("audit_export_status_invalid")
            context = event["context"]
            if context is not None:
                if state["context"] is not None and state["context"] != context:
                    raise Rejected("audit_export_context_invalid")
                state["context"] = context
            state["rank"], state["status"] = rank, event["status"]
            if rank == 3:
                state["terminal"] = "aborted" if stage == "aborted" else "completed"
    summary = {
        "schema_version": 1,
        "scope": "serving-audit-public-window-not-full-M13",
        "status": "pass",
        "release_ready": False,
        "events": records,
        "requests": {"completed": 0, "aborted": 0, "unresolved": 0},
        "routes": {"predict": 0, "ready": 0},
        "context_kinds": {"release-selection": 0, "candidate-qualification": 0, "none": 0},
    }
    for state in requests.values():
        outcome = (
            "unresolved" if state["unresolved"] or state["terminal"] is None else state["terminal"]
        )
        summary["requests"][outcome] += 1
        summary["routes"][state["route"]] += 1
        kind = state["context"]["kind"] if state["context"] is not None else "none"
        summary["context_kinds"][kind] += 1
    if summary["requests"]["unresolved"]:
        summary["status"] = "inconclusive"
    return summary


def main():
    try:
        from mlsecops.process_privacy import enforce as enforce_privacy

        enforce_privacy()
        from pathlib import Path

        from mlsecops import audit_snapshot
        from mlsecops.contracts import Rejected, canonical
        from mlsecops.private_cli import Arguments

        parser = Arguments(
            prog="public-audit-export",
            description="Export fixed public counters from a closed private audit spool",
        )
        parser.add_argument("--spool", type=Path, required=True)
        options = parser.parse_args()
        summary = project(audit_snapshot.read_closed(options.spool))
        payload = canonical(summary) + b"\n"
        if len(payload) > 4096:
            raise Rejected("audit_export_output_limit")
        sys.stdout.write(payload.decode())
        sys.stdout.flush()
        return 0 if summary["status"] == "pass" else 2
    except (Exception, KeyboardInterrupt) as error:
        print("audit_export_rejected", file=sys.stderr)
        return 130 if isinstance(error, KeyboardInterrupt) else 1


def cli():
    try:
        code = main()
    except SystemExit as error:
        code = error.code if type(error.code) is int else 1
    except (Exception, KeyboardInterrupt) as error:
        code = 130 if isinstance(error, KeyboardInterrupt) else 1
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.flush()
        except (Exception, KeyboardInterrupt):
            code = 1
    os._exit(code)


if __name__ == "__main__":
    cli()
