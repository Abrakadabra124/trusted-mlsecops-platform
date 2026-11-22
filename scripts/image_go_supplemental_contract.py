"""Bind one already-authorized release coordinate to Grype 0.120.1 evidence.

The fixed registry must authorize the tuple BEFORE scanner execution. This reader
does not prove source provenance, DB file identity, or the complete scan set.
Caller JSON decoding must reject duplicate keys and bound the original bytes;
decoded documents are independently bounded here. No input is logged or changed.

Pinned source for the sole permitted ERROR (not inferred from native ERROR count):
https://github.com/anchore/grype/blob/v0.120.1/grype/grypeerr/errors.go
SHA256 83fafd09736acc31f7522e046b573480b78d5aafc57d0899744eb363343cda3c
ExpectedErr preserves that literal; commands/util.go preserves a single error.
https://github.com/anchore/clio/blob/v0.1.1/application.go logs it at ERROR.
https://github.com/anchore/grype/blob/v0.120.1/grype/vulnerability_matcher.go
returns the threshold error BEFORE logListSummary. Other paths require its exact
summary. The default text formatter is go-logger v0.2.0 adapter/logrus/formatter.go.
Changed formats fail closed and require new evidence, not permissive fallbacks.
"""

import math
import re
from datetime import UTC, datetime

from mlsecops.contracts import Rejected
from scripts.image_audit_contract import SEVERITIES, database

_LABEL = "image_go_supplemental_rejected"
_THRESHOLD = "discovered vulnerabilities at or above the severity threshold"
_MODULE = re.compile(r"[a-z0-9]+(?:[.-][a-z0-9]+)+(?:/[A-Za-z0-9][A-Za-z0-9._-]*)+")
_RELEASE = re.compile(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")
_RECORD = re.compile(r"\[[0-9]{4,10}\]\s+(TRACE|DEBUG|INFO|WARN|ERROR|FATAL|PANIC)\s+(.*)")
_ERROR_WORD = re.compile(r"\b(?:errors?|failed|failure|fatal|panic)\b", re.IGNORECASE)


def _need(condition):
    if not condition:
        raise Rejected(_LABEL)


def _text(value, limit):
    _need(type(value) is str and 0 < len(value) <= limit)
    _need(all(32 <= ord(char) <= 126 for char in value))
    return value


def _document(value, limit):
    """Bound decoded JSON, including unused metadata, without serializing it."""
    _need(type(value) is dict)
    pending, nodes, size = [(value, 0)], 0, 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        size += 8
        _need(depth <= 16 and nodes <= 100000)
        kind = type(item)
        if kind is dict:
            _need(len(item) <= 10000)
            for key, child in item.items():
                _need(type(key) is str)
                pending.extend(((key, depth + 1), (child, depth + 1)))
        elif kind is list:
            _need(len(item) <= 10000)
            pending.extend((child, depth + 1) for child in item)
        elif kind is str:
            _need(len(item) <= 65536)
            encoded = item.encode("utf-8")
            _need(len(encoded) <= 65536)
            size += len(encoded)
        elif kind is int:
            _need(item.bit_length() <= 64)
        elif kind is float:
            _need(math.isfinite(item))
        else:
            _need(item is None or kind is bool)
        _need(size <= limit)


def _package(cdx, module, version, purl):
    _need(cdx["bomFormat"] == "CycloneDX")
    components = cdx["components"]
    _need(type(components) is list and len(components) == 1)
    component = components[0]
    _need(type(component) is dict)
    for field, expected in (
        ("name", module),
        ("version", version),
        ("purl", purl),
        ("type", "library"),
    ):
        _need(component[field] == expected)
    nested = component.get("components", [])
    _need(type(nested) is list and not nested)
    properties = component["properties"]
    _need(type(properties) is list and 1 <= len(properties) <= 256)
    types = []
    for prop in properties:
        _need(type(prop) is dict)
        name, value = _text(prop["name"], 256), _text(prop["value"], 1024)
        if name == "syft:package:type":
            types.append(value)
    _need(types == ["go-module"])


def _completed(trace, purl, count, blocked):
    _need(type(trace) is bytes and 0 < len(trace) <= 2 * 1024**2)
    text = re.sub(r"\x1b\[[0-9;]*m", "", trace.decode("utf-8")).replace("\r\n", "\n")
    _need(text.endswith("\n") and all(ord(c) >= 32 or c in "\n\t" for c in text))
    searches, summaries, thresholds, config = 0, [], 0, False
    for line in text.splitlines():
        if not line:
            continue
        record = _RECORD.fullmatch(line)
        if record is None:
            # Clio's DEBUG config dump is indented multiline YAML, not log records.
            _need(config and line.startswith("  ") and not _ERROR_WORD.search(line))
            continue
        level, message = record.groups()
        config = level == "DEBUG" and message == "config:"
        _need(level not in {"WARN", "FATAL", "PANIC"})
        if level == "ERROR":
            _need(blocked and message == _THRESHOLD and searches == 1)
            thresholds += 1
        else:
            _need(not _ERROR_WORD.search(message))
        if "searching for vulnerability matches" in message:
            _need(
                level == "TRACE"
                and message == f"searching for vulnerability matches package={purl}"
            )
            searches += 1
        if "vulnerability matches across" in message:
            _need(level == "INFO" and searches == 1)
            summary = re.fullmatch(
                r"found ([0-9]{1,5}) vulnerability matches across 1 packages", message
            )
            _need(summary is not None)
            summaries.append(int(summary[1]))
    _need(searches == 1 and thresholds == int(blocked))
    _need(summaries == ([] if blocked else [count]))


def assess(module, version, report, cdx, trace, returncode, expected_database, timestamp=None):
    """Assess one invocation; reject malformed/ambiguous evidence with a fixed label.

    Accept canonical vMAJOR.MINOR.PATCH releases and the pinned Cilium wrapper
    pseudo-version. timestamp=None uses actual UTC; injection is
    for controlled tests. Original findings and independent Go controls remain
    mandatory at the caller; this result cannot replace either.
    """
    try:
        _need(_MODULE.fullmatch(_text(module, 512)) is not None)
        _need(
            _RELEASE.fullmatch(_text(version, 64)) is not None
            or (module, version)
            == (
                "github.com/kubernetes-sigs/iptables-wrappers",
                "v0.0.0-20260420133543-bfef9e5087a1",
            )
        )
        purl = f"pkg:golang/{module}@{version}"
        _document(report, 16 * 1024**2)
        _document(cdx, 1024**2)
        _need(
            type(expected_database) is dict
            and set(expected_database) == {"schema_version", "built"}
        )
        _text(expected_database["schema_version"], 64)
        _text(expected_database["built"], 64)
        stamp = datetime.now(UTC) if timestamp is None else timestamp
        _need(type(stamp) is datetime and stamp.utcoffset() is not None)
        observed_database = database(report, stamp)
        _need(observed_database == expected_database)
        _need(report["source"] == {"type": "purl", "target": purl})
        _need(type(returncode) is int and returncode in (0, 2))
        for name in ("ignoredMatches", "alertsByPackage"):
            values = report.get(name, [])
            _need(type(values) is list and not values)
        _package(cdx, module, version, purl)
        _need(type(report["matches"]) is list)
        counts, findings = dict.fromkeys(SEVERITIES, 0), []
        for match in report["matches"]:
            artifact, vulnerability = match["artifact"], match["vulnerability"]
            for field, expected in (
                ("name", module),
                ("version", version),
                ("type", "go-module"),
                ("purl", purl),
            ):
                _need(artifact[field] == expected)
            identifier = _text(vulnerability["id"], 512)
            severity = vulnerability["severity"]
            _need(type(severity) is str and severity in SEVERITIES)
            fix = vulnerability.get("fix", {})
            _need(type(fix) is dict)
            state, versions = fix.get("state"), fix.get("versions", [])
            # Grype models.Fix.State is a plain string, including its empty Go
            # zero value. Preserve it without suppressing the finding/severity.
            if state not in (None, ""):
                _text(state, 64)
            _need(type(versions) is list and len(versions) <= 256)
            versions = [_text(value, 256) for value in versions]
            counts[severity] += 1
            findings.append(
                {
                    "id": identifier,
                    "severity": severity,
                    "package": module,
                    "installed": version,
                    "type": "go-module",
                    "fix": {"state": state, "versions": versions},
                }
            )
        blocked = counts["High"] + counts["Critical"] > 0
        _need(returncode == (2 if blocked else 0))
        _completed(trace, purl, len(findings), blocked)
        return {
            "status": "fail" if blocked else "inconclusive" if counts["Unknown"] else "pass",
            "matches": len(findings),
            "unique_vulnerabilities": len({f["id"] for f in findings}),
            "severity_counts": counts,
            "findings": findings,
            "database": observed_database,
            "scanner_exit_code": returncode,
            "purl": purl,
            "package_identity_bound": True,
            "matching_completed": True,
        }
    except (Rejected, KeyError, TypeError, AttributeError, ValueError, OverflowError):
        raise Rejected(_LABEL) from None
