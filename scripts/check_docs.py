from datetime import date
import json
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
DECISION_FILE = "docs/research-decisions.json"
GROUPS = (
    ("M", 23, "docs/acceptance.md"),
    ("T", 29, "tasks/todo.md"),
    ("S", 44, "docs/sources.md"),
)
REQUIRED = (
    "README.md", "GOAL.md", "STATUS.md", "AGENTS.md", "CHANGELOG.md",
    "docs/research.md", "docs/sources.md", "docs/provided-materials.md",
    "docs/baseline-gap.md", "docs/product-map.md", "docs/architecture.md",
    "docs/threat-model.md", "docs/acceptance.md", "docs/technology-decisions.md",
    "docs/runbooks.md", "docs/glossary.md", "tasks/plan.md", "tasks/todo.md",
    "docs/decisions/0001-reference-scope.md", "docs/decisions/0002-release-trust.md",
    "docs/decisions/0003-control-and-execution.md",
    "docs/global-research-2026-10.md", "docs/material-review.md",
    "docs/practice-adoption.md", DECISION_FILE,
    ".github/workflows/docs.yml",
)
SENSITIVE = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{50,}\b"),
    re.compile(r"https?://[^/\s:@]+:[^@\s/]+@"),
)


def fail(message):
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def anchor_names(content):
    anchors = set()
    counts = {}
    for heading in re.findall(r"^#{1,6}\s+(.+)$", content, re.MULTILINE):
        normalized = re.sub(r"[^\w\- ]", "", heading.lower()).replace(" ", "-")
        count = counts.get(normalized, 0)
        anchors.add(f"{normalized}-{count}" if count else normalized)
        counts[normalized] = count + 1
    return anchors


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def validate_decisions(documents, known, task_gates):
    try:
        register = json.loads(
            (ROOT / DECISION_FILE).read_text(encoding="utf-8"),
            object_pairs_hook=unique_object,
        )
    except json.JSONDecodeError:
        fail("invalid decision register JSON")
    if not isinstance(register, dict) or set(register) != {
        "schema_version", "as_of", "scope", "decisions"
    }:
        fail("invalid decision register fields")
    if type(register["schema_version"]) is not int or register["schema_version"] != 1:
        fail("unsupported decision schema version")
    if register["scope"] != "research-design-only":
        fail("decision register must remain research-design-only")
    snapshot = register["as_of"]
    if not isinstance(snapshot, str):
        fail("decision snapshot must be an ISO date")
    try:
        if date.fromisoformat(snapshot).isoformat() != snapshot:
            fail("decision snapshot must use YYYY-MM-DD")
    except ValueError:
        fail("invalid decision snapshot date")
    decisions = register["decisions"]
    if not isinstance(decisions, list) or len(decisions) != 8:
        fail("expected eight research decisions")
    expected = {f"D{number:02}" for number in range(1, 9)}
    identifiers = set()
    fields = {
        "id", "title", "status", "sources", "gates", "tasks", "artifacts",
        "owner", "verification", "limitation",
    }
    for decision in decisions:
        if not isinstance(decision, dict) or set(decision) != fields:
            fail("invalid decision fields")
        for field in ("id", "title", "status", "owner", "verification", "limitation"):
            if not isinstance(decision[field], str) or not decision[field].strip():
                fail(f"empty/invalid decision field: {field}")
        identifier = decision["id"]
        if identifier not in expected or identifier in identifiers:
            fail("unknown or duplicate decision ID")
        identifiers.add(identifier)
        if decision["status"] != "design-applied-runtime-planned":
            fail(f"{identifier}: runtime completion cannot be asserted by research register")
        for field, prefix in (("sources", "S"), ("gates", "M"), ("tasks", "T")):
            values = decision[field]
            if (
                not isinstance(values, list) or not values
                or any(not isinstance(value, str) for value in values)
                or len(set(values)) != len(values) or set(values) - known[prefix]
            ):
                fail(f"{identifier}: unknown, empty or duplicate {field}")
        covered_gates = set().union(*(task_gates[task] for task in decision["tasks"]))
        if set(decision["gates"]) - covered_gates:
            fail(f"{identifier}: selected tasks do not cover decision gates")
        artifacts = decision["artifacts"]
        if (
            not isinstance(artifacts, list) or not artifacts
            or any(not isinstance(value, str) or not value for value in artifacts)
            or len(set(artifacts)) != len(artifacts)
        ):
            fail(f"{identifier}: invalid artifact list")
        for artifact in artifacts:
            parsed = urlsplit(artifact)
            candidate = ROOT / artifact
            if (
                parsed.scheme or parsed.netloc or parsed.query or parsed.fragment
                or "\\" in artifact or Path(artifact).is_absolute()
                or ".." in Path(artifact).parts
                or not candidate.resolve().is_relative_to(ROOT)
                or candidate.resolve() not in documents
            ):
                fail(f"{identifier}: artifact must be an existing repository Markdown file")
    headings = re.findall(
        r"^## (D\d{2})$", documents[ROOT / "docs/practice-adoption.md"], re.MULTILINE
    )
    if set(headings) != expected or len(headings) != len(expected):
        fail("decision register and adoption headings differ")
    return len(decisions)


def main():
    if sys.version_info < (3, 12):
        fail("Python 3.12+ required")
    for name in REQUIRED:
        if not (ROOT / name).is_file():
            fail(f"missing required document: {name}")
    files = sorted(
        path for path in ROOT.rglob("*")
        if path.is_file() and ".git" not in path.relative_to(ROOT).parts
        and "__pycache__" not in path.relative_to(ROOT).parts
    )
    documents = {}
    for path in files:
        relative = path.relative_to(ROOT)
        if path.is_symlink() or not path.resolve().is_relative_to(ROOT):
            fail(f"symlink or external path: {relative}")
        if path.suffix.lower() not in {".md", ".py", ".yml"} and path.name not in {
            ".gitignore", ".gitattributes"
        } and relative.as_posix() != DECISION_FILE:
            fail(f"unexpected publication file: {relative}")
        content = path.read_text(encoding="utf-8")
        if any(pattern.search(content) for pattern in SENSITIVE):
            fail(f"potential credential in {relative}; value not printed")
        if re.search(r"^(?:<{7}|={7}|>{7})(?: |$)", content, re.MULTILINE):
            fail(f"merge marker: {relative}")
        if path.suffix == ".md":
            if "\u2014" in content or "\u2013" in content:
                fail(f"use short hyphens in prose: {relative}")
            if content.count("```") % 2:
                fail(f"unclosed fenced block: {relative}")
            documents[path] = content
    local_links = 0
    for path, content in documents.items():
        for target in re.findall(r"\[[^\]\n]+\]\(([^)\s]+)\)", content):
            parsed = urlsplit(target)
            if parsed.scheme in {"https", "mailto"}:
                continue
            if parsed.scheme or parsed.netloc:
                fail(f"unsupported link in {path.name}: {target}")
            destination = (path.parent / unquote(parsed.path)).resolve() if parsed.path else path
            if not destination.is_relative_to(ROOT) or not destination.is_file():
                fail(f"broken/escaping local link in {path.name}: {target}")
            if parsed.fragment:
                anchors = anchor_names(destination.read_text(encoding="utf-8"))
                if unquote(parsed.fragment) not in anchors:
                    fail(f"unknown anchor in {path.name}: {target}")
            local_links += 1
    known = {}
    for prefix, count, name in GROUPS:
        expected = {f"{prefix}{number:02}" for number in range(1, count + 1)}
        known[prefix] = expected
        identifiers = re.findall(rf"^## ({prefix}\d{{2}})$", documents[ROOT / name], re.MULTILINE)
        if set(identifiers) != expected or len(identifiers) != count:
            fail(f"missing/duplicate identifiers in {name}")
        for path, content in documents.items():
            used = set(re.findall(rf"\b{prefix}\d{{2}}\b", content))
            if used - expected:
                fail(f"unknown identifiers in {path.name}: {sorted(used - expected)}")
    backlog = documents[ROOT / "tasks/todo.md"]
    if backlog.count("- [ ]") != len(known["T"]) or "- [x]" in backlog.lower():
        fail("research-only backlog must keep all implementation tasks open")
    task_gates = {}
    for identifier, section in re.findall(
        r"^## (T\d{2})\n(.*?)(?=^## T\d{2}$|\Z)", backlog, re.MULTILINE | re.DOTALL
    ):
        if not re.search(r"\bM\d{2}\b", section) or "Проверка:" not in section:
            fail("each task needs an acceptance gate and verification")
        task_gates[identifier] = set(re.findall(r"\bM\d{2}\b", section))
    if set(task_gates) != known["T"]:
        fail("cannot parse all task sections")
    for section in re.split(r"^## M\d{2}$", documents[ROOT / "docs/acceptance.md"], flags=re.MULTILINE)[1:]:
        if not re.search(r"\bT\d{2}\b", section):
            fail("each acceptance gate needs an implementation task")
    decision_count = validate_decisions(documents, known, task_gates)
    print(f"PASS: {len(files)} files, {len(documents)} Markdown documents, {local_links} local links")
    print(
        f"PASS: {len(known['S'])} sources, {len(known['M'])} planned gates, "
        f"{len(known['T'])} open tasks, {decision_count} traceable design decisions"
    )
    print("Scope: documentation only; external URLs, ML controls and runtime are NOT validated")


if __name__ == "__main__":
    main()
