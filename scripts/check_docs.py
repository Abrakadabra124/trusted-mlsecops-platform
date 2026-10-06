from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
REQUIRED = (
    "README.md", "GOAL.md", "STATUS.md", "AGENTS.md",
    "docs/research.md", "docs/sources.md", "docs/provided-materials.md",
    "docs/baseline-gap.md", "docs/product-map.md", "docs/architecture.md",
    "docs/threat-model.md", "docs/acceptance.md", "docs/technology-decisions.md",
    "docs/runbooks.md", "docs/glossary.md", "tasks/plan.md", "tasks/todo.md",
    "docs/decisions/0001-reference-scope.md", "docs/decisions/0002-release-trust.md",
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
        }:
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
    for prefix, count, name in (
        ("M", 18, "docs/acceptance.md"),
        ("T", 24, "tasks/todo.md"),
        ("S", 24, "docs/sources.md"),
    ):
        expected = {f"{prefix}{number:02}" for number in range(1, count + 1)}
        identifiers = re.findall(rf"^## ({prefix}\d{{2}})$", documents[ROOT / name], re.MULTILINE)
        if set(identifiers) != expected or len(identifiers) != count:
            fail(f"missing/duplicate identifiers in {name}")
        for path, content in documents.items():
            used = set(re.findall(rf"\b{prefix}\d{{2}}\b", content))
            if used - expected:
                fail(f"unknown identifiers in {path.name}: {sorted(used - expected)}")
    backlog = documents[ROOT / "tasks/todo.md"]
    if backlog.count("- [ ]") != 24 or "- [x]" in backlog.lower():
        fail("research-only backlog must keep 24 implementation tasks open")
    for section in re.split(r"^## T\d{2}$", backlog, flags=re.MULTILINE)[1:]:
        if not re.search(r"\bM\d{2}\b", section) or "Проверка:" not in section:
            fail("each task needs an acceptance gate and verification")
    for section in re.split(r"^## M\d{2}$", documents[ROOT / "docs/acceptance.md"], flags=re.MULTILINE)[1:]:
        if not re.search(r"\bT\d{2}\b", section):
            fail("each acceptance gate needs an implementation task")
    print(f"PASS: {len(files)} files, {len(documents)} Markdown documents, {local_links} local links")
    print("PASS: 24 sources, 18 planned gates, 24 open tasks, bounded publication checks")
    print("Scope: documentation only; external URLs, ML controls and runtime are NOT validated")


if __name__ == "__main__":
    main()
