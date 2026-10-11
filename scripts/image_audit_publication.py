import json
from pathlib import Path

from mlsecops.contracts import Rejected, canonical, read_json


def render(report):
    if len(canonical(report)) > 16 * 1024**2:
        raise Rejected("image_audit_publication_size")
    content = json.dumps(report, sort_keys=True, ensure_ascii=True, allow_nan=False, indent=2)
    if any(len(line.encode("ascii")) > 16384 for line in content.splitlines()):
        raise Rejected("image_audit_publication_line_limit")
    return content


def main(path=None):
    path = (
        Path(path)
        if path is not None
        else Path(__file__).resolve().parents[1] / ".runtime/evidence/image-audit.json"
    )
    try:
        content = render(read_json(path))
    except (Rejected, OSError):
        print(
            render(
                {
                    "status": "inconclusive",
                    "release_ready": False,
                    "reason": "image_audit_publication_unavailable",
                }
            )
        )
        return 2
    print(content)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
