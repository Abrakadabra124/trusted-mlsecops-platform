"""Code location for qualification failures; never exception text or locals."""

import re
from pathlib import Path

KINDS = {"other", "Rejected", "KeyError", "TypeError", "ValueError", "OSError", "AttributeError"}


def validated(value):
    if type(value) is not dict or set(value) != {"exception", "source_file", "source_line"}:
        return None
    if (
        type(value["exception"]) is not str
        or value["exception"] not in KINDS
        or type(value["source_line"]) is not int
    ):
        return None
    if value["source_file"] == "unknown" and value["source_line"] == 0:
        return value
    path = value["source_file"]
    if (
        type(path) is str
        and re.fullmatch(r"(mlsecops|scripts)/[a-z_][a-z_0-9]*\.py", path)
        and 1 <= value["source_line"] <= 10000
        and (Path(__file__).absolute().parents[1] / path).is_file()
    ):
        return value
    return None


def location(error):
    # Keep the import path: ConfigMap projected files resolve through a
    # timestamp directory, while the Python package still lives at /app/scripts.
    root = Path(__file__).absolute().parents[1]
    result = {"exception": "other", "source_file": "unknown", "source_line": 0}
    kind = type(error).__name__
    if kind in KINDS:
        result["exception"] = kind
    frame = error.__traceback__
    while frame is not None:
        path = Path(frame.tb_frame.f_code.co_filename).absolute()
        try:
            relative = path.relative_to(root)
        except ValueError:
            relative = Path("unknown")
        if (
            len(relative.parts) == 2
            and relative.parts[0] in {"mlsecops", "scripts"}
            and path.is_file()
            and path.suffix == ".py"
        ):
            result.update(source_file=relative.as_posix(), source_line=frame.tb_lineno)
        frame = frame.tb_next
    return result
