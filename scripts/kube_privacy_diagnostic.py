"""Code location for qualification failures; never exception text or locals."""

from pathlib import Path


def location(error):
    root = Path(__file__).resolve().parents[1]
    result = {"exception": "other", "source_file": "unknown", "source_line": 0}
    kind = type(error).__name__
    if kind in {"Rejected", "KeyError", "TypeError", "ValueError", "OSError", "AttributeError"}:
        result["exception"] = kind
    frame = error.__traceback__
    while frame is not None:
        path = Path(frame.tb_frame.f_code.co_filename).resolve()
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
