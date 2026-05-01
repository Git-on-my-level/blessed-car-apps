from __future__ import annotations

import argparse
import json
from pathlib import Path

from _security_audit import (
    atomic_write_bytes,
    atomic_write_json,
    atomic_write_text,
    build_paths,
    build_scorecard_markdown,
    build_scorecard_png,
    parse_report,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report")
    args = parser.parse_args()

    paths = build_paths()
    report_path = (
        Path(args.report).expanduser().resolve() if args.report else paths.report_path
    )
    if not report_path.exists():
        raise RuntimeError(f"Report not found: {report_path}")
    data = parse_report(report_path.read_text(encoding="utf-8"))
    data["report_path"] = str(report_path)
    atomic_write_json(paths.report_data_path, data)
    if not data["valid"]:
        raise RuntimeError("; ".join(data["errors"]))

    atomic_write_text(paths.scorecard_md_path, build_scorecard_markdown(data))
    atomic_write_bytes(paths.scorecard_png_path, build_scorecard_png(data))
    print(
        json.dumps(
            {
                "report_data": str(paths.report_data_path),
                "scorecard_md": str(paths.scorecard_md_path),
                "scorecard_png": str(paths.scorecard_png_path),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
