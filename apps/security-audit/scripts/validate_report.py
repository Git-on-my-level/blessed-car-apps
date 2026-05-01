from __future__ import annotations

import argparse
import json
from pathlib import Path

from _security_audit import atomic_write_json, build_paths, parse_report


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
    print(json.dumps(data, indent=2, sort_keys=True))
    if not data["valid"]:
        raise RuntimeError("; ".join(data["errors"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
