from __future__ import annotations

import argparse
import json

from _security_audit import (
    append_jsonl,
    build_paths,
    load_findings,
    normalize_severity,
    normalize_text,
    now_iso,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--severity", required=True)
    parser.add_argument("--category", required=True)
    parser.add_argument("--title", required=True)
    parser.add_argument("--impact", required=True)
    parser.add_argument("--recommendation", required=True)
    parser.add_argument("--ticket")
    parser.add_argument("--location")
    args = parser.parse_args()

    paths = build_paths()
    finding_id = f"F-{len(load_findings(paths)) + 1:03d}"
    payload = {
        "id": finding_id,
        "severity": normalize_severity(args.severity),
        "category": normalize_text(args.category, label="category"),
        "title": normalize_text(args.title, label="title"),
        "impact": normalize_text(args.impact, label="impact"),
        "recommendation": normalize_text(args.recommendation, label="recommendation"),
        "ticket": normalize_text(args.ticket, label="ticket", required=False),
        "location": normalize_text(args.location, label="location", required=False),
        "created_at": now_iso(),
    }
    append_jsonl(paths.findings_path, payload)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
