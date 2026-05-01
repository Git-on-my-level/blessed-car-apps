from __future__ import annotations

import argparse
import json

from _security_audit import build_paths, finding_counts, load_audit, load_findings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    paths = build_paths()
    audit = load_audit(paths)
    findings = load_findings(paths)
    payload = {"audit": audit, **finding_counts(findings)}
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"scope: {audit.get('scope')}")
        print(f"findings: {payload['finding_count']}")
        print(f"severity_counts: {payload['severity_counts']}")
        print(f"category_counts: {payload['category_counts']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
