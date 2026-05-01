from __future__ import annotations

import argparse
import json

from _security_audit import atomic_write_json, build_paths, now_iso, normalize_text


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scope", required=True)
    parser.add_argument("--threat-model")
    parser.add_argument("--maturity-hint")
    parser.add_argument("--depth")
    args = parser.parse_args()

    paths = build_paths()
    payload = {
        "schema_version": 1,
        "scope": normalize_text(args.scope, label="scope"),
        "threat_model": normalize_text(
            args.threat_model, label="threat_model", required=False
        ),
        "maturity_hint": normalize_text(
            args.maturity_hint, label="maturity_hint", required=False
        ),
        "depth": normalize_text(args.depth, label="depth", required=False),
        "created_at": now_iso(),
    }
    atomic_write_json(paths.audit_path, payload)
    if not paths.findings_path.exists():
        paths.findings_path.write_text("", encoding="utf-8")
    print(json.dumps({"audit": str(paths.audit_path)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
