from __future__ import annotations

import sys

from _autooptimize import (
    build_paths,
    latest_iteration_warnings,
    load_iterations,
    load_run,
    validate_state,
)


def main() -> int:
    paths = build_paths()
    errors = validate_state(paths)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    run = load_run(paths)
    rows = load_iterations(paths)
    warnings = latest_iteration_warnings(run, rows)
    print("autooptimize state is valid")
    if warnings:
        print("latest iteration review:")
        for warning in warnings:
            print(f"- {warning}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
