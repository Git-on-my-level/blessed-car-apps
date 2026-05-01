from __future__ import annotations

import argparse
import sys

from _autooptimize import (
    amend_iteration_record,
    atomic_write_json,
    atomic_write_jsonl,
    build_metric_history_text,
    build_paths,
    compute_best_record,
    ensure_metric_unit,
    find_iteration,
    load_iterations,
    load_run,
    locked_state,
    now_iso,
)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iteration", required=True, type=int)
    parser.add_argument("--value", type=float)
    parser.add_argument("--unit")
    parser.add_argument("--decision")
    parser.add_argument("--guard-status")
    parser.add_argument("--hypothesis")
    parser.add_argument("--ticket")
    parser.add_argument("--commit-before")
    parser.add_argument("--commit-after")
    parser.add_argument("--milestone")
    parser.add_argument("--summary")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(list(sys.argv[1:] if argv is None else argv))
    if not any(
        value is not None
        for value in (
            args.value,
            args.unit,
            args.decision,
            args.guard_status,
            args.hypothesis,
            args.ticket,
            args.commit_before,
            args.commit_after,
            args.milestone,
            args.summary,
        )
    ):
        raise RuntimeError("Provide at least one field to amend")

    paths = build_paths()
    with locked_state(paths):
        run = load_run(paths)
        rows = load_iterations(paths)
        existing = find_iteration(rows, args.iteration)
        unit = ensure_metric_unit(run, args.unit)
        timestamp = now_iso()
        amended = amend_iteration_record(
            existing,
            value=args.value,
            unit=unit if args.unit is not None else None,
            decision=args.decision,
            guard_status=args.guard_status,
            hypothesis=args.hypothesis,
            ticket=args.ticket,
            commit_before=args.commit_before,
            commit_after=args.commit_after,
            milestone=args.milestone,
            summary=args.summary,
            timestamp=timestamp,
        )

        rows = [
            amended if int(row.get("iteration", 0)) == args.iteration else row
            for row in rows
        ]
        rows.sort(key=lambda item: int(item["iteration"]))
        run["best"] = compute_best_record(run, rows)
        run["updated_at"] = timestamp

        atomic_write_jsonl(paths.iterations_path, rows)
        atomic_write_json(paths.run_path, run)

    print("iteration amended")
    print(build_metric_history_text(run, rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
