from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

APP_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = APP_ROOT / "scripts"


def _app_env(tmp_path: Path) -> dict[str, str]:
    env = os.environ.copy()
    env["CAR_APP_STATE_DIR"] = str(tmp_path / "state")
    env["CAR_APP_ARTIFACT_DIR"] = str(tmp_path / "artifacts")
    return env


def _run_script(
    script_name: str,
    *args: str,
    env: dict[str, str],
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / script_name), *args],
        cwd=APP_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_security_audit_scripts_validate_and_render_scorecard(tmp_path: Path) -> None:
    env = _app_env(tmp_path)
    state_dir = Path(env["CAR_APP_STATE_DIR"])
    artifact_dir = Path(env["CAR_APP_ARTIFACT_DIR"])
    report_path = artifact_dir / "security-audit-report.md"

    init_result = _run_script(
        "init_audit.py",
        "--scope",
        "Full repo",
        "--threat-model",
        "internet-facing automation",
        "--maturity-hint",
        "production",
        "--depth",
        "standard",
        env=env,
    )
    assert init_result.returncode == 0, init_result.stderr
    audit_payload = json.loads((state_dir / "audit.json").read_text(encoding="utf-8"))
    assert audit_payload["scope"] == "Full repo"
    assert audit_payload["maturity_hint"] == "production"

    first_finding = _run_script(
        "record_finding.py",
        "--severity",
        "P1",
        "--category",
        "authorization",
        "--title",
        "Missing repo boundary check",
        "--impact",
        "A user can operate on another repo.",
        "--recommendation",
        "Enforce repo ownership before dispatch.",
        "--ticket",
        "TICKET-004-auth.md",
        env=env,
    )
    assert first_finding.returncode == 0, first_finding.stderr

    second_finding = _run_script(
        "record_finding.py",
        "--severity",
        "P2",
        "--category",
        "input parsing",
        "--title",
        "Path parser accepts ambiguous input",
        "--impact",
        "Unexpected paths may be normalized inconsistently.",
        "--recommendation",
        "Reject ambiguous separators before normalization.",
        env=env,
    )
    assert second_finding.returncode == 0, second_finding.stderr

    status_result = _run_script("status.py", "--json", env=env)
    assert status_result.returncode == 0, status_result.stderr
    status_payload = json.loads(status_result.stdout)
    assert status_payload["finding_count"] == 2
    assert status_payload["severity_counts"] == {"P0": 0, "P1": 1, "P2": 1, "P3": 0}
    assert status_payload["category_counts"] == {
        "authorization": 1,
        "input parsing": 1,
    }

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        """# Security Audit Report

## Executive Summary

Two focused findings were identified.

## Scope And Maturity

The audit covered the full repo at production maturity.

## Architecture And Trust Boundaries

Primary boundaries are repo ownership and command execution.

## Findings

### [P1] Missing repo boundary check
Severity: P1
Category: authorization
Impact: A user can operate on another repo.
Recommendation: Enforce repo ownership before dispatch.

### [P2] Path parser accepts ambiguous input
Severity: P2
Category: input parsing
Impact: Unexpected paths may be normalized inconsistently.
Recommendation: Reject ambiguous separators before normalization.

## Category Summary

Authorization and input parsing were the main issue categories.

## Scorecard Notes

The scorecard should show one P1 and one P2.
""",
        encoding="utf-8",
    )

    validate_result = _run_script("validate_report.py", env=env)
    assert validate_result.returncode == 0, validate_result.stderr
    report_data = json.loads((artifact_dir / "report-data.json").read_text())
    assert report_data["valid"] is True
    assert "health_score" not in report_data
    assert report_data["severity_counts"] == {"P0": 0, "P1": 1, "P2": 1, "P3": 0}
    assert report_data["category_counts"] == {
        "authorization": 1,
        "input parsing": 1,
    }

    render_result = _run_script("render_scorecard.py", env=env)
    assert render_result.returncode == 0, render_result.stderr

    scorecard_md = (artifact_dir / "scorecard.md").read_text(encoding="utf-8")
    scorecard_png = (artifact_dir / "security-audit-scorecard.png").read_bytes()
    assert "Security Audit Scorecard" in scorecard_md
    assert "Health score" not in scorecard_md
    assert "- P1: 1" in scorecard_md
    assert "- authorization: 1" in scorecard_md
    assert scorecard_png.startswith(b"\x89PNG\r\n\x1a\n")


def test_validate_report_rejects_report_missing_required_shape(tmp_path: Path) -> None:
    env = _app_env(tmp_path)
    artifact_dir = Path(env["CAR_APP_ARTIFACT_DIR"])
    report_path = artifact_dir / "security-audit-report.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        """# Security Audit Report

## Executive Summary

### [P1] Missing fields
Severity: P1
Category: authorization
""",
        encoding="utf-8",
    )

    result = _run_script("validate_report.py", env=env)

    assert result.returncode != 0
    assert "missing required section: ## Findings" in result.stderr
    data = json.loads((artifact_dir / "report-data.json").read_text())
    assert data["valid"] is False
    assert "finding 1 missing impact" in data["errors"]
