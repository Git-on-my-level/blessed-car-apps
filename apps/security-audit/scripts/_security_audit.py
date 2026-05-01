from __future__ import annotations

import json
import os
import re
import struct
import tempfile
import zlib
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

SEVERITIES = ("P0", "P1", "P2", "P3")
REQUIRED_REPORT_SECTIONS = (
    "Executive Summary",
    "Scope And Maturity",
    "Architecture And Trust Boundaries",
    "Findings",
)


@dataclass(frozen=True)
class AuditPaths:
    state_dir: Path
    artifact_dir: Path
    audit_path: Path
    findings_path: Path
    report_path: Path
    report_data_path: Path
    scorecard_md_path: Path
    scorecard_png_path: Path


def now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def build_paths() -> AuditPaths:
    state_dir = _require_env_path("CAR_APP_STATE_DIR")
    artifact_dir = _require_env_path("CAR_APP_ARTIFACT_DIR")
    state_dir.mkdir(parents=True, exist_ok=True)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    return AuditPaths(
        state_dir=state_dir,
        artifact_dir=artifact_dir,
        audit_path=state_dir / "audit.json",
        findings_path=state_dir / "findings.jsonl",
        report_path=artifact_dir / "security-audit-report.md",
        report_data_path=artifact_dir / "report-data.json",
        scorecard_md_path=artifact_dir / "scorecard.md",
        scorecard_png_path=artifact_dir / "security-audit-scorecard.png",
    )


def _require_env_path(name: str) -> Path:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return Path(value).expanduser().resolve()


def atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
    ) as handle:
        handle.write(content)
        tmp_path = Path(handle.name)
    tmp_path.replace(path)


def atomic_write_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "wb",
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
    ) as handle:
        handle.write(content)
        tmp_path = Path(handle.name)
    tmp_path.replace(path)


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def load_audit(paths: AuditPaths) -> dict[str, Any]:
    if not paths.audit_path.exists():
        raise RuntimeError(f"Audit state not found: {paths.audit_path}")
    payload = json.loads(paths.audit_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError("audit.json must contain an object")
    return payload


def load_findings(paths: AuditPaths) -> list[dict[str, Any]]:
    if not paths.findings_path.exists():
        return []
    rows = []
    for line_no, raw_line in enumerate(
        paths.findings_path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        text = raw_line.strip()
        if not text:
            continue
        payload = json.loads(text)
        if not isinstance(payload, dict):
            raise RuntimeError(f"findings.jsonl line {line_no} must be an object")
        rows.append(payload)
    return rows


def append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True) + "\n")


def normalize_severity(value: str) -> str:
    normalized = value.strip().upper()
    if normalized not in SEVERITIES:
        raise RuntimeError(f"severity must be one of {', '.join(SEVERITIES)}")
    return normalized


def normalize_text(value: Any, *, label: str, required: bool = True) -> str | None:
    if value is None:
        if required:
            raise RuntimeError(f"{label} is required")
        return None
    text = str(value).strip()
    if required and not text:
        raise RuntimeError(f"{label} is required")
    return text or None


def finding_counts(findings: Iterable[dict[str, Any]]) -> dict[str, Any]:
    severity_counts = Counter({severity: 0 for severity in SEVERITIES})
    category_counts: Counter[str] = Counter()
    for finding in findings:
        try:
            severity = normalize_severity(str(finding.get("severity", "")))
        except RuntimeError:
            severity = "P3"
        category = (
            normalize_text(
                finding.get("category"), label="finding.category", required=False
            )
            or "uncategorized"
        )
        severity_counts[severity] += 1
        category_counts[category] += 1
    return {
        "severity_counts": {
            severity: severity_counts[severity] for severity in SEVERITIES
        },
        "category_counts": dict(sorted(category_counts.items())),
        "finding_count": sum(severity_counts.values()),
    }


def parse_report(markdown: str) -> dict[str, Any]:
    errors: list[str] = []
    headings = _headings(markdown)
    for section in REQUIRED_REPORT_SECTIONS:
        if section not in headings:
            errors.append(f"missing required section: ## {section}")

    findings = _parse_report_findings(markdown)
    for index, finding in enumerate(findings, start=1):
        for field in ("severity", "category", "impact", "recommendation"):
            if not finding.get(field):
                errors.append(f"finding {index} missing {field}")

    return {
        "valid": not errors,
        "errors": errors,
        "required_sections": list(REQUIRED_REPORT_SECTIONS),
        "findings": findings,
        **finding_counts(findings),
    }


def _headings(markdown: str) -> set[str]:
    result = set()
    for line in markdown.splitlines():
        match = re.match(r"^##\s+(.+?)\s*$", line)
        if match:
            result.add(match.group(1).strip())
    return result


def _parse_report_findings(markdown: str) -> list[dict[str, Any]]:
    lines = markdown.splitlines()
    starts: list[tuple[int, str, str]] = []
    for index, line in enumerate(lines):
        match = re.match(r"^###\s+\[(P[0-3])\]\s+(.+?)\s*$", line.strip(), re.I)
        if match:
            starts.append((index, match.group(1).upper(), match.group(2).strip()))

    findings: list[dict[str, Any]] = []
    for offset, (start, severity, title) in enumerate(starts):
        end = starts[offset + 1][0] if offset + 1 < len(starts) else len(lines)
        block = lines[start + 1 : end]
        fields = _parse_fields(block)
        findings.append(
            {
                "severity": fields.get("severity", severity).upper(),
                "title": title,
                "category": fields.get("category"),
                "impact": fields.get("impact"),
                "recommendation": fields.get("recommendation"),
            }
        )
    return findings


def _parse_fields(lines: list[str]) -> dict[str, str]:
    fields: dict[str, str] = {}
    current: str | None = None
    for raw_line in lines:
        line = raw_line.rstrip()
        match = re.match(r"^(Severity|Category|Impact|Recommendation):\s*(.*)$", line)
        if match:
            current = match.group(1).lower()
            fields[current] = match.group(2).strip()
            continue
        if current and line.startswith("  ") and line.strip():
            fields[current] = (fields[current] + " " + line.strip()).strip()
    return fields


def build_scorecard_markdown(data: dict[str, Any]) -> str:
    severity_counts = data["severity_counts"]
    lines = [
        "# Security Audit Scorecard",
        "",
        f"- Findings: {data['finding_count']}",
        "",
        "## Severity Counts",
        "",
    ]
    for severity in SEVERITIES:
        lines.append(f"- {severity}: {severity_counts.get(severity, 0)}")
    lines.extend(["", "## Categories", ""])
    categories = data.get("category_counts") or {}
    if not categories:
        lines.append("- None")
    for category, count in sorted(
        categories.items(), key=lambda item: (-item[1], item[0])
    ):
        lines.append(f"- {category}: {count}")
    lines.append("")
    return "\n".join(lines)


def build_scorecard_png(data: dict[str, Any]) -> bytes:
    width = 1100
    height = 640
    image = _new_image(width, height, (248, 250, 252))
    _fill_rect(image, width, 24, 24, width - 48, height - 48, (255, 255, 255))
    _rect(image, width, 24, 24, width - 48, height - 48, (203, 213, 225))

    title = "SECURITY AUDIT SCORECARD"
    _draw_text(image, width, 50, 54, title, (15, 23, 42), scale=3)
    _draw_text(
        image,
        width,
        50,
        96,
        f"FINDINGS {data['finding_count']}",
        (51, 65, 85),
        scale=2,
    )

    severity_counts = data["severity_counts"]
    colors = {
        "P0": (185, 28, 28),
        "P1": (220, 38, 38),
        "P2": (217, 119, 6),
        "P3": (37, 99, 235),
    }
    max_count = max([1, *[int(severity_counts.get(sev, 0)) for sev in SEVERITIES]])
    left_x = 70
    left_y = 164
    column_width = 420
    chart_height = 330
    bar_width = 58
    gap = 44
    baseline_y = left_y + chart_height
    _draw_text(image, width, left_x, 132, "ISSUES BY SEVERITY", (15, 23, 42), scale=2)
    _fill_rect(
        image,
        width,
        left_x,
        baseline_y,
        column_width,
        2,
        (203, 213, 225),
    )
    for index, severity in enumerate(SEVERITIES):
        count = int(severity_counts.get(severity, 0))
        x = left_x + 28 + index * (bar_width + gap)
        filled_height = int((chart_height - 80) * count / max_count)
        _fill_rect(
            image,
            width,
            x,
            left_y + 34,
            bar_width,
            chart_height - 34,
            (241, 245, 249),
        )
        if filled_height:
            _fill_rect(
                image,
                width,
                x,
                baseline_y - filled_height,
                bar_width,
                filled_height,
                colors[severity],
            )
        _rect(
            image,
            width,
            x,
            left_y + 34,
            bar_width,
            chart_height - 34,
            (226, 232, 240),
        )
        _draw_text(image, width, x + 13, left_y, str(count), (15, 23, 42), scale=3)
        _draw_text(
            image, width, x + 8, baseline_y + 18, severity, (51, 65, 85), scale=2
        )

    divider_x = 545
    _fill_rect(image, width, divider_x, 130, 2, 440, (226, 232, 240))
    right_x = 590
    right_y = 132
    _draw_text(image, width, right_x, right_y, "TOP CATEGORIES", (15, 23, 42), scale=2)
    categories = sorted(
        (data.get("category_counts") or {}).items(),
        key=lambda item: (-item[1], item[0]),
    )[:10]
    if not categories:
        _draw_text(
            image, width, right_x, right_y + 48, "NONE", (100, 116, 139), scale=2
        )
    for index, (category, count) in enumerate(categories):
        y = right_y + 48 + index * 42
        color = (15, 118, 110) if index < 3 else (100, 116, 139)
        _fill_rect(image, width, right_x, y + 2, 18, 18, color)
        _draw_text(
            image,
            width,
            right_x + 34,
            y,
            _truncate(category.upper(), 30),
            (51, 65, 85),
            scale=2,
        )
        _draw_text(image, width, 1010, y, str(count), (15, 23, 42), scale=2)
    return _png_bytes(image, width, height)


def _new_image(width: int, height: int, color: tuple[int, int, int]) -> bytearray:
    return bytearray(color * width * height)


def _fill_rect(
    image: bytearray,
    width: int,
    x: int,
    y: int,
    rect_width: int,
    rect_height: int,
    color: tuple[int, int, int],
) -> None:
    for yy in range(max(0, y), max(0, y) + max(0, rect_height)):
        for xx in range(max(0, x), max(0, x) + max(0, rect_width)):
            if 0 <= xx < width and 0 <= yy < len(image) // (width * 3):
                offset = (yy * width + xx) * 3
                image[offset : offset + 3] = bytes(color)


def _rect(
    image: bytearray,
    width: int,
    x: int,
    y: int,
    rect_width: int,
    rect_height: int,
    color: tuple[int, int, int],
) -> None:
    _fill_rect(image, width, x, y, rect_width, 1, color)
    _fill_rect(image, width, x, y + rect_height - 1, rect_width, 1, color)
    _fill_rect(image, width, x, y, 1, rect_height, color)
    _fill_rect(image, width, x + rect_width - 1, y, 1, rect_height, color)


FONT = {
    " ": ["000", "000", "000", "000", "000", "000", "000"],
    "/": ["001", "001", "010", "010", "100", "100", "000"],
    "-": ["000", "000", "000", "111", "000", "000", "000"],
    ":": ["0", "1", "0", "0", "1", "0", "0"],
    ".": ["0", "0", "0", "0", "0", "1", "0"],
    "0": ["111", "101", "101", "101", "101", "101", "111"],
    "1": ["010", "110", "010", "010", "010", "010", "111"],
    "2": ["111", "001", "001", "111", "100", "100", "111"],
    "3": ["111", "001", "001", "111", "001", "001", "111"],
    "4": ["101", "101", "101", "111", "001", "001", "001"],
    "5": ["111", "100", "100", "111", "001", "001", "111"],
    "6": ["111", "100", "100", "111", "101", "101", "111"],
    "7": ["111", "001", "001", "010", "010", "100", "100"],
    "8": ["111", "101", "101", "111", "101", "101", "111"],
    "9": ["111", "101", "101", "111", "001", "001", "111"],
}
for _char, _rows in {
    "A": ["010", "101", "101", "111", "101", "101", "101"],
    "B": ["110", "101", "101", "110", "101", "101", "110"],
    "C": ["111", "100", "100", "100", "100", "100", "111"],
    "D": ["110", "101", "101", "101", "101", "101", "110"],
    "E": ["111", "100", "100", "110", "100", "100", "111"],
    "F": ["111", "100", "100", "110", "100", "100", "100"],
    "G": ["111", "100", "100", "101", "101", "101", "111"],
    "H": ["101", "101", "101", "111", "101", "101", "101"],
    "I": ["111", "010", "010", "010", "010", "010", "111"],
    "J": ["001", "001", "001", "001", "101", "101", "111"],
    "K": ["101", "101", "110", "100", "110", "101", "101"],
    "L": ["100", "100", "100", "100", "100", "100", "111"],
    "M": ["101", "111", "111", "101", "101", "101", "101"],
    "N": ["101", "111", "111", "111", "111", "111", "101"],
    "O": ["111", "101", "101", "101", "101", "101", "111"],
    "P": ["111", "101", "101", "111", "100", "100", "100"],
    "Q": ["111", "101", "101", "101", "111", "001", "001"],
    "R": ["110", "101", "101", "110", "101", "101", "101"],
    "S": ["111", "100", "100", "111", "001", "001", "111"],
    "T": ["111", "010", "010", "010", "010", "010", "010"],
    "U": ["101", "101", "101", "101", "101", "101", "111"],
    "V": ["101", "101", "101", "101", "101", "101", "010"],
    "W": ["101", "101", "101", "101", "111", "111", "101"],
    "X": ["101", "101", "101", "010", "101", "101", "101"],
    "Y": ["101", "101", "101", "010", "010", "010", "010"],
    "Z": ["111", "001", "001", "010", "100", "100", "111"],
}.items():
    FONT[_char] = _rows


def _draw_text(
    image: bytearray,
    width: int,
    x: int,
    y: int,
    text: str,
    color: tuple[int, int, int],
    *,
    scale: int = 1,
) -> None:
    cursor = x
    for char in text.upper():
        rows = FONT.get(char, FONT[" "])
        for row_index, row in enumerate(rows):
            for col_index, bit in enumerate(row):
                if bit == "1":
                    _fill_rect(
                        image,
                        width,
                        cursor + col_index * scale,
                        y + row_index * scale,
                        scale,
                        scale,
                        color,
                    )
        cursor += (len(rows[0]) + 1) * scale


def _truncate(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[: max(0, limit - 1)] + "."


def _png_bytes(image: bytearray, width: int, height: int) -> bytes:
    raw = bytearray()
    stride = width * 3
    for y in range(height):
        raw.append(0)
        start = y * stride
        raw.extend(image[start : start + stride])
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + _png_chunk(b"IDAT", zlib.compress(bytes(raw), level=9))
        + _png_chunk(b"IEND", b"")
    )


def _png_chunk(kind: bytes, data: bytes) -> bytes:
    return (
        struct.pack(">I", len(data))
        + kind
        + data
        + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    )
