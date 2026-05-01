---
agent: codex
done: false
title: Security audit checklist
goal: Audit one focused category, subsystem, or hot spot and record findings.
---

# Security Audit Checklist

Focus: `{{ focus }}`

## Tasks

1. Restate the architecture and maturity assumptions relevant to this focus.
2. Inspect code paths, configs, tests, and dependency surfaces for this category.
3. For every concrete issue, record it in this ticket and append normalized app
   state:
   - `car apps run blessed.security-audit record-finding -- --severity P2 --category "<category>" --title "<title>" --impact "<impact>" --recommendation "<recommendation>" --ticket "<ticket>"`
4. Use severities consistently:
   - `P0`: active or trivially exploitable critical compromise
   - `P1`: high-impact vulnerability or missing boundary
   - `P2`: meaningful risk or hardening gap
   - `P3`: low-risk hygiene, defense-in-depth, or documentation gap
5. If no issue is found, record what was checked and why the area appears
   acceptable for this maturity level.

## Findings

Add findings here as they are discovered.
