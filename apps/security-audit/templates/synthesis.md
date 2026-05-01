---
agent: codex
done: false
title: Security audit synthesis and report
goal: Write the final audit report, validate it, and render the scorecard PNG.
---

# Security Audit Synthesis And Report

## Tasks

1. Review all audit tickets and app finding state:
   - `car apps run blessed.security-audit status -- --json`
2. Write the final report to:
   - `.codex-autorunner/apps/blessed.security-audit/artifacts/security-audit-report.md`
3. Use this report structure:

```markdown
# Security Audit Report

## Executive Summary

## Scope And Maturity

## Architecture And Trust Boundaries

## Findings

### [P1] Example finding title
Severity: P1
Category: authorization
Impact: What can go wrong.
Recommendation: What should change.

## Category Summary

## Scorecard Notes
```

4. Validate that the report can be parsed by the scorecard generator:
   - `car apps run blessed.security-audit validate-report`
5. Render the report scorecard:
   - `car apps run blessed.security-audit render-scorecard`
6. Ensure the final answer references:
   - `artifacts/security-audit-report.md`
   - `artifacts/scorecard.md`
   - `artifacts/security-audit-scorecard.png`

## Report Quality Bar

- The executive summary should be understandable without reading every ticket.
- Each finding should have severity, category, impact, and recommendation.
- The scorecard should reflect P0/P1/P2/P3 counts and major issue categories.
