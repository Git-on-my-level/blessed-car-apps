---
agent: codex
done: false
title: Security audit maturity calibration
goal: Calibrate recommendations to the maturity and risk profile of the codebase.
---

# Security Audit Maturity Calibration

## Tasks

1. Determine project maturity: prototype, internal tool, beta, production,
   customer-facing, regulated, or high-value target.
2. Check operational maturity signals:
   - tests and CI
   - typed interfaces or schemas
   - deployment/dependency pinning
   - secrets management
   - observability
   - incident or rollback posture
3. Define recommendation level:
   - minimal viable guardrail
   - production hardening
   - compliance-grade controls
4. Record what would be overkill for this codebase so later findings stay
   scoped and actionable.
5. Queue focus mapping:
   - `car apps apply blessed.security-audit --template focus-map --set audit_scope="<audit_scope>"`

## Output Notes

- Maturity level:
- Risk appetite:
- Recommendation level:
- Controls already present:
- Controls that would be over-scoped:
