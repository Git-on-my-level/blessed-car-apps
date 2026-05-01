---
agent: codex
done: false
title: Security audit bootstrap
goal: Initialize the security audit workflow and queue architecture discovery.
---

# Security Audit Bootstrap

This ticket was created by the `blessed.security-audit` app.

## Tasks

1. Initialize app state:
   - `car apps run blessed.security-audit init-audit -- --scope "<audit_scope>"`
   - Include `--threat-model`, `--maturity-hint`, or `--depth` when known.
2. Confirm the audit scope and any explicit exclusions.
3. Queue the architecture discovery ticket:
   - `car apps apply blessed.security-audit --template architecture --set audit_scope="<audit_scope>"`
4. Keep early work descriptive. Do not start filing findings until architecture,
   maturity, and focus-map context exists.

## App Inputs

- `audit_scope`: `{{ audit_scope }}`
- `threat_model`: `{{ threat_model }}`
- `maturity_hint`: `{{ maturity_hint }}`
- `depth`: `{{ depth }}`
