---
agent: codex
done: false
title: Security audit architecture map
goal: Understand architecture, dependencies, data flow, and trust boundaries.
---

# Security Audit Architecture Map

## Tasks

1. Identify major components, entrypoints, background jobs, storage systems, and
   external integrations.
2. Map authentication, authorization, secrets, data ingress/egress, and trust
   boundaries.
3. Identify dependency classes and supply-chain surfaces:
   - package managers and lockfiles
   - build tooling
   - generated code
   - external services
   - privileged local or cloud resources
4. Record architecture notes directly in this ticket.
5. Queue maturity calibration:
   - `car apps apply blessed.security-audit --template maturity --set audit_scope="<audit_scope>"`

## Output Notes

- Architecture summary:
- Trust boundaries:
- Sensitive assets:
- Dependency surfaces:
- Unknowns to resolve:
