---
agent: codex
done: false
title: Security audit focus map
goal: Identify hot spots and attack-vector classes for focused audit tickets.
---

# Security Audit Focus Map

## Tasks

1. Use the architecture and maturity tickets to identify likely hot spots.
2. Choose focused audit categories. Prefer one ticket per category or subsystem.
3. Consider these attack-vector classes when relevant:
   - authentication and session handling
   - authorization and tenant boundaries
   - input parsing and injection
   - file, path, archive, and upload handling
   - command execution and sandbox boundaries
   - secrets and credential exposure
   - dependency and build-chain risks
   - data retention, logging, and privacy
   - webhooks, callbacks, and external integrations
   - concurrency, state races, and durable write integrity
4. Queue checklist tickets with explicit focus:
   - `car apps apply blessed.security-audit --template checklist --suffix -auth --set audit_scope="<audit_scope>" --set focus="authentication"`
5. Leave the synthesis ticket for the end:
   - `car apps apply blessed.security-audit --template synthesis --set audit_scope="<audit_scope>"`

## Output Notes

- Priority hot spots:
- Planned checklist tickets:
- Deferred or intentionally skipped areas:
