# Blessed CAR Apps

This repository is the default blessed app catalog for Codex Autorunner.

CAR apps are executable bundles discovered by `car apps list` and installed by
reference, for example:

```bash
car apps list
car apps show blessed:apps/autooptimize
car apps install blessed:apps/autooptimize --repo /path/to/repo
car apps apply blessed.autooptimize --repo /path/to/repo --input goal="Reduce p95 latency"
```

The default CAR hub config points the `blessed` app repo id at this repository.
Template repositories remain separate because CAR apps can declare executable
tools and hooks.

## Apps

| App | Path | Purpose |
| --- | --- | --- |
| `blessed.autooptimize` | `apps/autooptimize` | Metric-driven iterative optimization workflow with app-owned state, ticket templates, tools, hooks, and summary artifacts. |
| `blessed.security-audit` | `apps/security-audit` | Structured security audit workflow with architecture discovery, maturity calibration, focused checklist tickets, finding capture, final report validation, and PNG scorecard generation. |

## Trust

This catalog is intended for apps maintained with the CAR project. Third-party
or organization-specific apps should live in separate repositories configured
under `apps.repos`.

CAR records app provenance in each installed app lockfile. Tool and hook
execution requires a trusted installed app bundle.
