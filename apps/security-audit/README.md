# Security Audit

`blessed.security-audit` is a CAR app for structured security reviews.

The workflow intentionally starts with context before findings:

1. Understand architecture, dependencies, trust boundaries, and deployment shape.
2. Assess codebase maturity so recommendations fit the project stage.
3. Identify hot spots and attack-vector classes worth spending audit time on.
4. Work through focused audit tickets, one category or hot spot at a time.
5. Synthesize a final report and generate a PNG scorecard from the report.

The final report is validated before rendering. The validator checks that the
report has the sections and finding shape needed by the PNG scorecard generator.

Typical use:

```bash
car apps install blessed:apps/security-audit --repo /path/to/repo
car apps apply blessed.security-audit --repo /path/to/repo --set audit_scope="Full repo"
```

Useful tools:

```bash
car apps run blessed.security-audit init-audit --repo /path/to/repo -- --scope "Full repo"
car apps run blessed.security-audit record-finding --repo /path/to/repo -- --severity P1 --category auth --title "Missing authorization check" --impact "..." --recommendation "..."
car apps run blessed.security-audit validate-report --repo /path/to/repo
car apps run blessed.security-audit render-scorecard --repo /path/to/repo
```
