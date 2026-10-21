# Cursor

Cursor project rules live in `.cursor/rules/`.

```bash
mkdir -p .cursor/rules
cp integrations/cursor/laya-guard.mdc .cursor/rules/laya-guard.mdc
```

The rule is `alwaysApply: true`, so it is included in every request. It teaches the model to run
`laya-guard check` and follow the exit code. This is advisory to the model, not enforcement:
Cursor has no hook that this repository has tested, so there is no automatic gate. Pair it with
the git pre-commit hook (`../git/pre-commit`) for a deterministic secret check, and with Cursor's
own command allowlist / approval settings for shell commands. Frontmatter fields (`description`,
`globs`, `alwaysApply`) follow Cursor's `.mdc` rule format; verify against your Cursor version.
