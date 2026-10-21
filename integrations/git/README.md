# Git pre-commit hook

Scans the added lines of the staged diff with `laya-guard check --kind output --no-laya`
(secret rules only, milliseconds, no model).

```bash
cp integrations/git/pre-commit .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
# or share it with the team:  git config core.hooksPath integrations/git
```

- Block-level findings (private keys, AWS/GitHub/Slack tokens, `sk-` style keys) refuse the commit.
- Review-level findings (JWTs, `password = ...` assignments) warn; `LAYA_GUARD_STRICT=1` refuses.
- If `laya-guard` is missing or crashes, the commit is refused. Set `LAYA_GUARD_PYTHON=/path/to/python`
  to use `python -m laya_guard.cli` from an environment where the package is installed.
- Format-based rules also match documented test keys (for example `AKIAIOSFODNN7EXAMPLE`). If that is
  a false positive, `git commit --no-verify` is a deliberate human decision.
- Only added lines are scanned, and only the first 200000 characters (configurable by `max_chars`).
  It is a seatbelt, not a secret scanner: use a dedicated tool (gitleaks, trufflehog) in CI as well.
