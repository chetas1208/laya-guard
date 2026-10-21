# Contributing

Thanks for helping. This project is small and deliberately boring; honesty about limits matters
more than feature count.

## Setup

```bash
git clone https://github.com/chetas1208/laya-guard && cd laya-guard
pip install -e '.[test]'      # add '.[laya]' only if you work on the model backend
python -m pytest -q
```

Everything except the optional Laya backend runs on the standard library; tests use a stub scorer
and never download a model.

## Ground rules

- **Rules block narrowly, flag generously.** A false block on a coding agent costs more trust than a
  flag. A new `block` rule needs a clear unambiguous form; otherwise make it `review`.
- **Every rule change needs a positive and a negative test** in `tests/test_core.py` (what it must catch,
  and ordinary work it must leave alone), then run `python scripts/sync_rules_doc.py` so
  `skills/laya-guard/references/rules.md` matches. `python -m pytest` fails if a rule id is undocumented.
- **Laya stays advisory.** No change may let the model lower a rule's decision, or make `block`
  the default outcome of a model score.
- **No invented numbers.** Quote accuracy or latency only with dataset, size, date and commit, and
  put them in `eval/results/RESULTS.md`. Upstream Laya figures must link to their source.
- **Fail closed.** Docs and code must keep "anything other than exit 0/10/20 is not allowed".
- **Integration claims must be tested or labelled** ("verify against your version"). Hook snippets
  have end-to-end tests in `tests/integrations/`.
- Do not paste real secrets into tests or issues. Use documented example values (for instance
  `AKIAIOSFODNN7EXAMPLE`).

## Pull requests

- Small and focused; describe what the change catches or stops catching, and its false-positive risk.
- Update docs under `skills/laya-guard/references/` when behaviour or config changes.
- Do not add automated-tool attribution lines (co-author trailers or similar credits) to commits,
  files or PR text; the repository has a test that scans for them.
- Commit messages: imperative, one line summary.

## Reporting bypasses

Bypasses of the rules are expected (see the threat model). Send them as test cases in a normal
issue; vulnerabilities in the tooling itself go through [SECURITY.md](SECURITY.md).
