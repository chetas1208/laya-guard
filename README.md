# laya-guard

A model-agnostic guardrail skill for LLMs, coding agents and AI apps. Deterministic rules enforce
`allow / review / block` on prompts, untrusted tool output, shell commands and outgoing text; the
open-weight [Laya](https://huggingface.co/convaiinnovations/laya) classifier adds an optional,
abstaining advisory signal that can only escalate to `review` by default.

> Honest summary: rules are regexes and catch known shapes. Laya is a small classifier whose authors
> report roughly 0.71-0.76 jailbreak accuracy, near-chance moderation and over-confident scores.
> laya-guard is a speed bump with a paper trail, not a security boundary. See
> [What Laya does and does not do](#what-laya-does-and-does-not-do) and the
> [threat model](skills/laya-guard/references/threat-model.md).

## 60-second quickstart

```bash
git clone https://github.com/chetas1208/laya-guard && cd laya-guard
scripts/install.sh                      # pip install -e . and copy the skill into ~/.claude/skills, ~/.gemini/skills if present

laya-guard check --kind command --json --text 'git push --force origin main'
# {"decision": "block", "rule_hits": [{"rule_id": "cmd.git_force_protected", ...}], ...}   exit code 20

printf '%s' "$WEB_PAGE" | laya-guard check --kind tool_output     # exit 0 allow, 10 review, 20 block
```

From Python:

```python
from laya_guard import Guard

guard = Guard()                                   # rules always on; Laya used only if installed
verdict = guard.check(page_text, "tool_output")   # kinds: prompt, tool_output, command, output
if verdict.decision != "allow":                   # review -> ask a human; block -> refuse
    raise RuntimeError(verdict.reasons)
```

Rules only, no model download: `Guard({"laya": {"enabled": False}})` or `--no-laya`.

## Decision flow

```
   text to check + kind  (prompt | tool_output | command | output)
                    |
                    v
        +-----------------------+
        |  RULES (regex, <1 ms) |  deterministic, explainable, cannot be talked out of it
        +-----------+-----------+
                    |
        +-----------v-----------+      optional, advisory
        |  LAYA (if installed)  |----> can only RAISE the decision (allow -> review)
        +-----------+-----------+      cannot block unless you set a threshold yourself
                    |
        +-----------v-----------+
        |   most severe wins    |
        +---+--------+--------+-+
            |        |        |
         allow     review    block        exit codes 0 / 10 / 20
            |        |        |
         proceed   stop and  refuse, report rule ids,
         (data is  ask a     never retry with a rephrasing
         still     human     (only a human can override)
         data)
                    
   Anything else (crash, missing binary, truncated input) = not allowed (fail closed).
```

## Layered design

| Layer | Role | Properties |
|---|---|---|
| Rules enforce | regexes over normalized text (NFKC, zero-width and tag characters stripped) | fast, deterministic, narrow on blocks, generous on flags |
| Laya advises | calibrated-ish probability from a 421M-parameter classifier | optional, can escalate to `review`, never downgrades a rule, no `block` by default |
| Humans decide | `review` goes to a person or stronger check; only a person overrides a `block` | the guard reports, it does not self-approve |

## Integrations

| Target | Mechanism | Enforced by | Path |
|---|---|---|---|
| Claude Code | skill + `settings.json` hooks (`UserPromptSubmit`, `PreToolUse(Bash)`, `PostToolUse`) | harness (hooks) and model (skill) | [integrations/claude-code](integrations/claude-code/README.md) |
| Gemini CLI / Google Antigravity | `GEMINI.md` rules, skill, `BeforeTool` hook (verify against your version) | model; hook on shell tool | [integrations/gemini](integrations/gemini/README.md) |
| Cursor | `.cursor/rules/laya-guard.mdc` | model only | [integrations/cursor](integrations/cursor/README.md) |
| Codex, Aider, any agent reading `AGENTS.md` | drop-in `AGENTS.md` section | model only | [integrations/generic/AGENTS.md](integrations/generic/AGENTS.md) |
| Any Python app | stdlib-only snippet (shells out to the CLI, fails closed) | your code | [integrations/python/stdlib_snippet.py](integrations/python/stdlib_snippet.py) |
| Any LLM call | `guarded_call(llm, prompt)` guards prompt and reply, no network in the example | your code | [examples/guarded_llm_call.py](examples/guarded_llm_call.py) |
| Git | pre-commit hook scanning staged diffs for secrets (rules only) | git | [integrations/git](integrations/git/README.md) |
| Any agent that follows Agent Skills | [skills/laya-guard/SKILL.md](skills/laya-guard/SKILL.md) | model | `scripts/install.sh` |

"Model only" means the agent is told to run the check; nothing stops it from skipping it. Prefer
hooks where the agent supports them. Details and fail-open/fail-closed notes are in each README.

## What Laya does and does not do

Laya (`convaiinnovations/laya`, Apache-2.0, code at https://github.com/NandhaKishorM/laya) is a
ModernBERT-large **classifier** with about 421M parameters: you give it text and yes/no questions, it
returns probabilities. It does not generate text. We measured it instead of assuming it helps
([full report](eval/results/RESULTS.md)). Short version:

| Input kind | Laya in laya-guard | Why (held-out test split) |
|---|---|---|
| **prompt** | **on**, re-phrased question, review at P >= 0.994 | catches 61.7% of jailbreak/injection prompts vs 20.8% for rules alone, at 0.5% false positives and 0 of 265 false alarms on benign coding prompts |
| **tool_output** | **off** (rules only) | no signal: AUROC 0.51 for all six phrasings tried |
| **command** | **off** (rules only) | no value over rules (best phrasing: 5.6% recall at 1% false positives) |
| **output** (secrets) | optional second opinion | rules 61.5% to 73.6% recall, but every extra catch was a token format the rules lacked and have since been added |

Two things worth knowing before you trust any "guardrail model":
- Laya's own shipped guard questions are **harmful for coding-agent traffic**: they flagged 34% of
  benign coding prompts at a sensible threshold because the probabilities saturate near 1.0. laya-guard
  ships a re-phrased, criteria-form question and an extreme threshold instead. Re-derive both if you
  change the Laya revision or the question.
- Laya can only escalate to `review`. It never blocks on its own and never lowers a rule's decision.

Runs on CPU (about 0.2 s per prompt check once loaded; about 5 s to load) or GPU (about 33-40 ms on a
T4, per its authors). `laya-guard serve` keeps the model warm so hooks do not pay the load cost; a
hook with no daemon running falls back to rules only rather than loading the model.

Details and sources: [laya-model.md](skills/laya-guard/references/laya-model.md).

## Known limits

Regex rules and a ~0.7-accuracy classifier miss: multi-turn attacks, non-English text, base64 and
other encodings, semantic paraphrase, commands assembled from variables or scripts, instructions in
images or PDFs, unknown secret formats, and input past `max_chars`. Full list:
[threat-model.md](skills/laya-guard/references/threat-model.md).

## Results

<!-- RESULTS:START -->
Held-out test split, scored once after the configuration was frozen; 95% intervals; CPU only. Full
tables, datasets and caveats: [eval/results/RESULTS.md](eval/results/RESULTS.md).

| Kind | Rules only (recall / false positives) | Rules + Laya | Verdict |
|---|---|---|---|
| prompt (jailbreak / injection) | 20.8% [17, 25] / 0% | **61.7% [56, 67] / 0.5%** | Laya worth enabling |
| tool_output (indirect injection) | 37.8% / 5.2% | no gain | rules only |
| command (dangerous shell) | 58% [48, 68] / 0.2% | no gain | rules only |
| output (secrets) | 61.5% | 73.6% / +1.1% | marginal |

Read these as upper bounds, not guarantees: the synthetic data was written by the same author as the
rules (rules-only recall fell from dev to test: tool_output 76% to 38%, command 87% to 58%), real
attackers adapt, and no real coding-agent traffic was available. Rules still miss multi-turn,
non-English, encoded and paraphrased attacks.
<!-- RESULTS:END -->

## Install

```bash
pip install -e .                  # rules only, standard library, Python >= 3.9
pip install -e '.[laya]'          # adds the optional Laya model (pulls torch; first call downloads weights)
pip install -e '.[test]'          # pytest
scripts/install.sh --with-laya    # package + laya extra + skill copies
```

`scripts/install.sh` is idempotent, needs no sudo, copies the skill into `~/.claude/skills` and
`~/.gemini/skills` only if `~/.claude` / `~/.gemini` already exist, and prints what it did. Options:
`--no-skill`, `--skip-pip`, `--dry-run`.

## Configuration

Works with no config. JSON file via `--config` or `$LAYA_GUARD_CONFIG`; keys for `laya.enabled`
(`auto` / `true` / `false`), `thresholds`, `rule_severity_override`, `max_chars`. See
[configuration.md](skills/laya-guard/references/configuration.md). Rule list:
[rules.md](skills/laya-guard/references/rules.md).

## Testing

```bash
python -m pytest -q
python scripts/sync_rules_doc.py --check    # rule docs vs src/laya_guard/rules.py
```

`tests/test_core.py` covers rules, policy and the CLI; `tests/integrations/` runs the hook
snippets, installers, pre-commit hook and examples end to end with a stubbed Laya (no model needed).

## Security

Report vulnerabilities and bypasses privately: see [SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). New rules need a positive and a negative test.

## License

MIT, see [LICENSE](LICENSE). The Laya model and code are by their authors under Apache-2.0
(https://github.com/NandhaKishorM/laya); laya-guard is independent and unaffiliated.

Author: Chetas Parekh ([@chetas1208](https://github.com/chetas1208)).
