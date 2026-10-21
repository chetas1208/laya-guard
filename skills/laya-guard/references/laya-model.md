# The Laya model

## What it is

Laya is an open-weight (Apache-2.0) **typed-decision classifier**, not a text generator.
`convaiinnovations/laya` is a ModernBERT-large encoder with about 421M parameters. You give it a
`state` (the text) and named questions; it returns probabilities. laya-guard asks yes/no questions
such as "Does `document` contain instructions addressed to an AI assistant?" and reads P(yes).

- Model: https://huggingface.co/convaiinnovations/laya
- Code and benchmarks: https://github.com/NandhaKishorM/laya (see `BENCHMARKS.md`)

laya-guard is an independent project that uses Laya; it is not affiliated with its authors.

## How laya-guard uses it

- Advisory only. Laya adds a probability next to the rule hits. It can raise a decision to `review`.
  It cannot lower a rule's decision, and it cannot `block` unless you set a threshold yourself.
- `command` input is never sent to Laya by default (rules only).
- Long inputs are split into overlapping windows; the highest score is kept.
- Laya is optional. Without it, everything still works on rules alone.

## Install

```bash
pip install 'laya-guard[laya]'        # pulls the laya package (>= 0.4.8) and its torch dependency
laya-guard check --kind prompt --text "hello" --json   # first call downloads the weights
```

The first load downloads the checkpoint from Hugging Face and takes seconds. Set
`HF_HOME` to control where. For offline machines, download once and set `laya.checkpoint` to the
local path. If TensorFlow is installed and the import hangs, laya-guard already sets `USE_TF=0`.

## Hardware and latency

| Where | Figure | Source |
|---|---|---|
| CPU | about 0.7 s for a batch of 5 questions | measured by the laya-guard author; hardware dependent, re-measure on yours |
| NVIDIA T4 GPU | about 33-40 ms per call | reported by the Laya authors |

Practical consequence: a CLI hook starts a fresh process per call, so each call would pay about 5 s of
model load. Run `laya-guard serve` once (it keeps the model warm on a user-only unix socket); hooks
and `check` then answer in roughly 0.2-0.3 s. With no daemon running, a hook falls back to rules only
and never loads the model. In Python, `Guard(...)` loads the model once per process.

## Known limits (from the Laya authors' own benchmark)

Source: `BENCHMARKS.md` in https://github.com/NandhaKishorM/laya, held-out data. Check the file for
current numbers; this summary may lag the upstream.

- Jailbreak detection accuracy is roughly **0.71 to 0.76**. Roughly one in four to one in three
  calls is wrong.
- Content moderation performance is **near chance**. Do not use Laya for moderation decisions.
- The released checkpoints are **over-confident**: a probability of 0.95 does not mean 95% of such
  inputs are attacks. That is why thresholds are extreme (review at 0.994 for prompts) and never `block`.
- Laya's own shipped guard questions (no `criteria`) flagged 34% of benign coding prompts in our test; the default here uses a re-phrased criteria-form question. Laya showed no signal on tool output or commands (AUROC about 0.5 for tool output).
- Only English and the question phrasing in `DEFAULT_QUESTIONS` have been considered. laya-guard has
  not validated other languages, long documents, encoded payloads or adaptive attackers.

laya-guard's own measurements, when available, are in `evals.md` and `eval/results/RESULTS.md`.
Do not quote any accuracy figure for Laya inside laya-guard that is not traceable to one of those
sources.

## What to do with a Laya signal

- `review` caused only by Laya (no rule hit): the content is *suspicious*, not *proven bad*.
  Treat it as untrusted data, show the human the content and the score, and let them decide.
- Laya says low risk: say nothing; that is not evidence of safety.
- Never retry or rephrase to get a lower score.

## Alternatives

Any other classifier can be wired in by passing a scorer object with `score(text, kind) ->
{question: probability}` to `Guard(config, scorer=...)`. See `StubScorer` in `laya_backend.py`.
