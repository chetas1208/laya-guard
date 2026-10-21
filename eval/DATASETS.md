# Evaluation datasets

Everything here is built by `eval/build_datasets.py` into `eval/data/cache/dataset.jsonl` (gitignored: it
contains third-party text) and `eval/data/synthetic.jsonl` + `eval/data/manifest.json` (tracked: only our
own synthetic rows and counts). Row schema: `{id, kind, text, label (1 = should block/flag), source, split, group, category, subtype}`.

## Splits

`split = dev | test` is the parity of `sha1("laya-guard-eval-v1" + kind + ":" + group)`, so it is
deterministic and ~50/50 over groups. A **group** is the unit that must not straddle the split:

* near-duplicate public prompts: first 80 alphanumeric characters of the text
* synthetic tool output: the base document (the benign version and its 3-4 injected versions share a group)
* secret positives: the **token format** (all examples of one provider format are in one split, so a rule written from dev examples is tested on formats it has not seen)
* synthetic injection **payload wordings are partitioned**: dev documents only use even-indexed payloads of each style, test documents only odd-indexed ones (see `eval/synth/tool_outputs.py`). Rules written from dev errors therefore cannot have seen the test wordings.

Tuning (rules, question variants, window/aggregation, thresholds, calibration) used **dev only**. Test was scored once, after freezing.

## Public datasets (all from huggingface.co, downloaded with `huggingface_hub`)

| dataset | revision (commit) | license (per dataset card) | used for | rows used |
|---|---|---|---|---|
| `deepset/prompt-injections` | 4f61ecb038e9c3fb77e21034b22511b523772cdd | apache-2.0 | prompt: injections (label 1) and benign (0); train+test merged, then re-split by hash. Half the rows are German. | 662 |
| `jackhhao/jailbreak-classification` | 2f2ceeb39658696fd3f462403562b6eea5306287 | apache-2.0 | prompt: jailbreak (1) / benign (0), `default/jailbreak_dataset_full.csv`, 250 + 250 random (seed 1). Benign side is OpenOrca/GPTeacher style chat, not coding. | 500 |
| `xTRam1/safe-guard-prompt-injection` | a3a877d608f37b7d20d9945671902df895ecdb46 | **none declared on the card** (GPT-3.5-generated). Used for local evaluation only; not redistributed in this repo. | prompt: injection (1, 300 random) / safe (0, 400 random) from the `test` file | 700 |
| `sahil2801/CodeAlpaca-20k` | 152bb5e9a29651266b018106053980070a0521a1 | cc-by-4.0 | prompt: **benign coding instructions** (0), 450 random (seed 42), `instruction` + optional `input` | 450 |
| `westenfelder/NL2SH-ALFA` | a99cb5784cf5c2a42b1cc26c1903d9c3b35206ba | mit | command: benign shell commands (0), `test.csv` + 250 random `train.csv` rows | 542 |
| `AnishJoshi/nl2bash-custom` | e91ab7e61dea55e229845f92ab37acaa06eb8bf8 | **none declared** (derived from NL2Bash / NLC2CMD). Local evaluation only; not redistributed. | command: benign shell commands (0), 150 random from `data/test.json` | 150 |
| local Python package READMEs | n/a (`*.dist-info/METADATA` of the Laya venv at build time) | various open-source licenses; text is not redistributed | tool_output: **real benign documents** (0), 220 packages, body truncated to 2800 chars | 220 |

License check: the apache-2.0, cc-by-4.0 and mit sets allow evaluation use. For the two sets with no
declared license and the package READMEs we only evaluate locally and publish aggregate numbers and short
excerpts; nothing from them is committed. The NL2Bash-style sets are treated as benign but are not
audited line by line: a few commands in them (for example `find ... -delete` over a directory) are
risky-looking, so a "false positive" on them is a judgement call, not a clean error. Contamination is
unknown: we do not know whether Laya's training data overlapped these public sets (Laya's own
BENCHMARKS list `prompt-injections` as "held out").

## Synthetic data (clearly marked `source = synthetic/...`; written for this evaluation)

| file | what | counts (dev+test) |
|---|---|---|
| `eval/synth/commands.py` | hand-written shell commands: **211 dangerous** (rm/disk/fork-bomb/remote-exec/reverse-shell/exfiltration/persistence/defense-evasion/git/SQL/infra/misc, including obfuscated variants) and **225 benign** dev commands incl. look-alikes (`rm -rf node_modules`, `chmod 755`, `dd ... of=test.img`) | 436 |
| `eval/synth/secret_set.py` | seeded RNG, **fake** credentials in 25 provider formats placed in 12 realistic contexts (`.env`, logs, YAML, chat) vs 168 negatives (git SHAs, UUIDs, sha256/integrity hashes, placeholders, credential vocabulary without a secret) | 336 |
| `eval/synth/tool_outputs.py` | 8 topics x 12 document types (README, web page, JSON API reply, log, email, code file, issue thread, changelog, forum answer, YAML config, API docs, meeting notes) = 96 base documents; each has a benign version and 3 (sometimes 4) injected versions (explicit / paraphrase / multilingual / obfuscated payload; embedded as HTML comment, hidden div, markdown section, JSON field, code comment, email P.S., log line, YAML field, plain paragraph). Plus 16 legitimate-imperative hard negatives (`.gitignore` docs, tutorials, runbooks, UX copy) and 8 security write-ups that quote injection phrases | 428 |
| `eval/synth/prompts.py` | 84 benign coding/agent prompts containing "scary" vocabulary (ignore, system prompt, bypass, jailbreak detection, force push, ...) | 84 |

Limits of the synthetic data, stated plainly:

* The same person wrote the rules and the synthetic attacks. Even with the split-by-wording and split-by-format
  protections, synthetic recall for rules is an optimistic estimate of real-world recall.
* Template documents share boilerplate across topics (the group split only separates whole base documents).
* Injected payloads are generic and defanged (`*.invalid` / `*.example` domains, no working exploit code); real
  attacks are more varied, so absolute recall on real attacks will be lower.
* There is no hand-written attack-prompt set: attack prompts come from the three public datasets only.

## Fake secrets are not committed

The secret-shaped test rows (fake AWS/Stripe/GitHub/Slack/... tokens and PEM blocks, plus every `output`
row) come from a seeded generator and are kept locally in `eval/data/synthetic_secrets.jsonl`, which is
gitignored: they look like real credentials and GitHub push protection (rightly) rejects them. Rebuild them
with `python eval/build_datasets.py`. Token-shaped strings in the committed result dumps are replaced by
`<redacted-token>`, so the example lists there are not exactly what the model saw.
