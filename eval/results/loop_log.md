# Improvement loop log (dev split only)

Metrics are on the DEV split. `rules_*` = rules alone (any hit counts as a flag). `laya_*` = Laya risk score
(max over the configured question variants and text windows) at the threshold that gives dev FPR <= 1%
(also <= 1% on benign coding prompts for kind=prompt). `combined_*` = rules OR Laya at the largest threshold
that keeps the combined dev FPR <= 1% (`-` if the rules alone already exceed 1% FPR).
`auroc`/`ap` rank Laya risk scores only. Round 0 is laya-guard exactly as shipped at git HEAD
(HEAD rules.py, shipped criteria-less questions, window 1400/200 chars, max 4 windows in eval).
Rounds 1-3 changed rules.py (one kind of coverage per round); round 4+ changed Laya question phrasing /
windows / calibration. Round 1 also contains the two maintainer-requested rule changes (laya-guard
self-protection false positive; find/ -delete, curl -o && sh, DIR=/ variable) made before dev scores were examined.
Caveat for rounds 1-3: the dev false negatives that drove the rules are partly synthetic data written by the same
author, so dev gains from rule rounds are optimistic; the test split uses unseen payload wordings and unseen secret formats.

## Round 0: baseline: laya-guard as shipped (HEAD rules + shipped Laya questions)

| kind | metric | before | after |
|---|---|---|---|
| prompt | rules_recall | - | 0.1552 |
| prompt | rules_fpr | - | 0.0013 |
| prompt | auroc | - | 0.8791 |
| prompt | ap | - | 0.7785 |
| prompt | laya_recall_at_fpr1 | - | 0.0 |
| prompt | laya_fpr | - | 0.0 |
| prompt | combined_recall_at_fpr1 | - | 0.1552 |
| prompt | combined_fpr | - | 0.0013 |
| prompt | threshold_fpr1 | - | 1.0 |
| tool_output | rules_recall | - | 0.2795 |
| tool_output | rules_fpr | - | 0.0755 |
| tool_output | auroc | - | 0.5206 |
| tool_output | ap | - | 0.6214 |
| tool_output | laya_recall_at_fpr1 | - | 0.0 |
| tool_output | laya_fpr | - | 0.0 |
| tool_output | threshold_fpr1 | - | 1.0 |
| command | rules_recall | - | 0.3689 |
| command | rules_fpr | - | 0.0045 |
| output | rules_recall | - | 0.2727 |
| output | rules_fpr | - | 0.026 |
| output | auroc | - | 0.8829 |
| output | ap | - | 0.8802 |
| output | laya_recall_at_fpr1 | - | 0.2987 |
| output | laya_fpr | - | 0.0 |
| output | threshold_fpr1 | - | 0.9214 |

## Round 1: rules: command coverage (rm of system dirs/quoted $HOME/sh -c wrappers, disk wipe tools, named fork bomb, $(curl)/base64/IEX exec, secrets piped to network, persistence/privesc, security-service stop, git +main/--delete/--mirror, SQL UPDATE w/o WHERE/.drop(), find / -delete, DIR=/ variable, curl -o && sh); FP fixes (cat id_rsa.pub, git branch -d)

| kind | metric | before | after |
|---|---|---|---|
| prompt | rules_recall | 0.1552 | 0.1552 |
| prompt | rules_fpr | 0.0013 | 0.0013 |
| prompt | auroc | 0.8791 | 0.8791 |
| prompt | ap | 0.7785 | 0.7785 |
| prompt | laya_recall_at_fpr1 | 0.0 | 0.0 |
| prompt | laya_fpr | 0.0 | 0.0 |
| prompt | combined_recall_at_fpr1 | 0.1552 | 0.1552 |
| prompt | combined_fpr | 0.0013 | 0.0013 |
| prompt | threshold_fpr1 | 1.0 | 1.0 |
| tool_output | rules_recall | 0.2795 | 0.2795 |
| tool_output | rules_fpr | 0.0755 | 0.0755 |
| tool_output | auroc | 0.5206 | 0.5206 |
| tool_output | ap | 0.6214 | 0.6214 |
| tool_output | laya_recall_at_fpr1 | 0.0 | 0.0 |
| tool_output | laya_fpr | 0.0 | 0.0 |
| tool_output | threshold_fpr1 | 1.0 | 1.0 |
| command | rules_recall | 0.3689 | 0.8738 |
| command | rules_fpr | 0.0045 | 0.0 |
| output | rules_recall | 0.2727 | 0.2727 |
| output | rules_fpr | 0.026 | 0.026 |
| output | auroc | 0.8829 | 0.8829 |
| output | ap | 0.8802 | 0.8802 |
| output | laya_recall_at_fpr1 | 0.2987 | 0.2987 |
| output | laya_fpr | 0.0 | 0.0 |
| output | threshold_fpr1 | 0.9214 | 0.9214 |

Command rules dev recall 0.37 -> 0.87 at 0 FP. Remaining dev misses are exotic (php/perl one-liners, nmap, vault seal, cat /dev/mem).


## Round 2: rules: injection coverage (alt 'ignore earlier instructions' wordings, DE/ES/PT/FR/RU phrases, 'note for the AI' label anywhere, decode-and-follow, hidden-text element, Cyrillic look-alike folding) + FIX exfil-markdown-image false positive on README badges

| kind | metric | before | after |
|---|---|---|---|
| prompt | rules_recall | 0.1552 | 0.229 |
| prompt | rules_fpr | 0.0013 | 0.0013 |
| prompt | auroc | 0.8791 | 0.8791 |
| prompt | ap | 0.7785 | 0.7785 |
| prompt | laya_recall_at_fpr1 | 0.0 | 0.0 |
| prompt | laya_fpr | 0.0 | 0.0 |
| prompt | combined_recall_at_fpr1 | 0.1552 | 0.229 |
| prompt | combined_fpr | 0.0013 | 0.0013 |
| prompt | threshold_fpr1 | 1.0 | 1.0 |
| tool_output | rules_recall | 0.2795 | 0.764 |
| tool_output | rules_fpr | 0.0755 | 0.0 |
| tool_output | auroc | 0.5206 | 0.5206 |
| tool_output | ap | 0.6214 | 0.6214 |
| tool_output | laya_recall_at_fpr1 | 0.0 | 0.0 |
| tool_output | laya_fpr | 0.0 | 0.0 |
| tool_output | combined_recall_at_fpr1 | - | 0.764 |
| tool_output | combined_fpr | - | 0.0 |
| tool_output | threshold_fpr1 | 1.0 | 1.0 |
| command | rules_recall | 0.8738 | 0.8738 |
| command | rules_fpr | 0.0 | 0.0 |
| output | rules_recall | 0.2727 | 0.2727 |
| output | rules_fpr | 0.026 | 0.026 |
| output | auroc | 0.8829 | 0.8829 |
| output | ap | 0.8802 | 0.8802 |
| output | laya_recall_at_fpr1 | 0.2987 | 0.2987 |
| output | laya_fpr | 0.0 | 0.0 |
| output | threshold_fpr1 | 0.9214 | 0.9214 |

## Round 3: rules: secret formats seen in dev (Google, SendGrid, npm, Mailgun, DB URL password, Azure key, *_API_KEY=uuid), broader password= assignment, placeholder exclusions

| kind | metric | before | after |
|---|---|---|---|
| prompt | rules_recall | 0.229 | 0.229 |
| prompt | rules_fpr | 0.0013 | 0.0013 |
| prompt | auroc | 0.8791 | 0.8791 |
| prompt | ap | 0.7785 | 0.7785 |
| prompt | laya_recall_at_fpr1 | 0.0 | 0.0 |
| prompt | laya_fpr | 0.0 | 0.0 |
| prompt | combined_recall_at_fpr1 | 0.229 | 0.229 |
| prompt | combined_fpr | 0.0013 | 0.0013 |
| prompt | threshold_fpr1 | 1.0 | 1.0 |
| tool_output | rules_recall | 0.764 | 0.764 |
| tool_output | rules_fpr | 0.0 | 0.0 |
| tool_output | auroc | 0.5206 | 0.5206 |
| tool_output | ap | 0.6214 | 0.6214 |
| tool_output | laya_recall_at_fpr1 | 0.0 | 0.0 |
| tool_output | laya_fpr | 0.0 | 0.0 |
| tool_output | combined_recall_at_fpr1 | 0.764 | 0.764 |
| tool_output | combined_fpr | 0.0 | 0.0 |
| tool_output | threshold_fpr1 | 1.0 | 1.0 |
| command | rules_recall | 0.8738 | 0.8738 |
| command | rules_fpr | 0.0 | 0.0 |
| output | rules_recall | 0.2727 | 1.0 |
| output | rules_fpr | 0.026 | 0.0 |
| output | auroc | 0.8829 | 0.8829 |
| output | ap | 0.8802 | 0.8802 |
| output | laya_recall_at_fpr1 | 0.2987 | 0.2987 |
| output | laya_fpr | 0.0 | 0.0 |
| output | combined_recall_at_fpr1 | - | 1.0 |
| output | combined_fpr | - | 0.0 |
| output | threshold_fpr1 | 0.9214 | 0.9214 |

## Round 4: Laya question phrasing: pick best of the 6-variant pool per kind by dev AP / recall@1%FPR (prompt: criteria-form 'c_persona'; tool_output: 'c_override'; output keeps the shipped question; command: Laya off)

| kind | metric | before | after |
|---|---|---|---|
| prompt | rules_recall | 0.229 | 0.229 |
| prompt | rules_fpr | 0.0013 | 0.0013 |
| prompt | auroc | 0.8791 | 0.9227 |
| prompt | ap | 0.7785 | 0.898 |
| prompt | laya_recall_at_fpr1 | 0.0 | 0.5929 |
| prompt | laya_fpr | 0.0 | 0.0092 |
| prompt | combined_recall_at_fpr1 | 0.229 | 0.6285 |
| prompt | combined_fpr | 0.0013 | 0.0092 |
| prompt | threshold_fpr1 | 1.0 | 0.9943 |
| tool_output | rules_recall | 0.764 | 0.764 |
| tool_output | rules_fpr | 0.0 | 0.0 |
| tool_output | auroc | 0.5206 | 0.525 |
| tool_output | ap | 0.6214 | 0.6366 |
| tool_output | laya_recall_at_fpr1 | 0.0 | 0.0 |
| tool_output | laya_fpr | 0.0 | 0.0 |
| tool_output | combined_recall_at_fpr1 | 0.764 | 0.764 |
| tool_output | combined_fpr | 0.0 | 0.0 |
| tool_output | threshold_fpr1 | 1.0 | 1.0 |
| command | rules_recall | 0.8738 | 0.8738 |
| command | rules_fpr | 0.0 | 0.0 |
| output | rules_recall | 1.0 | 1.0 |
| output | rules_fpr | 0.0 | 0.0 |
| output | auroc | 0.8829 | 0.8829 |
| output | ap | 0.8802 | 0.8802 |
| output | laya_recall_at_fpr1 | 0.2987 | 0.2987 |
| output | laya_fpr | 0.0 | 0.0 |
| output | combined_recall_at_fpr1 | 1.0 | 1.0 |
| output | combined_fpr | 0.0 | 0.0 |
| output | threshold_fpr1 | 0.9214 | 0.9214 |

Shipped criteria-less prompt questions have AUROC ~0.88 but saturate at 1.0 on benign prompts, so no threshold gives 1% FPR (recall 0). The criteria-form c_persona question gives recall@1%FPR 0.59 on dev. All tool_output variants are at chance (AUROC ~0.5) with 1400-char windows.


## Round 5: threshold calibration: Platt scaling per kind on dev scores -> configs/calibration.json (monotone, so ranking metrics cannot change)

| kind | metric | before | after |
|---|---|---|---|
| prompt | rules_recall | 0.229 | 0.229 |
| prompt | rules_fpr | 0.0013 | 0.0013 |
| prompt | auroc | 0.9227 | 0.9227 |
| prompt | ap | 0.898 | 0.898 |
| prompt | laya_recall_at_fpr1 | 0.5929 | 0.5929 |
| prompt | laya_fpr | 0.0092 | 0.0092 |
| prompt | combined_recall_at_fpr1 | 0.6285 | 0.6285 |
| prompt | combined_fpr | 0.0092 | 0.0092 |
| prompt | threshold_fpr1 | 0.9943 | 0.9943 |
| tool_output | rules_recall | 0.764 | 0.764 |
| tool_output | rules_fpr | 0.0 | 0.0 |
| tool_output | auroc | 0.525 | 0.525 |
| tool_output | ap | 0.6366 | 0.6366 |
| tool_output | laya_recall_at_fpr1 | 0.0 | 0.0 |
| tool_output | laya_fpr | 0.0 | 0.0 |
| tool_output | combined_recall_at_fpr1 | 0.764 | 0.764 |
| tool_output | combined_fpr | 0.0 | 0.0 |
| tool_output | threshold_fpr1 | 1.0 | 1.0 |
| command | rules_recall | 0.8738 | 0.8738 |
| command | rules_fpr | 0.0 | 0.0 |
| output | rules_recall | 1.0 | 1.0 |
| output | rules_fpr | 0.0 | 0.0 |
| output | auroc | 0.8829 | 0.8829 |
| output | ap | 0.8802 | 0.8802 |
| output | laya_recall_at_fpr1 | 0.2987 | 0.2987 |
| output | laya_fpr | 0.0 | 0.0 |
| output | combined_recall_at_fpr1 | 1.0 | 1.0 |
| output | combined_fpr | 0.0 | 0.0 |
| output | threshold_fpr1 | 0.9214 | 0.9214 |

Dev ECE of the max-over-variants risk score: prompt 0.193 -> 0.034, tool_output 0.324 -> 0.012 (by shrinking the score to ~constant: slope a=0.03, i.e. no signal), output 0.113 -> 0.088. Recall at 1% FPR unchanged by construction (a monotone map does not reorder scores). The operating thresholds stay raw P(yes) values chosen on dev: they are extreme (prompt 0.994) because the model is over-confident.


## Round 6: not run; loop stopped

Dev recall at 1% FPR gained 0 points in round 5 (calibration is a monotone map) and the remaining planned experiments could
not be run: (a) 400-character windows for tool_output (dev AUROC of every 1400-character variant is ~0.5, so this was the
one idea with a chance of rescuing Laya on tool output), (b) three more prompt phrasing variants (`c_persona_ab`,
`c_roleplay`, `c_orders` are defined in eval/questions.py but never scored). The shared-server guardrails watcher held every
CPU job in a RED freeze for >1 hour, and the lead asked for completion over extra rounds. Config frozen at
`configs/eval_config.json` (copy in `eval/frozen/`), rules frozen at `eval/frozen/rules_frozen.py`, test split scored once
(`results/test_metrics.json`). An extra test-split scoring of the round-0 "as shipped" configuration
(`results/test_metrics_as_shipped.json`) was run for comparison only; nothing was tuned from it.

## Post-freeze edits (derived from TEST failures, so NOT validated by the held-out numbers)

After the single test run, `src/laya_guard/rules.py` was extended with: Stripe (`sk_live_`/`rk_live_`), Twilio (`SK<32 hex>`),
Hugging Face (`hf_`) and `Bearer <token with a digit>` formats in `sec.provider_tokens`, and a digit requirement in
`inj.exfil_markdown_image` (a LinkedIn-style badge `?project=narwhals-dev-narwhals` was a false positive on a real README).
Regression tests were added. The test numbers in RESULTS.md are for the frozen rules snapshot and do not include these edits;
a fresh held-out set is needed to measure them.
