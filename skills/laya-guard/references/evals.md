# Evaluation

Measured on a held-out test split that was scored once after the configuration was frozen. Full
report, datasets, licences and caveats: `eval/results/RESULTS.md` (raw numbers in
`eval/results/test_metrics.json`, loop history in `eval/results/loop_log.md`).

| Kind | Rules only: recall / false positives | Rules OR Laya | Default |
|---|---|---|---|
| prompt | 20.8% / 0% | 61.7% / 0.5% (0 of 265 benign coding prompts flagged) | Laya on |
| tool_output | 37.8% / 5.2% | no gain (AUROC 0.51) | rules only |
| command | 58% / 0.2% | no gain | rules only |
| output (secrets) | 61.5% | 73.6% / +1.1% | optional |

Findings that change how you use the guard:

- Laya's own shipped guard questions flag about 34% of benign coding prompts; do not use them. The
  default here is a re-phrased question with `criteria` and a review threshold of 0.994.
- Laya's probabilities are over-confident, so thresholds are extreme and were chosen on a dev split.
- Rules-only recall dropped from dev to test (tool_output 76% to 38%, command 87% to 58%): the test
  split holds out payload wordings the rules never saw. Expect real-world recall to be lower than
  these numbers.
- The data is public sets plus synthetic cases written by the rules' author; there was no real
  coding-agent traffic.

## Rules for quoting numbers

- Quote a number only with its dataset, size, date and the laya-guard commit.
- Say "on this data" rather than "the guard detects X%".
- Report false positives next to detections.
- Upstream Laya numbers come from the Laya authors' benchmark and are not ours.
