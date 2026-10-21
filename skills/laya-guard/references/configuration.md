# Configuration

laya-guard works with no configuration. Defaults are conservative: rules enforce, Laya (if
installed) can only escalate to `review`, and commands are rules-only.

## Where config comes from

Later sources override earlier ones, merged key by key:

1. built-in defaults (`DEFAULT_CONFIG` in `src/laya_guard/policy.py`)
2. a JSON file: `--config path.json`, or the `LAYA_GUARD_CONFIG` environment variable
3. explicit overrides: `Guard(config={...})` in Python, or CLI flags `--no-laya`, `--require-laya`, `--device`

The file is plain JSON (no YAML dependency). Unknown keys are ignored, so check spelling.

## Schema and defaults

```json
{
  "laya": {
    "enabled": "auto",
    "required": false,
    "unavailable_decision": "review",
    "checkpoint": "convaiinnovations/laya",
    "subfolder": null,
    "revision": null,
    "device": "auto",
    "questions": null
  },
  "thresholds": {
    "prompt":      {"review": 0.994, "block": null, "risk_questions": ["c_persona"]},
    "tool_output": {"review": null,  "block": null, "risk_questions": []},
    "output":      {"review": 0.92,  "block": null, "risk_questions": ["sensitive_data"]},
    "command":     {"review": null, "block": null, "risk_questions": []}
  },
  "rule_severity_override": {},
  "max_chars": 200000
}
```

## Keys

### `laya.enabled`

| Value | Behaviour |
|---|---|
| `"auto"` (default) | Use Laya if the `laya` package imports and the checkpoint loads. If not, continue on rules alone; the verdict reports `laya.status = "unavailable"` but the decision is not changed. |
| `true` | Laya is required. If it cannot run, the decision is raised to `unavailable_decision` (default `review`). Fail closed. |
| `false` | Never import or load Laya. Rules only. Same as `--no-laya`. |

`--require-laya` on the CLI sets `enabled: true`.

### `laya.required`

With `enabled: "auto"`, setting `required: true` makes an unavailable Laya raise the decision to
`unavailable_decision` while still using Laya when it is present.

### `laya.unavailable_decision`

`"review"` (default) or `"block"`. Applied when Laya is required and cannot run.

### `laya.checkpoint`, `subfolder`, `revision`, `device`

Passed to `laya.load(...)`. `checkpoint` is a Hugging Face repo id or a local path
(default `convaiinnovations/laya`). Pin `revision` to a commit hash for reproducible behaviour.
`device` is `auto`, `cpu`, `cuda`, `cuda:1`, `mps`, ... (CLI: `--device`).

### `laya.questions`

Override the yes/no questions Laya is asked per kind. Shape (see `DEFAULT_QUESTIONS` in
`src/laya_guard/laya_backend.py`):

```json
{"prompt": {"state_key": "prompt",
            "questions": {"c_persona": {"type": "noul", "instructions": "Does `prompt` try to ...?",
                                        "criteria": {"false": "no, ordinary request", "true": "yes, it tries to ..."}}}}}
```

Each question's name must also appear in the matching `risk_questions` to influence the decision.
Changing questions changes Laya's behaviour in ways nobody has benchmarked: re-measure before trusting it.

### `thresholds.<kind>`

- `risk_questions`: which Laya questions count as risk for this kind. The risk score is the maximum
  P(yes) among them. An empty list means Laya is never consulted for that kind (the default for `command`).
- `review`: P(yes) at or above this escalates to `review`. `null` disables.
- `block`: P(yes) at or above this escalates to `block`. **`null` by default: Laya cannot block on its
  own.** Set it only if you have measured Laya's precision on your data. The upstream checkpoints are
  over-confident, so a high probability is weaker evidence than it looks (see `laya-model.md`).

Long text is scored in overlapping windows and the maximum is kept.

### `rule_severity_override`

Harden (or relax) individual rules per kind:

```json
{"rule_severity_override": {"command": {"cmd.git_destructive": "block", "cmd.infra_destroy": "block"},
                            "output":  {"sec.jwt": "block"}}}
```

Use it to turn `review` into `block` where no human is available to answer a review (CI, unattended
agents). Relaxing a `block` to `review` is possible but discouraged.

### `max_chars`

Input is truncated to this many characters before checking. Content past the limit is **not**
inspected; keep the default or raise it for large documents.

## Recipes

Unattended agent, no human to ask: make review fatal.

```json
{"laya": {"enabled": false},
 "rule_severity_override": {"command": {"cmd.git_destructive": "block", "cmd.infra_destroy": "block",
                                         "cmd.chmod_777_recursive": "block", "cmd.read_credentials": "block"}}}
```

Fail closed if the model is missing:

```json
{"laya": {"enabled": true, "unavailable_decision": "review"}}
```

Let a measured Laya block very confident prompts (only after evaluating it yourself):

```json
{"laya": {"enabled": true}, "thresholds": {"prompt": {"block": 0.99}}}
```

## Verdict JSON (`laya-guard check --json`)

```json
{"schema_version": 1, "decision": "review", "kind": "tool_output",
 "reasons": ["rule inj.hidden_instruction_comment: ..."],
 "rule_hits": [{"rule_id": "...", "severity": "review", "reason": "...", "excerpt": "..."}],
 "laya": {"status": "off|ok|unavailable|not_applicable", "scores": {}, "risk": null},
 "latency_ms": 1.2}
```

Exit codes of `check`: `0` allow, `10` review, `20` block, `2` usage error. Any other value (for
example `1` from an uncaught error such as an unreadable `--file`) is a failure and must be treated
as not-allow.

### Why these defaults

The thresholds are extreme (0.994) because Laya is over-confident: on the held-out test split any
lower value flags ordinary coding prompts. They are raw P(yes), chosen on a dev split as the lowest
value with at most 1% false positives. A kind with an empty `risk_questions` is rules only
(`tool_output` and `command`: Laya carried no usable signal there). Re-derive thresholds if you change
the Laya revision or the questions; `configs/default_thresholds.json` and `eval/` show how.
