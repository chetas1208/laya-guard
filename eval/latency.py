"""Latency of rules and Laya (CPU, 3 threads under the guardrails launcher). Writes eval/results/latency.json."""
import json, os
import common
import run_eval

cfg = json.load(open(os.path.join(os.path.dirname(common.HERE), "configs", "eval_config.json")))
out = run_eval.latency(cfg, common.load_rows())
json.dump(out, open(os.path.join(common.HERE, "results", "latency.json"), "w"), indent=1)
print(json.dumps(out, indent=1))
