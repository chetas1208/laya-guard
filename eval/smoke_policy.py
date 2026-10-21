"""End-to-end check: the real Guard + configs/default_thresholds.json reproduce the cached eval scores."""
import json, os, sys
import common, questions as Q
from laya_guard import Guard, load_config
cfg = load_config(os.path.join(os.path.dirname(common.HERE), "configs", "default_thresholds.json"))
g = Guard(cfg)
rows = common.load_rows()
import random
random.Random(1).shuffle(rows)
for kind in ("prompt", "output", "tool_output", "command"):
    for r in [x for x in rows if x["kind"] == kind and x["split"] == "dev"][:6]:
        v = g.check(r["text"], kind)
        print(kind, r["label"], v.decision, v.laya_status, v.laya_scores, v.laya_risk, round(v.latency_ms), r["text"][:50].replace("\n", " "))
