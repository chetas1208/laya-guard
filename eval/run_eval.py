"""Evaluate rules / Laya / combined per kind on a split with cluster-bootstrap 95% CIs.

  python eval/run_eval.py --split dev  --out eval/results/dev_metrics.json
  python eval/run_eval.py --split test --out eval/results/test_metrics.json --latency

Thresholds are ALWAYS chosen on the dev split (even when --split test); the test split is only scored.
Scores must already be cached (eval/score_cache.py). --latency loads Laya and times single-window calls.
"""
import argparse
import json
import os
import random
import time

import numpy as np

import common
import eval_lib as E
import questions as Q

ROOT = os.path.dirname(common.HERE)


def ece(p, y, bins=10):
    p = np.asarray(p); y = np.asarray(y, float)
    edges = np.linspace(0, 1, bins + 1)
    tot = 0.0
    for i in range(bins):
        m = (p >= edges[i]) & (p < edges[i + 1] if i < bins - 1 else p <= 1)
        if m.sum():
            tot += m.mean() * abs(p[m].mean() - y[m].mean())
    return float(tot)


def latency(cfg, rows_all):
    os.environ.setdefault("USE_TF", "0")
    import laya
    agent = laya.load("convaiinnovations/laya", device="cpu")
    rng = random.Random(0)
    out = {}
    rules = E.load_rules()
    for kind in E.KINDS:
        rs = [r for r in rows_all if r["kind"] == kind]
        ts = []
        for r in rs[:: max(1, len(rs) // 400)]:
            t = time.perf_counter(); rules.scan(r["text"], kind); ts.append((time.perf_counter() - t) * 1000)
        o = {"rules_ms_p50": round(float(np.percentile(ts, 50)), 3), "rules_ms_p95": round(float(np.percentile(ts, 95)), 3)}
        variants = cfg["kinds"][kind].get("variants", [])
        if variants:
            qs = {v: Q.QUESTIONS[kind][v] for v in variants}
            sample = [r for r in rs if r["split"] == "dev"]
            rng.shuffle(sample)
            lt = []
            agent.predict({Q.STATE_KEY[kind]: "warmup"}, qs)
            for r in sample[:40]:
                w = common.windows(r["text"], cfg.get("window"))[0]
                t = time.perf_counter(); agent.predict({Q.STATE_KEY[kind]: w}, qs); lt.append((time.perf_counter() - t) * 1000)
            o.update(laya_ms_p50=round(float(np.percentile(lt, 50)), 1), laya_ms_p95=round(float(np.percentile(lt, 95)), 1),
                     laya_questions=len(qs), laya_windows_mean=round(float(np.mean([len(common.windows(r["text"], cfg.get("window"))) for r in rs])), 2))
        out[kind] = o
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", default="dev")
    ap.add_argument("--config", default=os.path.join(ROOT, "configs", "eval_config.json"))
    ap.add_argument("--out")
    ap.add_argument("--boots", type=int, default=500)
    ap.add_argument("--latency", action="store_true")
    ap.add_argument("--rules", default=None, help="rules.py path (default: live)")
    ap.add_argument("--examples", action="store_true")
    a = ap.parse_args()
    cfg = json.load(open(a.config))
    rows_all = common.load_rows()
    cal = None
    p = os.path.join(ROOT, "configs", "calibration.json")
    if os.path.exists(p):
        cal = json.load(open(p))
    out = {"split": a.split, "config": cfg, "rules": a.rules or "live src/laya_guard/rules.py", "kinds": {}}
    for kind in E.KINDS:
        kc = cfg["kinds"][kind]
        th = E.choose_thresholds(kind, cfg, rows_all, a.rules) if kc.get("variants") else None
        r = E.evaluate_kind(kind, a.split, cfg, rows_all, thresholds=th, boots_n=a.boots, rules_path=a.rules, with_examples=a.examples or a.split == "test")
        arr = r.pop("_arrays", None)
        if arr is not None and cal and kind in cal["kinds"]:
            c = cal["kinds"][kind]
            x = np.clip(arr["risk"], 1e-4, 1 - 1e-4)
            pc = 1 / (1 + np.exp(-(c["a"] * np.log(x / (1 - x)) + c["b"])))
            r["calibration"] = {"ece_raw": round(ece(arr["risk"], arr["y"]), 4), "ece_platt_dev_fit": round(ece(pc, arr["y"]), 4)}
        r["dev_thresholds"] = th
        out["kinds"][kind] = r
        print(kind, "done", flush=True)
    if a.latency:
        out["latency"] = latency(cfg, rows_all)
    if a.out:
        json.dump(out, open(a.out, "w"), indent=1, default=lambda o: None)
        print("wrote", a.out)


if __name__ == "__main__":
    main()
