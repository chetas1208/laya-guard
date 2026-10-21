"""Dev-only tuning helpers for the improvement loop. NEVER reads test labels or scores.

  python eval/tune_loop.py status                 dev summary of the current config + live rules.py
  python eval/tune_loop.py errors KIND [--n 30]   dev false negatives / false positives (rules AND Laya)
  python eval/tune_loop.py select KIND            rank question variants and greedy subsets on dev
  python eval/tune_loop.py log --round N --change "text" [--config PATH]
                                                  append dev before/after to eval/results/loop_log.md
  python eval/tune_loop.py calibrate              Platt scaling per kind on dev -> configs/calibration.json
"""
import argparse
import itertools
import json
import os
import sys

import numpy as np

import common
import eval_lib as E
from metrics import ap, auroc, prf, threshold_at_fpr

ROOT = os.path.dirname(common.HERE)
CFG_PATH = os.path.join(ROOT, "configs", "eval_config.json")
STATE = os.path.join(common.HERE, "results", "loop_state.json")
LOG = os.path.join(common.HERE, "results", "loop_log.md")
ROWS = None


def rows():
    global ROWS
    if ROWS is None:
        ROWS = common.load_rows()
    return ROWS


def dev_rows(kind):
    return [r for r in rows() if r["kind"] == kind and r["split"] == "dev"]


def load_cfg(path=None):
    return json.load(open(path or CFG_PATH))


def cmd_status(a):
    cfg = load_cfg(a.config)
    s = E.dev_summary(cfg, rows())
    print(json.dumps(s, indent=1))


def cmd_errors(a):
    cfg = load_cfg(a.config)
    kind = a.kind
    rs = dev_rows(kind)
    y = np.array([r["label"] for r in rs]).astype(bool)
    ra, _, ids = E.rule_flags(rs, kind)
    kc = cfg["kinds"][kind]
    risk = E.risk_scores(rs, kind, kc.get("variants", []), cfg.get("window"), cfg.get("agg", "max")) if kc.get("variants") else np.zeros(len(rs))
    risk = np.nan_to_num(risk, nan=0.0)
    th = E.choose_thresholds(kind, cfg, rows())["fpr1"] if kc.get("variants") else 2.0
    print(f"# {kind} dev  laya fpr1 threshold={th:.4f}")

    def show(title, idxs):
        print(f"\n## {title} ({len(idxs)})")
        for i in idxs[: a.n]:
            r = rs[i]
            print(f"- [{r['source']}|{r.get('subtype') or r['category']}] risk={risk[i]:.3f} rules={ids[i]} :: {r['text'][:a.w].replace(chr(10), ' ')}")

    show("RULES false negatives", [i for i in range(len(rs)) if y[i] and not ra[i]])
    show("RULES false positives", [i for i in range(len(rs)) if (not y[i]) and ra[i]])
    show("LAYA false negatives (not caught by rules either)", [i for i in range(len(rs)) if y[i] and risk[i] < th and not ra[i]])
    show("LAYA false positives at fpr1 threshold", [i for i in range(len(rs)) if (not y[i]) and risk[i] >= th])


def cmd_select(a):
    cfg = load_cfg(a.config)
    kind = a.kind
    rs = dev_rows(kind)
    y = np.array([r["label"] for r in rs]).astype(bool)
    wcfg, agg = cfg.get("window"), cfg.get("agg", "max")
    names = list(E.Q.QUESTIONS[kind])
    sc = {n: E.variant_scores(rs, kind, n, wcfg, agg) for n in names}
    names = [n for n in names if not np.isnan(sc[n]).any()]
    print(f"# {kind}: dev variants with complete scores: {names}")
    res = []
    for n in names:
        t, rec, fpr = threshold_at_fpr(sc[n], y, 0.01)
        res.append((n, auroc(sc[n], y), ap(sc[n], y), rec))
    for n, au, apv, rec in sorted(res, key=lambda x: -x[2]):
        print(f"  {n:28s} auroc={au:.3f} ap={apv:.3f} recall@1%FPR={rec:.3f}")
    ra, _, _ = E.rule_flags(rs, kind)
    print("  -- subsets (max over variants), by dev AP:")
    best = []
    for k in (1, 2, 3):
        for sub in itertools.combinations(names, k):
            s = np.max(np.vstack([sc[n] for n in sub]), axis=0)
            comb = np.where(ra, 9.0, s)
            t, rec, _ = threshold_at_fpr(s, y, 0.01)
            tc, recc, fprc = threshold_at_fpr(comb, y, 0.01)
            best.append((sub, auroc(s, y), ap(s, y), rec, recc))
    for sub, au, apv, rec, recc in sorted(best, key=lambda x: -x[2])[: a.top]:
        print(f"  {','.join(sub):70s} auroc={au:.3f} ap={apv:.3f} laya_rec@1%={rec:.3f} combined_rec@1%={recc:.3f}")


def _platt(x, y):
    """Platt scaling: logistic regression of y on logit(clip(x)). Uses sklearn (eval-only dependency)."""
    from sklearn.linear_model import LogisticRegression
    xc = np.clip(x, 1e-4, 1 - 1e-4)
    z = np.log(xc / (1 - xc)).reshape(-1, 1)
    m = LogisticRegression(C=1.0, max_iter=1000).fit(z, y.astype(int))
    return float(m.coef_[0][0]), float(m.intercept_[0])


def cmd_calibrate(a):
    cfg = load_cfg(a.config)
    out = {"schema_version": 1, "method": "platt_on_logit", "fit_split": "dev",
           "note": "p_cal = sigmoid(a*logit(clip(p_raw,1e-4,1-1e-4)) + b), where p_raw = max over the kind's risk variants and windows. "
                   "Fit on dev only; base rate of the dev mixture is NOT the deployment base rate, so treat p_cal as a monotone re-scaling, "
                   "not a literal probability. policy.py does not read this file yet.",
           "kinds": {}}
    for kind in E.KINDS:
        kc = cfg["kinds"][kind]
        if not kc.get("variants"):
            continue
        rs = dev_rows(kind)
        y = np.array([r["label"] for r in rs]).astype(float)
        risk = np.nan_to_num(E.risk_scores(rs, kind, kc["variants"], cfg.get("window"), cfg.get("agg", "max")), nan=0.0)
        a_, b_ = _platt(risk, y)
        out["kinds"][kind] = {"risk_questions": kc["variants"], "a": round(a_, 4), "b": round(b_, 4), "n_dev": len(rs), "dev_pos_rate": round(float(y.mean()), 3)}
    path = os.path.join(ROOT, "configs", "calibration.json")
    json.dump(out, open(path, "w"), indent=1)
    print(json.dumps(out, indent=1))


def cmd_log(a):
    cfg = load_cfg(a.config)
    now = E.dev_summary(cfg, rows(), rules_path=a.rules, boots_n=50)
    prev = json.load(open(STATE)) if os.path.exists(STATE) else None
    lines = [f"\n## Round {a.round}: {a.change}\n"]
    lines.append("| kind | metric | before | after |\n|---|---|---|---|")
    keys = ["rules_recall", "rules_fpr", "auroc", "ap", "laya_recall_at_fpr1", "laya_fpr", "combined_recall_at_fpr1", "combined_fpr", "threshold_fpr1"]
    for kind in E.KINDS:
        for k in keys:
            if k in now[kind]:
                b = prev[kind].get(k) if prev and kind in prev else None
                lines.append(f"| {kind} | {k} | {b if b is not None else '-'} | {now[kind][k]} |")
    if a.note:
        lines.append(f"\n{a.note}\n")
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    with open(LOG, "a") as f:
        f.write("\n".join(lines) + "\n")
    json.dump(now, open(STATE, "w"), indent=1)
    print("\n".join(lines))


def main():
    ap_ = argparse.ArgumentParser()
    sub = ap_.add_subparsers(dest="cmd", required=True)
    for name in ("status", "errors", "select", "log", "calibrate"):
        p = sub.add_parser(name)
        p.add_argument("--config")
        if name in ("errors", "select"):
            p.add_argument("kind")
        if name == "errors":
            p.add_argument("--n", type=int, default=30)
            p.add_argument("--w", type=int, default=160)
        if name == "select":
            p.add_argument("--top", type=int, default=8)
        if name == "log":
            p.add_argument("--round", type=int, required=True)
            p.add_argument("--change", required=True)
            p.add_argument("--note", default="")
            p.add_argument("--rules", default=None)
    a = ap_.parse_args()
    {"status": cmd_status, "errors": cmd_errors, "select": cmd_select, "log": cmd_log, "calibrate": cmd_calibrate}[a.cmd](a)


if __name__ == "__main__":
    main()
