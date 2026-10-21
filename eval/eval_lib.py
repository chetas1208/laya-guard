"""Evaluation core shared by run_eval.py and tune_loop.py.

A *config* (dict, see configs/eval_config.json) says, per kind, which Laya question variants form the
risk score (max over variants and over text windows), the window settings and the thresholds.
Rules come from a rules.py path (default: the live src/laya_guard/rules.py).
"""
import importlib.util
import json
import os
import sys
import time

import numpy as np

import common
import questions as Q
from common import ScoreStore, whash, windows
from metrics import ap, auroc, prf, threshold_at_fpr

KINDS = ("prompt", "tool_output", "command", "output")
LIVE_RULES = os.path.join(os.path.dirname(common.HERE), "src", "laya_guard", "rules.py")
GRID = (0.5, 0.8, 0.9, 0.95, 0.99)
CODING_CATS = ("benign_coding", "benign_coding_hard", "benign_coding_agent")

_store = ScoreStore()
_rules_cache = {}


def load_rules(path=None):
    path = path or LIVE_RULES
    key = (path, os.path.getmtime(path))
    if key not in _rules_cache:
        spec = importlib.util.spec_from_file_location("rules_" + str(abs(hash(key))), path)
        m = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = m
        spec.loader.exec_module(m)
        _rules_cache[key] = m
    return _rules_cache[key]


def rule_flags(rows, kind, rules_path=None):
    m = load_rules(rules_path)
    any_, blk, ids = [], [], []
    for r in rows:
        hits = m.scan(r["text"], kind)
        any_.append(bool(hits))
        blk.append(any(h.severity == "block" for h in hits))
        ids.append(sorted({h.rule_id for h in hits}))
    return np.array(any_), np.array(blk), ids


def variant_scores(rows, kind, variant, wcfg=None, agg="max"):
    """Per-row Laya P(yes) for one question variant (NaN where the cache has no score)."""
    q = Q.QUESTIONS[kind][variant]
    d = _store.get(Q.qhash(kind, q))
    out = np.full(len(rows), np.nan)
    for i, r in enumerate(rows):
        vals = [d.get(whash(w)) for w in windows(r["text"], wcfg)]
        if not vals or any(v is None for v in vals):
            continue
        if agg == "max":
            out[i] = max(vals)
        elif agg == "mean":
            out[i] = float(np.mean(vals))
        elif agg == "top2":
            out[i] = float(np.mean(sorted(vals)[-2:]))
        else:
            raise ValueError(agg)
    return out


def risk_scores(rows, kind, variants, wcfg=None, agg="max"):
    if not variants:
        return np.full(len(rows), np.nan)
    mat = np.vstack([variant_scores(rows, kind, v, wcfg, agg) for v in variants])
    with np.errstate(invalid="ignore"):
        return np.where(np.isnan(mat).any(axis=0), np.nan, mat.max(axis=0))


def boot_indices(groups, n=500, seed=0):
    rng = np.random.default_rng(seed)
    uniq, inv = np.unique(np.asarray(groups), return_inverse=True)
    members = [np.where(inv == g)[0] for g in range(len(uniq))]
    out = []
    for _ in range(n):
        pick = rng.integers(0, len(uniq), len(uniq))
        out.append(np.concatenate([members[p] for p in pick]))
    return out


def ci_of(fn, boots):
    vals = []
    for idx in boots:
        try:
            v = fn(idx)
        except Exception:
            continue
        if v == v:
            vals.append(v)
    if len(vals) < 20:
        return [None, None]
    return [float(np.percentile(vals, 2.5)), float(np.percentile(vals, 97.5))]


def _r(x, k=4):
    return None if x is None or (isinstance(x, float) and x != x) else round(float(x), k)


def sys_metrics(pred, y, boots, neg_subset=None):
    m = prf(pred, y)
    res = {k: _r(m[k]) for k in ("precision", "recall", "f1", "fpr")}
    res.update(tp=m["tp"], fp=m["fp"], fn=m["fn"], tn=m["tn"])
    for k in ("precision", "recall", "f1", "fpr"):
        res[k + "_ci"] = [_r(v) for v in ci_of(lambda idx, k=k: prf(pred[idx], y[idx])[k], boots)]
    if neg_subset is not None and neg_subset.sum() > 0:
        n = int(neg_subset.sum())
        res["fpr_coding"] = _r(float(pred[neg_subset].mean()))
        res["fpr_coding_n"] = n
        res["fpr_coding_ci"] = [_r(v) for v in ci_of(lambda idx: float(pred[idx][neg_subset[idx]].mean()), boots)]
    return res


def dev_thresholds(rows_dev, kind, cfg, y, risk, rule_any):
    """Thresholds chosen on dev only. Returns dict name -> threshold for the Laya risk score."""
    out = {}
    neg_cod = np.array([r["label"] == 0 and r["category"] in CODING_CATS for r in rows_dev])
    for name, fpr in (("fpr1", 0.01), ("fpr5", 0.05)):
        ok = ~np.isnan(risk)
        t_all, _, _ = threshold_at_fpr(risk[ok], y[ok], fpr)
        t = t_all
        if neg_cod.sum() >= 30:
            # coding-only negatives must also respect the budget
            t_c, _, _ = threshold_at_fpr(risk[ok][neg_cod[ok] | (y[ok] == 1)], y[ok][neg_cod[ok] | (y[ok] == 1)], fpr)
            t = max(t_all, t_c)
        out[name] = float(t)
    return out


def evaluate_kind(kind, split, cfg, rows_all=None, thresholds=None, boots_n=500, rules_path=None, with_examples=False):
    """Evaluate one kind on a split. `thresholds` (dict) must come from dev when split == 'test'."""
    rows_all = rows_all or common.load_rows()
    kc = cfg["kinds"][kind]
    wcfg = cfg.get("window") or common.WIN
    agg = cfg.get("agg", "max")
    rows = [r for r in rows_all if r["kind"] == kind and r["split"] == split]
    y = np.array([r["label"] for r in rows]).astype(bool)
    rule_any, rule_blk, rule_ids = rule_flags(rows, kind, rules_path)
    variants = kc.get("variants", [])
    risk = risk_scores(rows, kind, variants, wcfg, agg) if variants else None
    boots = boot_indices([r["group"] for r in rows], boots_n)
    neg_cod = np.array([r["label"] == 0 and r["category"] in CODING_CATS for r in rows])
    res = {"kind": kind, "split": split, "n": len(rows), "n_pos": int(y.sum()), "n_neg": int((~y).sum()),
           "variants": variants, "systems": {}, "per_variant": {}, "rules_path": rules_path or "live"}
    S = res["systems"]
    S["rules_any"] = sys_metrics(rule_any, y, boots, neg_cod if neg_cod.any() else None)
    S["rules_block_only"] = sys_metrics(rule_blk, y, boots, neg_cod if neg_cod.any() else None)

    # per-variant ranking quality (all variants in the pool, not just the configured ones)
    for v in Q.QUESTIONS[kind]:
        s = variant_scores(rows, kind, v, wcfg, agg)
        ok = ~np.isnan(s)
        if ok.sum() < 20:
            continue
        pv = {"n_scored": int(ok.sum()), "auroc": _r(auroc(s[ok], y[ok])), "ap": _r(ap(s[ok], y[ok]))}
        t1, r1, f1_ = threshold_at_fpr(s[ok], y[ok], 0.01)
        pv["recall_at_fpr1_on_this_split"] = _r(r1)
        pv["auroc_ci"] = [_r(x) for x in ci_of(lambda idx: auroc(s[idx][ok[idx]], y[idx][ok[idx]]), boots)]
        res["per_variant"][v] = pv
    if risk is None or np.isnan(risk).all():
        return res
    okm = ~np.isnan(risk)
    res["laya_risk"] = {"auroc": _r(auroc(risk[okm], y[okm])), "ap": _r(ap(risk[okm], y[okm])), "n_scored": int(okm.sum()),
                        "auroc_ci": [_r(x) for x in ci_of(lambda idx: auroc(risk[idx], y[idx]), boots)],
                        "ap_ci": [_r(x) for x in ci_of(lambda idx: ap(risk[idx], y[idx]), boots)]}
    # benign vs positive score summary
    res["laya_risk"]["mean_score_pos"] = _r(float(np.nanmean(risk[y])))
    res["laya_risk"]["mean_score_neg"] = _r(float(np.nanmean(risk[~y])))
    risk0 = np.nan_to_num(risk, nan=0.0)

    th = dict(thresholds or {})
    th.update({f"fixed{t}": t for t in GRID})
    res["thresholds"] = th
    for name, t in th.items():
        if t is None:
            continue
        pred = risk0 >= t
        if not name.startswith("comb_"):
            S[f"laya@{name}"] = dict(sys_metrics(pred, y, boots, neg_cod if neg_cod.any() else None), threshold=_r(t, 5))
        S[f"combined@{name}"] = dict(sys_metrics(pred | rule_any, y, boots, neg_cod if neg_cod.any() else None), threshold=_r(t, 5))

    # per-source / per-category breakdown at the dev-chosen fpr1 threshold if present, else 0.9
    tb = th.get("fpr1", 0.9)
    pred_l = risk0 >= tb
    bd = {}
    for i, r in enumerate(rows):
        key = (r["source"], "pos:" + (r["subtype"] or r["category"]) if r["label"] else "neg:" + r["category"])
        b = bd.setdefault(key, [0, 0, 0, 0])
        b[0] += 1; b[1] += int(rule_any[i]); b[2] += int(pred_l[i]); b[3] += int(pred_l[i] or rule_any[i])
    res["breakdown"] = {f"{s} | {c}": {"n": v[0], "rules_flag": v[1], "laya_flag": v[2], "combined_flag": v[3]} for (s, c), v in sorted(bd.items())}
    res["breakdown_threshold"] = _r(tb, 5)

    if with_examples:
        ex = {"laya_only_catches": [], "laya_added_false_alarms": [], "both_miss": [], "rules_false_alarms": []}
        for i, r in enumerate(rows):
            item = {"id": r["id"], "source": r["source"], "category": r["category"], "subtype": r.get("subtype", ""),
                    "risk": _r(risk0[i]), "text": r["text"][:300].replace("\n", " ")}
            if y[i] and pred_l[i] and not rule_any[i]:
                ex["laya_only_catches"].append(item)
            if (not y[i]) and pred_l[i] and not rule_any[i]:
                ex["laya_added_false_alarms"].append(item)
            if y[i] and not pred_l[i] and not rule_any[i]:
                ex["both_miss"].append(item)
            if (not y[i]) and rule_any[i]:
                item["rules"] = rule_ids[i]
                ex["rules_false_alarms"].append(item)
        res["examples"] = ex
    res["_arrays"] = {"risk": risk0, "y": y, "rule_any": rule_any}
    return res


def choose_thresholds(kind, cfg, rows_all=None, rules_path=None):
    """Dev-only thresholds for the configured risk score."""
    rows_all = rows_all or common.load_rows()
    rows = [r for r in rows_all if r["kind"] == kind and r["split"] == "dev"]
    kc = cfg["kinds"][kind]
    wcfg = cfg.get("window") or common.WIN
    risk = risk_scores(rows, kind, kc.get("variants", []), wcfg, cfg.get("agg", "max"))
    y = np.array([r["label"] for r in rows]).astype(bool)
    ra, _, _ = rule_flags(rows, kind, rules_path)
    comb = np.where(ra, np.inf, np.nan_to_num(risk, nan=0.0))
    # Laya-only thresholds
    th = dev_thresholds(rows, kind, cfg, y, np.nan_to_num(risk, nan=0.0), ra)
    # combined: threshold such that (rules OR laya>=t) has dev FPR <= 1% / 5%, if the rules alone allow it
    out = dict(th)
    for name, fpr in (("comb_fpr1", 0.01), ("comb_fpr5", 0.05)):
        neg = ~y
        rule_fp = int((ra & neg).sum())
        allowed = int(np.floor(fpr * neg.sum() + 1e-9))
        if rule_fp > allowed:
            out[name] = None  # rules alone already exceed the budget; Laya cannot be added within it
            continue
        left = allowed - rule_fp
        rem = np.sort(np.nan_to_num(risk, nan=0.0)[neg & ~ra])[::-1]
        out[name] = float(np.nextafter(rem[left], np.inf)) if left < len(rem) else float("-inf")
    return out


def dev_summary(cfg, rows_all=None, rules_path=None, boots_n=100):
    """Compact dev numbers used by the loop log."""
    rows_all = rows_all or common.load_rows()
    out = {}
    for kind in KINDS:
        th = choose_thresholds(kind, cfg, rows_all, rules_path) if cfg["kinds"][kind].get("variants") else None
        r = evaluate_kind(kind, "dev", cfg, rows_all, thresholds=th, boots_n=boots_n, rules_path=rules_path)
        o = {"rules_recall": r["systems"]["rules_any"]["recall"], "rules_fpr": r["systems"]["rules_any"]["fpr"],
             "rules_f1": r["systems"]["rules_any"]["f1"]}
        if "laya_risk" in r:
            o.update(auroc=r["laya_risk"]["auroc"], ap=r["laya_risk"]["ap"])
            for name in ("fpr1", "comb_fpr1"):
                if th.get(name) is None:
                    continue
                key = ("laya@" if name == "fpr1" else "combined@") + "fpr1"
                if name == "comb_fpr1":
                    # evaluate combined at its own threshold
                    risk = r["_arrays"]["risk"]; y = r["_arrays"]["y"]; ra = r["_arrays"]["rule_any"]
                    m = prf((risk >= th[name]) | ra, y)
                    o["combined_recall_at_fpr1"] = _r(m["recall"]); o["combined_fpr"] = _r(m["fpr"])
                else:
                    o["laya_recall_at_fpr1"] = r["systems"][key]["recall"]; o["laya_fpr"] = r["systems"][key]["fpr"]
            o["threshold_fpr1"] = _r(th["fpr1"], 5)
        out[kind] = o
    return out
