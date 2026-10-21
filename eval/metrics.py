import numpy as np


def prf(pred, y):
    pred = np.asarray(pred, bool); y = np.asarray(y, bool)
    tp = int((pred & y).sum()); fp = int((pred & ~y).sum()); fn = int((~pred & y).sum()); tn = int((~pred & ~y).sum())
    p = tp / (tp + fp) if tp + fp else float("nan")
    r = tp / (tp + fn) if tp + fn else float("nan")
    f1 = 2 * p * r / (p + r) if tp and p == p and r == r and (p + r) else (0.0 if tp + fp + fn else float("nan"))
    fpr = fp / (fp + tn) if fp + tn else float("nan")
    return dict(precision=p, recall=r, f1=f1, fpr=fpr, tp=tp, fp=fp, fn=fn, tn=tn)


def auroc(s, y):
    s = np.asarray(s, float); y = np.asarray(y, bool)
    n1, n0 = y.sum(), (~y).sum()
    if n1 == 0 or n0 == 0:
        return float("nan")
    order = np.argsort(s, kind="mergesort")
    ranks = np.empty(len(s)); ss = s[order]
    i = 0
    while i < len(s):
        j = i
        while j + 1 < len(s) and ss[j + 1] == ss[i]:
            j += 1
        ranks[order[i:j + 1]] = (i + j) / 2 + 1
        i = j + 1
    return float((ranks[y].sum() - n1 * (n1 + 1) / 2) / (n1 * n0))


def ap(s, y):
    s = np.asarray(s, float); y = np.asarray(y, bool)
    if y.sum() == 0:
        return float("nan")
    order = np.argsort(-s, kind="mergesort")
    yy = y[order]; ss = s[order]
    tp = np.cumsum(yy); k = np.arange(1, len(yy) + 1)
    # only evaluate at distinct score boundaries
    last = np.r_[ss[1:] != ss[:-1], True]
    prec = tp / k; rec = tp / y.sum()
    rec_l, prec_l = rec[last], prec[last]
    prev = np.r_[0.0, rec_l[:-1]]
    return float(((rec_l - prev) * prec_l).sum())


def threshold_at_fpr(s, y, max_fpr):
    """Smallest threshold t such that FPR(s>=t) <= max_fpr (flag if s >= t). Returns (t, recall, fpr)."""
    s = np.asarray(s, float); y = np.asarray(y, bool)
    neg = np.sort(s[~y])[::-1]
    n0 = len(neg)
    allowed = int(np.floor(max_fpr * n0 + 1e-9))
    if allowed >= n0:
        t = -np.inf
    else:
        # need at most `allowed` negatives >= t -> t just above the (allowed+1)th largest negative
        t = np.nextafter(neg[allowed], np.inf)
    pred = s >= t
    m = prf(pred, y)
    return float(t), m["recall"], m["fpr"]


def cluster_bootstrap(fn, groups, n=1000, seed=0, **arrays):
    """fn(**{name: array[idx]}) -> float. Resamples groups with replacement. Returns (lo, hi)."""
    rng = np.random.default_rng(seed)
    groups = np.asarray(groups)
    uniq, inv = np.unique(groups, return_inverse=True)
    members = [np.where(inv == g)[0] for g in range(len(uniq))]
    vals = []
    for _ in range(n):
        pick = rng.integers(0, len(uniq), len(uniq))
        idx = np.concatenate([members[p] for p in pick])
        try:
            v = fn(**{k: np.asarray(a)[idx] for k, a in arrays.items()})
        except Exception:
            continue
        if v == v:
            vals.append(v)
    if not vals:
        return (float("nan"), float("nan"))
    return float(np.percentile(vals, 2.5)), float(np.percentile(vals, 97.5))
