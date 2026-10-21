import json
import math
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CACHE = os.path.join(HERE, "data", "cache")
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "src"))
sys.path.insert(0, HERE)

WIN = dict(size=1400, overlap=200, max_windows=4)  # eval default; production default max_windows=6


def load_rows(path=None):
    path = path or os.path.join(CACHE, "dataset.jsonl")
    return [json.loads(l) for l in open(path)]


def windows(text, cfg=None):
    from laya_guard.laya_backend import split_windows
    cfg = cfg or WIN
    return split_windows(text, cfg["size"], cfg["overlap"], cfg["max_windows"])


def whash(text):
    import hashlib
    return hashlib.sha1(text.encode()).hexdigest()[:16]


class ScoreStore:
    """Disk cache: scores_<qhash>.jsonl with {k: window-sha, p: P(yes)} lines."""

    def __init__(self):
        self.mem = {}

    def path(self, qh):
        return os.path.join(CACHE, f"scores_{qh}.jsonl")

    def get(self, qh):
        if qh not in self.mem:
            d = {}
            p = self.path(qh)
            if os.path.exists(p):
                for l in open(p):
                    try:
                        j = json.loads(l)
                        d[j["k"]] = j["p"]
                    except Exception:
                        pass
            self.mem[qh] = d
        return self.mem[qh]

    def add(self, qh, items):
        d = self.get(qh)
        with open(self.path(qh), "a") as f:
            for k, p in items:
                d[k] = p
                f.write(json.dumps({"k": k, "p": p}) + "\n")
