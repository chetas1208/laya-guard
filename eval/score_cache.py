"""Score all dataset windows with every Laya question variant and cache to disk (CPU).

Usage: python eval/score_cache.py [--kinds prompt,tool_output,command,output] [--variants a,b]
Only (window, question) pairs missing from the cache are computed. Safe to re-run/interrupt.
"""
import argparse
import os
import sys
import time

os.environ.setdefault("USE_TF", "0")
import common  # noqa: E402
from common import ScoreStore, whash, windows  # noqa: E402
import questions as Q  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kinds", default="prompt,tool_output,command,output")
    ap.add_argument("--variants", default="")
    ap.add_argument("--batch", type=int, default=16)
    ap.add_argument("--win-size", type=int, default=common.WIN["size"])
    ap.add_argument("--win-overlap", type=int, default=common.WIN["overlap"])
    ap.add_argument("--max-windows", type=int, default=common.WIN["max_windows"])
    a = ap.parse_args()
    cfg = dict(common.WIN, size=a.win_size, overlap=a.win_overlap, max_windows=a.max_windows)
    rows = common.load_rows()
    store = ScoreStore()
    agent = None
    for kind in a.kinds.split(","):
        wins = {}
        for r in rows:
            if r["kind"] == kind:
                for w in windows(r["text"], cfg):
                    wins[whash(w)] = w
        print(f"[{kind}] unique windows: {len(wins)}", flush=True)
        for name, q in Q.QUESTIONS[kind].items():
            if a.variants and name not in a.variants.split(","):
                continue
            qh = Q.qhash(kind, q)
            have = store.get(qh)
            todo = [(k, w) for k, w in wins.items() if k not in have]
            print(f"  {name} [{qh}] todo {len(todo)}", flush=True)
            if not todo:
                continue
            if agent is None:
                import laya
                agent = laya.load("convaiinnovations/laya", device="cpu")
            todo.sort(key=lambda kw: len(kw[1]))
            t0 = time.time()
            for i in range(0, len(todo), a.batch):
                chunk = todo[i:i + a.batch]
                res = agent.predict_batch([{Q.STATE_KEY[kind]: w} for _, w in chunk], {"q": q}, batch_size=a.batch)
                store.add(qh, [(k, float(r["answers"]["q"]["noul"])) for (k, _), r in zip(chunk, res)])
                if (i // a.batch) % 10 == 0:
                    print(f"    {i + len(chunk)}/{len(todo)} {time.time() - t0:.0f}s", flush=True)
    print("done")


if __name__ == "__main__":
    main()
