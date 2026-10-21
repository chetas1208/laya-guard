"""Quick rules-only report; python eval/rules_eval.py [rules.py path]"""
import importlib.util, sys, os, collections
import common
from metrics import prf

def load(path):
    spec = importlib.util.spec_from_file_location("rules_x", path)
    m = importlib.util.module_from_spec(spec); sys.modules["rules_x"] = m; spec.loader.exec_module(m); return m

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(common.HERE), "src/laya_guard/rules.py")
    split = sys.argv[2] if len(sys.argv) > 2 else "dev"
    m = load(path)
    rows = [r for r in common.load_rows() if r["split"] == split]
    for kind in ("prompt", "tool_output", "command", "output"):
        rs = [r for r in rows if r["kind"] == kind]
        hits = [m.scan(r["text"], kind) for r in rs]
        pred = [bool(h) for h in hits]
        y = [r["label"] for r in rs]
        p = prf(pred, y)
        print(kind, {k: round(v, 3) if isinstance(v, float) else v for k, v in p.items()})
        bysrc = collections.defaultdict(lambda: [0, 0, 0, 0])
        for r, h in zip(rs, hits):
            b = bysrc[(r["source"], r["label"])]; b[0] += 1; b[1] += bool(h)
        for k, v in sorted(bysrc.items()):
            print("    ", k, f"flag {v[1]}/{v[0]}")
main()
