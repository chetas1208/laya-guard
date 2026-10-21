"""Render markdown tables from eval/results/{test,dev}_metrics.json (used to assemble RESULTS.md)."""
import json
import os
import sys

RES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")


def f(x, ci=None, pct=True):
    if x is None:
        return "-"
    s = f"{100 * x:.1f}%" if pct else f"{x:.3f}"
    if ci and ci[0] is not None:
        s += f" [{100 * ci[0]:.1f}, {100 * ci[1]:.1f}]" if pct else f" [{ci[0]:.3f}, {ci[1]:.3f}]"
    return s


def sys_row(name, m):
    return (f"| {name} | {f(m['precision'], m.get('precision_ci'))} | {f(m['recall'], m.get('recall_ci'))} | "
            f"{f(m['f1'], m.get('f1_ci'))} | {f(m['fpr'], m.get('fpr_ci'))} | {m['tp']}/{m['fp']}/{m['fn']}/{m['tn']} |")


def kind_table(k, d, labels):
    S = d["systems"]
    out = [f"| system ({k}, n={d['n']}, {d['n_pos']} pos / {d['n_neg']} neg) | precision | recall | F1 | FPR | TP/FP/FN/TN |", "|---|---|---|---|---|---|"]
    for key, label in labels:
        if key in S:
            t = S[key].get("threshold")
            out.append(sys_row(label + (f" (t={t:.3f})" if t is not None else ""), S[key]))
    return "\n".join(out)


def main(path):
    data = json.load(open(path))
    lines = []
    for k, d in data["kinds"].items():
        lines.append(f"\n#### {k}\n")
        labels = [("rules_any", "rules only (any hit)"), ("rules_block_only", "rules only (block-severity hits)")]
        if "laya_risk" in d:
            labels += [("laya@fixed0.9", "Laya only @ shipped threshold 0.90"), ("laya@fpr1", "Laya only @ dev recall-at-1%-FPR threshold"),
                       ("combined@fixed0.9", "rules OR Laya @ 0.90"), ("combined@fpr1", "rules OR Laya @ dev 1%-FPR threshold"),
                       ("combined@comb_fpr1", "rules OR Laya @ dev combined-1%-FPR threshold")]
        lines.append(kind_table(k, d, labels))
        if "laya_risk" in d:
            r = d["laya_risk"]
            lines.append(f"\nLaya risk score ranking: AUROC {r['auroc']:.3f} {r['auroc_ci']}, AP {r['ap']:.3f} {r['ap_ci']}; mean score positives {r['mean_score_pos']}, negatives {r['mean_score_neg']}.")
        pv = d.get("per_variant", {})
        if pv:
            lines.append("\n| question variant | AUROC | AP | recall@1%FPR (this split) |\n|---|---|---|---|")
            for v, m in pv.items():
                lines.append(f"| {v} | {m['auroc']:.3f} | {m['ap']:.3f} | {m['recall_at_fpr1_on_this_split']:.3f} |")
        if "breakdown" in d:
            lines.append(f"\nPer-source breakdown (Laya threshold {d['breakdown_threshold']}):\n\n| source / class | n | rules flag | Laya flag | combined flag |\n|---|---|---|---|---|")
            for key, v in d["breakdown"].items():
                lines.append(f"| {key} | {v['n']} | {v['rules_flag']} | {v['laya_flag']} | {v['combined_flag']} |")
    return "\n".join(lines)


if __name__ == "__main__":
    print(main(sys.argv[1] if len(sys.argv) > 1 else os.path.join(RES, "test_metrics.json")))
