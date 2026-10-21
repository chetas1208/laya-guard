"""Build the evaluation dataset: eval/data/cache/dataset.jsonl (all rows, gitignored because it
contains third-party text) and eval/data/synthetic.jsonl (our hand-written/generated rows only).

Row schema: {id, kind, text, label (1 = should block/flag), source, split (dev|test), group,
             category, subtype}. split = sha1(salt + group) parity, so a group (paired benign/injected
versions of one document, near-duplicate prompts) never straddles dev and test.

Run: python eval/build_datasets.py [--site-packages DIR]
Requires pandas + pyarrow for the parquet files (present in the Laya venv).
"""
import argparse
import glob
import hashlib
import json
import os
import random
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "synth"))
import commands as cmdset  # noqa: E402
import prompts as promptset  # noqa: E402
import secret_set  # noqa: E402
import tool_outputs  # noqa: E402

CACHE = os.path.join(HERE, "data", "cache", "hf")
SALT = "laya-guard-eval-v1"
DEFAULT_SITE = "/home/923873155/Tabular_Foundation_Model/.venv/lib/python3.11/site-packages"


def norm_key(text, n=80):
    return re.sub(r"[^a-z0-9]+", "", text.lower())[:n]


def split_of(group):
    h = hashlib.sha1((SALT + str(group)).encode()).digest()[0]
    return "dev" if h % 2 == 0 else "test"


def rid(kind, source, text):
    return kind[:3] + "_" + hashlib.sha1((source + text).encode()).hexdigest()[:10]


def row(kind, text, label, source, category, subtype="", group=None, id=None):
    group = group if group is not None else norm_key(text)
    return dict(id=id or rid(kind, source, text), kind=kind, text=text, label=int(label), source=source,
                split=split_of(kind + ":" + str(group)), group=str(group), category=category, subtype=subtype)


def build(site):
    import pandas as pd
    rng = random.Random(42)
    rows, synth = [], []

    # ---------------- prompts (public) ----------------
    d = os.path.join(CACHE, "deepset__prompt-injections", "data")
    for f in sorted(glob.glob(d + "/*.parquet")):
        df = pd.read_parquet(f)
        for t, l in zip(df.text, df.label):
            rows.append(row("prompt", t[:6000], l, "deepset/prompt-injections", "injection" if l else "benign_general"))
    df = pd.read_csv(os.path.join(CACHE, "jackhhao__jailbreak-classification", "default", "jailbreak_dataset_full.csv"))
    jb = df[df.type == "jailbreak"].sample(250, random_state=1)
    bn = df[df.type == "benign"].sample(250, random_state=1)
    for t in jb.prompt:
        rows.append(row("prompt", t[:6000], 1, "jackhhao/jailbreak-classification", "jailbreak"))
    for t in bn.prompt:
        rows.append(row("prompt", t[:6000], 0, "jackhhao/jailbreak-classification", "benign_general"))
    df = pd.read_parquet(os.path.join(CACHE, "xTRam1__safe-guard-prompt-injection", "data", "test-00000-of-00001.parquet"))
    p = df[df.label == 1].sample(300, random_state=1)
    n = df[df.label == 0].sample(400, random_state=1)
    for t in p.text:
        rows.append(row("prompt", t[:6000], 1, "xTRam1/safe-guard-prompt-injection", "injection"))
    for t in n.text:
        rows.append(row("prompt", t[:6000], 0, "xTRam1/safe-guard-prompt-injection", "benign_general"))
    import json as _j
    ca = _j.load(open(os.path.join(CACHE, "sahil2801__CodeAlpaca-20k", "code_alpaca_20k.json")))
    rng.shuffle(ca)
    for it in ca[:450]:
        t = it["instruction"] + (("\n\n" + it["input"]) if it.get("input") else "")
        rows.append(row("prompt", t[:3000], 0, "sahil2801/CodeAlpaca-20k", "benign_coding"))
    for cat, t in promptset.HARD_NEGATIVES:
        r = row("prompt", t, 0, "synthetic/prompts", "benign_coding_hard" if cat != "agent_task" else "benign_coding_agent", subtype=cat)
        rows.append(r); synth.append(r)

    # ---------------- commands ----------------
    for cat, c in cmdset.DANGEROUS:
        r = row("command", c, 1, "synthetic/commands", "dangerous", subtype=cat)
        rows.append(r); synth.append(r)
    for cat, c in cmdset.BENIGN:
        r = row("command", c, 0, "synthetic/commands", "benign_dev", subtype=cat)
        rows.append(r); synth.append(r)
    seen = set()
    nl = pd.read_csv(os.path.join(CACHE, "westenfelder__NL2SH-ALFA", "test.csv"))
    tr = pd.read_csv(os.path.join(CACHE, "westenfelder__NL2SH-ALFA", "train.csv")).sample(250, random_state=1)
    for c in list(nl.bash) + list(tr.bash):
        c = str(c).strip()
        if 2 < len(c) < 300 and "\n" not in c and c not in seen:
            seen.add(c)
            rows.append(row("command", c, 0, "westenfelder/NL2SH-ALFA", "benign_nl2bash"))
    an = _j.load(open(os.path.join(CACHE, "AnishJoshi__nl2bash-custom", "data", "test.json")))
    rng.shuffle(an)
    k = 0
    for it in an:
        c = it["bash_code"].strip()
        if 2 < len(c) < 300 and "\n" not in c and c not in seen:
            seen.add(c)
            rows.append(row("command", c, 0, "AnishJoshi/nl2bash-custom", "benign_nl2bash"))
            k += 1
            if k >= 150:
                break

    # ---------------- secrets (kind=output) ----------------
    for i, s in enumerate(secret_set.build()):
        r = row("output", s["text"], s["label"], "synthetic/secrets", ("secret_" if s["label"] else "notsecret_") + s["category"], subtype=s["category"], group=(("secfmt_" + s["category"]) if s["label"] else f"sec{i}"))
        rows.append(r); synth.append(r)

    # ---------------- tool_output ----------------
    for s in tool_outputs.build(split_fn=lambda g: split_of("tool_output:" + g)):
        r = row("tool_output", s["text"], s["label"], "synthetic/tool_output", s["category"], subtype=s["subtype"], group=s["group"], id=s["id"])
        for extra in ("payload", "form"):
            if extra in s:
                r[extra] = s[extra]
        rows.append(r); synth.append(r)
    metas = sorted(glob.glob(os.path.join(site, "*.dist-info", "METADATA")))
    rng.shuffle(metas)
    k = 0
    for m in metas:
        txt = open(m, encoding="utf-8", errors="ignore").read()
        if "\n\n" not in txt:
            continue
        head, body = txt.split("\n\n", 1)
        body = body.strip()
        if len(body) < 600:
            continue
        pkg = os.path.basename(os.path.dirname(m)).split("-")[0]
        rows.append(row("tool_output", body[:2800], 0, "local/python-package-READMEs", "benign_real_readme", group="pkg_" + pkg, id="to_real_" + pkg))
        k += 1
        if k >= 220:
            break
    return rows, synth


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--site-packages", default=DEFAULT_SITE)
    a = ap.parse_args()
    rows, synth = build(a.site_packages)
    ids = set()
    uniq = []
    for r in rows:
        if r["id"] in ids:
            continue
        ids.add(r["id"]); uniq.append(r)
    rows = uniq
    os.makedirs(os.path.join(HERE, "data", "cache"), exist_ok=True)
    with open(os.path.join(HERE, "data", "cache", "dataset.jsonl"), "w") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    with open(os.path.join(HERE, "data", "synthetic.jsonl"), "w") as f:
        for r in synth:
            if r["id"] in ids:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
    # manifest
    from collections import Counter
    man = Counter((r["kind"], r["source"], r["split"], r["label"]) for r in rows)
    out = [dict(kind=k, source=s, split=sp, label=l, n=n) for (k, s, sp, l), n in sorted(man.items())]
    json.dump(out, open(os.path.join(HERE, "data", "manifest.json"), "w"), indent=1)
    c = Counter((r["kind"], r["split"], r["label"]) for r in rows)
    for k in sorted(c):
        print(k, c[k])
    print("total", len(rows))


if __name__ == "__main__":
    main()
