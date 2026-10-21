"""Copy-paste guard for any Python app. Standard library only; no laya-guard import.

It shells out to the `laya-guard` CLI, so the package only has to be installed on the PATH, and
it fails closed: anything other than a clean exit 0 is "not allowed".

    from stdlib_snippet import guard, GuardDecision

    d = guard(user_text, "prompt")
    if d.decision != "allow":
        raise RuntimeError(f"blocked by laya-guard: {d.decision} {d.reasons}")
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from typing import List

KINDS = ("prompt", "tool_output", "command", "output")


@dataclass
class GuardDecision:
    decision: str  # allow | review | block
    reasons: List[str] = field(default_factory=list)
    rule_ids: List[str] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"


def guard(text: str, kind: str = "prompt", *, rules_only: bool = True, timeout: float = 30.0,
          cli: str = "laya-guard") -> GuardDecision:
    """Check `text` as `kind`. Never raises; failures come back as decision="block"."""
    if kind not in KINDS:
        raise ValueError(f"kind must be one of {KINDS}")
    exe = shutil.which(cli)
    if exe is None:
        return GuardDecision("block", [f"{cli} not found on PATH (failing closed)"])
    cmd = [exe, "check", "--kind", kind, "--json"] + (["--no-laya"] if rules_only else [])
    try:
        # text goes on stdin, never into the argument list
        proc = subprocess.run(cmd, input=text, text=True, capture_output=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        return GuardDecision("block", [f"laya-guard did not run: {exc} (failing closed)"])
    if proc.returncode not in (0, 10, 20):
        return GuardDecision("block", [f"laya-guard exited {proc.returncode} (failing closed)"])
    try:
        verdict = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return GuardDecision("block", ["unreadable laya-guard output (failing closed)"])
    decision = {0: "allow", 10: "review", 20: "block"}[proc.returncode]
    return GuardDecision(decision, list(verdict.get("reasons", [])),
                         [h["rule_id"] for h in verdict.get("rule_hits", [])])


if __name__ == "__main__":
    kind = sys.argv[1] if len(sys.argv) > 1 else "prompt"
    d = guard(sys.stdin.read(), kind)
    print(json.dumps({"decision": d.decision, "reasons": d.reasons, "rule_ids": d.rule_ids}))
    sys.exit({"allow": 0, "review": 10, "block": 20}[d.decision])
