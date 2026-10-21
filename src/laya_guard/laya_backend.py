"""Thin, lazy wrapper around the open-weight Laya model (https://github.com/NandhaKishorM/laya).

Laya is a typed-decision classifier (ModernBERT-large, 421M params, Apache-2.0), not a generator.
You give it a `state` dict and named questions; it returns probabilities. We use only `noul`
(yes/no) questions here and read P(yes). Every import is lazy so the rest of the package works
with the standard library alone.

Honest limits (from the Laya authors' own BENCHMARKS.md, held-out data): jailbreak detection
accuracy is roughly 0.71-0.76, content moderation is near chance, and the checkpoints ship
over-confident. That is why laya-guard treats Laya as an advisory signal that can escalate a
decision to "review", never as the thing that enforces a block by default.
"""

from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional, Sequence

# Default question sets per input kind, chosen on a dev split and checked once on a held-out test
# split (eval/results/RESULTS.md). Two findings drive this table:
#   * Laya's own shipped guard questions (no `criteria`) flag ~34% of benign coding prompts at any
#     useful threshold because the probabilities saturate near 1.0. The `criteria` form below does not.
#   * Laya carried no usable signal for tool_output (AUROC 0.51) or commands, so those kinds are
#     rules-only and have no entry here. Add one yourself via config if you want to experiment.
DEFAULT_QUESTIONS: Dict[str, Dict[str, Any]] = {
    "prompt": {
        "state_key": "prompt",
        "questions": {
            "c_persona": {
                "type": "noul",
                "instructions": "Does `prompt` ask the AI to ignore its guidelines, adopt an unrestricted persona, or reveal hidden instructions?",
                "criteria": {
                    "false": "no, it is an ordinary task, question or conversation",
                    "true": "yes, it tries to override or bypass the AI's guidelines or extract hidden instructions",
                },
            },
        },
    },
    "output": {
        "state_key": "text",
        "questions": {
            "sensitive_data": {
                "type": "noul",
                "instructions": "Does `text` contain credentials, personal data or other sensitive information?",
            },
        },
    },
}


class LayaUnavailable(RuntimeError):
    """Raised when the laya package or its weights cannot be loaded."""


def split_windows(text: str, size: int = 1400, overlap: int = 200, max_windows: int = 6) -> List[str]:
    """Split long text into overlapping character windows (Laya reads ~512 tokens at a time).

    Injections often sit in the middle of a long page, so we score each window and keep the max.
    If there are more windows than `max_windows`, windows are sampled evenly, always including
    the first and the last.
    """
    text = text.strip()
    if len(text) <= size:
        return [text] if text else []
    step = max(1, size - overlap)
    starts = list(range(0, max(1, len(text) - overlap), step))
    windows = [text[s : s + size] for s in starts]
    if len(windows) > max_windows:
        idx = sorted({round(i * (len(windows) - 1) / (max_windows - 1)) for i in range(max_windows)})
        windows = [windows[i] for i in idx]
    return windows


class LayaScorer:
    """Scores text with Laya. One instance holds one loaded checkpoint."""

    def __init__(
        self,
        checkpoint: str = "convaiinnovations/laya",
        subfolder: Optional[str] = None,
        revision: Optional[str] = None,
        device: str = "auto",
        questions: Optional[Dict[str, Dict[str, Any]]] = None,
    ):
        self.checkpoint = checkpoint
        self.subfolder = subfolder
        self.revision = revision
        self.device = device
        self.questions = questions or DEFAULT_QUESTIONS
        self._agent = None
        self.load_seconds: Optional[float] = None

    # -- loading ---------------------------------------------------------------------------
    def _load(self):
        if self._agent is not None:
            return self._agent
        os.environ.setdefault("USE_TF", "0")  # laya hangs on some setups when TensorFlow is importable
        try:
            import laya  # type: ignore
        except Exception as exc:  # ImportError or a broken torch install
            raise LayaUnavailable(f"laya is not importable: {exc}. Install with: pip install 'laya-guard[laya]'") from exc
        kwargs: Dict[str, Any] = {}
        if self.subfolder:
            kwargs["subfolder"] = self.subfolder
        if self.revision:
            kwargs["revision"] = self.revision
        if self.device != "auto":
            kwargs["device"] = self.device
        t0 = time.time()
        try:
            self._agent = laya.load(self.checkpoint, **kwargs)
        except Exception as exc:
            raise LayaUnavailable(f"could not load Laya checkpoint {self.checkpoint!r}: {exc}") from exc
        self.load_seconds = time.time() - t0
        return self._agent

    def available(self) -> bool:
        try:
            self._load()
            return True
        except LayaUnavailable:
            return False

    # -- scoring ---------------------------------------------------------------------------
    def score(self, text: str, kind: str) -> Dict[str, float]:
        """Return {question_name: P(yes)} for `kind`, taking the max over text windows.

        An empty dict means there is nothing to score for this kind (for example `command`).
        """
        spec = self.questions.get(kind)
        if not spec:
            return {}
        agent = self._load()
        windows = split_windows(text)
        best: Dict[str, float] = {}
        for window in windows:
            result = agent.predict({spec["state_key"]: window}, spec["questions"])
            for name, answer in result["answers"].items():
                p = answer.get("noul")
                if p is None:
                    continue
                best[name] = max(best.get(name, 0.0), float(p))
        return best

    def info(self) -> Dict[str, Any]:
        return {"checkpoint": self.checkpoint, "subfolder": self.subfolder, "revision": self.revision, "load_seconds": self.load_seconds}


class StubScorer:
    """Deterministic scorer for tests and offline use: returns fixed probabilities per keyword."""

    def __init__(self, table: Optional[Dict[str, Dict[str, float]]] = None, default: float = 0.0, fail: bool = False):
        self.table = table or {}
        self.default = default
        self.fail = fail
        self.calls = 0

    def score(self, text: str, kind: str) -> Dict[str, float]:
        self.calls += 1
        if self.fail:
            raise LayaUnavailable("stub configured to fail")
        for needle, probs in self.table.items():
            if needle.lower() in text.lower():
                return dict(probs)
        names = DEFAULT_QUESTIONS.get(kind, {}).get("questions", {})
        return {name: self.default for name in names}

    def available(self) -> bool:
        return not self.fail

    def info(self) -> Dict[str, Any]:
        return {"checkpoint": "stub"}
