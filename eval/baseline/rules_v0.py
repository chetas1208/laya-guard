"""Deterministic rules. These are the enforcement layer: cheap, explainable, no model needed.

Each rule applies to one or more input kinds:

  prompt       text a user (or an upstream system) is sending to a model
  tool_output  untrusted content returned to an agent (web pages, files, API/MCP results, emails)
  command      a shell command an agent is about to run
  output       text a model is about to show or send out (secret leak check)

A rule has a severity. "block" means do not proceed without a human; "review" means escalate
to a stronger check or a person. Rules are intentionally conservative about what they BLOCK
and generous about what they flag, because a false block on a coding agent costs more
trust than a flag.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Iterable, List, Pattern, Sequence

KINDS = ("prompt", "tool_output", "command", "output")


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str  # "block" | "review"
    kinds: Sequence[str]
    pattern: Pattern[str]
    reason: str


@dataclass
class RuleHit:
    rule_id: str
    severity: str
    reason: str
    excerpt: str = ""

    def to_dict(self) -> dict:
        return {"rule_id": self.rule_id, "severity": self.severity, "reason": self.reason, "excerpt": self.excerpt}


def _r(id: str, severity: str, kinds: Sequence[str], pattern: str, reason: str, flags: int = re.I) -> Rule:
    return Rule(id, severity, tuple(kinds), re.compile(pattern, flags), reason)


_AI = r"(?:ai|assistant|model|llm|agent|claude|gpt|chatgpt|gemini|copilot|bot|system)"

RULES: List[Rule] = [
    # --- instruction hijack / jailbreak (prompt + untrusted content) -------------------------
    _r("inj.ignore_previous", "block", ("prompt", "tool_output"),
       r"\b(?:ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(?:all\s+|any\s+|your\s+|the\s+|these\s+|those\s+)?"
       r"(?:previous|prior|above|earlier|preceding|system|developer|original)\b[^.\n]{0,20}\b(?:instruction|prompt|rule|message|directive|guideline|polic)",
       "tries to cancel earlier instructions"),
    _r("inj.reveal_system_prompt", "block", ("prompt", "tool_output"),
       r"\b(?:reveal|show|print|repeat|output|display|leak|tell me)\b[^.\n]{0,40}\b(?:your|the)\s+(?:system|hidden|initial|secret)\s+(?:prompt|instruction|message)",
       "asks for the hidden system prompt"),
    _r("inj.role_override", "block", ("prompt", "tool_output"),
       r"\b(?:you are now|from now on,? you (?:are|will)|act as if you (?:have|had) no|pretend (?:that )?you (?:have|are) no)\b[^.\n]{0,60}"
       r"(?:unrestricted|jailbroken|no (?:rules|restrictions|limits|filters)|dan\b|developer mode|without (?:any )?(?:rules|restrictions|filters))",
       "role override / jailbreak persona"),
    _r("inj.dan_mode", "block", ("prompt", "tool_output"),
       r"\b(?:do anything now|developer mode enabled|jailbreak mode|dan mode)\b",
       "known jailbreak persona phrase"),
    _r("inj.chat_template_tokens", "block", ("prompt", "tool_output"),
       r"(?:<\|im_(?:start|end)\|>|<\|(?:system|assistant|user|endoftext)\|>|\[/?INST\]|<<SYS>>|<\|start_header_id\|>)",
       "contains chat-template control tokens"),
    _r("inj.agent_addressed", "block", ("tool_output",),
       rf"(?:<!--|\[|\(|#|//|/\*|\n)\s*(?:note|message|instruction|important|attention|hey|hi)?\s*(?:to|for)\s+(?:the\s+)?{_AI}s?\b[^\n]{{0,200}}"
       r"\b(?:ignore|disregard|do not tell|don't tell|instead|must|should|run|execute|send|fetch|download|exfiltrate|email|forward)\b",
       "content addresses the AI agent directly and gives it orders"),
    _r("inj.hidden_instruction_comment", "review", ("tool_output",),
       rf"<!--[^>]{{0,400}}\b{_AI}\b[^>]{{0,400}}-->",
       "HTML comment mentioning an AI/assistant (common hiding spot for injected instructions)"),
    _r("inj.do_not_tell_user", "block", ("tool_output",),
       r"\b(?:do not|don't|never)\s+(?:tell|inform|mention|reveal|show)\s+(?:this to\s+)?the\s+user\b",
       "asks the agent to hide actions from the user"),
    _r("inj.exfil_markdown_image", "block", ("tool_output", "output"),
       r"!\[[^\]]*\]\(\s*https?://[^)\s]*[?&][^)\s]*(?:=|%3d)[^)\s]{12,}",
       "markdown image URL with a long query payload (exfiltration channel)"),

    # --- secrets (any kind; mostly prompt/output) --------------------------------------------
    _r("sec.private_key", "block", ("prompt", "tool_output", "output", "command"),
       r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----",
       "private key material", re.I),
    _r("sec.aws_access_key", "block", ("prompt", "tool_output", "output", "command"),
       r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", "AWS access key id", 0),
    _r("sec.github_token", "block", ("prompt", "tool_output", "output", "command"),
       r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{50,}\b", "GitHub token", 0),
    _r("sec.slack_token", "block", ("prompt", "tool_output", "output", "command"),
       r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", "Slack token", 0),
    _r("sec.api_key_prefix", "block", ("prompt", "tool_output", "output", "command"),
       r"\bsk-(?:ant-|proj-|live-)?[A-Za-z0-9_-]{32,}\b", "API key with a common secret-key prefix", 0),
    _r("sec.jwt", "review", ("prompt", "tool_output", "output"),
       r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", "JWT", 0),
    _r("sec.generic_assignment", "review", ("prompt", "output"),
       r"\b(?:api[_-]?key|secret|passwd|password|token|access[_-]?key)\b\s*[:=]\s*['\"]?[A-Za-z0-9/+_\-]{20,}",
       "credential-looking assignment"),

    # --- dangerous shell commands (agent about to run) ---------------------------------------
    _r("cmd.rm_rf_root_home", "block", ("command",),
       r"\brm\s+(?:-[a-z]*[rf][a-z]*\s+){1,3}(?:--no-preserve-root\s+)?(?:/\*?|~/?\*?|\$HOME/?\*?|\.\.?/?)(?:\s|$)",
       "recursive delete of root, home or current/parent directory"),
    _r("cmd.pipe_to_shell", "block", ("command",),
       r"\b(?:curl|wget|fetch)\b[^|;&\n]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b",
       "pipes a download straight into a shell"),
    _r("cmd.disk_overwrite", "block", ("command",),
       r"\b(?:dd\s+[^\n]*\bof=/dev/(?:sd|nvme|hd|vd|disk)|mkfs(?:\.\w+)?\s+/dev/|>\s*/dev/(?:sd|nvme|hd|vd)\w*|shred\s+[^\n]*/dev/)",
       "overwrites a disk or block device"),
    _r("cmd.fork_bomb", "block", ("command",), r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", "fork bomb"),
    _r("cmd.chmod_777_recursive", "review", ("command",),
       r"\bchmod\s+(?:-[a-z]*R[a-z]*\s+)?(?:-R\s+)?0?777\b", "world-writable permissions"),
    _r("cmd.git_force_protected", "block", ("command",),
       r"\bgit\s+push\b[^\n]*(?:--force(?!-with-lease)|\s-f\b)[^\n]*\b(?:main|master|prod|production|release)\b"
       r"|\bgit\s+push\b[^\n]*\b(?:main|master|prod|production|release)\b[^\n]*(?:--force(?!-with-lease)|\s-f\b)",
       "force-push to a protected branch"),
    _r("cmd.git_destructive", "review", ("command",),
       r"\bgit\s+(?:reset\s+--hard|clean\s+-[a-z]*f[a-z]*d|checkout\s+--\s+\.|branch\s+-D|stash\s+(?:drop|clear))\b",
       "discards uncommitted work or history"),
    _r("cmd.sql_destructive", "block", ("command",),
       r"\b(?:drop\s+(?:table|database|schema)|truncate\s+table)\b|\bdelete\s+from\s+\w+\s*(?:;|$|\"|')",
       "destructive SQL without a WHERE clause"),
    _r("cmd.infra_destroy", "review", ("command",),
       r"\b(?:terraform\s+(?:destroy|apply\s+[^\n]*-auto-approve)|kubectl\s+delete\s+(?:ns|namespace|node|pv|crd)\b|"
       r"aws\s+(?:s3\s+(?:rb|rm\s+[^\n]*--recursive)|ec2\s+terminate-instances|rds\s+delete-db)|gcloud\s+[^\n]*\bdelete\b[^\n]*(?:--quiet|-q))",
       "destroys cloud or cluster resources"),
    _r("cmd.reverse_shell", "block", ("command",),
       r"(?:\bnc(?:at)?\b[^\n]*\s-e\s|/dev/tcp/\d|bash\s+-i\s*>&|python\d?\s+-c\s+['\"][^\n]*socket[^\n]*connect|mkfifo\s+/tmp/\S+;\s*(?:nc|cat))",
       "reverse shell pattern"),
    _r("cmd.exfil_secrets", "block", ("command",),
       r"\b(?:curl|wget|nc|scp|rsync|http)\b[^\n]*(?:@|<|`cat\s+|\$\(cat\s+)\s*(?:~|\$HOME|/home/\w+|/root)?/?\S*(?:\.ssh/|\.aws/|\.env\b|\.netrc|\.npmrc|\.pypirc|id_rsa|credentials)",
       "sends credential files over the network"),
    _r("cmd.read_credentials", "review", ("command",),
       r"\b(?:cat|less|more|head|tail|cp|base64|xxd|strings)\b[^\n|;&]*(?:~|\$HOME|/home/\w+|/root)?/?\S*(?:\.ssh/id_\w+|\.aws/credentials|\.netrc|\.pypirc|\.npmrc|\.docker/config\.json|\.kube/config)",
       "reads a credential file"),
    _r("cmd.history_wipe", "review", ("command",),
       r"\b(?:history\s+-c|unset\s+HISTFILE|shred\s+[^\n]*\.bash_history|rm\s+[^\n]*\.bash_history|auditctl\s+-D|journalctl\s+--vacuum)",
       "erases shell or audit history"),
    _r("cmd.disable_guard", "block", ("command",),
       r"\b(?:kill(?:all)?\s+(?:-9\s+)?[^\n]*guardrails|pkill\s+[^\n]*guardrails|systemctl\s+(?:stop|disable)\s+[^\n]*guardrails|"
       r"rm\s+[^\n]*\.claude/(?:settings|hooks)|rm\s+[^\n]*laya[-_]guard)",
       "tries to stop or remove a guardrail"),
]

# Characters that hide text from a human reader but not from a model.
_INVISIBLE = {
    "​", "‌", "‍", "⁠", "﻿", "᠎",
    *(chr(c) for c in range(0x202A, 0x202F)),  # bidi embeddings/overrides
    *(chr(c) for c in range(0x2066, 0x206A)),  # bidi isolates
}


def _tag_chars(text: str) -> int:
    return sum(1 for ch in text if 0xE0000 <= ord(ch) <= 0xE007F)


def normalize(text: str) -> str:
    """NFKC-fold and strip invisible characters so obfuscated payloads still match."""
    folded = unicodedata.normalize("NFKC", text)
    return "".join(ch for ch in folded if ch not in _INVISIBLE and not (0xE0000 <= ord(ch) <= 0xE007F))


def _excerpt(text: str, m: "re.Match[str]", width: int = 80) -> str:
    start = max(0, m.start() - 10)
    snippet = text[start : m.end() + width // 2].replace("\n", " ")
    return snippet[:width * 2]


def scan(text: str, kind: str, rules: Iterable[Rule] = RULES) -> List[RuleHit]:
    """Run every rule that applies to `kind` and return the hits (empty list = clean)."""
    if kind not in KINDS:
        raise ValueError(f"unknown kind {kind!r}; expected one of {KINDS}")
    hits: List[RuleHit] = []

    # obfuscation signals first: they apply to any kind that can carry hidden text
    if kind in ("prompt", "tool_output"):
        hidden = sum(1 for ch in text if ch in _INVISIBLE)
        tags = _tag_chars(text)
        if tags >= 4:
            hits.append(RuleHit("obf.unicode_tags", "block", "Unicode tag characters (invisible text smuggling)", f"{tags} tag chars"))
        elif hidden >= 8:
            hits.append(RuleHit("obf.invisible_chars", "review", "many zero-width / bidi control characters", f"{hidden} chars"))

    folded = normalize(text)
    for rule in rules:
        if kind not in rule.kinds:
            continue
        m = rule.pattern.search(folded)
        if m:
            hits.append(RuleHit(rule.id, rule.severity, rule.reason, _excerpt(folded, m)))
    return hits
