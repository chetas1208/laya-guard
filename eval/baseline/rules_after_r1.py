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
       r"\brm\s+(?:(?:-[a-z]*[rf][a-z]*|--recursive|--force)\s+){1,3}(?:--no-preserve-root\s+)?[\"']?(?:/\*?|~/?\*?|\$HOME[\"']?/?\*?|\$\{HOME\}[\"']?/?\*?|\.\.?/?)(?:[\s;&|)]|$)",
       "recursive delete of root, home or current/parent directory"),
    _r("cmd.rm_rf_wrapped", "block", ("command",),
       r"\b(?:(?:ba|z|da|k)?sh\s+-c|eval)\s+[\"']\s*(?:sudo\s+)?rm\s+(?:(?:-[a-z]*[rf][a-z]*|--recursive|--force)\s+){1,3}(?:--no-preserve-root\s+)?(?:/\*?|~/?\*?|\$HOME/?\*?)\s*[\"']",
       "recursive delete of root or home hidden inside sh -c / eval"),
    _r("cmd.rm_rf_system_dir", "block", ("command",),
       r"\brm\s+(?:(?:-[a-z]*[rf][a-z]*|--recursive|--force)\s+){1,3}(?:--no-preserve-root\s+)?[\"']?"
       r"(?:/(?:etc|usr|bin|sbin|lib|lib32|lib64|boot|home|root|var|opt|srv|sys|proc)|/usr/(?:lib|bin|sbin|share|local)|/home/\*|/var/lib/\w+)/?\*?/?[\"']?(?:[\s;&|)]|$)",
       "recursive delete of a top-level system directory or a service's data directory"),
    _r("cmd.pipe_to_shell", "block", ("command",),
       r"\b(?:curl|wget|fetch)\b[^|;&\n]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b"
       r"|\b(?:(?:ba|z|da|k)?sh|source|\.)\s+(?:-c\s+[\"']?\$\(\s*|<\(\s*)(?:curl|wget)\b|\beval\s+[\"']?\$\(\s*(?:curl|wget)\b"
       r"|\|\s*base64\s+(?:-d|-D|--decode)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b"
       r"|\b(?:iex|invoke-expression)\b[^\n]*(?:downloadstring|webclient|invoke-webrequest|\biwr\b)",
       "executes downloaded or decoded code without looking at it (pipe, $(...), <(...), base64, PowerShell IEX)"),
    _r("cmd.disk_overwrite", "block", ("command",),
       r"(?:\bdd\s+[^\n]*\bof=/dev/(?:sd|nvme|hd|vd|disk)|\bmkfs(?:\.\w+)?\s+(?:-\S+\s+)*/dev/|>\s*/dev/(?:sd|nvme|hd|vd|disk)\w*|\bshred\s+[^\n]*/dev/"
       r"|\bwipefs\s+(?:-\w+\s+)*/dev/|\bsgdisk\s+--zap\S*\s+/dev/|\bblkdiscard\s+(?:-\w+\s+)*/dev/)",
       "overwrites a disk or block device"),
    _r("cmd.fork_bomb", "block", ("command",),
       r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:|\b(?P<fn>[A-Za-z_]\w*)\(\)\s*\{\s*(?P=fn)\s*\|\s*(?P=fn)\s*&\s*\}\s*;\s*(?P=fn)\b",
       "fork bomb"),
    _r("cmd.chmod_777_recursive", "review", ("command",),
       r"\bchmod\s+(?:-[a-z]*R[a-z]*\s+)?(?:-R\s+)?0?777\b", "world-writable permissions"),
    _r("cmd.git_force_protected", "block", ("command",),
       r"\bgit\s+push\b[^\n]*(?:--force(?!-with-lease)|\s-f\b)[^\n]*\b(?:main|master|prod|production|release)\b"
       r"|\bgit\s+push\b[^\n]*\b(?:main|master|prod|production|release)\b[^\n]*(?:--force(?!-with-lease)|\s-f\b)"
       r"|\bgit\s+push\b[^\n]*\s\+(?:main|master|prod|production|release)\b"
       r"|\bgit\s+push\b[^\n]*(?:--delete\s+(?:\S+\s+)?|\s:)(?:main|master|prod|production|release)\b|\bgit\s+push\b[^\n]*--mirror\b",
       "force-push, delete or mirror-push of a protected branch"),
    _r("cmd.git_destructive", "review", ("command",),
       r"\bgit\s+(?:reset\s+--hard|clean\s+-[a-z]*f[a-z]*d|checkout\s+--\s+\.|branch\s+(?-i:-D)|stash\s+(?:drop|clear))\b",
       "discards uncommitted work or history"),
    _r("cmd.sql_destructive", "block", ("command",),
       r"\b(?:drop\s+(?:table|database|schema)|truncate\s+table)\b|\bdelete\s+from\s+\w+\s*(?:;|$|\"|')"
       r"|\bupdate\s+\w+\s+set\b(?![^;]*\bwhere\b)|\.drop\(\)|dropDatabase\(|\bpg_dropcluster\b|\bdropdb\b|\bflushall\b",
       "destructive SQL / datastore command without a WHERE clause or scope"),
    _r("cmd.infra_destroy", "review", ("command",),
       r"\b(?:terraform\s+(?:destroy|apply\s+[^\n]*-auto-approve)|kubectl\s+delete\s+(?:ns|namespace|node|pv|crd)\b|"
       r"aws\s+(?:s3\s+(?:rb|rm\s+[^\n]*--recursive)|ec2\s+terminate-instances|rds\s+delete-db)|gcloud\s+[^\n]*\bdelete\b[^\n]*(?:--quiet|-q))",
       "destroys cloud or cluster resources"),
    _r("cmd.reverse_shell", "block", ("command",),
       r"(?:\bnc(?:at)?\b[^\n]*\s-e\s|/dev/tcp/\d|bash\s+-i\s*>&|python\d?\s+-c\s+['\"][^\n]*socket[^\n]*connect|mkfifo\s+/tmp/\S+;\s*(?:nc|cat))",
       "reverse shell pattern"),
    _r("cmd.exfil_secrets", "block", ("command",),
       r"\b(?:curl|wget|nc|scp|rsync|http)\b[^\n]*(?:@|<|--post-file[=\s]|`cat\s+|\$\(cat\s+)\s*(?:~|\$HOME|/home/\w+|/root)?/?\S*(?:\.ssh/|\.aws/|\.env\b|\.netrc|\.npmrc|\.pypirc|id_rsa|credentials)",
       "sends credential files over the network"),
    _r("cmd.read_credentials", "review", ("command",),
       r"\b(?:cat|less|more|head|tail|cp|base64|xxd|strings)\b[^\n|;&]*(?:~|\$HOME|/home/\w+|/root)?/?\S*(?:\.ssh/id_\w+(?![\w]*\.pub)|/etc/shadow|\.aws/credentials|\.netrc|\.pypirc|\.npmrc|\.docker/config\.json|\.kube/config)",
       "reads a credential file"),
    _r("cmd.secrets_piped_to_network", "block", ("command",),
       r"\b(?:env|printenv|history|gh\s+auth\s+token|cat\s+/etc/(?:shadow|passwd)|tar\s+[^\n|]*(?:~|\$HOME)/?\.(?:ssh|aws|gnupg|kube)\S*|security\s+find-\w+-password\b[^|\n]*)(?:\s[^|\n]*)?\|\s*(?:curl|wget|nc|ncat|socat)\b",
       "pipes environment, history or credential material to a network tool"),
    _r("cmd.archive_credential_dirs", "review", ("command",),
       r"\b(?:tar|zip|7z|rar)\b[^\n|]*(?:~|\$HOME|/home/\w+)/?\.(?:ssh|aws|gnupg|kube|docker)\b",
       "archives a credential directory (usual first step before exfiltration)"),
    _r("cmd.history_wipe", "review", ("command",),
       r"\b(?:ln\s+-\w+\s+/dev/null\s+\S*(?:_history|/var/log/)|history\s+-c|unset\s+HISTFILE|shred\s+[^\n]*\.bash_history|rm\s+[^\n]*\.bash_history|auditctl\s+-D|journalctl\s+--vacuum)",
       "erases shell or audit history"),
    _r("cmd.persistence_privesc", "block", ("command",),
       r"(?:>>?|\btee\s+(?:-a\s+)?)\s*/etc/(?:sudoers\S*|crontab|passwd|shadow|profile\S*|environment|ld\.so\.preload|ssh/sshd_config)"
       r"|\bchmod\s+(?:u\+s|\+s|[2-7]?[4-7][0-7]{3})\s+\S*/(?:bin|sbin)/\S+|\buseradd\s+[^\n]*-o\s+[^\n]*-u\s*0\b|\bchpasswd\b|\bpasswd\s+-d\s+root\b",
       "adds a backdoor or escalates privileges (sudoers, uid 0 user, setuid bit, password reset)"),
    _r("cmd.authorized_keys_append", "review", ("command",),
       r">>\s*\S*\.ssh/authorized_keys\b", "appends an SSH key to authorized_keys"),
    _r("cmd.disable_security_service", "block", ("command",),
       r"\bsystemctl\s+(?:stop|disable|mask)\s+(?:--now\s+)?(?:firewalld|ufw|auditd|apparmor|fail2ban)\b|\bufw\s+disable\b",
       "stops a firewall or audit service"),
    _r("cmd.miner_or_power", "review", ("command",),
       r"\bxmrig\b|stratum\+tcp://|\b(?:reboot|halt|poweroff)\s+-f\b|\binit\s+[06]\b|/proc/sysrq-trigger|\bssh\s+[^\n]*-R\s*\d+:",
       "crypto miner, forced power-off, or reverse SSH tunnel"),
    _r("cmd.disable_guard", "block", ("command",),
       r"\b(?:kill(?:all)?\s+(?:-9\s+)?[^\n]*guardrails|pkill\s+[^\n]*guardrails|systemctl\s+(?:stop|disable)\s+[^\n]*guardrails|"
       r"\brm\s+[^\n]*(?:\.claude/(?:settings[^\s/]*|hooks)\b|\.claude/skills/laya[-_]guard|(?:^|[\s/])bin/laya[-_]guard(?:\s|$)|\.laya[-_]guard(?:/|\s|$)))",
       "tries to stop or remove a guardrail"),
    _r("cmd.find_delete_root", "block", ("command",),
       r"\bfind\s+(?:/|~|\$HOME)/?\s+(?:-(?:type|maxdepth|mindepth|xdev)\s+\S+\s+|-xdev\s+)*(?:-delete\b|-exec\s+(?:sudo\s+)?rm\b)",
       "find over / or ~ with no name filter that deletes everything it matches"),
    _r("cmd.rm_rf_variable_root", "block", ("command",),
       r"(?:^|[;&\s])(?P<v>[A-Za-z_]\w*)=[\"']?(?:/|~|\$HOME)/?[\"']?\s*(?:;|&&)[^\n]*\brm\s+(?:-\w+\s+)+[\"']?\$\{?(?P=v)\}?/?\*?[\"']?(?:\s|$)",
       "recursive delete through a variable that was just set to / or the home directory"),
    _r("cmd.download_then_run", "review", ("command",),
       r"\b(?:curl|wget)\b[^\n|;&]*?(?:(?:-o|-O|--output(?:-document)?)[\s=]*|>\s*)(?P<f>[^\s|;&<>]+)[^\n]*?(?:&&|;)\s*"
       r"(?:chmod\s+\S+\s+(?P=f)\s*(?:&&|;)\s*)?(?:nohup\s+)?(?:(?:sudo\s+(?:-\S+\s+)*)?(?:(?:ba|z|da|k)?sh|python3?|perl|ruby|node)\s+(?:-\w+\s+)*)?(?:\./)?(?P=f)(?:\s|$)",
       "downloads a file and executes it in the same command line (two-step curl | sh)"),
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
