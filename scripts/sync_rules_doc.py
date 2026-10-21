#!/usr/bin/env python3
"""Regenerate the rule table in skills/laya-guard/references/rules.md from src/laya_guard/rules.py.

    python scripts/sync_rules_doc.py           # rewrite the table between the RULES markers
    python scripts/sync_rules_doc.py --check   # exit 1 if the table is out of date

The id, severity, kinds and one-line description come straight from rules.py, so they cannot
drift. The "why it exists / known gaps" column is hand-written below; a rule without an entry
gets a visible placeholder so a new rule never goes undocumented silently.
"""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from laya_guard.rules import RULES  # noqa: E402

DOC = ROOT / "skills" / "laya-guard" / "references" / "rules.md"
START, END = "<!-- RULES:START -->", "<!-- RULES:END -->"

# Rules emitted directly by scan() rather than listed in RULES.
OBFUSCATION = {
    "obf.unicode_tags": ("block", "prompt, tool_output", "Unicode tag characters (invisible text smuggling)"),
    "obf.invisible_chars": ("review", "prompt, tool_output", "many zero-width / bidi control characters"),
}

WHY = {
    "inj.ignore_previous": "The canonical direct-injection phrase. Matches 'ignore/disregard/forget ... previous/system ... instructions' within a short window. Misses paraphrases and other languages.",
    "inj.reveal_system_prompt": "Prompt-extraction attempts leak the operator's hidden instructions. Misses indirect phrasings ('what were you told before this chat?').",
    "inj.role_override": "Persona jailbreaks ('you are now ... with no restrictions'). Requires both an override verb and an 'unrestricted' term, so roleplay requests without that vocabulary pass.",
    "inj.dan_mode": "Fixed phrases from well-known jailbreak personas. Trivially evaded by renaming the persona.",
    "inj.chat_template_tokens": "Control tokens such as <|im_start|> or [INST] have no business in prose and are used to fake a system turn. Can false-positive on documentation about chat templates.",
    "inj.agent_addressed": "Indirect injection: text in a web page, file or tool result that speaks to 'the AI/assistant/agent' and gives an order. The main defense for tool output. Misses instructions that never name the AI.",
    "inj.ignore_previous_variants": "Other wordings of the same attack: 'ignore all instructions you received before', 'do not follow the previous instructions', 'forget everything you know', 'your earlier guidelines have been replaced', 'simulate developer mode'. Found from dev false negatives on public prompt-injection data.",
    "inj.ignore_previous_multilingual": "'Ignore previous instructions' in German, Spanish, Portuguese, French and Russian (the public deepset set is half German). Other languages (Chinese, Japanese, Korean, Arabic ...) are not covered by rules.",
    "inj.agent_label": "'Note/instruction/message for the AI ...' followed by an order, anywhere in the text. The older inj.agent_addressed needed a comment delimiter in front, so JSON fields, YAML values, log lines and plain prose slipped through.",
    "inj.agent_label_multilingual": "'Note for the AI assistant' in German, Spanish, Portuguese and Russian. Same limitation: other languages are not covered.",
    "inj.decode_and_follow": "'Decode this and carry it out' - the base64 smuggling pattern. Cannot read the encoded blob itself.",
    "inj.hidden_html_text": "A sentence of prose inside an element styled display:none / visibility:hidden / font-size:0. Review-only: menus and templates also hide text.",
    "inj.hidden_instruction_comment": "HTML comments that mention an AI are a common hiding place. Review-only because benign pages mention assistants in comments too.",
    "inj.do_not_tell_user": "Asking the agent to hide actions from the user is a strong tell of an attack and never legitimate in fetched content.",
    "inj.exfil_markdown_image": "A markdown image whose URL carries a long (20+ char, base64-like) query value, excluding common badge hosts (shields.io etc.; the old pattern fired on 16% of real READMEs) is a zero-click data-exfiltration channel when the client renders it. Checked on tool output and on model output.",
    "sec.private_key": "Private key material should never enter a prompt, a log, a commit or a reply.",
    "sec.aws_access_key": "AWS access key id (AKIA/ASIA prefix). Format-based, so test keys such as AKI" "AIOSFODNN7EXAMPLE also match.",
    "sec.github_token": "GitHub personal/OAuth/app tokens. Format-based.",
    "sec.slack_token": "Slack bot/user tokens. Format-based.",
    "sec.api_key_prefix": "Keys with a common 'sk-' style prefix and 32+ characters. Will not recognise providers with other formats.",
    "sec.provider_tokens": "Google AIza keys, SendGrid SG., npm_, Mailgun key-, DB URLs with an inline password, Azure AccountKey=, *_API_KEY=<uuid>. Added from dev false negatives only: Stripe (sk_live_), Twilio, Hugging Face, bearer tokens and AWS secret keys were NOT added during evaluation and are known gaps.",
    "sec.jwt": "Three-part base64url JWTs. Review-only: JWTs are often public or expired, but they can be live bearer credentials.",
    "sec.generic_assignment": "`password = ...`, `DB_PASSWORD: ...`, `api_key=...` with a 12+ character value that contains a digit and is not a placeholder (`changeme`, `${...}`, `os.environ`, `****`). Heuristic and noisy by design, hence review-only. Not applied to commands, where it would flag ordinary env assignments.",
    "cmd.rm_rf_system_dir": "`rm -rf /etc`, `/usr/lib`, `/boot/*`, `/home/*`, `/var/lib/<service>`. Top-level system directories and service data dirs only, so `rm -rf /var/lib/apt/lists/*` and `rm -rf /tmp/x` pass.",
    "cmd.rm_rf_wrapped": "The same root/home delete hidden inside `sh -c '...'` or `eval '...'`. Needs the wrapper so `echo 'rm -rf /' > notes.txt` stays quiet.",
    "cmd.secrets_piped_to_network": "`env`, `history`, `/etc/shadow` or an archive of ~/.ssh piped into curl/wget/nc. Other pipelines (`env | grep PATH`) pass.",
    "cmd.archive_credential_dirs": "Archiving ~/.ssh, ~/.aws, ~/.gnupg is the usual staging step before exfiltration; review-only because backups exist.",
    "cmd.persistence_privesc": "Writes to /etc/sudoers, /etc/crontab, /etc/passwd, setuid on a binary, a second uid-0 user, chpasswd. Persistence and privilege escalation have no place in an agent session.",
    "cmd.authorized_keys_append": "Appending a key to authorized_keys grants login. Review-only because setting up your own SSH access is routine.",
    "cmd.disable_security_service": "Stopping firewalld/ufw/auditd/apparmor/fail2ban removes a defensive control. Known gap: setenforce 0 and iptables -F are not covered.",
    "cmd.miner_or_power": "xmrig/stratum miners, forced reboot/halt, sysrq, and `ssh -R` reverse tunnels. Review-only: rare in dev work but not always malicious.",
    "cmd.find_delete_root": "`find / -delete` / `find ~ -exec rm` with no name filter wipes everything. Filtered finds (`find . -name '*.pyc' -delete`) pass. Added from the evaluation (known evasion of cmd.rm_rf_root_home).",
    "cmd.rm_rf_variable_root": "`DIR=/; rm -rf \"$DIR/\"`: the same destructive delete hidden behind a variable set on the same line. Only fires when the variable was just assigned / or ~; later-defined variables are not tracked.",
    "cmd.download_then_run": "Two-step `curl -o x.sh && sh x.sh` (or chmod +x then run) on one line, the cheap evasion of cmd.pipe_to_shell. Review-only because official installers legitimately do this; a download in one command and execution in the next is not seen.",
    "cmd.rm_rf_root_home": "Recursive delete of /, ~, $HOME, . or .. . Deliberately narrow: `rm -rf node_modules` and `rm -rf ./build` pass.",
    "cmd.pipe_to_shell": "Executing a remote script unseen (`curl ... | sh`). Two-step download-then-run on one line is covered by cmd.download_then_run; across separate commands it is not seen.",
    "cmd.disk_overwrite": "dd/mkfs/shred or redirects onto block devices destroy data irrecoverably.",
    "cmd.fork_bomb": "The classic `:(){ :|:& };:` resource-exhaustion payload.",
    "cmd.chmod_777_recursive": "World-writable permissions are rarely intended. Review-only.",
    "cmd.git_force_protected": "Force-push to main/master/prod/production/release rewrites shared history. `--force-with-lease` and feature branches pass.",
    "cmd.git_destructive": "`reset --hard`, `clean -fd`, `checkout -- .`, `branch -D`, `stash drop/clear` discard uncommitted work. Review-only because they are routine for humans.",
    "cmd.sql_destructive": "DROP TABLE/DATABASE/SCHEMA, TRUNCATE, or DELETE without a WHERE clause.",
    "cmd.infra_destroy": "terraform destroy / auto-approve, kubectl delete ns/node/pv/crd, aws s3 rb/terminate-instances/delete-db, gcloud delete --quiet. Review-only so a human confirms.",
    "cmd.reverse_shell": "nc -e, /dev/tcp, bash -i >&, python socket one-liners: remote access handed to an attacker.",
    "cmd.exfil_secrets": "Sending ~/.ssh, ~/.aws, .env, .netrc, .npmrc, id_rsa and similar files over the network.",
    "cmd.read_credentials": "Reading a credential file is not itself an attack, but it is the first step of most exfiltration, so a human should see it.",
    "cmd.history_wipe": "Clearing shell or audit history hides what an agent did. Review-only.",
    "cmd.disable_guard": "An agent must not be able to stop or remove its own guardrail. Known false positive: any `rm` whose arguments contain `laya-guard` or `laya_guard` (for example cleaning a build directory in this repo) also matches.",
    "obf.unicode_tags": "Tag characters U+E0000-E007F render as nothing to a human but are readable by a model. Four or more is treated as smuggling. Other rules run on text with these characters stripped.",
    "obf.invisible_chars": "Zero-width and bidi control characters in bulk. Review-only (a few are normal in some scripts).",
}


def build_table() -> str:
    rows = [
        "| Rule id | Severity | Applies to | What it catches | Why it exists / known gaps |",
        "|---|---|---|---|---|",
    ]
    entries = [(r.id, r.severity, ", ".join(r.kinds), r.reason) for r in RULES]
    entries += [(i, s, k, d) for i, (s, k, d) in OBFUSCATION.items()]
    for rid, sev, kinds, reason in entries:
        why = WHY.get(rid, "(rationale not yet written: add it to WHY in scripts/sync_rules_doc.py)")
        rows.append(f"| `{rid}` | {sev} | {kinds} | {reason} | {why} |")
    return "\n".join(rows)


def render(doc: str) -> str:
    block = f"{START}\n{build_table()}\n{END}"
    pattern = re.compile(re.escape(START) + r".*?" + re.escape(END), re.S)
    if not pattern.search(doc):
        raise SystemExit(f"{DOC} has no {START} ... {END} block")
    return pattern.sub(lambda _m: block, doc)


def main(argv: list) -> int:
    current = DOC.read_text(encoding="utf-8")
    updated = render(current)
    if "--check" in argv:
        if current != updated:
            print("rules.md is out of date; run: python scripts/sync_rules_doc.py", file=sys.stderr)
            return 1
        print("rules.md is up to date")
        return 0
    DOC.write_text(updated, encoding="utf-8")
    print(f"updated {DOC.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
