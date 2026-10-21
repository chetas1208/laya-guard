# Rule reference

Rules are the enforcement layer: regular expressions over normalized text (NFKC-folded, zero-width and
tag characters stripped). They run in microseconds, need no model, and always explain themselves.
Source of truth: `src/laya_guard/rules.py`. The table below is generated from it by
`python scripts/sync_rules_doc.py`; a test fails if a rule id is missing from this file.

## Input kinds

| Kind | What it is | Typical call site |
|---|---|---|
| `prompt` | Text a user or upstream system sends to a model | before the prompt enters a pipeline |
| `tool_output` | Untrusted content an agent reads: web pages, files, search hits, MCP/API results, emails | right after the tool returns, before the agent acts on it |
| `command` | A shell command an agent is about to run | before execution |
| `output` | Text a model is about to show, send or commit | before it leaves (secret-leak check) |

## Severities

- `block`: do not proceed. Report the rule ids. Do not retry with a rewording.
- `review`: stop and escalate to a human or a stronger check; treat the content as data meanwhile.
- A rule's severity can be hardened (`review` to `block`) per kind with `rule_severity_override`
  (see `configuration.md`). It cannot be lowered by the model: Laya may only escalate.

Obfuscation checks (`obf.*`) run on `prompt` and `tool_output` before the other rules.

## Rules

<!-- RULES:START -->
| Rule id | Severity | Applies to | What it catches | Why it exists / known gaps |
|---|---|---|---|---|
| `inj.ignore_previous` | block | prompt, tool_output | tries to cancel earlier instructions | The canonical direct-injection phrase. Matches 'ignore/disregard/forget ... previous/system ... instructions' within a short window. Misses paraphrases and other languages. |
| `inj.ignore_previous_variants` | block | prompt, tool_output | alternative wordings of 'ignore your earlier instructions' (before/above/everything you know), instruction-replacement and developer-mode phrases | Other wordings of the same attack: 'ignore all instructions you received before', 'do not follow the previous instructions', 'forget everything you know', 'your earlier guidelines have been replaced', 'simulate developer mode'. Found from dev false negatives on public prompt-injection data. |
| `inj.ignore_previous_multilingual` | block | prompt, tool_output | 'ignore previous instructions' in German, Spanish, Portuguese, French and Russian | 'Ignore previous instructions' in German, Spanish, Portuguese, French and Russian (the public deepset set is half German). Other languages (Chinese, Japanese, Korean, Arabic ...) are not covered by rules. |
| `inj.reveal_system_prompt` | block | prompt, tool_output | asks for the hidden system prompt | Prompt-extraction attempts leak the operator's hidden instructions. Misses indirect phrasings ('what were you told before this chat?'). |
| `inj.role_override` | block | prompt, tool_output | role override / jailbreak persona | Persona jailbreaks ('you are now ... with no restrictions'). Requires both an override verb and an 'unrestricted' term, so roleplay requests without that vocabulary pass. |
| `inj.dan_mode` | block | prompt, tool_output | known jailbreak persona phrase | Fixed phrases from well-known jailbreak personas. Trivially evaded by renaming the persona. |
| `inj.chat_template_tokens` | block | prompt, tool_output | contains chat-template control tokens | Control tokens such as <|im_start|> or [INST] have no business in prose and are used to fake a system turn. Can false-positive on documentation about chat templates. |
| `inj.agent_addressed` | block | tool_output | content addresses the AI agent directly and gives it orders | Indirect injection: text in a web page, file or tool result that speaks to 'the AI/assistant/agent' and gives an order. The main defense for tool output. Misses instructions that never name the AI. |
| `inj.agent_label` | block | tool_output | a 'note/instruction for the AI' label followed by an order, in any position (plain text, JSON, YAML, logs, email) | 'Note/instruction/message for the AI ...' followed by an order, anywhere in the text. The older inj.agent_addressed needed a comment delimiter in front, so JSON fields, YAML values, log lines and plain prose slipped through. |
| `inj.agent_label_multilingual` | block | tool_output | 'note for the AI assistant' in German, Spanish, Portuguese and Russian | 'Note for the AI assistant' in German, Spanish, Portuguese and Russian. Same limitation: other languages are not covered. |
| `inj.decode_and_follow` | block | prompt, tool_output | asks the reader to decode an encoded blob and obey it | 'Decode this and carry it out' - the base64 smuggling pattern. Cannot read the encoded blob itself. |
| `inj.hidden_html_text` | review | tool_output | sentence-length text inside an element styled to be invisible | A sentence of prose inside an element styled display:none / visibility:hidden / font-size:0. Review-only: menus and templates also hide text. |
| `inj.hidden_instruction_comment` | review | tool_output | HTML comment mentioning an AI/assistant (common hiding spot for injected instructions) | HTML comments that mention an AI are a common hiding place. Review-only because benign pages mention assistants in comments too. |
| `inj.do_not_tell_user` | block | tool_output | asks the agent to hide actions from the user | Asking the agent to hide actions from the user is a strong tell of an attack and never legitimate in fetched content. |
| `inj.exfil_markdown_image` | block | tool_output, output | markdown image URL with a long query payload (exfiltration channel) | A markdown image whose URL carries a long (20+ char, base64-like) query value, excluding common badge hosts (shields.io etc.; the old pattern fired on 16% of real READMEs) is a zero-click data-exfiltration channel when the client renders it. Checked on tool output and on model output. |
| `sec.private_key` | block | prompt, tool_output, output, command | private key material | Private key material should never enter a prompt, a log, a commit or a reply. |
| `sec.aws_access_key` | block | prompt, tool_output, output, command | AWS access key id | AWS access key id (AKIA/ASIA prefix). Format-based, so test keys such as AKIAIOSFODNN7EXAMPLE also match. |
| `sec.github_token` | block | prompt, tool_output, output, command | GitHub token | GitHub personal/OAuth/app tokens. Format-based. |
| `sec.slack_token` | block | prompt, tool_output, output, command | Slack token | Slack bot/user tokens. Format-based. |
| `sec.api_key_prefix` | block | prompt, tool_output, output, command | API key with a common secret-key prefix | Keys with a common 'sk-' style prefix and 32+ characters. Will not recognise providers with other formats. |
| `sec.provider_tokens` | block | prompt, tool_output, output, command | token in a well-known provider format (Google, SendGrid, npm, Mailgun, DB URL with password, Azure storage key, *_API_KEY=uuid; post-freeze: Stripe, Twilio, Hugging Face, bearer) | Google AIza keys, SendGrid SG., npm_, Mailgun key-, DB URLs with an inline password, Azure AccountKey=, *_API_KEY=<uuid>. Added from dev false negatives only: Stripe (sk_live_), Twilio, Hugging Face, bearer tokens and AWS secret keys were NOT added during evaluation and are known gaps. |
| `sec.jwt` | review | prompt, tool_output, output | JWT | Three-part base64url JWTs. Review-only: JWTs are often public or expired, but they can be live bearer credentials. |
| `sec.generic_assignment` | review | prompt, output | credential-looking assignment | `password = ...`, `DB_PASSWORD: ...`, `api_key=...` with a 12+ character value that contains a digit and is not a placeholder (`changeme`, `${...}`, `os.environ`, `****`). Heuristic and noisy by design, hence review-only. Not applied to commands, where it would flag ordinary env assignments. |
| `cmd.rm_rf_root_home` | block | command | recursive delete of root, home or current/parent directory | Recursive delete of /, ~, $HOME, . or .. . Deliberately narrow: `rm -rf node_modules` and `rm -rf ./build` pass. |
| `cmd.rm_rf_wrapped` | block | command | recursive delete of root or home hidden inside sh -c / eval | The same root/home delete hidden inside `sh -c '...'` or `eval '...'`. Needs the wrapper so `echo 'rm -rf /' > notes.txt` stays quiet. |
| `cmd.rm_rf_system_dir` | block | command | recursive delete of a top-level system directory or a service's data directory | `rm -rf /etc`, `/usr/lib`, `/boot/*`, `/home/*`, `/var/lib/<service>`. Top-level system directories and service data dirs only, so `rm -rf /var/lib/apt/lists/*` and `rm -rf /tmp/x` pass. |
| `cmd.pipe_to_shell` | block | command | executes downloaded or decoded code without looking at it (pipe, $(...), <(...), base64, PowerShell IEX) | Executing a remote script unseen (`curl ... | sh`). Two-step download-then-run on one line is covered by cmd.download_then_run; across separate commands it is not seen. |
| `cmd.disk_overwrite` | block | command | overwrites a disk or block device | dd/mkfs/shred or redirects onto block devices destroy data irrecoverably. |
| `cmd.fork_bomb` | block | command | fork bomb | The classic `:(){ :|:& };:` resource-exhaustion payload. |
| `cmd.chmod_777_recursive` | review | command | world-writable permissions | World-writable permissions are rarely intended. Review-only. |
| `cmd.git_force_protected` | block | command | force-push, delete or mirror-push of a protected branch | Force-push to main/master/prod/production/release rewrites shared history. `--force-with-lease` and feature branches pass. |
| `cmd.git_destructive` | review | command | discards uncommitted work or history | `reset --hard`, `clean -fd`, `checkout -- .`, `branch -D`, `stash drop/clear` discard uncommitted work. Review-only because they are routine for humans. |
| `cmd.sql_destructive` | block | command | destructive SQL / datastore command without a WHERE clause or scope | DROP TABLE/DATABASE/SCHEMA, TRUNCATE, or DELETE without a WHERE clause. |
| `cmd.infra_destroy` | review | command | destroys cloud or cluster resources | terraform destroy / auto-approve, kubectl delete ns/node/pv/crd, aws s3 rb/terminate-instances/delete-db, gcloud delete --quiet. Review-only so a human confirms. |
| `cmd.reverse_shell` | block | command | reverse shell pattern | nc -e, /dev/tcp, bash -i >&, python socket one-liners: remote access handed to an attacker. |
| `cmd.exfil_secrets` | block | command | sends credential files over the network | Sending ~/.ssh, ~/.aws, .env, .netrc, .npmrc, id_rsa and similar files over the network. |
| `cmd.read_credentials` | review | command | reads a credential file | Reading a credential file is not itself an attack, but it is the first step of most exfiltration, so a human should see it. |
| `cmd.secrets_piped_to_network` | block | command | pipes environment, history or credential material to a network tool | `env`, `history`, `/etc/shadow` or an archive of ~/.ssh piped into curl/wget/nc. Other pipelines (`env | grep PATH`) pass. |
| `cmd.archive_credential_dirs` | review | command | archives a credential directory (usual first step before exfiltration) | Archiving ~/.ssh, ~/.aws, ~/.gnupg is the usual staging step before exfiltration; review-only because backups exist. |
| `cmd.history_wipe` | review | command | erases shell or audit history | Clearing shell or audit history hides what an agent did. Review-only. |
| `cmd.persistence_privesc` | block | command | adds a backdoor or escalates privileges (sudoers, uid 0 user, setuid bit, password reset) | Writes to /etc/sudoers, /etc/crontab, /etc/passwd, setuid on a binary, a second uid-0 user, chpasswd. Persistence and privilege escalation have no place in an agent session. |
| `cmd.authorized_keys_append` | review | command | appends an SSH key to authorized_keys | Appending a key to authorized_keys grants login. Review-only because setting up your own SSH access is routine. |
| `cmd.disable_security_service` | block | command | stops a firewall or audit service | Stopping firewalld/ufw/auditd/apparmor/fail2ban removes a defensive control. Known gap: setenforce 0 and iptables -F are not covered. |
| `cmd.miner_or_power` | review | command | crypto miner, forced power-off, or reverse SSH tunnel | xmrig/stratum miners, forced reboot/halt, sysrq, and `ssh -R` reverse tunnels. Review-only: rare in dev work but not always malicious. |
| `cmd.disable_guard` | block | command | tries to stop or remove a guardrail | An agent must not be able to stop or remove its own guardrail. Known false positive: any `rm` whose arguments contain `laya-guard` or `laya_guard` (for example cleaning a build directory in this repo) also matches. |
| `cmd.find_delete_root` | block | command | find over / or ~ with no name filter that deletes everything it matches | `find / -delete` / `find ~ -exec rm` with no name filter wipes everything. Filtered finds (`find . -name '*.pyc' -delete`) pass. Added from the evaluation (known evasion of cmd.rm_rf_root_home). |
| `cmd.rm_rf_variable_root` | block | command | recursive delete through a variable that was just set to / or the home directory | `DIR=/; rm -rf "$DIR/"`: the same destructive delete hidden behind a variable set on the same line. Only fires when the variable was just assigned / or ~; later-defined variables are not tracked. |
| `cmd.download_then_run` | review | command | downloads a file and executes it in the same command line (two-step curl | sh) | Two-step `curl -o x.sh && sh x.sh` (or chmod +x then run) on one line, the cheap evasion of cmd.pipe_to_shell. Review-only because official installers legitimately do this; a download in one command and execution in the next is not seen. |
| `obf.unicode_tags` | block | prompt, tool_output | Unicode tag characters (invisible text smuggling) | Tag characters U+E0000-E007F render as nothing to a human but are readable by a model. Four or more is treated as smuggling. Other rules run on text with these characters stripped. |
| `obf.invisible_chars` | review | prompt, tool_output | many zero-width / bidi control characters | Zero-width and bidi control characters in bulk. Review-only (a few are normal in some scripts). |
<!-- RULES:END -->

## Design stance

- Rules block narrowly and flag generously. A false block on a coding agent costs more trust than a
  flag, so destructive-command rules target unambiguous forms (`rm -rf /`, not `rm -rf build`).
- Every rule is a regular expression. Anything an attacker can rephrase, split across turns,
  translate, encode or paraphrase will slip past. See `threat-model.md` for the evasion list.
- To change a rule, edit `src/laya_guard/rules.py`, add a positive and a negative test, then run
  `python scripts/sync_rules_doc.py`.
