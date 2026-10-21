# Threat model

laya-guard is a **speed bump with a paper trail**, not a security boundary. It catches common,
unsophisticated attacks and obvious mistakes cheaply. A determined, adaptive attacker will get past
regular expressions and a 0.7-accuracy classifier. Use it alongside least privilege, sandboxing,
human approval for irreversible actions, and secret scoping.

## Covered (to the degree rules can cover them)

| Threat | Where it enters | Check | Rules |
|---|---|---|---|
| Direct prompt injection / jailbreak | user prompt entering a pipeline | `--kind prompt` | `inj.ignore_previous`, `inj.role_override`, `inj.dan_mode`, `inj.chat_template_tokens`, `inj.reveal_system_prompt` |
| Indirect injection via tools | web pages, files, MCP/API results, email read by an agent | `--kind tool_output` | `inj.agent_addressed`, `inj.hidden_instruction_comment`, `inj.do_not_tell_user`, plus the `inj.*` set |
| Hidden-text smuggling | zero-width, bidi, Unicode tag characters | automatic on prompt and tool_output | `obf.unicode_tags`, `obf.invisible_chars`; text is normalized before matching |
| Secret exposure | prompts, model replies, tool output, commits | `--kind output` / `prompt` | `sec.*` |
| Destructive commands | an agent about to run shell | `--kind command` | `cmd.rm_rf_root_home`, `cmd.disk_overwrite`, `cmd.sql_destructive`, `cmd.git_force_protected`, `cmd.git_destructive`, `cmd.infra_destroy`, `cmd.fork_bomb`, `cmd.chmod_777_recursive` |
| Remote code and shells | commands fetched or constructed by an agent | `--kind command` | `cmd.pipe_to_shell`, `cmd.reverse_shell` |
| Exfiltration | commands that send credential files; markdown-image beacons | `command`, `tool_output`, `output` | `cmd.exfil_secrets`, `cmd.read_credentials`, `inj.exfil_markdown_image` |
| Tampering with the guard | agent tries to kill or delete it | `--kind command` | `cmd.disable_guard`, `cmd.history_wipe` |

Laya adds an advisory probability for `prompt`, `tool_output` and `output` text. It does not see commands.

## Not covered, or easily evaded

Treat each of these as an open hole unless you add another control.

1. **Multi-turn attacks.** Each call is checked in isolation. An attack spread over several turns,
   or built up in memory or a scratch file, is invisible.
2. **Non-English text.** Rules are English regexes. Laya has not been validated on other languages.
3. **Encoded payloads.** Base64, hex, rot13, URL-encoding, ciphers, or text inside images and PDFs
   scans as noise. A model that decodes it later will follow it.
4. **Semantic paraphrase.** "Kindly set aside what you were told earlier" has no keyword. Only the
   advisory classifier might notice, at about 0.71-0.76 accuracy.
5. **Split payloads.** A command or instruction assembled from pieces (variables, concatenation,
   `eval`, here-docs, two-step download then run) is not matched. `rm -rf "$DIR/"` with `DIR=/`
   passes.
6. **Indirect commands.** Destructive effects through scripts, Makefiles, package hooks, `find
   -delete`, `python -c "shutil.rmtree('/')"` and similar are mostly not recognised.
7. **Unknown secret formats.** Only listed prefixes and generic `key = value` shapes are caught.
8. **Truncation.** Input beyond `max_chars` (200000 by default) is not inspected.
9. **Tool coverage.** Hooks only see the tools you matched. An agent with an unmatched tool,
   or one that can edit its own settings, can bypass the hook. Lock the settings file.
10. **Rule false positives.** For example `cmd.disable_guard` also matches any `rm` whose arguments
    contain `laya-guard`. Expect some noise; review it rather than disabling rules.
11. **Adaptive attackers.** Anyone who can probe the guard can iterate until it passes. Do not
    expose verdicts or rule ids to untrusted parties.

## Trust assumptions

- The operator and the user are trusted to configure and override the guard. The guard defends the
  agent against **content**, not against the person at the keyboard.
- The process running the guard is trusted. A compromised host defeats it.
- Hook configuration is not protected by laya-guard itself.

## Failure behaviour

- Rules cannot "fail": they are pure regexes.
- Laya unavailable with `laya.enabled: "auto"`: rules continue, `laya.status` says `unavailable`.
  With `enabled: true` or `required: true`: decision is at least `review`.
- Hook payload unreadable: allowed by default, exit 2 with `--strict`.
- The CLI crashing (exit code other than 0/10/20) must be treated as not-allow by callers.
- A missing `laya-guard` binary makes a hook command exit 127, which most agents treat as a
  non-blocking error. Use the `strict` hook variants (`|| exit 2`) when you want fail-closed.
