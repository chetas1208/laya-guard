# Security policy

## Reporting

Please report vulnerabilities and bypasses privately, not in a public issue:

- GitHub: use "Report a vulnerability" under the Security tab of https://github.com/chetas1208/laya-guard
  (private advisory), or
- open a minimal public issue titled "security contact request" with no details and the maintainer
  will move the conversation to a private channel.

Include: the input, the `kind`, the laya-guard version and commit, the config, and the verdict you
got versus the one you expected. Expect an acknowledgement within a few days; this is a
single-maintainer project and there is no bug bounty.

## Scope

In scope:
- crashes, hangs or catastrophic regex backtracking (ReDoS) on crafted input;
- the CLI, hook adapters and installer scripts doing something unsafe (command injection through
  hook input, unsafe file writes, fail-open where the docs promise fail-closed);
- a verdict or exit code that contradicts the documented contract;
- secrets or sensitive input leaking into verdict output, logs or temp files.

Out of scope, because they are known and documented limits (still welcome as test cases, as a
normal issue or pull request):
- bypasses of regex rules by paraphrase, translation, encoding, multi-turn splitting or assembled commands;
- Laya's classification errors, over-confidence or lack of robustness (upstream: https://github.com/NandhaKishorM/laya);
- vulnerabilities in third-party agents, in torch, or in the Laya package itself;
- an agent or user who has write access to the hook configuration disabling the guard.

## Known bypass classes

laya-guard is a speed bump, not a security boundary. These classes get through today:

1. Multi-turn attacks: each call is judged in isolation.
2. Non-English text: rules are English regexes; Laya is unvalidated outside English.
3. Encoded payloads: base64, hex, rot13, URL-encoding; text in images or PDFs.
4. Semantic paraphrase with none of the trigger vocabulary.
5. Split or assembled commands: variables, `eval`, scripts, Makefiles, package hooks, two-step download then run.
6. Credential formats not in the rule list.
7. Input beyond `max_chars` (default 200000 characters) is not inspected.
8. Tools the hooks do not match, and agents allowed to edit their own hook configuration.
9. Adaptive attackers who can observe verdicts and iterate.

Defence in depth is expected: least privilege, sandboxing, scoped credentials, and human approval for
irreversible actions. Details: `skills/laya-guard/references/threat-model.md`.

## Supported versions

Only the latest release on the default branch receives fixes.
