# Claude Code

Two independent pieces. Use either or both.

1. **Skill** (the model reads the protocol and runs `laya-guard check` itself).
2. **Hooks** (the harness runs the check automatically; the model cannot skip it).

Hooks are the stronger control because they do not depend on the model remembering anything.

## Install the skill

```bash
integrations/claude-code/install-skill.sh              # ~/.claude/skills/laya-guard
integrations/claude-code/install-skill.sh --project    # ./.claude/skills/laya-guard
```

## Install the hooks

Prerequisite: `laya-guard` on the PATH used by Claude Code (`pip install -e .` from this repo).
Merge `settings.hooks.json` into `~/.claude/settings.json` (user) or `.claude/settings.json`
(project). If you already have a `hooks` object, merge the three event arrays rather than
replacing them.

| Event | Matcher | What laya-guard does |
|---|---|---|
| `UserPromptSubmit` | (none) | `prompt` check. A rule `block` blocks the prompt; `review` adds a note for the model. |
| `PreToolUse` | `Bash` | `command` check. `block` becomes permission `deny`, `review` becomes `ask` (the user is prompted). |
| `PostToolUse` | `WebFetch\|WebSearch\|Read\|mcp__.*` | `tool_output` check. If flagged, adds a note telling the model to treat the result as untrusted data. The result itself is not removed. |

Notes:

- The adapter uses the hook JSON on stdin (`hook_event_name`, `tool_name`, `tool_input`,
  `tool_response`, `prompt`) and answers with `hookSpecificOutput.permissionDecision`
  (PreToolUse) or `decision: "block"` (UserPromptSubmit). This matches the Claude Code hooks
  reference at the time of writing; verify against your version at https://docs.claude.com/en/docs/claude-code/hooks
- A hook is a new process per call, so it never loads the Laya model itself. Start `laya-guard serve`
  once (keeps the model warm on a user-only unix socket) and hooks use it automatically (about 0.2-0.3 s
  per prompt check); with no daemon running they fall back to rules only. Add `--no-laya` to force rules only.
- `PostToolUse` cannot undo a tool call that already ran; it can only warn the model. Use
  `PreToolUse` for anything that must be prevented.
- Only the matched tools are checked. Add other tool names to the matcher if you use them.

### Fail-open vs fail-closed

Claude Code treats a hook that exits with a code other than 0 or 2 as a non-blocking error, and
exit 2 as blocking. So if `laya-guard` is missing or crashes (exit 127 or 1), the default snippet
**lets the action through**. `settings.hooks.strict.json` appends `--strict || exit 2` so a missing
binary, a crash or an unreadable payload blocks instead. Strict mode will block every matched
action while laya-guard is broken, which is the point and also an annoyance; pick deliberately.

### Protect the hook itself

An agent that can edit `.claude/settings.json` can remove the hook. Deny it in permissions, for example:

```json
{ "permissions": { "deny": ["Edit(.claude/settings*.json)", "Write(.claude/settings*.json)"] } }
```

and keep user-level `~/.claude/settings.json` outside the agent's writable area where possible.
(`cmd.disable_guard` catches only crude `rm`/`kill` attempts.)

### Test it

```bash
echo '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' \
  | laya-guard hook --agent claude-code
# -> {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", ...}}
```
