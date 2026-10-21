# Hook adapters: formats and caveats

`laya-guard hook --agent <claude-code|gemini|generic>` reads one JSON event on stdin and answers in
the agent's format. This page records what the adapters assume, and how sure we are.

| Agent | Event | Input fields used | Output on block | Confidence |
|---|---|---|---|---|
| claude-code | `PreToolUse` (tool `Bash`) | `tool_name`, `tool_input.command` | stdout `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":...}}`, exit 0; `review` uses `"ask"` | Matches the Claude Code hooks reference as understood at writing; tested against synthetic events only |
| claude-code | `PostToolUse` | `tool_name`, `tool_response` | stdout `additionalContext` note telling the model to treat the result as untrusted data (the result is not removed) | same |
| claude-code | `UserPromptSubmit` | `prompt` | block: `{"decision":"block","reason":...}`; review: `additionalContext` | same |
| gemini | `BeforeTool` (tool `run_shell_command`) | `tool_name`, `tool_input.command` | stdout `{"decision":"deny","reason":...}` and stderr reason, exit 2; review is also denied | Not verified against a live Gemini CLI. Verify against your version |
| generic | any | `{"kind": ..., "text": ...}` | stdout full verdict JSON, exit 0/10/20 | Our own contract |

## Exit-code semantics worth knowing

- Claude Code: exit 0 reads stdout JSON; exit 2 blocks (stderr to the model); other non-zero is a
  non-blocking error, so a missing or crashing `laya-guard` lets the action through. Use the strict
  snippet (`--strict || exit 2`) for fail-closed.
- Gemini CLI: exit 2 blocks with stderr; the same fail-open caveat applies to other codes. Verify.
- Hooks start a new process per event. Laya would reload on every call, so snippets default to `--no-laya`.

## Known gaps

- No `AfterTool` adapter for Gemini, so Gemini tool output is covered by the rules file only.
- Only shell commands are screened pre-execution; file-edit tools are not (secrets in a written file
  are caught by the git pre-commit hook instead).
- Hooks protect nothing if the agent may edit its own settings file. Deny that in the agent's permissions.
