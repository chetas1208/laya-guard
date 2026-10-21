# Gemini CLI and Google Antigravity

What is verified here and what is not:

| Piece | Status |
|---|---|
| `laya-guard hook --agent gemini` adapter | Tested in this repo against a synthetic `BeforeTool` event for `run_shell_command` (exit 2 plus `{"decision":"deny"}` on block). |
| `settings.hooks.json` is valid JSON and runs the adapter | Tested. |
| That your Gemini CLI version reads this schema | **Verify against your version.** |
| Antigravity hook support and file locations | **Verify against your version.** Not tested. |

## Rules file (works everywhere)

Copy `GEMINI.md` into your project root (or `~/.gemini/GEMINI.md`). This makes the model follow the
protocol; it does not enforce anything by itself. For tools that read `AGENTS.md`, use
`../generic/AGENTS.md` instead.

## Skill

Gemini CLI supports Agent Skills in recent versions (**verify against your version**). If yours does:

```bash
mkdir -p ~/.gemini/skills && cp -R skills/laya-guard ~/.gemini/skills/laya-guard
```

`scripts/install.sh` does this automatically when `~/.gemini` exists.

## BeforeTool hook

`settings.hooks.json` is meant to be merged into `~/.gemini/settings.json` or
`.gemini/settings.json`. Assumptions to verify against the Gemini CLI hooks documentation for your version:

- hooks are enabled in your settings (older builds had an experimental flag, such as `tools.enableHooks`, that had to be switched on);
- the event name is `BeforeTool` and the matcher is a regex on the tool name; the shell tool is `run_shell_command`;
- `timeout` is in milliseconds;
- the hook receives JSON on stdin with `hook_event_name`, `tool_name`, `tool_input`;
- exit code 2 blocks the tool call and the stderr text is reported back to the model.

The adapter prints `{"decision":"deny","reason":...}` on stdout and exits 2 on block, so it works
under either a JSON-decision or an exit-code reading of the contract.

Limits:

- Only shell commands are checked, with severity `review` also denied (Gemini has no "ask" in this
  adapter, so a review is treated as a deny). Raise the matcher or add tools yourself if needed.
- No `AfterTool` adapter ships yet, so untrusted tool output is covered only by the rules file
  (model discipline), not by a hook. For output you can check manually:
  `laya-guard check --kind tool_output --file page.txt`.
- A missing `laya-guard` binary makes the hook fail with a non-2 code, which Gemini likely treats as non-blocking. Use
  `laya-guard hook --agent gemini --strict || exit 2` for fail-closed behaviour.
