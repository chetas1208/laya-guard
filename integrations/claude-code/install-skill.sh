#!/usr/bin/env bash
# Install the laya-guard skill for Claude Code.
#   integrations/claude-code/install-skill.sh            -> ~/.claude/skills/laya-guard (all projects)
#   integrations/claude-code/install-skill.sh --project  -> ./.claude/skills/laya-guard (this project)
# Idempotent: re-running replaces the installed copy. No sudo.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
src="$here/../../skills/laya-guard"

if [ "${1:-}" = "--project" ]; then
  dest_root="$PWD/.claude/skills"
else
  dest_root="${CLAUDE_HOME:-$HOME/.claude}/skills"
fi

[ -f "$src/SKILL.md" ] || { echo "laya-guard skill not found at $src" >&2; exit 1; }

mkdir -p "$dest_root"
rm -rf "$dest_root/laya-guard"
cp -R "$src" "$dest_root/laya-guard"
echo "installed skill: $dest_root/laya-guard"
echo "hooks are separate: merge integrations/claude-code/settings.hooks.json into your settings.json (see README.md there)"
