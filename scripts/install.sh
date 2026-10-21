#!/usr/bin/env bash
# Install laya-guard from this checkout. Idempotent, no sudo, no Docker.
#
#   scripts/install.sh                 pip install -e . ; copy the skill to ~/.claude/skills and ~/.gemini/skills
#   scripts/install.sh --with-laya     also install the optional Laya model extra ('.[laya]', pulls torch)
#   scripts/install.sh --no-skill      only the Python package
#   scripts/install.sh --skip-pip      only the skill copies
#   scripts/install.sh --dry-run       print what would happen
#
# Environment: PYTHON (default python3), CLAUDE_HOME (default ~/.claude), GEMINI_HOME (default ~/.gemini)
# A skill is installed only if its parent directory (~/.claude, ~/.gemini) already exists, so this
# never creates tooling directories for agents you do not use.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
py="${PYTHON:-python3}"
extra=""; do_skill=1; do_pip=1; dry=0

for arg in "$@"; do
  case "$arg" in
    --with-laya) extra="[laya]" ;;
    --no-skill)  do_skill=0 ;;
    --skip-pip)  do_pip=0 ;;
    --dry-run)   dry=1 ;;
    -h|--help)   sed -n '2,11p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

run() { if [ "$dry" = 1 ]; then echo "[dry-run] $*"; else "$@"; fi; }

echo "laya-guard install (repo: $repo)"

if [ "$do_pip" = 1 ]; then
  echo "- pip: editable install ${extra:+with extra $extra}"
  run "$py" -m pip install --quiet -e "$repo$extra"
  [ "$dry" = 1 ] || echo "  installed: $("$py" -m laya_guard.cli --version 2>/dev/null || echo 'version check failed')"
fi

install_skill() {
  local agent="$1" home="$2"
  if [ ! -d "$home" ]; then
    echo "- skill: skipped $agent ($home does not exist)"
    return
  fi
  local dest="$home/skills/laya-guard"
  if [ "$dry" = 1 ]; then echo "[dry-run] copy $repo/skills/laya-guard -> $dest"; return; fi
  mkdir -p "$home/skills"
  rm -rf "$dest"
  cp -R "$repo/skills/laya-guard" "$dest"
  echo "- skill: installed for $agent at $dest"
}

if [ "$do_skill" = 1 ]; then
  install_skill "Claude Code" "${CLAUDE_HOME:-$HOME/.claude}"
  install_skill "Gemini CLI"  "${GEMINI_HOME:-$HOME/.gemini}"
fi

cat <<MSG

Not done automatically (do these deliberately):
- hooks: merge integrations/claude-code/settings.hooks.json (Claude Code) or integrations/gemini/settings.hooks.json (Gemini CLI) into your settings.json
- Cursor: cp integrations/cursor/laya-guard.mdc .cursor/rules/
- git:    cp integrations/git/pre-commit .git/hooks/pre-commit
- Laya:   re-run with --with-laya to enable the optional model (rules work without it)
MSG
