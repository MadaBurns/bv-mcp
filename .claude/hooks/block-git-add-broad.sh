#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# Claude Code PreToolUse:Bash hook — block `git add .` / `git add -A` / `git add --all`.
#
# Reads the JSON event payload from stdin and inspects ONLY `.tool_input.command`.
# Mirrors the pattern in block-force-push.sh: previous attempts using settings.json
# `if:` clauses (`if: "Bash(git add .:*)"`) did NOT actually gate by command content
# — that syntax is for permission rules, not hooks. The clauses were silently ignored
# and the hook fired on every Bash call. This script restores correct gating.
#
# Exit codes (Claude Code convention):
#   0 — allow the tool call
#   2 — block; stderr is surfaced to the model as the stop reason

set -u

payload="$(cat)"

if command -v jq >/dev/null 2>&1; then
	tool_name="$(printf '%s' "$payload" | jq -r '.tool_name // empty')"
	command_str="$(printf '%s' "$payload" | jq -r '.tool_input.command // empty')"
else
	tool_name="$(printf '%s' "$payload" | sed -n 's/.*"tool_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
	command_str="$(printf '%s' "$payload" | sed -n 's/.*"command"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
fi

if [ "$tool_name" != "Bash" ]; then
	exit 0
fi

if [ -z "$command_str" ]; then
	exit 0
fi

# Match `git add <broad-target>` only when the target is a word-position argument
# (not inside an echo string, not a path that happens to start with `.`).
matches_broad_git_add() {
	local cmd="$1"
	local IFS=$'\n'
	local stmts
	stmts="$(printf '%s' "$cmd" | sed -E 's/(\|\||&&|;|\||&)/\n/g')"
	while IFS= read -r stmt; do
		stmt="$(printf '%s' "$stmt" | sed -E 's/^[[:space:]]*//; s/^(\$\(|`|\()//')"
		if printf '%s' "$stmt" | grep -Eq '^git[[:space:]]+add([[:space:]]|$)'; then
			# Broad targets: `.` `-A` `--all` as a standalone argument.
			if printf '%s' "$stmt" | grep -Eq '([[:space:]])(\.|-A|--all)([[:space:]]|$)'; then
				return 0
			fi
		fi
	done <<<"$stmts"
	return 1
}

if matches_broad_git_add "$command_str"; then
	echo "Use specific file paths with git add. Avoid '.', '-A', and '--all' to prevent staging sensitive or unintended files." 1>&2
	exit 2
fi

exit 0
