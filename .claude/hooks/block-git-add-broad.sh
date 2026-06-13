#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# Claude Code PreToolUse:Bash hook — block broad `git add` / `git stage` targets.
#
# Reads the JSON event payload from stdin and inspects ONLY `.tool_input.command`.
# Mirrors the pattern in block-force-push.sh: previous attempts using settings.json
# `if:` clauses (`if: "Bash(git add .:*)"`) did NOT actually gate by command content
# — that syntax is for permission rules, not hooks. The clauses were silently ignored
# and the hook fired on every Bash call. This script restores correct gating.
#
# Hardened against bypass prefixes (2026-06-12):
#   - `git -C <dir> add .` / `git -c key=val add .` (global option prefixes,
#     spaced or attached form) — common in the worktree-heavy workflow
#   - `command git add .` (leading `command` builtin)
#   - `GIT_DIR=x git add .` (leading VAR=value environment assignments)
#   - `git stage .` (stage is a built-in alias for add)
#   - broad targets `./`, `:/`, `*`, and combined short flags containing A (`-Av`)
#
# Fail-open: anything this parser cannot understand is allowed (exit 0) — this is
# a developer guardrail, not an adversarial security boundary.
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

# Skip only when the payload explicitly names a different tool. (The settings.json
# matcher already scopes this hook to Bash; an absent tool_name is treated as Bash.)
if [ -n "$tool_name" ] && [ "$tool_name" != "Bash" ]; then
	exit 0
fi

if [ -z "$command_str" ]; then
	exit 0
fi

# Evaluate one shell statement: does it invoke `git add`/`git stage` with a broad
# target? Tolerates leading env assignments, `command`, and git global options.
stmt_is_broad_git_add() {
	local stmt="$1"
	local -a words
	IFS=' 	' read -ra words <<<"$stmt" || return 1
	local n=${#words[@]}
	local i=0 w
	# Skip leading `command` and VAR=value environment assignments.
	while [ "$i" -lt "$n" ]; do
		w="${words[$i]}"
		if [ "$w" = "command" ]; then
			i=$((i + 1))
			continue
		fi
		if printf '%s' "$w" | grep -Eq '^[A-Za-z_][A-Za-z_0-9]*='; then
			i=$((i + 1))
			continue
		fi
		break
	done
	[ "$i" -lt "$n" ] || return 1
	[ "${words[$i]}" = "git" ] || return 1
	i=$((i + 1))
	# Skip git global options before the subcommand (-C <path>, -c <key=val>, ...).
	while [ "$i" -lt "$n" ]; do
		w="${words[$i]}"
		case "$w" in
		-C | -c | --git-dir | --work-tree | --namespace | --exec-path)
			i=$((i + 2))
			continue
			;;
		-C?* | -c?* | --git-dir=* | --work-tree=* | --namespace=* | --exec-path=* | -p | --paginate | -P | --no-pager | --no-replace-objects | --literal-pathspecs | --glob-pathspecs | --noglob-pathspecs | --icase-pathspecs | --no-optional-locks)
			i=$((i + 1))
			continue
			;;
		*) break ;;
		esac
	done
	[ "$i" -lt "$n" ] || return 1
	case "${words[$i]}" in
	add | stage) ;;
	*) return 1 ;;
	esac
	i=$((i + 1))
	# Scan the arguments for broad targets.
	while [ "$i" -lt "$n" ]; do
		w="${words[$i]}"
		case "$w" in
		. | ./ | :/ | \*) return 0 ;;                       # whole-tree pathspecs / glob
		-A | --all) return 0 ;;                             # explicit all flags
		--) ;;                                              # pathspec separator — keep scanning
		--*) ;;                                             # other long options — not broad
		-[A-Za-z]*)                                         # combined short flags, e.g. -Av
			case "$w" in *A*) return 0 ;; esac
			;;
		esac
		i=$((i + 1))
	done
	return 1
}

matches_broad_git_add() {
	local cmd="$1"
	local stmts
	stmts="$(printf '%s' "$cmd" | sed -E 's/(\|\||&&|;|\||&)/\n/g')"
	while IFS= read -r stmt; do
		stmt="$(printf '%s' "$stmt" | sed -E 's/^[[:space:]]*//; s/^(\$\(|`|\()//')"
		[ -n "$stmt" ] || continue
		if stmt_is_broad_git_add "$stmt"; then
			return 0
		fi
	done <<<"$stmts"
	return 1
}

if matches_broad_git_add "$command_str"; then
	echo "Use specific file paths with git add. Avoid '.', './', ':/', '*', '-A', and '--all' to prevent staging sensitive or unintended files." 1>&2
	exit 2
fi

exit 0
