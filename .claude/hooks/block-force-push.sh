#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# Claude Code PreToolUse:Bash hook — block destructive `git push --force`.
#
# Reads the JSON event payload from stdin and inspects ONLY `.tool_input.command`.
# Never matches against stdout, script content, or other parts of the payload —
# false positives (e.g. `npm run report:qa` triggering this hook) were caused by
# unscoped matching in earlier settings.json `if:` clauses.
#
# Hardened against bypass prefixes (2026-06-12):
#   - `git -C <dir> push --force` / `git -c key=val push -f` (global option
#     prefixes, spaced or attached form) — common in the worktree-heavy workflow
#   - `command git push -f` (leading `command` builtin)
#   - `GIT_DIR=x git push --force` (leading VAR=value environment assignments)
#   - refspec force: `git push origin +main` (refspec starting with +)
#   - combined short flags containing f (e.g. `-uf`)
#
# Fail-open: anything this parser cannot understand is allowed (exit 0) — this is
# a developer guardrail, not an adversarial security boundary.
#
# Exit codes (Claude Code convention):
#   0 — allow the tool call
#   2 — block; stderr is surfaced to the model as the stop reason

set -u

# Read the payload (small, bounded).
payload="$(cat)"

# Extract tool_name and tool_input.command. Use jq if present; fall back to
# permissive shell parsing so the hook still works in stripped environments.
if command -v jq >/dev/null 2>&1; then
	tool_name="$(printf '%s' "$payload" | jq -r '.tool_name // empty')"
	command_str="$(printf '%s' "$payload" | jq -r '.tool_input.command // empty')"
else
	# Minimal fallback — extracts the first .tool_input.command string. Best-effort only.
	tool_name="$(printf '%s' "$payload" | sed -n 's/.*"tool_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
	command_str="$(printf '%s' "$payload" | sed -n 's/.*"command"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
fi

# Skip only when the payload explicitly names a different tool. (The settings.json
# matcher already scopes this hook to Bash; an absent tool_name is treated as Bash.)
if [ -n "$tool_name" ] && [ "$tool_name" != "Bash" ]; then
	exit 0
fi

# Empty / missing command — nothing to evaluate.
if [ -z "$command_str" ]; then
	exit 0
fi

# Evaluate one shell statement: does it invoke `git push` with a force flag or a
# force refspec? Tolerates leading env assignments, `command`, and git global options.
stmt_is_force_push() {
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
	[ "${words[$i]}" = "push" ] || return 1
	i=$((i + 1))
	# Scan the arguments for force flags and force refspecs.
	while [ "$i" -lt "$n" ]; do
		w="${words[$i]}"
		case "$w" in
		-f | --force | --force-with-lease | --force-with-lease=* | --force-if-includes) return 0 ;;
		+*) return 0 ;;                                     # refspec force, e.g. +main
		--) ;;                                              # separator — keep scanning
		--*) ;;                                             # other long options — not force
		-[A-Za-z]*)                                         # combined short flags, e.g. -uf
			case "$w" in *f*) return 0 ;; esac
			;;
		esac
		i=$((i + 1))
	done
	return 1
}

# Split the command on shell statement terminators (;, &&, ||, |, &, newlines)
# and check each statement. Backslash escapes are not handled — adversarial
# input is out of scope; this is a developer guardrail.
matches_force_push() {
	local cmd="$1"
	local stmts
	stmts="$(printf '%s' "$cmd" | sed -E 's/(\|\||&&|;|\||&)/\n/g')"
	while IFS= read -r stmt; do
		# Trim leading whitespace and common subshell openers `$(`, `` ` ``, `(`.
		stmt="$(printf '%s' "$stmt" | sed -E 's/^[[:space:]]*//; s/^(\$\(|`|\()//')"
		[ -n "$stmt" ] || continue
		if stmt_is_force_push "$stmt"; then
			return 0
		fi
	done <<<"$stmts"
	return 1
}

if matches_force_push "$command_str"; then
	echo "Force push blocked. This rewrites history and breaks clones/forks. Use git push (without --force) or discuss with the user first." 1>&2
	exit 2
fi

exit 0
