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

# Only apply to Bash tool calls.
if [ "$tool_name" != "Bash" ]; then
	exit 0
fi

# Empty / missing command — nothing to evaluate.
if [ -z "$command_str" ]; then
	exit 0
fi

# Match force-push patterns. We require:
#   1) The command starts with (or contains a pipeline/&&/; leading to) `git`
#      followed by `push`, then a force flag in actual argument position.
#   2) The force flag must be a real argument — not inside quotes / part of an
#      echo. We approximate this by anchoring on shell-statement boundaries
#      (start of string, `;`, `&&`, `||`, `|`, or a backtick/$( opener).
#
# Force flags we consider destructive:
#   --force, --force-with-lease, --force-if-includes, -f
#
# Use grep -E with a Perl-ish style. Pattern explanation:
#   (^|[;&|`(])  — start of a command statement
#   [[:space:]]*git[[:space:]]+push\b  — `git push` as a word
#   [^;&|]*       — same statement (no statement terminator)
#   ([[:space:]](--force(-with-lease|-if-includes)?|-f)\b|[[:space:]]-[A-Za-z]*f[A-Za-z]*\b)?
#
# Simpler split: first check `git push` invocation boundary, then look for the
# force flag in the same statement.

# Extract candidate `git push ...` statement segments (up to next ; && || or |).
# Then check each segment for a force flag in word position.
matches_force_push() {
	local cmd="$1"
	# Split on shell statement terminators. We treat ;, &&, ||, |, &, and
	# newlines as statement boundaries. Backslash-escapes are not handled —
	# adversarial input is out of scope; this is a developer guardrail.
	local IFS=$'\n'
	local stmts
	# Replace separators with newlines using tr-style sed.
	stmts="$(printf '%s' "$cmd" | sed -E 's/(\|\||&&|;|\||&)/\n/g')"
	while IFS= read -r stmt; do
		# Trim leading whitespace and common subshell openers `$(`, `` ` ``, `(`.
		stmt="$(printf '%s' "$stmt" | sed -E 's/^[[:space:]]*//; s/^(\$\(|`|\()//')"
		# Match: starts with `git push` (whitespace tolerant), then has a force
		# flag as a standalone word.
		if printf '%s' "$stmt" | grep -Eq '^git[[:space:]]+push([[:space:]]|$)'; then
			if printf '%s' "$stmt" | grep -Eq '([[:space:]]|^)(--force(-with-lease|-if-includes)?|-f)([[:space:]=]|$)'; then
				return 0
			fi
		fi
	done <<<"$stmts"
	return 1
}

if matches_force_push "$command_str"; then
	echo "Force push blocked. This rewrites history and breaks clones/forks. Use git push (without --force) or discuss with the user first." 1>&2
	exit 2
fi

exit 0
