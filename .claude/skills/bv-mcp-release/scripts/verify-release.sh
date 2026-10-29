#!/usr/bin/env bash
# verify-release.sh <X.Y.Z> [--before-publish] [--probes N]
#
# Post-deploy check for a bv-mcp release, run against the LIVE service (no repo state is read).
# Replaces the probe script that used to be re-improvised for every release.
#
# Checks, each printed as PASS/FAIL:
#   1. serverInfo.version == X.Y.Z on both hosts, N probes each (a mixed result = still propagating)
#   2. an unknown tool argument is rejected ("unknown argument(s)"). If the anonymous quota for this
#      IP is spent (JSON-RPC -32029) the probe is retried once on an authenticated session when a key
#      is available (BV_VERIFY_KEY, else BV_INTERNAL_DEV_KEY from the main checkout's .dev.vars);
#      with no key it reports SKIP, not FAIL — a spent quota says nothing about the release.
#   3. tools/list: every tool publishes additionalProperties:false, and the tool count equals the
#      "N MCP tools" claim in serverInfo.description
#   4. MCP Registry /versions/latest == X.Y.Z, active, isLatest       (skipped with --before-publish)
#   5. GitHub Release vX.Y.Z exists and is not a draft                 (skipped with --before-publish)
#
# Limits — read before citing a PASS:
#   - Anonymous tier only, except check 2's quota fallback, which only re-asks the same question
#     authenticated and prints the tier the key resolved to (x-quota-tier; owner also needs the egress
#     IP on the owner allowlist — measured 2026-10-29 resolving owner on BOTH hosts). It proves nothing
#     about owner/paid tools, auth or quotas. The key is passed to curl via a mode-600 header file and
#     is never printed or put on a command line.
#   - It does not measure scoring or any check's correctness; a behaviour probe for the release's
#     actual change is still yours to run.
#   - Registry reads are CDN-cached; a cache-buster is sent, but a FAIL seconds after publishing
#     can be a stale edge. Re-run before acting on it.
#   - The GitHub Release is cut by publish.yml ~15 min after the tag push; a FAIL inside that
#     window is expected (gh run list --workflow publish.yml).
#
# Exit: 0 all PASS, 1 any FAIL, 2 usage or missing prerequisite. bash 3.2 / macOS safe.

set -u
VERSION="${1:-}"
case "$VERSION" in [0-9]*.[0-9]*.[0-9]*) ;; *) echo "usage: $0 <X.Y.Z> [--before-publish] [--probes N]" >&2; exit 2;; esac
shift
BEFORE_PUBLISH=0
PROBES=3
while [ $# -gt 0 ]; do
	case "$1" in
	--before-publish) BEFORE_PUBLISH=1 ;;
	--probes) shift; PROBES="${1:-3}" ;;
	*) echo "unknown option: $1" >&2; exit 2 ;;
	esac
	shift
done
for bin in curl node; do command -v "$bin" >/dev/null 2>&1 || { echo "missing prerequisite: $bin" >&2; exit 2; }; done

HOSTS="https://dns-mcp.blackveilsecurity.com https://bv-dns-security-mcp.bv-edge.workers.dev"
REGISTRY="https://registry.modelcontextprotocol.io/v0/servers/com.blackveilsecurity%2Fdns/versions/latest"
REPO="MadaBurns/bv-mcp"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
FAILS=0
SKIPS=0
pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; FAILS=$((FAILS + 1)); }
skip() { printf 'SKIP  %s\n' "$1"; SKIPS=$((SKIPS + 1)); }

# Optional key for check 2's quota fallback. Read, never echoed; written only to a 600 header file.
AUTH_HDR="$TMP/auth.hdr"
NOAUTH_HDR="$TMP/noauth.hdr"
: >"$NOAUTH_HDR"
key="${BV_VERIFY_KEY:-}"
if [ -z "$key" ]; then
	common=$(git rev-parse --path-format=absolute --git-common-dir 2>/dev/null) && vars="$(dirname "$common")/.dev.vars"
	[ -n "${vars:-}" ] && [ -f "$vars" ] && key=$(awk -F= '/^[[:space:]]*BV_INTERNAL_DEV_KEY[[:space:]]*=/{v=substr($0,index($0,"=")+1);gsub(/^[[:space:]"]+|[[:space:]"]+$/,"",v);k=v}END{printf "%s",k}' "$vars")
fi
if [ -n "$key" ]; then (umask 077; printf 'authorization: Bearer %s\n' "$key" >"$AUTH_HDR"); fi
unset key
HDR="$NOAUTH_HDR"

# Streamable HTTP answers either JSON or one SSE "data:" line; print the JSON-RPC object.
rpc_json() { node -e 'const t=require("fs").readFileSync(0,"utf8");const l=t.split("\n").find(x=>x.startsWith("data:"));process.stdout.write(l?l.slice(5).trim():t.trim())'; }

post() { # host session body -> JSON-RPC object on stdout
	curl -sS --max-time 30 -D "$TMP/post.hdr" -X POST "$1/mcp" -H @"$HDR" -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' \
		-H "mcp-session-id: $2" -H 'mcp-protocol-version: 2025-06-18' -d "$3" | rpc_json
}

open_session() { # host -> sets sid, writes $TMP/init.out
	curl -sS --max-time 30 -D "$TMP/hdr" -o "$TMP/init.out" -X POST "$1/mcp" -H @"$HDR" -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' -d "$INIT"
	sid=$(awk -F': ' 'tolower($1)=="mcp-session-id"{print $2}' "$TMP/hdr" | tr -d '\r')
	[ -n "$sid" ] && post "$1" "$sid" '{"jsonrpc":"2.0","method":"notifications/initialized"}' >/dev/null
}

INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"verify-release","version":"1"}}}'

for H in $HOSTS; do
	# 1. version, N probes
	seen=""
	i=0
	while [ "$i" -lt "$PROBES" ]; do
		i=$((i + 1))
		v=$(curl -sS --max-time 30 -X POST "$H/mcp?cb=$(date +%s)$i" -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' -d "$INIT" | rpc_json |
			node -e 'try{const j=JSON.parse(require("fs").readFileSync(0,"utf8"));process.stdout.write(j.result.serverInfo.version)}catch(e){process.stdout.write("unreadable")}')
		seen="$seen $v"
	done
	bad=$(printf '%s\n' $seen | grep -vxF "$VERSION" | sort -u | tr '\n' ' ')
	if [ -z "$bad" ]; then pass "$H serverInfo.version $VERSION ($PROBES/$PROBES probes)"; else fail "$H serverInfo.version: saw [$seen ] want $VERSION"; fi

	# session for the tool probes
	open_session "$H"
	if [ -z "$sid" ]; then fail "$H no mcp-session-id on initialize; tool probes skipped"; continue; fi
	desc=$(rpc_json <"$TMP/init.out" | node -e 'try{process.stdout.write(JSON.parse(require("fs").readFileSync(0,"utf8")).result.serverInfo.description||"")}catch(e){}')

	# 2. unknown argument rejected
	CALL='{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"check_spf","arguments":{"domain":"isc.org","verify_release_bogus":1}}}'
	r=$(post "$H" "$sid" "$CALL")
	case "$r" in *"session expired or terminated"*)
		# Observed 2026-10-25 on the custom domain: a session minted by initialize was not yet
		# recognised by the next request. Retry once on a fresh session and say so.
		echo "NOTE  $H fresh session was rejected as expired; retrying once on a new session"
		open_session "$H"; r=$(post "$H" "$sid" "$CALL") ;;
	esac
	retried=0
	case "$r" in *'"code":-32029'*)
		if [ -s "$AUTH_HDR" ]; then
			echo "NOTE  $H anonymous quota spent (-32029); retrying once on an authenticated session"
			retried=1; HDR="$AUTH_HDR"; open_session "$H"; r=$(post "$H" "$sid" "$CALL"); HDR="$NOAUTH_HDR"
			tier=$(awk -F': ' 'tolower($1)=="x-quota-tier"{print $2}' "$TMP/post.hdr" | tr -d '\r')
			echo "NOTE  $H authenticated retry resolved to tier: ${tier:-unreported}"
		fi ;;
	esac
	case "$r" in
	*"unknown argument(s): verify_release_bogus"*) pass "$H unknown argument rejected" ;;
	*'"code":-32029'*) skip "$H unknown-argument probe: quota spent (-32029) and no key to retry with; set BV_VERIFY_KEY" ;;
	*) fail "$H unknown argument NOT rejected: $(printf %s "$r" | cut -c1-160)" ;;
	esac
	# Later probes reuse this session; re-open anonymously so check 3 stays an anonymous-tier read.
	[ "$retried" -eq 1 ] && open_session "$H"

	# 3. tools/list shape vs the advertised count
	post "$H" "$sid" '{"jsonrpc":"2.0","id":3,"method":"tools/list"}' >"$TMP/tools.json"
	out=$(DESC="$desc" node -e '
		const j=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));const ts=j.result.tools;
		const loose=ts.filter(t=>t.inputSchema?.additionalProperties!==false).map(t=>t.name);
		const m=/(\d+) MCP tools/.exec(process.env.DESC||"");const claim=m?Number(m[1]):null;
		const ok=loose.length===0&&claim===ts.length;
		console.log((ok?"ok":"bad")+" tools="+ts.length+" advertised="+claim+" non-strict="+(loose.join(",")||"none"));' "$TMP/tools.json" 2>&1)
	case "$out" in ok*) pass "$H tools/list ${out#ok }" ;; *) fail "$H tools/list $out" ;; esac
done

if [ "$BEFORE_PUBLISH" -eq 1 ]; then
	echo "SKIP  registry + GitHub Release (--before-publish)"
else
	# 4. registry
	r=$(curl -sS --max-time 30 "$REGISTRY?cb=$(date +%s)" | node -e '
		try{const j=JSON.parse(require("fs").readFileSync(0,"utf8"));const s=j.server||j;const m=j._meta?.["io.modelcontextprotocol.registry/official"]||{};
		process.stdout.write([s.version,m.status,m.isLatest].join(" "))}catch(e){process.stdout.write("unreadable")}')
	if [ "$r" = "$VERSION active true" ]; then pass "registry latest $VERSION active isLatest"; else fail "registry latest: [$r] want [$VERSION active true]"; fi

	# 5. GitHub Release
	if command -v gh >/dev/null 2>&1; then
		g=$(gh release view "v$VERSION" --repo "$REPO" --json isDraft,publishedAt -q '"draft=\(.isDraft) at=\(.publishedAt)"' 2>&1)
		case "$g" in draft=false*) pass "GitHub Release v$VERSION ($g)" ;; *) fail "GitHub Release v$VERSION: $g" ;; esac
	else
		fail "GitHub Release v$VERSION: gh not installed"
	fi
fi

[ "$FAILS" -eq 0 ] && { [ "$SKIPS" -gt 0 ] && echo "ALL PASS ($VERSION), $SKIPS probe(s) SKIPPED — not verified" || echo "ALL PASS ($VERSION)"; exit 0; }
echo "$FAILS check(s) FAILED ($VERSION)"
exit 1
