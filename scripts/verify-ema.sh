#!/usr/bin/env bash
# verify-ema.sh [--base <url>] [--tool <paid_only_tool>] [--assertion <file>] [--self-test]
#
# Operator-run live check of Enterprise Managed Auth (ID-JAG / jwt-bearer) readiness on a deployed
# Worker. Default base: https://dns-mcp.blackveilsecurity.com. Each check prints PASS/FAIL plus the
# measured value; exit 1 if any check fails, 2 on usage or a missing prerequisite.
#
# Checks:
#   1. AS metadata: jwt-bearer grant, id-jag grant profile, CIMD support, auth method none, PKCE S256
#   2. PRM at the root and /mcp-suffixed well-known paths: resource == <base>/mcp, authorization_servers[0] == <base>
#   3. Lazy auth: unauthenticated tools/call of a paid-only tool -> 401 + WWW-Authenticate with
#      resource_metadata= and scope="mcp"
#   4. Grant negative probe: jwt-bearer with a junk assertion -> 400 invalid_grant
#      (unsupported_grant_type means the grant is NOT deployed)
#   5. Optional --assertion <file>: exchange a real ID-JAG; prints the error code or expires_in/scope and
#      the token LENGTH only, never the token
#   --self-test: run the parsing/assertion helpers on inline fixtures, no network, exit 0 (CI-safe)
#
# Limits: check 3 and 4 are anonymous probes; they prove the surface exists, not that a given tenant
# is registered or that a given IdP's signing keys verify (that is what --assertion is for).
#
# JSON parsing uses node (already required by this repo's tooling), so it needs no jq. bash 3.2 / BSD
# tools only: no GNU flags, no `timeout` (curl --max-time bounds every request).

set -euo pipefail

BASE="https://dns-mcp.blackveilsecurity.com"
TOOL="register_brand_audit_watch"
ASSERTION=""
SELF_TEST=0
JWT_BEARER="urn:ietf:params:oauth:grant-type:jwt-bearer"
ID_JAG="urn:ietf:params:oauth:grant-profile:id-jag"
CLAUDE_CLIENT="https://claude.ai/oauth/mcp-oauth-client-metadata"

usage() { echo "usage: $0 [--base <url>] [--tool <name>] [--assertion <file>] [--self-test]" >&2; exit 2; }
while [ $# -gt 0 ]; do
	case "$1" in
	--base) [ $# -ge 2 ] || usage; BASE="$2"; shift ;;
	--tool) [ $# -ge 2 ] || usage; TOOL="$2"; shift ;;
	--assertion) [ $# -ge 2 ] || usage; ASSERTION="$2"; shift ;;
	--self-test) SELF_TEST=1 ;;
	*) usage ;;
	esac
	shift
done
BASE="${BASE%/}"

FAILS=0
pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; FAILS=$((FAILS + 1)); }

# --- pure helpers (stdin JSON -> stdout / exit status) -----------------------------------------
# jget <dotted.path>: print the value (strings raw, others JSON); "" when absent or unparsable.
jget() {
	node -e '
let j; try { j = JSON.parse(require("fs").readFileSync(0, "utf8")); } catch (e) { process.exit(0); }
let v = j;
for (const k of process.argv[1].split(".")) { if (v == null) break; v = v[k]; }
if (v === undefined || v === null) process.exit(0);
process.stdout.write(typeof v === "string" ? v : JSON.stringify(v));
' "$1"
}
# jhas <array.path> <value>: exit 0 iff the array contains the value.
jhas() {
	node -e '
let j; try { j = JSON.parse(require("fs").readFileSync(0, "utf8")); } catch (e) { process.exit(1); }
let v = j;
for (const k of process.argv[1].split(".")) { if (v == null) break; v = v[k]; }
process.exit(Array.isArray(v) && v.indexOf(process.argv[2]) !== -1 ? 0 : 1);
' "$1" "$2"
}
# sse_json: Streamable HTTP answers JSON or one SSE "data:" line; print the JSON object.
sse_json() { node -e 'const t=require("fs").readFileSync(0,"utf8");const l=t.split("\n").find(x=>x.startsWith("data:"));process.stdout.write(l?l.slice(5).trim():t.trim())'; }

# check_as_metadata <json> ; check_prm <json> <label> ; check_challenge <status> <headers-text>
check_as_metadata() {
	local m="$1"
	jhas grant_types_supported "$JWT_BEARER" <<<"$m" && pass "AS grant_types_supported has jwt-bearer" || fail "AS grant_types_supported lacks jwt-bearer: $(jget grant_types_supported <<<"$m")"
	jhas authorization_grant_profiles_supported "$ID_JAG" <<<"$m" && pass "AS authorization_grant_profiles_supported has id-jag" || fail "AS authorization_grant_profiles_supported lacks id-jag: $(jget authorization_grant_profiles_supported <<<"$m")"
	local cimd; cimd=$(jget client_id_metadata_document_supported <<<"$m")
	[ "$cimd" = "true" ] && pass "AS client_id_metadata_document_supported=true" || fail "AS client_id_metadata_document_supported='$cimd'"
	jhas token_endpoint_auth_methods_supported none <<<"$m" && pass "AS token_endpoint_auth_methods_supported has none" || fail "AS token_endpoint_auth_methods_supported lacks none: $(jget token_endpoint_auth_methods_supported <<<"$m")"
	jhas code_challenge_methods_supported S256 <<<"$m" && pass "AS code_challenge_methods_supported has S256" || fail "AS code_challenge_methods_supported lacks S256: $(jget code_challenge_methods_supported <<<"$m")"
}
check_prm() {
	local m="$1" label="$2" res as0
	res=$(jget resource <<<"$m"); as0=$(jget authorization_servers.0 <<<"$m")
	[ "$res" = "$BASE/mcp" ] && pass "PRM $label resource=$res" || fail "PRM $label resource='$res' want $BASE/mcp"
	[ "$as0" = "$BASE" ] && pass "PRM $label authorization_servers[0]=$as0" || fail "PRM $label authorization_servers[0]='$as0' want $BASE"
}
check_challenge() {
	local status="$1" hdrs="$2" wa
	wa=$(printf '%s\n' "$hdrs" | awk 'tolower($1)=="www-authenticate:"{sub(/^[^:]*: */,""); print; exit}' | tr -d '\r')
	[ "$status" = "401" ] && pass "lazy auth: unauthenticated paid tool call -> HTTP $status" || fail "lazy auth: HTTP $status want 401"
	case "$wa" in *'resource_metadata='*) pass "WWW-Authenticate has resource_metadata=" ;; *) fail "WWW-Authenticate lacks resource_metadata=: '$wa'" ;; esac
	case "$wa" in *'scope="mcp"'*) pass 'WWW-Authenticate has scope="mcp"' ;; *) fail "WWW-Authenticate lacks scope=\"mcp\": '$wa'" ;; esac
}
check_grant_probe() { # status body
	local err; err=$(jget error <<<"$2")
	if [ "$1" = "400" ] && [ "$err" = "invalid_grant" ]; then pass "jwt-bearer probe -> 400 invalid_grant (grant deployed)"
	elif [ "$err" = "unsupported_grant_type" ]; then fail "jwt-bearer probe -> $1 unsupported_grant_type (grant NOT deployed)"
	else fail "jwt-bearer probe -> HTTP $1 error='$err' want 400 invalid_grant"; fi
}

# --- self-test ---------------------------------------------------------------------------------
if [ "$SELF_TEST" = 1 ]; then
	BASE="https://x.test"
	command -v node >/dev/null 2>&1 || { echo "missing prerequisite: node" >&2; exit 2; }
	good_as='{"grant_types_supported":["authorization_code","'$JWT_BEARER'"],"authorization_grant_profiles_supported":["'$ID_JAG'"],"client_id_metadata_document_supported":true,"token_endpoint_auth_methods_supported":["none"],"code_challenge_methods_supported":["S256"]}'
	check_as_metadata "$good_as" >/dev/null; [ "$FAILS" = 0 ] || { echo "self-test: good AS metadata failed" >&2; exit 1; }
	check_as_metadata '{"grant_types_supported":["authorization_code"],"client_id_metadata_document_supported":false}' >/dev/null
	[ "$FAILS" = 5 ] || { echo "self-test: bad AS metadata gave $FAILS fails, want 5" >&2; exit 1; }
	FAILS=0
	check_prm '{"resource":"https://x.test/mcp","authorization_servers":["https://x.test"]}' root >/dev/null; [ "$FAILS" = 0 ] || { echo "self-test: good PRM failed" >&2; exit 1; }
	check_prm '{"resource":"https://x.test/other","authorization_servers":["https://y.test"]}' root >/dev/null
	[ "$FAILS" = 2 ] || { echo "self-test: bad PRM gave $FAILS fails, want 2" >&2; exit 1; }
	FAILS=0
	check_challenge 401 $'HTTP/2 401\r\nWWW-Authenticate: Bearer resource_metadata="https://x.test/.well-known/oauth-protected-resource", scope="mcp"\r\n' >/dev/null
	[ "$FAILS" = 0 ] || { echo "self-test: good challenge failed" >&2; exit 1; }
	check_challenge 403 $'HTTP/2 403\r\n' >/dev/null
	[ "$FAILS" = 3 ] || { echo "self-test: bad challenge gave $FAILS fails, want 3" >&2; exit 1; }
	FAILS=0
	check_grant_probe 400 '{"error":"invalid_grant"}' >/dev/null; [ "$FAILS" = 0 ] || { echo "self-test: good probe failed" >&2; exit 1; }
	check_grant_probe 400 '{"error":"unsupported_grant_type"}' >/dev/null
	[ "$FAILS" = 1 ] || { echo "self-test: undeployed grant not flagged" >&2; exit 1; }
	[ "$(printf 'event: message\ndata: {"a":1}\n' | sse_json)" = '{"a":1}' ] || { echo "self-test: sse_json" >&2; exit 1; }
	echo "self-test OK"
	exit 0
fi

for bin in curl node; do command -v "$bin" >/dev/null 2>&1 || { echo "missing prerequisite: $bin" >&2; exit 2; }; done
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
CURL="curl -sS --max-time 15"
echo "EMA verification against $BASE"

# 1. AS metadata
check_as_metadata "$($CURL "$BASE/.well-known/oauth-authorization-server" || true)"

# 2. PRM, both forms
check_prm "$($CURL "$BASE/.well-known/oauth-protected-resource" || true)" root
check_prm "$($CURL "$BASE/.well-known/oauth-protected-resource/mcp" || true)" /mcp

# 3. Lazy auth challenge
INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"verify-ema","version":"1"}}}'
$CURL -D "$TMP/init.hdr" -o /dev/null -X POST "$BASE/mcp" -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' -d "$INIT" || true
sid=$(awk 'tolower($1)=="mcp-session-id:"{print $2}' "$TMP/init.hdr" 2>/dev/null | tr -d '\r')
if [ -z "$sid" ]; then
	fail "lazy auth: no mcp-session-id on initialize"
else
	$CURL -o /dev/null -X POST "$BASE/mcp" -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' \
		-H "mcp-session-id: $sid" -H 'mcp-protocol-version: 2025-06-18' -d '{"jsonrpc":"2.0","method":"notifications/initialized"}' || true
	call='{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"'"$TOOL"'","arguments":{"domain":"example.com"}}}'
	status=$($CURL -D "$TMP/call.hdr" -o "$TMP/call.out" -w '%{http_code}' -X POST "$BASE/mcp" -H 'content-type: application/json' \
		-H 'accept: application/json, text/event-stream' -H "mcp-session-id: $sid" -H 'mcp-protocol-version: 2025-06-18' -d "$call" || echo 000)
	check_challenge "$status" "$(cat "$TMP/call.hdr")"
fi

# 4. Grant negative probe
status=$($CURL -o "$TMP/grant.out" -w '%{http_code}' -X POST "$BASE/oauth/token" -H 'content-type: application/x-www-form-urlencoded' \
	--data-urlencode "grant_type=$JWT_BEARER" --data-urlencode "assertion=not.a.jwt" --data-urlencode "client_id=$CLAUDE_CLIENT" || echo 000)
check_grant_probe "$status" "$(cat "$TMP/grant.out")"

# 5. Optional real assertion
if [ -n "$ASSERTION" ]; then
	if [ ! -r "$ASSERTION" ]; then
		fail "assertion file not readable: $ASSERTION"
	else
		jag=$(tr -d '\r\n' <"$ASSERTION")
		status=$($CURL -o "$TMP/ex.out" -w '%{http_code}' -X POST "$BASE/oauth/token" -H 'content-type: application/x-www-form-urlencoded' \
			--data-urlencode "grant_type=$JWT_BEARER" --data-urlencode "assertion=$jag" --data-urlencode "client_id=$CLAUDE_CLIENT" || echo 000)
		body=$(cat "$TMP/ex.out")
		err=$(jget error <<<"$body")
		if [ "$status" = "200" ]; then
			tlen=$(jget access_token <<<"$body" | tr -d '\n' | wc -c | tr -d ' ')
			pass "assertion exchange HTTP 200 expires_in=$(jget expires_in <<<"$body") scope=$(jget scope <<<"$body") access_token_length=$tlen"
		else
			fail "assertion exchange HTTP $status error=${err:-unparsable} $(jget error_description <<<"$body")"
		fi
	fi
fi

if [ "$FAILS" -gt 0 ]; then echo "$FAILS check(s) FAILED"; exit 1; fi
echo "all checks passed"
