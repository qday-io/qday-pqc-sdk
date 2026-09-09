#!/usr/bin/env bash
# End-to-end check of a running qday-pqc-server.
# Usage: ./scripts/verify-api.sh [base_url]
# Default: http://127.0.0.1:8080
set -euo pipefail

BASE="${1:-${PQC_BASE:-http://127.0.0.1:8080}}"
BASE="${BASE%/}"
MSG="hello pqc"
TAMPERED="hello pqd"
FAILS=0

need() {
	command -v "$1" >/dev/null 2>&1 || {
		echo "missing dependency: $1" >&2
		exit 1
	}
}

need curl
need python3

json_get() {
	python3 -c 'import json,sys
d=json.load(sys.stdin)
v=d
for k in sys.argv[1].split("."):
    v=v[k]
if isinstance(v, bool):
    print("true" if v else "false")
elif v is None:
    print("")
else:
    print(v)' "$1"
}

http() {
	local method="$1" path="$2" payload="${3-}"
	local tmp status
	tmp="$(mktemp)"
	if [ -n "$payload" ]; then
		status="$(curl -sS -o "$tmp" -w "%{http_code}" -X "$method" "${BASE}${path}" \
			-H "Content-Type: application/json" -d "$payload" || true)"
	else
		status="$(curl -sS -o "$tmp" -w "%{http_code}" -X "$method" "${BASE}${path}" || true)"
	fi
	printf '%s %s\n' "$status" "$tmp"
}

pass() { printf "PASS  %s\n" "$1"; }
fail() {
	printf "FAIL  %s\n" "$1" >&2
	FAILS=$((FAILS + 1))
}

check_status() {
	local want="$1" got="$2" name="$3" body_file="$4"
	if [ "$got" != "$want" ]; then
		fail "$name (HTTP $got, want $want): $(head -c 400 "$body_file")"
		return 1
	fi
	return 0
}

echo "qday-pqc-server API check  ${BASE}"
echo

read -r status body < <(http GET /health)
if check_status 200 "$status" "GET /health" "$body"; then
	got="$(json_get status <"$body")"
	if [ "$got" = "ok" ]; then
		pass "GET /health  status=ok"
	else
		fail "GET /health  status=${got}"
	fi
fi
rm -f "$body"

read -r status body < <(http GET /v1/info)
if check_status 200 "$status" "GET /v1/info" "$body"; then
	alg="$(json_get algorithm <"$body")"
	ver="$(json_get liboqs_version <"$body")"
	pk="$(json_get public_key_b64 <"$body")"
	if [ -n "$alg" ] && [ -n "$ver" ] && [ -n "$pk" ]; then
		pass "GET /v1/info  algorithm=${alg} liboqs=${ver} public_key_b64_len=${#pk}"
	else
		fail "GET /v1/info  missing algorithm, liboqs_version, or public_key_b64"
	fi
fi
rm -f "$body"

SIGN_BODY="$(python3 -c 'import json,sys; print(json.dumps({"message":sys.argv[1]}))' "$MSG")"
read -r status body < <(http POST /v1/sign "$SIGN_BODY")
if check_status 200 "$status" "POST /v1/sign" "$body"; then
	SIG="$(json_get signature_b64 <"$body")"
	PUB="$(json_get public_key_b64 <"$body")"
	SALG="$(json_get algorithm <"$body")"
	if [ -n "$SIG" ] && [ -n "$PUB" ] && [ -n "$SALG" ]; then
		pass "POST /v1/sign  algorithm=${SALG} signature_b64_len=${#SIG}"
	else
		fail "POST /v1/sign  empty signature or public key"
		SIG=""
		PUB=""
	fi
else
	SIG=""
	PUB=""
fi
rm -f "$body"

if [ -n "$SIG" ]; then
	VERIFY_BODY="$(python3 -c 'import json,sys; print(json.dumps({"message":sys.argv[1],"signature_b64":sys.argv[2],"public_key_b64":sys.argv[3]}))' "$MSG" "$SIG" "$PUB")"
	read -r status body < <(http POST /v1/verify "$VERIFY_BODY")
	if check_status 200 "$status" "POST /v1/verify (with public_key_b64)" "$body"; then
		got="$(json_get valid <"$body")"
		if [ "$got" = "true" ]; then
			pass "POST /v1/verify  with public_key_b64  valid=true"
		else
			fail "POST /v1/verify  with public_key_b64  valid=${got} (want true)"
		fi
	fi
	rm -f "$body"

	VERIFY_BODY="$(python3 -c 'import json,sys; print(json.dumps({"message":sys.argv[1],"signature_b64":sys.argv[2]}))' "$MSG" "$SIG")"
	read -r status body < <(http POST /v1/verify "$VERIFY_BODY")
	if check_status 200 "$status" "POST /v1/verify (server key)" "$body"; then
		got="$(json_get valid <"$body")"
		if [ "$got" = "true" ]; then
			pass "POST /v1/verify  server public key  valid=true"
		else
			fail "POST /v1/verify  server public key  valid=${got} (want true)"
		fi
	fi
	rm -f "$body"

	VERIFY_BODY="$(python3 -c 'import json,sys; print(json.dumps({"message":sys.argv[1],"signature_b64":sys.argv[2],"public_key_b64":sys.argv[3]}))' "$TAMPERED" "$SIG" "$PUB")"
	read -r status body < <(http POST /v1/verify "$VERIFY_BODY")
	if check_status 200 "$status" "POST /v1/verify (tampered)" "$body"; then
		got="$(json_get valid <"$body")"
		if [ "$got" = "false" ]; then
			pass "POST /v1/verify  tampered message  valid=false"
		else
			fail "POST /v1/verify  tampered message  valid=${got} (want false)"
		fi
	fi
	rm -f "$body"
fi

MSG_B64="$(python3 -c 'import base64; print(base64.b64encode(b"hello\x00pqc").decode())')"
SIGN_BODY="$(python3 -c 'import json,sys; print(json.dumps({"message_b64":sys.argv[1]}))' "$MSG_B64")"
read -r status body < <(http POST /v1/sign "$SIGN_BODY")
if check_status 200 "$status" "POST /v1/sign (message_b64)" "$body"; then
	BSIG="$(json_get signature_b64 <"$body")"
	BPUB="$(json_get public_key_b64 <"$body")"
	if [ -n "$BSIG" ]; then
		pass "POST /v1/sign  message_b64"
		VERIFY_BODY="$(python3 -c 'import json,sys; print(json.dumps({"message_b64":sys.argv[1],"signature_b64":sys.argv[2],"public_key_b64":sys.argv[3]}))' "$MSG_B64" "$BSIG" "$BPUB")"
		read -r vstatus vbody < <(http POST /v1/verify "$VERIFY_BODY")
		if check_status 200 "$vstatus" "POST /v1/verify (message_b64)" "$vbody"; then
			got="$(json_get valid <"$vbody")"
			if [ "$got" = "true" ]; then
				pass "POST /v1/verify  message_b64  valid=true"
			else
				fail "POST /v1/verify  message_b64  valid=${got} (want true)"
			fi
		fi
		rm -f "$vbody"
	else
		fail "POST /v1/sign  message_b64  empty signature"
	fi
fi
rm -f "$body"

read -r status body < <(http POST /v1/sign "{}")
if [ "$status" = "400" ]; then
	pass "POST /v1/sign  empty body  HTTP 400"
else
	fail "POST /v1/sign  empty body  HTTP ${status} (want 400)"
fi
rm -f "$body"

echo
if [ "$FAILS" -eq 0 ]; then
	echo "all checks passed"
	exit 0
fi
echo "${FAILS} check(s) failed" >&2
exit 1
