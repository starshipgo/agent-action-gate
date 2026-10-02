#!/usr/bin/env bash

# Future Preview-only use. This script is intentionally not run by local CI:
# BASE_URL=https://<preview-url> \
# AAG_API_KEY=... \
# OPERATOR_API_KEY=... \
# ./scripts/step7-smoke-test.sh

set -euo pipefail
set +x
umask 077

pass() {
  printf 'PASS %s\n' "$1"
}

fail() {
  printf 'FAIL %s\n' "$1" >&2
  exit 1
}

command -v curl >/dev/null 2>&1 || fail "curl is required"
command -v bun >/dev/null 2>&1 || fail "Bun is required"

[[ -n "${BASE_URL:-}" ]] || fail "BASE_URL is required"
[[ -n "${AAG_API_KEY:-}" ]] || fail "AAG_API_KEY is required"
[[ -n "${OPERATOR_API_KEY:-}" ]] || fail "OPERATOR_API_KEY is required"
[[ ! "$AAG_API_KEY" =~ [[:space:]] ]] ||
  fail "AAG_API_KEY contains invalid characters"
[[ ! "$OPERATOR_API_KEY" =~ [[:space:]] ]] ||
  fail "OPERATOR_API_KEY contains invalid characters"

base_url="$(
  bun -e '
    try {
      const url = new URL(process.argv[1]);
      if (
        url.protocol !== "https:" ||
        url.username !== "" ||
        url.password !== "" ||
        (url.pathname !== "" && url.pathname !== "/") ||
        url.search !== "" ||
        url.hash !== ""
      ) {
        process.exit(1);
      }
      process.stdout.write(url.origin);
    } catch {
      process.exit(1);
    }
  ' "$BASE_URL" 2>/dev/null
)" || fail "BASE_URL must be an HTTPS origin"

temporary_directory="$(
  mktemp -d "${TMPDIR:-/tmp}/agent-action-gate-step7-smoke.XXXXXX" 2>/dev/null
)" || fail "could not create temporary directory"
cookie_file="$temporary_directory/operator-cookies.txt"
: >"$cookie_file"

disposable_key_id=""
disposable_key_revoked=false
disposable_key_creation_attempted=false
disposable_label=""

cleanup() {
  local cleanup_key_id="$disposable_key_id"
  local cleanup_list_file="$temporary_directory/cleanup-api-keys.json"
  local cleanup_status=""

  if \
    [[ "$disposable_key_creation_attempted" == true ]] &&
    [[ "$disposable_key_revoked" == false ]] &&
    [[ -z "$cleanup_key_id" ]] &&
    [[ -n "$disposable_label" ]] &&
    [[ -s "$cookie_file" ]]
  then
    cleanup_status="$(
      curl \
        --silent \
        --connect-timeout 5 \
        --max-time 15 \
        --output "$cleanup_list_file" \
        --write-out '%{http_code}' \
        --request GET \
        --cookie "$cookie_file" \
        "${base_url}/v1/api-keys?tenant_id=acme&status=active&limit=100" \
        2>/dev/null
    )" || cleanup_status=""

    if [[ "$cleanup_status" == 200 ]]; then
      cleanup_key_id="$(
        bun -e '
          try {
            const [path, expectedLabel] = process.argv.slice(1);
            const body = await Bun.file(path).json();
            const keys = Array.isArray(body?.api_keys) ? body.api_keys : [];
            const matches = keys.filter(
              (key) =>
                key !== null &&
                typeof key === "object" &&
                !Array.isArray(key) &&
                key.label === expectedLabel &&
                key.tenant_id === "acme" &&
                key.status === "active" &&
                typeof key.key_id === "string" &&
                /^[A-Za-z0-9_-]{1,128}$/.test(key.key_id),
            );
            if (matches.length !== 1) process.exit(1);
            process.stdout.write(matches[0].key_id);
          } catch {
            process.exit(1);
          }
        ' "$cleanup_list_file" "$disposable_label" 2>/dev/null
      )" || cleanup_key_id=""
    fi
  fi

  if \
    [[ "$cleanup_key_id" =~ ^[A-Za-z0-9_-]{1,128}$ ]] &&
    [[ "$disposable_key_revoked" == false ]] &&
    [[ -s "$cookie_file" ]]
  then
    curl \
      --silent \
      --connect-timeout 5 \
      --max-time 15 \
      --output /dev/null \
      --request POST \
      --cookie "$cookie_file" \
      --header "Origin: $base_url" \
      "${base_url}/v1/api-keys/${cleanup_key_id}/revoke" \
      >/dev/null 2>&1 || true
  fi
  rm -rf -- "$temporary_directory" >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

run_nonce="$(bun -e 'process.stdout.write(crypto.randomUUID())' 2>/dev/null)" ||
  fail "could not create smoke-test marker"
source_text="Agent Action Gate Step 7 smoke-test source marker ${run_nonce}."
disposable_label="Step 7 smoke ${run_nonce}"
email_arguments_json='{"to":"customer@example.com","subject":"Quarterly account summary","body":"Private body that must never enter audit or approval display.","target_tenant":"acme"}'

printf '%s' "$OPERATOR_API_KEY" |
  bun -e '
    const path = process.argv[1];
    const operatorKey = await Bun.stdin.text();
    await Bun.write(path, JSON.stringify({ operator_api_key: operatorKey }));
  ' "$temporary_directory/session.json" >/dev/null 2>&1 ||
  fail "could not prepare session request"

bun -e '
  const [path, label] = process.argv.slice(1);
  await Bun.write(path, JSON.stringify({
    tenant_id: "acme",
    label,
    daily_ai_limit: 1,
  }));
' "$temporary_directory/api-key.json" "$disposable_label" >/dev/null 2>&1 ||
  fail "could not prepare API-key request"

bun -e '
  const [path, sourceText, argumentsJson] = process.argv.slice(1);
  await Bun.write(path, JSON.stringify({
    agent_role: "support_agent",
    tool_name: "email.send",
    arguments_json: argumentsJson,
    source_text: sourceText,
    request_tenant: "acme",
  }));
' \
  "$temporary_directory/email-send.json" \
  "$source_text" \
  "$email_arguments_json" \
  >/dev/null 2>&1 || fail "could not prepare evaluation request"

request_number=0
evaluation_request_count=0
response_file=""
response_headers_file=""

request_capture() {
  local label="$1"
  local expected_status="$2"
  local method="$3"
  local path="$4"
  local credential="$5"
  local payload_file="${6:-}"
  local include_origin="${7:-false}"
  local curl_status
  local curl_exit
  local token=""

  request_number=$((request_number + 1))
  if [[ "$path" == "/v1/evaluate" ]]; then
    evaluation_request_count=$((evaluation_request_count + 1))
    [[ $evaluation_request_count -le 2 ]] ||
      fail "semantic evaluation limit exceeded"
  fi

  response_file="$temporary_directory/response-$request_number.json"
  response_headers_file="$temporary_directory/headers-$request_number.txt"

  local curl_arguments=(
    --silent
    --connect-timeout 10
    --max-time 120
    --output "$response_file"
    --dump-header "$response_headers_file"
    --write-out '%{http_code}'
    --request "$method"
  )

  if [[ -n "$payload_file" ]]; then
    curl_arguments+=(
      --header 'Content-Type: application/json'
      --data-binary "@$payload_file"
    )
  fi
  if [[ "$include_origin" == true ]]; then
    curl_arguments+=(--header "Origin: $base_url")
  fi

  case "$credential" in
    none)
      if [[ "$method" == POST && "$path" == "/v1/operator/session" ]]; then
        curl_arguments+=(--cookie-jar "$cookie_file")
      fi
      ;;
    agent) token="$AAG_API_KEY" ;;
    browser)
      curl_arguments+=(--cookie "$cookie_file" --cookie-jar "$cookie_file")
      ;;
    *) fail "$label has an invalid credential mode" ;;
  esac

  set +e
  if [[ "$credential" == agent ]]; then
    curl_status="$(
      printf 'Authorization: Bearer %s\n' "$token" |
        curl "${curl_arguments[@]}" --header @- "${base_url}${path}"
    )"
    curl_exit=$?
  else
    curl_status="$(curl "${curl_arguments[@]}" "${base_url}${path}")"
    curl_exit=$?
  fi
  set -e

  [[ $curl_exit -eq 0 ]] || fail "$label request failed"
  [[ "$curl_status" == "$expected_status" ]] ||
    fail "$label returned an unexpected HTTP status"
}

json_check() {
  local mode="$1"
  shift

  bun -e '
    const [mode, responsePath, headersPath, ...args] = process.argv.slice(1);
    const isRecord = (value) =>
      value !== null && typeof value === "object" && !Array.isArray(value);
    const exactKeys = (value, keys) =>
      isRecord(value) &&
      Object.keys(value).sort().join("\u0000") ===
        [...keys].sort().join("\u0000");
    const exactStrings = (value, expected) =>
      Array.isArray(value) &&
      value.length === expected.length &&
      value.every((entry, index) => entry === expected[index]);
    const safeKeyFields = [
      "key_id",
      "key_prefix",
      "tenant_id",
      "label",
      "status",
      "created_at",
      "revoked_at",
      "daily_ai_limit",
    ];

    try {
      const body = await Bun.file(responsePath).json();
      const headers = await Bun.file(headersPath).text();
      let ok = false;

      switch (mode) {
        case "health":
          ok =
            exactKeys(body, ["status", "service"]) &&
            body.status === "ok" &&
            body.service === "agent-action-gate";
          break;
        case "session":
          ok =
            exactKeys(body, ["authenticated", "expires_at"]) &&
            body.authenticated === true &&
            typeof body.expires_at === "string" &&
            Number.isFinite(Date.parse(body.expires_at)) &&
            /set-cookie:\s*__Host-aag_operator_session=/iu.test(headers) &&
            /;\s*HttpOnly/iu.test(headers) &&
            /;\s*Secure/iu.test(headers) &&
            /;\s*SameSite=Strict/iu.test(headers) &&
            !headers.includes(process.env.OPERATOR_API_KEY ?? "") &&
            !JSON.stringify(body).includes(process.env.OPERATOR_API_KEY ?? "");
          break;
        case "overview":
          ok =
            exactKeys(body, ["policy_version", "metrics", "recent_activity"]) &&
            typeof body.policy_version === "string" &&
            body.policy_version.length > 0 &&
            exactKeys(body.metrics, [
              "allowed",
              "blocked",
              "pending_approvals",
              "approval_required",
              "ai_quota_usage",
            ]) &&
            [
              body.metrics.allowed,
              body.metrics.blocked,
              body.metrics.pending_approvals,
              body.metrics.approval_required,
            ].every((value) => Number.isInteger(value) && value >= 0) &&
            exactKeys(body.metrics.ai_quota_usage, ["used_today", "daily_limit"]) &&
            Number.isInteger(body.metrics.ai_quota_usage.used_today) &&
            body.metrics.ai_quota_usage.used_today >= 0 &&
            Number.isInteger(body.metrics.ai_quota_usage.daily_limit) &&
            body.metrics.ai_quota_usage.daily_limit >= 0 &&
            Array.isArray(body.recent_activity) &&
            body.recent_activity.length <= 10;
          break;
        case "key-created": {
          const [label] = args;
          const key = body.api_key;
          ok =
            exactKeys(body, ["api_key", "raw_api_key"]) &&
            exactKeys(key, safeKeyFields) &&
            typeof body.raw_api_key === "string" &&
            /^aag_test_[A-Za-z0-9_-]{43}$/.test(body.raw_api_key) &&
            body.raw_api_key !== process.env.AAG_API_KEY &&
            body.raw_api_key !== process.env.OPERATOR_API_KEY &&
            typeof key.key_id === "string" &&
            /^[A-Za-z0-9_-]{1,128}$/.test(key.key_id) &&
            typeof key.key_prefix === "string" &&
            body.raw_api_key.startsWith(key.key_prefix) &&
            key.tenant_id === "acme" &&
            key.label === label &&
            key.status === "active" &&
            Number.isInteger(key.created_at) &&
            key.revoked_at === null &&
            key.daily_ai_limit === 1;
          break;
        }
        case "key-listed": {
          const [createPath, keyId] = args;
          const created = await Bun.file(createPath).json();
          ok =
            exactKeys(body, ["api_keys"]) &&
            Array.isArray(body.api_keys) &&
            body.api_keys.some(
              (key) =>
                exactKeys(key, safeKeyFields) &&
                key.key_id === keyId &&
                key.status === "active" &&
                key.tenant_id === "acme",
            ) &&
            !JSON.stringify(body).includes(created.raw_api_key) &&
            !JSON.stringify(body).includes("key_hash") &&
            !JSON.stringify(body).includes("principal_id");
          break;
        }
        case "key-revoked":
          ok =
            exactKeys(body, ["api_key"]) &&
            exactKeys(body.api_key, safeKeyFields) &&
            body.api_key.key_id === args[0] &&
            body.api_key.status === "revoked" &&
            Number.isInteger(body.api_key.revoked_at);
          break;
        case "approval-evaluation":
          ok =
            exactKeys(body, [
              "decision",
              "risk_level",
              "policy_codes",
              "requires_approval",
              "normalized_tool",
              "normalized_args",
              "approval_id",
              "expires_at",
            ]) &&
            body.decision === "REQUIRE_APPROVAL" &&
            body.risk_level === "medium" &&
            exactStrings(body.policy_codes, ["OUTBOUND_SEND"]) &&
            body.requires_approval === true &&
            body.normalized_tool === "email.send" &&
            body.normalized_args?.to === "customer@example.com" &&
            body.normalized_args?.subject === "Quarterly account summary" &&
            body.normalized_args?.body ===
              "Private body that must never enter audit or approval display." &&
            body.normalized_args?.target_tenant === "acme" &&
            typeof body.approval_id === "string" &&
            /^[A-Za-z0-9_-]{1,128}$/.test(body.approval_id) &&
            typeof body.expires_at === "string" &&
            Number.isFinite(Date.parse(body.expires_at));
          break;
        case "pending-approval": {
          const [approvalId, policyVersion] = args;
          ok =
            exactKeys(body, ["approvals"]) &&
            Array.isArray(body.approvals) &&
            body.approvals.some(
              (approval) =>
                approval?.approval_id === approvalId &&
                approval?.tenant_id === "acme" &&
                approval?.tool_name === "email.send" &&
                approval?.status === "PENDING" &&
                approval?.policy_version === policyVersion &&
                exactStrings(approval?.policy_codes, ["OUTBOUND_SEND"]) &&
                exactKeys(approval?.approval_display, [
                  "kind",
                  "recipient",
                  "subject",
                  "has_attachments",
                ]) &&
                approval.approval_display.kind === "email_send" &&
                approval.approval_display.recipient === "customer@example.com" &&
                approval.approval_display.subject === "Quarterly account summary" &&
                approval.approval_display.has_attachments === false &&
                !JSON.stringify(approval.approval_display).includes("Private body"),
            );
          break;
        }
        case "approved":
          ok =
            exactKeys(body, ["approval"]) &&
            body.approval?.approval_id === args[0] &&
            body.approval?.status === "APPROVED" &&
            body.approval?.policy_version === args[1];
          break;
        case "authorized":
          ok =
            exactKeys(body, [
              "authorized",
              "approval_id",
              "tool_name",
              "normalized_args",
            ]) &&
            body.authorized === true &&
            body.approval_id === args[0] &&
            body.tool_name === "email.send" &&
            body.normalized_args?.to === "customer@example.com";
          break;
        case "policies":
          ok =
            exactKeys(body, ["policy_version", "policies"]) &&
            body.policy_version === args[0] &&
            Array.isArray(body.policies) &&
            body.policies.length === 14 &&
            body.policies.every(
              (policy) =>
                exactKeys(policy, ["id", "outcome", "summary", "policy_codes"]) &&
                typeof policy.id === "string" &&
                ["ALLOW", "REQUIRE_APPROVAL", "DENY"].includes(policy.outcome) &&
                typeof policy.summary === "string" &&
                Array.isArray(policy.policy_codes),
            );
          break;
        case "audit": {
          const [approvalId, policyVersion, sourceText, keyCreatePath] = args;
          const createdKey = await Bun.file(keyCreatePath).json();
          const events = body.audit_events;
          const has = (type) =>
            Array.isArray(events) &&
            events.some(
              (event) =>
                event?.approval_id === approvalId &&
                event?.event_type === type &&
                event?.tool_name === "email.send" &&
                event?.tenant_id === "acme" &&
                event?.policy_version === policyVersion,
            );
          const fragments = [];
          const collect = (value) => {
            if (typeof value === "string") fragments.push(value);
            else if (Array.isArray(value)) value.forEach(collect);
            else if (isRecord(value)) {
              for (const [key, entry] of Object.entries(value)) {
                fragments.push(key);
                collect(entry);
              }
            }
          };
          collect(body);
          const forbidden = [
            sourceText,
            "customer@example.com",
            "Quarterly account summary",
            "Private body that must never enter audit or approval display.",
            process.env.AAG_API_KEY,
            process.env.OPERATOR_API_KEY,
            createdKey.raw_api_key,
          ].filter((value) => typeof value === "string" && value.length > 0);
          ok =
            exactKeys(body, ["audit_events"]) &&
            Array.isArray(events) &&
            has("EVALUATED") &&
            has("APPROVED") &&
            has("CONSUMED") &&
            forbidden.every(
              (value) => !fragments.some((fragment) => fragment.includes(value)),
            ) &&
            fragments.every((fragment) => !/authorization/iu.test(fragment));
          break;
        }
        case "logout":
          ok =
            exactKeys(body, ["authenticated"]) &&
            body.authenticated === false &&
            /set-cookie:\s*__Host-aag_operator_session=/iu.test(headers) &&
            /Max-Age=0/iu.test(headers);
          break;
        case "unauthorized":
          ok = exactKeys(body, ["error"]) && body.error === "UNAUTHORIZED";
          break;
      }

      process.exit(ok ? 0 : 1);
    } catch {
      process.exit(1);
    }
  ' "$mode" "$response_file" "$response_headers_file" "$@" >/dev/null 2>&1
}

extract_field() {
  local path="$1"
  local field_path="$2"

  bun -e '
    try {
      const value = process.argv[2]
        .split(".")
        .reduce((current, field) => current?.[field], await Bun.file(process.argv[1]).json());
      if (typeof value !== "string" || value.length === 0) process.exit(1);
      process.stdout.write(value);
    } catch {
      process.exit(1);
    }
  ' "$path" "$field_path" 2>/dev/null
}

request_capture "health" 200 GET /health none
json_check health || fail "health response was invalid"
pass "health"

request_capture \
  "operator session" \
  200 \
  POST \
  /v1/operator/session \
  none \
  "$temporary_directory/session.json" \
  true
json_check session || fail "operator session was not securely issued"
pass "operator session"

request_capture "operator overview" 200 GET /v1/operator/overview browser
json_check overview || fail "overview response was invalid"
policy_version="$(extract_field "$response_file" policy_version)" ||
  fail "overview omitted policy_version"
pass "operator overview"

disposable_key_creation_attempted=true
request_capture \
  "disposable API key creation" \
  201 \
  POST \
  /v1/api-keys \
  browser \
  "$temporary_directory/api-key.json" \
  true
created_key_response_file="$response_file"
created_key_id="$(extract_field "$created_key_response_file" api_key.key_id)" ||
  fail "disposable API key response omitted key_id"
[[ "$created_key_id" =~ ^[A-Za-z0-9_-]{1,128}$ ]] ||
  fail "disposable API key response contained an invalid key_id"
disposable_key_id="$created_key_id"
json_check key-created "$disposable_label" ||
  fail "disposable API key response was invalid"
pass "API key created once"

request_capture \
  "API key list" \
  200 \
  GET \
  "/v1/api-keys?tenant_id=acme&status=active&limit=100" \
  browser
json_check key-listed "$created_key_response_file" "$disposable_key_id" ||
  fail "API key list was unsafe or omitted the disposable key"
pass "API key listed without secret"

request_capture \
  "API key revoke" \
  200 \
  POST \
  "/v1/api-keys/${disposable_key_id}/revoke" \
  browser \
  "" \
  true
json_check key-revoked "$disposable_key_id" ||
  fail "disposable API key was not revoked"
disposable_key_revoked=true
pass "API key revoked"

audit_window_start="$(( $(date +%s) - 300 ))"
request_capture \
  "email.send evaluation" \
  200 \
  POST \
  /v1/evaluate \
  agent \
  "$temporary_directory/email-send.json"
json_check approval-evaluation ||
  fail "email.send did not return REQUIRE_APPROVAL"
approval_id="$(extract_field "$response_file" approval_id)" ||
  fail "email.send response omitted approval_id"
pass "approval-required action created"

request_capture \
  "pending approval list" \
  200 \
  GET \
  "/v1/approvals?status=PENDING&tenant_id=acme&limit=100" \
  browser
json_check pending-approval "$approval_id" "$policy_version" ||
  fail "pending approval summary was missing or unsafe"
pass "pending approval listed safely"

request_capture \
  "operator approval" \
  200 \
  POST \
  "/v1/approvals/${approval_id}/approve" \
  browser \
  "" \
  true
json_check approved "$approval_id" "$policy_version" ||
  fail "operator approval response was invalid"
pass "operator approved request"

request_capture \
  "approval consume" \
  200 \
  POST \
  "/v1/approvals/${approval_id}/consume" \
  agent \
  "$temporary_directory/email-send.json"
json_check authorized "$approval_id" ||
  fail "exact approval consumption was not authorized"
pass "exact request consumed without tool execution"

request_capture "policy catalog" 200 GET /v1/policies browser
json_check policies "$policy_version" || fail "policy catalog was invalid"
pass "policy catalog"

audit_window_end="$(( $(date +%s) + 300 ))"
request_capture \
  "audit query" \
  200 \
  GET \
  "/v1/audit?tenant_id=acme&created_from=${audit_window_start}&created_to=${audit_window_end}&limit=100" \
  browser
json_check \
  audit \
  "$approval_id" \
  "$policy_version" \
  "$source_text" \
  "$created_key_response_file" ||
  fail "audit evidence was incomplete or exposed sensitive data"
pass "audit evidence present and sanitized"

request_capture \
  "operator logout" \
  200 \
  DELETE \
  /v1/operator/session \
  browser \
  "" \
  true
json_check logout || fail "operator logout response was invalid"
pass "operator logout"

request_capture "post-logout authorization" 401 GET /v1/policies browser
json_check unauthorized || fail "cleared browser session remained authorized"
pass "post-logout session rejected"

[[ $evaluation_request_count -eq 1 ]] ||
  fail "semantic evaluation count was not exactly 1"
pass "semantic evaluations limited to 1"
