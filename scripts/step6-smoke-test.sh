#!/usr/bin/env bash

# Future Preview-only use:
# BASE_URL=https://preview.example \
# AAG_API_KEY=... \
# OPERATOR_API_KEY=... \
# ./scripts/step6-smoke-test.sh

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

case "$BASE_URL" in
  http://* | https://*) ;;
  *) fail "BASE_URL must use HTTP or HTTPS" ;;
esac

if [[ "$AAG_API_KEY" =~ [[:space:]] ]]; then
  fail "AAG_API_KEY contains invalid characters"
fi
if [[ "$OPERATOR_API_KEY" =~ [[:space:]] ]]; then
  fail "OPERATOR_API_KEY contains invalid characters"
fi

base_url="${BASE_URL%/}"
temporary_directory="$(
  mktemp -d "${TMPDIR:-/tmp}/agent-action-gate-step6-smoke.XXXXXX" 2>/dev/null
)" || fail "could not create temporary directory"

cleanup() {
  rm -rf -- "$temporary_directory" >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

run_nonce="$(bun -e 'process.stdout.write(crypto.randomUUID())' 2>/dev/null)" ||
  fail "could not create smoke-test marker"
contact_id="contact-step6-${run_nonce}"
source_text="Agent Action Gate Step 6 smoke-test source marker ${run_nonce}."
crm_arguments_json="{\"contact_id\":\"${contact_id}\",\"target_tenant\":\"acme\"}"
email_original_arguments_json='{"to":"customer@example.com","subject":"Account update","body":"Your requested account update is attached.","target_tenant":"acme"}'
email_mutated_arguments_json='{"to":"attacker@example.com","subject":"Account update","body":"Your requested account update is attached.","target_tenant":"acme"}'

export SMOKE_SOURCE_TEXT="$source_text"
export SMOKE_CONTACT_ID="$contact_id"
export SMOKE_CRM_ARGUMENTS_JSON="$crm_arguments_json"
export SMOKE_EMAIL_ORIGINAL_ARGUMENTS_JSON="$email_original_arguments_json"
export SMOKE_EMAIL_MUTATED_ARGUMENTS_JSON="$email_mutated_arguments_json"

write_request_payload() {
  local path="$1"
  local tool_name="$2"
  local arguments_json="$3"

  bun -e '
    const [path, toolName, argumentsJson, sourceText] = process.argv.slice(1);
    await Bun.write(
      path,
      JSON.stringify({
        agent_role: "support_agent",
        tool_name: toolName,
        arguments_json: argumentsJson,
        source_text: sourceText,
        request_tenant: "acme",
      }),
    );
  ' "$path" "$tool_name" "$arguments_json" "$source_text" >/dev/null 2>&1 ||
    fail "could not prepare request payload"
}

sha256_text() {
  bun -e '
    const digest = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(process.argv[1]),
    );
    process.stdout.write(
      Array.from(new Uint8Array(digest), (byte) =>
        byte.toString(16).padStart(2, "0"),
      ).join(""),
    );
  ' "$1" 2>/dev/null
}

normalized_arguments_hash() {
  bun -e '
    const canonicalJson = (value, depth = 0) => {
      if (depth > 64) throw new TypeError("JSON nesting exceeds limit");
      if (value === null || typeof value !== "object") {
        const serialized = JSON.stringify(value);
        if (serialized === undefined) throw new TypeError("invalid JSON value");
        return serialized;
      }
      if (Array.isArray(value)) {
        return `[${value.map((entry) => canonicalJson(entry, depth + 1)).join(",")}]`;
      }
      return `{${Object.keys(value)
        .sort()
        .map(
          (key) =>
            `${JSON.stringify(key)}:${canonicalJson(value[key], depth + 1)}`,
        )
        .join(",")}}`;
    };

    const value = JSON.parse(process.argv[1]);
    const input = `normalized-json-v1:${canonicalJson(value)}`;
    const digest = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(input),
    );
    process.stdout.write(
      Array.from(new Uint8Array(digest), (byte) =>
        byte.toString(16).padStart(2, "0"),
      ).join(""),
    );
  ' "$1" 2>/dev/null
}

write_request_payload \
  "$temporary_directory/crm-read.json" \
  crm.read_contact \
  "$crm_arguments_json"
write_request_payload \
  "$temporary_directory/email-original.json" \
  email.send \
  "$email_original_arguments_json"
write_request_payload \
  "$temporary_directory/email-mutated.json" \
  email.send \
  "$email_mutated_arguments_json"

source_text_hash="$(sha256_text "$source_text")" ||
  fail "could not hash source marker"
crm_arguments_hash="$(normalized_arguments_hash "$crm_arguments_json")" ||
  fail "could not hash crm.read_contact arguments"
email_arguments_hash="$(
  normalized_arguments_hash "$email_original_arguments_json"
)" || fail "could not hash email.send arguments"

request_number=0
evaluation_request_count=0
response_file=""

request_capture() {
  local label="$1"
  local expected_status="$2"
  local method="$3"
  local path="$4"
  local credential="$5"
  local payload_file="${6:-}"
  local curl_status
  local curl_exit
  local token=""

  request_number=$((request_number + 1))
  if [[ "$path" == "/v1/evaluate" ]]; then
    evaluation_request_count=$((evaluation_request_count + 1))
    [[ $evaluation_request_count -le 3 ]] ||
      fail "semantic evaluation limit exceeded"
  fi
  response_file="$temporary_directory/response-$request_number.json"

  local curl_arguments=(
    --silent
    --connect-timeout 10
    --max-time 120
    --output "$response_file"
    --write-out '%{http_code}'
    --request "$method"
  )

  if [[ -n "$payload_file" ]]; then
    curl_arguments+=(
      --header 'Content-Type: application/json'
      --data-binary "@$payload_file"
    )
  fi

  case "$credential" in
    none) ;;
    agent) token="$AAG_API_KEY" ;;
    operator) token="$OPERATOR_API_KEY" ;;
    *) fail "$label has an invalid credential mode" ;;
  esac

  set +e
  if [[ "$credential" == "none" ]]; then
    curl_status="$(curl "${curl_arguments[@]}" "${base_url}${path}")"
    curl_exit=$?
  else
    curl_status="$(
      printf 'Authorization: Bearer %s\n' "$token" |
        curl "${curl_arguments[@]}" --header @- "${base_url}${path}"
    )"
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
    const [mode, path, ...args] = process.argv.slice(1);

    try {
      const body = await Bun.file(path).json();
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
      const publicApprovalKeys = [
        "approval_id",
        "principal_id",
        "tenant_id",
        "tool_name",
        "risk_level",
        "policy_codes",
        "status",
        "created_at",
        "expires_at",
        "decided_at",
        "consumed_at",
      ];
      const publicAuditKeys = [
        "id",
        "request_id",
        "principal_id",
        "key_id",
        "tenant_id",
        "tool_name",
        "event_type",
        "decision",
        "risk_level",
        "policy_codes",
        "arguments_hash",
        "source_text_hash",
        "approval_id",
        "created_at",
      ];
      let ok = false;

      switch (mode) {
        case "health":
          ok =
            exactKeys(body, ["status", "service"]) &&
            body.status === "ok" &&
            body.service === "agent-action-gate";
          break;
        case "allow-crm": {
          const [contactId] = args;
          ok =
            exactKeys(body, [
              "decision",
              "risk_level",
              "policy_codes",
              "requires_approval",
              "normalized_tool",
              "normalized_args",
            ]) &&
            body.decision === "ALLOW" &&
            body.risk_level === "low" &&
            exactStrings(body.policy_codes, []) &&
            body.requires_approval === false &&
            body.normalized_tool === "crm.read_contact" &&
            exactKeys(body.normalized_args, ["contact_id", "target_tenant"]) &&
            body.normalized_args.contact_id === contactId &&
            body.normalized_args.target_tenant === "acme";
          break;
        }
        case "approval-email":
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
            exactKeys(body.normalized_args, [
              "to",
              "subject",
              "body",
              "target_tenant",
            ]) &&
            body.normalized_args.to === "customer@example.com" &&
            body.normalized_args.subject === "Account update" &&
            body.normalized_args.body ===
              "Your requested account update is attached." &&
            body.normalized_args.target_tenant === "acme" &&
            typeof body.approval_id === "string" &&
            /^[A-Za-z0-9_-]{1,128}$/.test(body.approval_id) &&
            typeof body.expires_at === "string" &&
            Number.isFinite(Date.parse(body.expires_at));
          break;
        case "error":
          ok = exactKeys(body, ["error"]) && body.error === args[0];
          break;
        case "pending-list": {
          const [approvalId] = args;
          ok =
            exactKeys(body, ["approvals"]) &&
            Array.isArray(body.approvals) &&
            body.approvals.some(
              (approval) =>
                exactKeys(approval, publicApprovalKeys) &&
                approval.approval_id === approvalId &&
                typeof approval.principal_id === "string" &&
                approval.principal_id.length > 0 &&
                approval.tenant_id === "acme" &&
                approval.tool_name === "email.send" &&
                approval.risk_level === "medium" &&
                exactStrings(approval.policy_codes, ["OUTBOUND_SEND"]) &&
                approval.status === "PENDING" &&
                Number.isInteger(approval.created_at) &&
                Number.isInteger(approval.expires_at) &&
                approval.decided_at === null &&
                approval.consumed_at === null,
            );
          break;
        }
        case "approval-status": {
          const [approvalId, status] = args;
          ok =
            exactKeys(body, ["approval"]) &&
            exactKeys(body.approval, publicApprovalKeys) &&
            body.approval.approval_id === approvalId &&
            typeof body.approval.principal_id === "string" &&
            body.approval.principal_id.length > 0 &&
            body.approval.tenant_id === "acme" &&
            body.approval.tool_name === "email.send" &&
            body.approval.risk_level === "medium" &&
            exactStrings(body.approval.policy_codes, ["OUTBOUND_SEND"]) &&
            body.approval.status === status &&
            Number.isInteger(body.approval.created_at) &&
            Number.isInteger(body.approval.expires_at) &&
            Number.isInteger(body.approval.decided_at) &&
            body.approval.consumed_at === null;
          break;
        }
        case "authorized": {
          const [approvalId] = args;
          ok =
            exactKeys(body, [
              "authorized",
              "approval_id",
              "tool_name",
              "normalized_args",
            ]) &&
            body.authorized === true &&
            body.approval_id === approvalId &&
            body.tool_name === "email.send" &&
            exactKeys(body.normalized_args, [
              "to",
              "subject",
              "body",
              "target_tenant",
            ]) &&
            body.normalized_args.to === "customer@example.com" &&
            body.normalized_args.subject === "Account update" &&
            body.normalized_args.body ===
              "Your requested account update is attached." &&
            body.normalized_args.target_tenant === "acme";
          break;
        }
        case "audit": {
          const [
            firstApprovalId,
            secondApprovalId,
            expectedSourceHash,
            expectedCrmArgumentsHash,
            expectedEmailArgumentsHash,
          ] = args;
          const events = body.audit_events;
          const has = (predicate) => Array.isArray(events) && events.some(predicate);
          const validPublicEvent = (event) =>
            exactKeys(event, publicAuditKeys) &&
            typeof event.id === "string" &&
            event.id.length > 0 &&
            typeof event.request_id === "string" &&
            event.request_id.length > 0 &&
            typeof event.principal_id === "string" &&
            event.principal_id.length > 0 &&
            event.tenant_id === "acme" &&
            Number.isInteger(event.created_at);
          const evaluated = ({
            event,
            tool,
            decision,
            risk,
            codes,
            argumentsHash,
            approvalId,
          }) =>
            validPublicEvent(event) &&
            event.event_type === "EVALUATED" &&
            typeof event.key_id === "string" &&
            event.key_id.length > 0 &&
            event.tool_name === tool &&
            event.decision === decision &&
            event.risk_level === risk &&
            exactStrings(event.policy_codes, codes) &&
            event.arguments_hash === argumentsHash &&
            event.source_text_hash === expectedSourceHash &&
            event.approval_id === approvalId;
          const lifecycle = (event, eventType, approvalId) =>
            validPublicEvent(event) &&
            event.request_id === approvalId &&
            event.key_id === null &&
            event.tool_name === "email.send" &&
            event.event_type === eventType &&
            event.decision === null &&
            event.risk_level === null &&
            exactStrings(event.policy_codes, ["OUTBOUND_SEND"]) &&
            event.arguments_hash === null &&
            event.source_text_hash === null &&
            event.approval_id === approvalId;
          const evaluatedHashesAreSafe =
            Array.isArray(events) &&
            events
              .filter((event) => event?.event_type === "EVALUATED")
              .every(
                (event) =>
                  /^[0-9a-f]{64}$/.test(event?.arguments_hash ?? "") &&
                  /^[0-9a-f]{64}$/.test(event?.source_text_hash ?? ""),
              );
          const fragments = [];
          const collectFragments = (value) => {
            if (typeof value === "string") {
              fragments.push(value);
              return;
            }
            if (Array.isArray(value)) {
              value.forEach(collectFragments);
              return;
            }
            if (isRecord(value)) {
              for (const [key, entry] of Object.entries(value)) {
                fragments.push(key);
                collectFragments(entry);
              }
            }
          };
          collectFragments(body);
          const forbidden = [
            process.env.SMOKE_SOURCE_TEXT,
            process.env.SMOKE_CONTACT_ID,
            process.env.SMOKE_CRM_ARGUMENTS_JSON,
            process.env.SMOKE_EMAIL_ORIGINAL_ARGUMENTS_JSON,
            process.env.SMOKE_EMAIL_MUTATED_ARGUMENTS_JSON,
            "customer@example.com",
            "attacker@example.com",
            "Account update",
            "Your requested account update is attached.",
            process.env.AAG_API_KEY,
            process.env.OPERATOR_API_KEY,
            `Bearer ${process.env.AAG_API_KEY ?? ""}`,
            `Bearer ${process.env.OPERATOR_API_KEY ?? ""}`,
          ].filter((value) => typeof value === "string" && value.length > 0);

          ok =
            exactKeys(body, ["audit_events"]) &&
            Array.isArray(events) &&
            events.length >= 6 &&
            events.every(validPublicEvent) &&
            has(
              (event) => evaluated({
                event,
                tool: "crm.read_contact",
                decision: "ALLOW",
                risk: "low",
                codes: [],
                argumentsHash: expectedCrmArgumentsHash,
                approvalId: null,
              }),
            ) &&
            has(
              (event) => evaluated({
                event,
                tool: "email.send",
                decision: "REQUIRE_APPROVAL",
                risk: "medium",
                codes: ["OUTBOUND_SEND"],
                argumentsHash: expectedEmailArgumentsHash,
                approvalId: firstApprovalId,
              }),
            ) &&
            has((event) => lifecycle(event, "APPROVED", firstApprovalId)) &&
            has((event) => lifecycle(event, "CONSUMED", firstApprovalId)) &&
            has(
              (event) => evaluated({
                event,
                tool: "email.send",
                decision: "REQUIRE_APPROVAL",
                risk: "medium",
                codes: ["OUTBOUND_SEND"],
                argumentsHash: expectedEmailArgumentsHash,
                approvalId: secondApprovalId,
              }),
            ) &&
            has((event) => lifecycle(event, "APPROVED", secondApprovalId)) &&
            evaluatedHashesAreSafe &&
            forbidden.every(
              (value) => !fragments.some((fragment) => fragment.includes(value)),
            ) &&
            fragments.every((fragment) => !/authorization/i.test(fragment));
          break;
        }
      }

      process.exit(ok ? 0 : 1);
    } catch {
      process.exit(1);
    }
  ' "$mode" "$response_file" "$@" >/dev/null 2>&1
}

extract_approval_id() {
  bun -e '
    try {
      const body = await Bun.file(process.argv[1]).json();
      if (
        typeof body?.approval_id !== "string" ||
        !/^[A-Za-z0-9_-]{1,128}$/.test(body.approval_id)
      ) {
        process.exit(1);
      }
      process.stdout.write(body.approval_id);
    } catch {
      process.exit(1);
    }
  ' "$response_file" 2>/dev/null
}

request_capture "health" 200 GET /health none
json_check health || fail "GET /health returned unexpected JSON"
pass "GET /health"

request_capture \
  "crm.read_contact evaluation" \
  200 \
  POST \
  /v1/evaluate \
  agent \
  "$temporary_directory/crm-read.json"
json_check allow-crm "$contact_id" ||
  fail "crm.read_contact did not return ALLOW"
pass "crm.read_contact -> ALLOW"

request_capture \
  "first email.send evaluation" \
  200 \
  POST \
  /v1/evaluate \
  agent \
  "$temporary_directory/email-original.json"
json_check approval-email ||
  fail "email.send did not return REQUIRE_APPROVAL"
first_approval_id="$(extract_approval_id)" ||
  fail "first email.send returned no valid approval_id"
pass "email.send -> REQUIRE_APPROVAL"

request_capture \
  "Agent approval attempt" \
  401 \
  POST \
  "/v1/approvals/${first_approval_id}/approve" \
  agent
json_check error UNAUTHORIZED || fail "Agent credential gained operator authority"
pass "Agent approval authority rejected"

request_capture \
  "pre-approval consume" \
  409 \
  POST \
  "/v1/approvals/${first_approval_id}/consume" \
  agent \
  "$temporary_directory/email-original.json"
json_check error APPROVAL_NOT_APPROVED ||
  fail "pre-approval consume returned an unexpected result"
pass "pre-approval consume rejected"

request_capture \
  "pending approval list" \
  200 \
  GET \
  "/v1/approvals?status=PENDING&tenant_id=acme&limit=100" \
  operator
json_check pending-list "$first_approval_id" ||
  fail "captured approval was absent from the pending list"
pass "pending approval listed"

request_capture \
  "first operator approval" \
  200 \
  POST \
  "/v1/approvals/${first_approval_id}/approve" \
  operator
json_check approval-status "$first_approval_id" APPROVED ||
  fail "operator approval returned an unexpected result"
pass "operator approved first request"

request_capture \
  "authorized consume" \
  200 \
  POST \
  "/v1/approvals/${first_approval_id}/consume" \
  agent \
  "$temporary_directory/email-original.json"
json_check authorized "$first_approval_id" ||
  fail "approved request did not return explicit authorization"
pass "approved request consumed once"

request_capture \
  "replayed consume" \
  409 \
  POST \
  "/v1/approvals/${first_approval_id}/consume" \
  agent \
  "$temporary_directory/email-original.json"
json_check error APPROVAL_ALREADY_CONSUMED ||
  fail "replayed consume returned an unexpected result"
pass "consume replay rejected"

request_capture \
  "second email.send evaluation" \
  200 \
  POST \
  /v1/evaluate \
  agent \
  "$temporary_directory/email-original.json"
json_check approval-email ||
  fail "second email.send did not return REQUIRE_APPROVAL"
second_approval_id="$(extract_approval_id)" ||
  fail "second email.send returned no valid approval_id"
[[ "$second_approval_id" != "$first_approval_id" ]] ||
  fail "second email.send reused the first approval_id"
pass "second email.send -> REQUIRE_APPROVAL"

request_capture \
  "second operator approval" \
  200 \
  POST \
  "/v1/approvals/${second_approval_id}/approve" \
  operator
json_check approval-status "$second_approval_id" APPROVED ||
  fail "second operator approval returned an unexpected result"
pass "operator approved second request"

request_capture \
  "mutated recipient consume" \
  409 \
  POST \
  "/v1/approvals/${second_approval_id}/consume" \
  agent \
  "$temporary_directory/email-mutated.json"
json_check error APPROVAL_REQUEST_MISMATCH ||
  fail "mutated recipient did not produce APPROVAL_REQUEST_MISMATCH"
pass "mutated recipient rejected"

request_capture \
  "audit query" \
  200 \
  GET \
  "/v1/audit?tenant_id=acme&limit=100" \
  operator
json_check \
  audit \
  "$first_approval_id" \
  "$second_approval_id" \
  "$source_text_hash" \
  "$crm_arguments_hash" \
  "$email_arguments_hash" ||
  fail "audit records were incomplete or exposed sensitive data"
pass "audit records present and sanitized"

[[ $evaluation_request_count -eq 3 ]] ||
  fail "semantic evaluation count was not exactly 3"
pass "semantic evaluations limited to 3"
