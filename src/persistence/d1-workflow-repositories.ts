import {
  APPROVAL_COLUMNS,
  D1ApprovalRepository,
  INSERT_APPROVAL_SQL,
  approvalRequestFromD1Row,
} from "./d1-approval-repository";
import {
  D1AuditRepository,
  INSERT_AUDIT_EVENT_SQL,
} from "./d1-audit-repository";
import type {
  EvaluationPersistenceInput,
  EvaluationPersistenceRepository,
  WorkflowRepositories,
} from "./types";
import { auditToolName } from "../approvals/workflow";
import { serializeApprovalDisplaySummary } from "../approvals/display-summary";
import { POLICY_VERSION } from "../policy-metadata";
import {
  COMPLETE_IDEMPOTENCY_SQL,
  serializeStoredEvaluationResult,
} from "../security/d1-repositories";

type D1Connection = Pick<D1DatabaseSession, "prepare" | "batch">;

const INSERT_APPROVAL_FOR_CLAIM_SQL = `
INSERT INTO approval_requests (
  id, principal_id, tenant_id, tool_name, request_hash, risk_level,
  policy_codes_json, policy_version, approval_display_json, status, created_at,
  expires_at, decided_at, decided_by, consumed_at
)
SELECT
  ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'PENDING', ?10, ?11,
  NULL, NULL, NULL
WHERE EXISTS (
  SELECT 1 FROM idempotency_records
  WHERE principal_id = ?12
    AND idempotency_key_hash = ?13
    AND request_hash = ?14
    AND policy_version = ?8
    AND state = 'pending'
    AND claim_token = ?15
    AND expires_at > ?16
)
RETURNING ${APPROVAL_COLUMNS}
`;

const INSERT_AUDIT_FOR_CLAIM_SQL = `
INSERT INTO audit_events (
  id, request_id, principal_id, key_id, tenant_id, tool_name, event_type,
  decision, risk_level, policy_codes_json, arguments_hash, source_text_hash,
  approval_id, policy_version, created_at
)
SELECT
  ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15
WHERE EXISTS (
  SELECT 1 FROM idempotency_records
  WHERE principal_id = ?16
    AND idempotency_key_hash = ?17
    AND request_hash = ?18
    AND policy_version = ?14
    AND state = 'pending'
    AND claim_token = ?19
    AND expires_at > ?20
)
`;

async function assertCoherentEvaluation(
  input: EvaluationPersistenceInput,
): Promise<void> {
  const { approval, event, idempotency = null } = input;

  if (event.event_type !== "EVALUATED") {
    throw new TypeError("evaluation persistence requires an EVALUATED audit event");
  }
  if (event.policy_version !== POLICY_VERSION) {
    throw new TypeError("evaluation policy version is not current");
  }

  const expectedAuditTool =
    idempotency === null
      ? null
      : await auditToolName(idempotency.response.normalized_tool);

  if (
    idempotency !== null &&
    (idempotency.principal_id !== event.principal_id ||
      idempotency.response.decision !== event.decision ||
      idempotency.response.risk_level !== event.risk_level ||
      expectedAuditTool !== event.tool_name ||
      JSON.stringify(idempotency.response.policy_codes) !==
        JSON.stringify(event.policy_codes))
  ) {
    throw new TypeError("idempotency response and audit event do not match");
  }

  if (approval === null) {
    if (
      event.decision === "REQUIRE_APPROVAL" ||
      event.approval_id !== null ||
      (idempotency !== null &&
        (idempotency.response.requires_approval ||
          idempotency.response.approval_id !== undefined ||
          idempotency.response.expires_at !== undefined))
    ) {
      throw new TypeError("REQUIRE_APPROVAL must include a pending approval");
    }
    return;
  }

  if (
    event.decision !== "REQUIRE_APPROVAL" ||
    event.approval_id !== approval.id ||
    event.principal_id !== approval.principal_id ||
    event.tenant_id !== approval.tenant_id ||
    event.tool_name !== approval.tool_name ||
    event.risk_level !== approval.risk_level ||
    event.policy_version !== approval.policy_version ||
    JSON.stringify(event.policy_codes) !== JSON.stringify(approval.policy_codes) ||
    (idempotency !== null &&
      (idempotency.response.requires_approval !== true ||
        idempotency.response.approval_id !== approval.id ||
        idempotency.response.expires_at !==
          new Date(approval.expires_at * 1000).toISOString()))
  ) {
    throw new TypeError("audit event and approval binding do not match");
  }
}

class D1EvaluationPersistenceRepository
  implements EvaluationPersistenceRepository
{
  constructor(
    private readonly database: D1Connection,
    private readonly audit: D1AuditRepository,
  ) {}

  async persist(input: EvaluationPersistenceInput) {
    await assertCoherentEvaluation(input);
    const { approval, event, idempotency = null } = input;

    if (idempotency !== null) {
      const statements: D1PreparedStatement[] = [];

      if (approval !== null) {
        statements.push(
          this.database
            .prepare(INSERT_APPROVAL_FOR_CLAIM_SQL)
            .bind(
              approval.id,
              approval.principal_id,
              approval.tenant_id,
              approval.tool_name,
              approval.request_hash,
              approval.risk_level,
              JSON.stringify(approval.policy_codes),
              approval.policy_version,
              serializeApprovalDisplaySummary(approval.approval_display),
              approval.created_at,
              approval.expires_at,
              idempotency.principal_id,
              idempotency.idempotency_key_hash,
              idempotency.request_hash,
              idempotency.owner_token,
              idempotency.now,
            ),
        );
      }

      statements.push(
        this.database
          .prepare(INSERT_AUDIT_FOR_CLAIM_SQL)
          .bind(
            event.id,
            event.request_id,
            event.principal_id,
            event.key_id,
            event.tenant_id,
            event.tool_name,
            event.event_type,
            event.decision,
            event.risk_level,
            JSON.stringify(event.policy_codes),
            event.arguments_hash,
            event.source_text_hash,
            event.approval_id,
            event.policy_version,
            event.created_at,
            idempotency.principal_id,
            idempotency.idempotency_key_hash,
            idempotency.request_hash,
            idempotency.owner_token,
            idempotency.now,
          ),
        this.database
          .prepare(COMPLETE_IDEMPOTENCY_SQL)
          .bind(
            idempotency.principal_id,
            idempotency.idempotency_key_hash,
            idempotency.request_hash,
            idempotency.owner_token,
            serializeStoredEvaluationResult(idempotency.response),
            idempotency.now,
            event.policy_version,
          ),
      );

      const results = await this.database.batch<Record<string, unknown>>(
        statements,
      );
      const completion = results.at(-1)?.results[0];

      if (completion === undefined) {
        throw new Error("idempotency completion lost ownership");
      }

      if (approval === null) {
        return { approval: null };
      }

      const approvalRow = results[0]?.results[0];
      if (approvalRow === undefined) {
        throw new Error("atomic approval persistence returned no row");
      }
      return { approval: approvalRequestFromD1Row(approvalRow) };
    }

    if (approval === null) {
      await this.audit.append(event);
      return { approval: null };
    }

    const approvalStatement = this.database
      .prepare(INSERT_APPROVAL_SQL)
      .bind(
        approval.id,
        approval.principal_id,
        approval.tenant_id,
        approval.tool_name,
        approval.request_hash,
        approval.risk_level,
        JSON.stringify(approval.policy_codes),
        approval.policy_version,
        serializeApprovalDisplaySummary(approval.approval_display),
        approval.created_at,
        approval.expires_at,
      );
    const auditStatement = this.database
      .prepare(INSERT_AUDIT_EVENT_SQL)
      .bind(
        event.id,
        event.request_id,
        event.principal_id,
        event.key_id,
        event.tenant_id,
        event.tool_name,
        event.event_type,
        event.decision,
        event.risk_level,
        JSON.stringify(event.policy_codes),
        event.arguments_hash,
        event.source_text_hash,
        event.approval_id,
        event.policy_version,
        event.created_at,
      );
    const results = await this.database.batch<Record<string, unknown>>([
      approvalStatement,
      auditStatement,
    ]);
    const row = results[0]?.results[0];

    if (row === undefined) {
      throw new Error("atomic approval persistence returned no row");
    }

    return { approval: approvalRequestFromD1Row(row) };
  }
}

export function createD1WorkflowRepositories(
  database: D1Database,
): WorkflowRepositories {
  const session = database.withSession("first-primary");
  const audit = new D1AuditRepository(session);
  const approvals = new D1ApprovalRepository(session);

  return {
    audit,
    approvals,
    evaluations: new D1EvaluationPersistenceRepository(session, audit),
  };
}
