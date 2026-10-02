import type { JsonValue, NormalizedToolCall } from "../contracts";

export type ApprovalDisplaySummary =
  | {
      kind: "email_send";
      recipient: string;
      subject?: string;
      has_attachments: boolean;
    }
  | {
      kind: "refund_create";
      amount_minor: number;
      currency?: string;
      order_id?: string;
    }
  | { kind: "generic" };

const MAX_RECIPIENT_LENGTH = 320;
const MAX_SUBJECT_LENGTH = 500;
const MAX_ORDER_ID_LENGTH = 128;

function boundedText(
  value: JsonValue | undefined,
  maxLength: number,
): string | null {
  if (typeof value !== "string") return null;

  const text = value.trim();
  if (
    text.length === 0 ||
    text.length > maxLength ||
    /[\p{Cc}\p{Cf}]/u.test(text)
  ) {
    return null;
  }

  return text;
}

function attachmentValueIsPresent(value: JsonValue | undefined): boolean {
  if (value === undefined || value === null || value === false) return false;
  if (typeof value === "string") return value.trim().length > 0;
  if (Array.isArray(value)) return value.length > 0;
  return true;
}

/**
 * Produces display-only metadata from a deliberately small field allowlist.
 * The result must never participate in authorization; request_hash remains
 * the exact-request authority.
 */
export function buildApprovalDisplaySummary(
  normalized: NormalizedToolCall,
): ApprovalDisplaySummary {
  if (normalized.tool_name === "email.send") {
    const recipient = boundedText(normalized.args.to, MAX_RECIPIENT_LENGTH) ?? "";
    const subject = boundedText(normalized.args.subject, MAX_SUBJECT_LENGTH);
    const result: ApprovalDisplaySummary = {
      kind: "email_send",
      recipient,
      has_attachments:
        attachmentValueIsPresent(normalized.args.attachment) ||
        attachmentValueIsPresent(normalized.args.attachments),
    };

    if (subject !== null) result.subject = subject;
    return result;
  }

  if (
    normalized.tool_name === "refund.create" &&
    typeof normalized.amount_minor === "number" &&
    Number.isSafeInteger(normalized.amount_minor)
  ) {
    const currencyValue = boundedText(normalized.args.currency, 3);
    const currency =
      currencyValue !== null && /^[a-z]{3}$/i.test(currencyValue)
        ? currencyValue.toUpperCase()
        : null;
    const orderId = boundedText(normalized.args.order_id, MAX_ORDER_ID_LENGTH);
    const result: ApprovalDisplaySummary = {
      kind: "refund_create",
      amount_minor: normalized.amount_minor,
    };

    if (currency !== null) result.currency = currency;
    if (orderId !== null) result.order_id = orderId;
    return result;
  }

  return { kind: "generic" };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isPersistableDisplayText(
  value: unknown,
  maxLength: number,
  allowEmpty = false,
): value is string {
  return (
    typeof value === "string" &&
    value === value.trim() &&
    (allowEmpty || value.length >= 1) &&
    value.length <= maxLength &&
    !/[\p{Cc}\p{Cf}]/u.test(value)
  );
}

function hasExactKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[] = [],
): boolean {
  const keys = Object.keys(value);
  const allowed = new Set([...required, ...optional]);
  return (
    required.every((key) => Object.hasOwn(value, key)) &&
    keys.every((key) => allowed.has(key))
  );
}

/** Parses only the allowlisted persisted presentation shapes. */
export function parseApprovalDisplaySummary(
  value: unknown,
): ApprovalDisplaySummary {
  if (!isRecord(value) || typeof value.kind !== "string") {
    throw new TypeError("invalid D1 approval_display_json");
  }

  if (value.kind === "generic" && hasExactKeys(value, ["kind"])) {
    return { kind: "generic" };
  }

  if (
    value.kind === "email_send" &&
    hasExactKeys(value, ["kind", "recipient", "has_attachments"], ["subject"]) &&
    isPersistableDisplayText(value.recipient, MAX_RECIPIENT_LENGTH, true) &&
    typeof value.has_attachments === "boolean" &&
    (value.subject === undefined ||
      isPersistableDisplayText(value.subject, MAX_SUBJECT_LENGTH))
  ) {
    const result: ApprovalDisplaySummary = {
      kind: "email_send",
      recipient: value.recipient,
      has_attachments: value.has_attachments,
    };
    if (typeof value.subject === "string") result.subject = value.subject;
    return result;
  }

  if (
    value.kind === "refund_create" &&
    hasExactKeys(value, ["kind", "amount_minor"], ["currency", "order_id"]) &&
    typeof value.amount_minor === "number" &&
    Number.isSafeInteger(value.amount_minor) &&
    value.amount_minor > 0 &&
    value.amount_minor <= 50_000 &&
    (value.currency === undefined ||
      (typeof value.currency === "string" && /^[A-Z]{3}$/.test(value.currency))) &&
    (value.order_id === undefined ||
      isPersistableDisplayText(value.order_id, MAX_ORDER_ID_LENGTH))
  ) {
    const result: ApprovalDisplaySummary = {
      kind: "refund_create",
      amount_minor: value.amount_minor,
    };
    if (typeof value.currency === "string") result.currency = value.currency;
    if (typeof value.order_id === "string") result.order_id = value.order_id;
    return result;
  }

  throw new TypeError("invalid D1 approval_display_json");
}

export function serializeApprovalDisplaySummary(
  summary: ApprovalDisplaySummary,
): string {
  // Re-parse before persistence so injected adapters cannot smuggle extra
  // runtime properties through a structurally typed object.
  return JSON.stringify(parseApprovalDisplaySummary(summary));
}
