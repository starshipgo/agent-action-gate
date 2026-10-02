import { sha256Hex } from "./crypto";
import type {
  ApiKeyRecord,
  PrincipalRepository,
  TrustedPrincipal,
} from "./types";

export type AuthenticationResult =
  | { ok: true; principal: TrustedPrincipal }
  | { ok: false; reason: "unauthorized" | "unavailable" };

const API_KEY_PATTERN = /^aag_test_[A-Za-z0-9_-]{16,247}$/;

function extractBearerToken(request: Request): string | null {
  const authorization = request.headers.get("authorization");

  if (authorization === null) {
    return null;
  }

  const match = /^Bearer ([^\s]+)$/i.exec(authorization);
  const token = match?.[1];

  return token !== undefined && API_KEY_PATTERN.test(token) ? token : null;
}

function isCanonicalTenant(value: string): boolean {
  return value.length > 0 && value === value.trim().toLowerCase();
}

function validRecord(record: ApiKeyRecord): boolean {
  return (
    record.key_id.trim() !== "" &&
    record.principal_id.trim() !== "" &&
    isCanonicalTenant(record.tenant_id) &&
    (record.status === "active" || record.status === "revoked") &&
    Number.isSafeInteger(record.daily_ai_limit) &&
    record.daily_ai_limit >= 0
  );
}

export async function authenticateRequest(
  request: Request,
  repository: PrincipalRepository,
): Promise<AuthenticationResult> {
  const token = extractBearerToken(request);

  if (token === null) {
    return { ok: false, reason: "unauthorized" };
  }

  try {
    const keyHash = await sha256Hex(token);
    const record = await repository.findByKeyHash(keyHash);

    if (record === null || record.status === "revoked") {
      return { ok: false, reason: "unauthorized" };
    }

    if (!validRecord(record)) {
      return { ok: false, reason: "unavailable" };
    }

    return {
      ok: true,
      principal: {
        principal_id: record.principal_id,
        tenant_id: record.tenant_id,
        key_id: record.key_id,
        daily_ai_limit: record.daily_ai_limit,
      },
    };
  } catch {
    return { ok: false, reason: "unavailable" };
  }
}
