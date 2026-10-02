import { describe, expect, test } from "bun:test";
import { authenticateRequest } from "../src/security/authenticate";
import { CloudflareBurstRateLimiter } from "../src/security/cloudflare-rate-limiter";
import {
  canonicalJson,
  hashApprovalRequest,
  hashMalformedArguments,
  hashNormalizedArguments,
  sha256Hex,
} from "../src/security/crypto";
import { ATOMIC_QUOTA_SQL } from "../src/security/d1-repositories";
import type {
  ApiKeyRecord,
  PrincipalRepository,
} from "../src/security/types";

function obviousFakeToken(): string {
  return ["aag", "test", "obviously-fake-unit-test-token"].join("_");
}

function requestWithAuthorization(authorization?: string): Request {
  const headers = new Headers();

  if (authorization !== undefined) {
    headers.set("authorization", authorization);
  }

  return new Request("https://gate.example/v1/evaluate", { headers });
}

const activeRecord: ApiKeyRecord = {
  key_id: "key-fixture",
  principal_id: "principal-fixture",
  tenant_id: "tenant-a",
  daily_ai_limit: 25,
  status: "active",
};

describe("security hashing", () => {
  test("sha256Hex is deterministic and emits a 64-character lowercase hex digest", async () => {
    const first = await sha256Hex("deterministic fixture");
    const second = await sha256Hex("deterministic fixture");
    const different = await sha256Hex("different fixture");

    expect(first).toBe(second);
    expect(first).not.toBe(different);
    expect(first).toMatch(/^[0-9a-f]{64}$/);
  });

  test("canonical argument hashing ignores object key order but preserves array order", async () => {
    const first = await hashNormalizedArguments({
      nested: { z: 1, a: true },
      sequence: ["first", "second"],
    });
    const reordered = await hashNormalizedArguments({
      sequence: ["first", "second"],
      nested: { a: true, z: 1 },
    });
    const changedArray = await hashNormalizedArguments({
      nested: { a: true, z: 1 },
      sequence: ["second", "first"],
    });

    expect(first).toBe(reordered);
    expect(first).not.toBe(changedArray);
  });

  test("malformed argument hashes are domain-separated from valid empty objects", async () => {
    expect(await hashMalformedArguments("{}"))
      .not.toBe(await hashNormalizedArguments({}));
  });

  test("canonical JSON rejects non-finite and excessively nested values", () => {
    expect(() => canonicalJson({ value: Number.POSITIVE_INFINITY })).toThrow();

    let nested: unknown = null;
    for (let index = 0; index < 66; index += 1) nested = [nested];
    expect(() => canonicalJson(nested as never)).toThrow();
  });

  test("approval binding rejects unsafe integers that could hash ambiguously", async () => {
    await expect(
      hashApprovalRequest({
        principal_id: "principal-a",
        trusted_tenant_id: "tenant-a",
        normalized: {
          agent_role: "support-agent",
          tool_name: "email.send",
          args: {
            target_tenant: "tenant-a",
            unsafe: Number.MAX_SAFE_INTEGER + 1,
          },
        },
        source_text: "Send the message.",
        policy: {
          decision: "REQUIRE_APPROVAL",
          risk_level: "medium",
          policy_codes: ["OUTBOUND_SEND"],
          requires_approval: true,
        },
      }),
    ).rejects.toThrow("unsafe number");
  });
});

describe("API-key authentication", () => {
  test("returns a trusted principal for an active key", async () => {
    const repository: PrincipalRepository = {
      findByKeyHash: async () => activeRecord,
    };

    const result = await authenticateRequest(
      requestWithAuthorization(`Bearer ${obviousFakeToken()}`),
      repository,
    );

    expect(result).toEqual({
      ok: true,
      principal: {
        key_id: "key-fixture",
        principal_id: "principal-fixture",
        tenant_id: "tenant-a",
        daily_ai_limit: 25,
      },
    });
  });

  test("rejects an unknown key", async () => {
    const repository: PrincipalRepository = {
      findByKeyHash: async () => null,
    };

    const result = await authenticateRequest(
      requestWithAuthorization(`Bearer ${obviousFakeToken()}`),
      repository,
    );

    expect(result).toEqual({ ok: false, reason: "unauthorized" });
  });

  test("rejects a revoked key", async () => {
    const repository: PrincipalRepository = {
      findByKeyHash: async () => ({ ...activeRecord, status: "revoked" }),
    };

    const result = await authenticateRequest(
      requestWithAuthorization(`Bearer ${obviousFakeToken()}`),
      repository,
    );

    expect(result).toEqual({ ok: false, reason: "unauthorized" });
  });

  test("rejects malformed authorization without consulting the repository", async () => {
    let repositoryCalls = 0;
    const repository: PrincipalRepository = {
      findByKeyHash: async () => {
        repositoryCalls += 1;
        return activeRecord;
      },
    };
    const malformed = [
      undefined,
      "Basic not-a-bearer-token",
      "Bearer short",
      ["Bearer", ["aag", "test", "too-short"].join("_")].join(" "),
      `Bearer ${obviousFakeToken()} trailing-data`,
    ];

    for (const authorization of malformed) {
      const result = await authenticateRequest(
        requestWithAuthorization(authorization),
        repository,
      );
      expect(result).toEqual({ ok: false, reason: "unauthorized" });
    }

    expect(repositoryCalls).toBe(0);
  });

  test("passes only the SHA-256 digest, never the raw bearer token, to storage", async () => {
    const token = obviousFakeToken();
    const observedLookupValues: string[] = [];
    const repository: PrincipalRepository = {
      findByKeyHash: async (keyHash) => {
        observedLookupValues.push(keyHash);
        return activeRecord;
      },
    };

    const result = await authenticateRequest(
      requestWithAuthorization(`Bearer ${token}`),
      repository,
    );

    expect(result.ok).toBe(true);
    expect(observedLookupValues).toEqual([await sha256Hex(token)]);
    expect(observedLookupValues).not.toContain(token);
    expect(observedLookupValues[0]).toMatch(/^[0-9a-f]{64}$/);
  });

  test("fails closed as unavailable when the repository fails", async () => {
    const repository: PrincipalRepository = {
      findByKeyHash: async () => {
        throw new Error("simulated D1 outage");
      },
    };

    const result = await authenticateRequest(
      requestWithAuthorization(`Bearer ${obviousFakeToken()}`),
      repository,
    );

    expect(result).toEqual({ ok: false, reason: "unavailable" });
  });

  test("fails closed as unavailable for corrupt principal metadata", async () => {
    const repository: PrincipalRepository = {
      findByKeyHash: async () => ({
        ...activeRecord,
        tenant_id: " Non-Canonical ",
      }),
    };

    const result = await authenticateRequest(
      requestWithAuthorization(`Bearer ${obviousFakeToken()}`),
      repository,
    );

    expect(result).toEqual({ ok: false, reason: "unavailable" });
  });
});

describe("per-principal burst limiting", () => {
  test("uses an evaluate-prefixed principal key", async () => {
    const observedKeys: string[] = [];
    const binding: RateLimit = {
      limit: async ({ key }) => {
        observedKeys.push(key);
        return { success: true };
      },
    };
    const limiter = new CloudflareBurstRateLimiter(binding);

    expect(await limiter.allow("principal-fixture")).toBe(true);
    expect(observedKeys).toEqual(["evaluate:principal-fixture"]);
  });
});

describe("D1 quota statement", () => {
  test("is a single conditional upsert with RETURNING, not a read-then-update sequence", () => {
    const sql = ATOMIC_QUOTA_SQL.trim().replace(/\s+/g, " ");

    expect(sql).toMatch(/^INSERT INTO daily_ai_usage\b/i);
    expect(sql).toMatch(/\bSELECT\b.+\bWHERE\b.+\bON CONFLICT\b/is);
    expect(sql).toMatch(/\bDO UPDATE SET\b.+\bWHERE\b.+\bRETURNING\b/is);
    expect(sql.match(/\bINSERT INTO\b/gi)).toHaveLength(1);
    expect(sql).not.toMatch(/;\s*(?:SELECT|UPDATE)\b/i);
    expect(sql).not.toMatch(/^SELECT\b/i);
  });
});
