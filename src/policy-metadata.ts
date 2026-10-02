/**
 * Immutable identifier for the built-in deterministic policy set.
 *
 * Change this value only when policy semantics change. Persisted decisions,
 * idempotency records, and approvals are bound to this value so an older
 * decision cannot silently acquire authority under a newer policy.
 */
export const POLICY_VERSION = "aag-policy-v1" as const;

export function isValidPolicyVersion(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length >= 1 &&
    value.length <= 64 &&
    /^[a-z0-9][a-z0-9._-]*$/i.test(value)
  );
}
