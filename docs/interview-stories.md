# Interview stories: security decisions and tradeoffs

These are engineering stories from the codebase, not customer or performance claims.

1. **A typed schema was not a runtime guarantee.** The Dify prototype emitted a boolean-like `"true"` string for a semantic signal. A strict boolean assumption could miss it. The native boundary normalizes both representations and keeps a regression test. Lesson: validate actual runtime values at the trust boundary.
2. **The caller cannot choose its tenant.** An early request contract included `request_tenant`, but that value is controlled by the caller. The Worker now authenticates a hashed, tenant-bound key and derives trusted identity from it; any supplied tenant must match. Target tenant remains a separate policy comparison.
3. **Rate limiting is not billing or quota accounting.** Cloudflare's Rate Limiting binding is useful for bursts but should not be treated as an exact daily counter. A D1-backed conditional quota records AI-classifier use and denies when exhausted. This is separate from the rate limiter.
4. **Approval has a TOCTOU boundary.** A model or caller could propose a harmless email, obtain approval, then change the recipient. The approval binds a hash of the exact original request and principal; the consume transition is conditional and one-time. Changing the request fails with `APPROVAL_REQUEST_MISMATCH`.
5. **One-time authorization is not exactly-once delivery.** After consume succeeds, a downstream provider may time out after performing an action. Retrying blindly could duplicate an email or refund. The gate prevents a second consume, but integrations still need provider idempotency, receipts, and reconciliation.
6. **Classifier failure fails closed.** If semantic classification errors, times out, or returns malformed signals, the deterministic engine denies with `SEMANTIC_CLASSIFIER_FAILURE` rather than assuming benign risk. Availability is sacrificed to preserve the authorization boundary.
