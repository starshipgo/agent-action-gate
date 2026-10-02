import { useCallback } from "react";
import { api } from "../api";
import { ErrorBanner, LoadingBlock, PageHeader, StatusPill } from "../components";
import { ShieldIcon } from "../icons";
import { useResource } from "../use-resource";

export function PoliciesPage({ onUnauthorized }: { onUnauthorized: () => void }) {
  const load = useCallback(() => api.policies(), []);
  const { data, error, loading, refresh } = useResource(load, onUnauthorized);

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Read-only policy"
        title="Built-in policies"
        description="The deterministic TypeScript policy engine remains the source of truth. This page is a human-readable view, not an editor."
        actions={<button className="button button-secondary" type="button" onClick={refresh}>Refresh</button>}
      />
      {error === null ? null : <ErrorBanner message={error} />}
      {loading && data === null ? <LoadingBlock label="Loading policies" /> : (
        <>
          <section className="policy-version-hero">
            <div className="policy-seal"><ShieldIcon /></div>
            <div>
              <span>Current immutable version</span>
              <strong>{data?.policy_version ?? "—"}</strong>
              <p>Evaluation, approval binding, and idempotency include this version.</p>
            </div>
          </section>
          <section className="panel policy-table">
            <header className="panel-header">
              <div><span className="panel-kicker">Evaluation order</span><h2>Authorization rules</h2></div>
              <span className="read-only-chip">Read only</span>
            </header>
            <div className="policy-list">
              {(data?.policies ?? []).map((policy, index) => (
                <article key={policy.id}>
                  <span className="policy-order">{String(index + 1).padStart(2, "0")}</span>
                  <div><strong>{policy.summary}</strong><code>{policy.id}</code></div>
                  <StatusPill value={policy.outcome} />
                </article>
              ))}
            </div>
          </section>
          <div className="trust-note">
            <ShieldIcon />
            <p><strong>Fail-closed by design.</strong> Unknown tools, cross-tenant targets, unsafe exports, secret access, and unmatched conditions do not authorize execution.</p>
          </div>
        </>
      )}
    </div>
  );
}
