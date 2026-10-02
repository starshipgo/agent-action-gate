import { useCallback, useEffect, useState } from "react";
import { api } from "../api";
import { ErrorBanner, LoadingBlock, PageHeader, StatusPill, formatTimestamp } from "../components";
import { ApprovalIcon, CheckIcon, ClockIcon, ShieldIcon, TimelineIcon } from "../icons";
import { policyLabel } from "../policy-labels";
import { useResource } from "../use-resource";

export function OverviewPage({ onUnauthorized }: { onUnauthorized: () => void }) {
  const load = useCallback(() => api.overview(), []);
  const { data, error, loading, refresh } = useResource(load, onUnauthorized);
  const [funnel, setFunnel] = useState<Awaited<ReturnType<typeof api.betaFunnel>> | null>(null);
  useEffect(() => { void api.betaFunnel().then(setFunnel).catch(() => setFunnel(null)); }, []);

  const quotaValue = data === null
    ? "—"
    : `${data.metrics.ai_quota_usage.used_today.toLocaleString()} / ${data.metrics.ai_quota_usage.daily_limit.toLocaleString()}`;
  const quotaPercent = data?.metrics.ai_quota_usage.daily_limit
    ? Math.min(100, Math.round((data.metrics.ai_quota_usage.used_today / data.metrics.ai_quota_usage.daily_limit) * 100))
    : 0;

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Control plane"
        title="Overview"
        description="A current view of decisions, approvals, quota, and policy state."
        actions={<button className="button button-secondary" type="button" onClick={refresh}>Refresh</button>}
      />
      {error === null ? null : <ErrorBanner message={error} />}
      {loading && data === null ? <LoadingBlock label="Loading overview" /> : (
        <>
          <section className="metric-grid" aria-label="Decision summary">
            <article className="metric-card metric-positive">
              <div><span>Allowed</span><CheckIcon /></div>
              <strong>{data?.metrics.allowed.toLocaleString() ?? "—"}</strong>
              <small>Authorized evaluations</small>
            </article>
            <article className="metric-card metric-negative">
              <div><span>Blocked</span><ShieldIcon /></div>
              <strong>{data?.metrics.blocked.toLocaleString() ?? "—"}</strong>
              <small>Denied evaluations</small>
            </article>
            <article className="metric-card metric-warning">
              <div><span>Pending approvals</span><ClockIcon /></div>
              <strong>{data?.metrics.pending_approvals.toLocaleString() ?? "—"}</strong>
              <small>Waiting for an operator</small>
            </article>
            <article className="metric-card">
              <div><span>Approval-required</span><ApprovalIcon /></div>
              <strong>{data?.metrics.approval_required.toLocaleString() ?? "—"}</strong>
              <small>All approval decisions</small>
            </article>
          </section>

          <section className="overview-grid">
            <article className="panel activity-panel">
              <header className="panel-header">
                <div>
                  <span className="panel-kicker">Latest events</span>
                  <h2>Recent activity</h2>
                </div>
                <TimelineIcon />
              </header>
              {data?.recent_activity.length ? (
                <ol className="activity-list">
                  {data.recent_activity.map((event) => (
                    <li key={event.id}>
                      <span className={`activity-marker decision-${event.decision ?? "event"}`} />
                      <div className="activity-primary">
                        <div>
                          <strong>{event.tool_name}</strong>
                          <StatusPill value={event.decision ?? event.event_type} />
                        </div>
                        <span>{event.tenant_id} · {formatTimestamp(event.created_at)}</span>
                        {event.policy_codes[0] === undefined ? null : <small>{policyLabel(event.policy_codes[0])}</small>}
                      </div>
                    </li>
                  ))}
                </ol>
              ) : <p className="panel-empty">No activity has been recorded yet.</p>}
            </article>

            <div className="overview-side">
              <article className="panel quota-panel">
                <span className="panel-kicker">Classifier capacity</span>
                <h2>AI quota usage</h2>
                <div className="quota-number">{quotaValue}</div>
                <progress
                  className="quota-progress"
                  max={100}
                  value={quotaPercent}
                  aria-label={`${quotaPercent}% of quota used`}
                />
                <p>Only requests that reach semantic classification use this quota.</p>
              </article>
              <article className="panel policy-version-panel">
                <span className="panel-kicker">Enforcement baseline</span>
                <h2>Current policy</h2>
                <code>{data?.policy_version ?? "—"}</code>
                <p>Approvals and idempotent evaluations are bound to this immutable version.</p>
              </article>
            </div>
          </section>
          <section className="panel" aria-label="Beta funnel summary">
            <h2>Beta funnel · aggregate counts</h2>
            <p>First-party counters only. No prompts, arguments, keys, or personal details.</p>
            {funnel === null ? <p>Funnel summary unavailable.</p> : <dl className="demo-grid">{Object.entries(funnel.events).map(([event, count]) => <div key={event}><dt>{event.replaceAll("_", " ")}</dt><dd>{count.toLocaleString()}</dd></div>)}</dl>}
          </section>
        </>
      )}
    </div>
  );
}
