import { useCallback, useState, type FormEvent } from "react";
import { api, type Decision } from "../api";
import { EmptyState, ErrorBanner, LoadingBlock, PageHeader, StatusPill, formatTimestamp } from "../components";
import { TimelineIcon } from "../icons";
import { policyLabel } from "../policy-labels";
import { useResource } from "../use-resource";

interface AuditFilters {
  decision: "" | Decision;
  tool_name: string;
  tenant_id: string;
  window: "1h" | "24h" | "7d" | "30d" | "all";
  limit: number;
}

const INITIAL_FILTERS: AuditFilters = {
  decision: "",
  tool_name: "",
  tenant_id: "",
  window: "24h",
  limit: 50,
};

function timeRange(window: AuditFilters["window"]): { created_from?: number; created_to?: number } {
  if (window === "all") return {};
  const seconds = { "1h": 3_600, "24h": 86_400, "7d": 604_800, "30d": 2_592_000 }[window];
  const now = Math.floor(Date.now() / 1_000);
  return { created_from: now - seconds, created_to: now + 1 };
}

export function AuditPage({ onUnauthorized }: { onUnauthorized: () => void }) {
  const [draft, setDraft] = useState<AuditFilters>(INITIAL_FILTERS);
  const [applied, setApplied] = useState<AuditFilters>(INITIAL_FILTERS);
  const load = useCallback(
    () => api.audit({
      ...(applied.decision === "" ? {} : { decision: applied.decision }),
      ...(applied.tool_name === "" ? {} : { tool_name: applied.tool_name.trim().toLowerCase() }),
      ...(applied.tenant_id === "" ? {} : { tenant_id: applied.tenant_id.trim().toLowerCase() }),
      ...timeRange(applied.window),
      limit: applied.limit,
    }),
    [applied],
  );
  const { data, error, loading, refresh } = useResource(load, onUnauthorized, [load]);

  function apply(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setApplied({ ...draft });
  }

  function reset() {
    setDraft(INITIAL_FILTERS);
    setApplied(INITIAL_FILTERS);
  }

  const events = data?.audit_events ?? [];

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Append-only evidence"
        title="Audit timeline"
        description="Review sanitized decision and approval lifecycle events without exposing prompts, credentials, or raw arguments."
        actions={<button className="button button-secondary" type="button" onClick={refresh}>Refresh</button>}
      />

      <form className="filter-bar" onSubmit={apply}>
        <label>
          <span>Decision</span>
          <select value={draft.decision} onChange={(event) => setDraft({ ...draft, decision: event.target.value as AuditFilters["decision"] })}>
            <option value="">All decisions</option>
            <option value="ALLOW">Allowed</option>
            <option value="REQUIRE_APPROVAL">Approval required</option>
            <option value="DENY">Blocked</option>
          </select>
        </label>
        <label>
          <span>Tool</span>
          <input value={draft.tool_name} onChange={(event) => setDraft({ ...draft, tool_name: event.target.value })} placeholder="email.send" />
        </label>
        <label>
          <span>Tenant</span>
          <input value={draft.tenant_id} onChange={(event) => setDraft({ ...draft, tenant_id: event.target.value })} placeholder="acme" />
        </label>
        <label>
          <span>Time window</span>
          <select value={draft.window} onChange={(event) => setDraft({ ...draft, window: event.target.value as AuditFilters["window"] })}>
            <option value="1h">Last hour</option>
            <option value="24h">Last 24 hours</option>
            <option value="7d">Last 7 days</option>
            <option value="30d">Last 30 days</option>
            <option value="all">All available</option>
          </select>
        </label>
        <label>
          <span>Limit</span>
          <select value={draft.limit} onChange={(event) => setDraft({ ...draft, limit: Number(event.target.value) })}>
            <option value={25}>25</option>
            <option value={50}>50</option>
            <option value={100}>100</option>
          </select>
        </label>
        <div className="filter-actions">
          <button className="button button-primary button-small" type="submit">Apply</button>
          <button className="button button-quiet button-small" type="button" onClick={reset}>Reset</button>
        </div>
      </form>

      {error === null ? null : <ErrorBanner message={error} />}
      {loading && data === null ? <LoadingBlock label="Loading audit events" /> : events.length === 0 ? (
        <EmptyState title="No matching events">Try a wider time window or remove one of the filters.</EmptyState>
      ) : (
        <section className="panel audit-panel">
          <div className="audit-heading">
            <span>{events.length} event{events.length === 1 ? "" : "s"}</span>
            <span>Newest first</span>
          </div>
          <ol className="audit-timeline">
            {events.map((event) => (
              <li key={event.id}>
                <span className={`timeline-node decision-${event.decision ?? "event"}`}><TimelineIcon /></span>
                <article>
                  <header>
                    <div>
                      <strong>{event.tool_name}</strong>
                      <StatusPill value={event.decision ?? event.event_type} />
                    </div>
                    <time dateTime={new Date(event.created_at * 1_000).toISOString()}>{formatTimestamp(event.created_at)}</time>
                  </header>
                  <p>{event.tenant_id} <span aria-hidden="true">·</span> {event.principal_id}</p>
                  {event.policy_codes.length === 0 ? null : (
                    <div className="audit-reasons">
                      {event.policy_codes.map((code) => <span key={code}>{policyLabel(code)}</span>)}
                    </div>
                  )}
                  <footer>
                    <span>{event.event_type.replaceAll("_", " ").toLowerCase()}</span>
                    <code>Policy {event.policy_version}</code>
                  </footer>
                </article>
              </li>
            ))}
          </ol>
        </section>
      )}
    </div>
  );
}
