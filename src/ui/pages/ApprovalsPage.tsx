import { useCallback, useEffect, useMemo, useState } from "react";
import { api, ApiError, type Approval } from "../api";
import {
  EmptyState,
  ErrorBanner,
  LoadingBlock,
  Modal,
  PageHeader,
  PolicyReasons,
  formatTimestamp,
  relativeTime,
} from "../components";
import { ApprovalIcon, CheckIcon, ClockIcon, CloseIcon } from "../icons";
import { useResource } from "../use-resource";

function titleCase(value: string): string {
  return value.replaceAll("_", " ").replace(/\b\w/g, (character) => character.toUpperCase());
}

function displayValue(value: unknown): string {
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (typeof value === "string") return value === "" ? "Missing or invalid" : value;
  if (typeof value === "number") return String(value);
  return "Not provided";
}

function ApprovalSummary({ approval }: { approval: Approval }) {
  const display = approval.approval_display;
  const entries: Array<[string, string | number | boolean]> =
    display.kind === "email_send"
      ? [
          ["recipient", display.recipient],
          ...(display.subject === undefined ? [] : [["subject", display.subject] as [string, string]]),
          ["has_attachments", display.has_attachments],
        ]
      : display.kind === "refund_create"
        ? [
            ["amount_minor", display.amount_minor],
            ...(display.currency === undefined ? [] : [["currency", display.currency] as [string, string]]),
            ...(display.order_id === undefined ? [] : [["order_id", display.order_id] as [string, string]]),
          ]
        : [];
  if (entries.length === 0) {
    return <p className="generic-summary">No tool-specific display fields are available for this request.</p>;
  }
  return (
    <dl className="approval-summary">
      {entries.map(([key, value]) => (
        <div key={key}>
          <dt>{titleCase(key)}</dt>
          <dd>{displayValue(value)}</dd>
        </div>
      ))}
    </dl>
  );
}

export function ApprovalsPage({ onUnauthorized }: { onUnauthorized: () => void }) {
  const load = useCallback(() => api.approvals({ status: "PENDING", limit: 100 }), []);
  const { data, setData, error, setError, loading, refresh } = useResource(load, onUnauthorized);
  const [confirming, setConfirming] = useState<{ approval: Approval; action: "approve" | "reject" } | null>(null);
  const [deciding, setDeciding] = useState(false);
  const [, updateClock] = useState(0);

  useEffect(() => {
    const interval = window.setInterval(() => updateClock((value) => value + 1), 30_000);
    return () => window.clearInterval(interval);
  }, []);

  const approvals = useMemo(() => data?.approvals ?? [], [data]);

  async function decide() {
    if (confirming === null) return;
    setDeciding(true);
    setError(null);
    try {
      await api.decideApproval(confirming.approval.approval_id, confirming.action);
      setData((current) => current === null
        ? current
        : { approvals: current.approvals.filter((item) => item.approval_id !== confirming.approval.approval_id) });
      setConfirming(null);
    } catch (cause) {
      if (cause instanceof ApiError && cause.status === 401) {
        onUnauthorized();
      } else {
        setError(cause instanceof Error ? cause.message : "The approval could not be updated.");
      }
      setConfirming(null);
    } finally {
      setDeciding(false);
    }
  }

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Human checkpoint"
        title="Approval inbox"
        description="Review what will happen, why the gate paused it, and who requested it."
        actions={<button className="button button-secondary" type="button" onClick={refresh}>Refresh inbox</button>}
      />
      <div className="trust-note">
        <ApprovalIcon />
        <p><strong>The summary is for display only.</strong> Authorization remains bound to the exact request hash and policy version.</p>
      </div>
      {error === null ? null : <ErrorBanner message={error} />}
      {loading && data === null ? <LoadingBlock label="Loading pending approvals" /> : approvals.length === 0 ? (
        <EmptyState title="Inbox clear">There are no pending actions waiting for an operator.</EmptyState>
      ) : (
        <div className="approval-list">
          {approvals.map((approval) => (
            <article className="approval-card" key={approval.approval_id}>
              <header>
                <div className="tool-identity">
                  <span className="tool-glyph"><ApprovalIcon /></span>
                  <div>
                    <span className="panel-kicker">Action waiting</span>
                    <h2>{approval.tool_name}</h2>
                  </div>
                </div>
                <span className="expiry-badge"><ClockIcon /> Expires {relativeTime(approval.expires_at)}</span>
              </header>
              <div className="approval-body">
                <section>
                  <h3>What the agent wants to do</h3>
                  <ApprovalSummary approval={approval} />
                </section>
                <section>
                  <h3>Why review is required</h3>
                  <PolicyReasons codes={approval.policy_codes} />
                </section>
              </div>
              <footer>
                <dl className="approval-meta">
                  <div><dt>Tenant</dt><dd>{approval.tenant_id}</dd></div>
                  <div><dt>Principal</dt><dd>{approval.principal_id}</dd></div>
                  <div><dt>Created</dt><dd>{formatTimestamp(approval.created_at)}</dd></div>
                  <div><dt>Policy</dt><dd><code>{approval.policy_version}</code></dd></div>
                </dl>
                <div className="approval-actions">
                  <button className="button button-danger" type="button" onClick={() => setConfirming({ approval, action: "reject" })}>
                    <CloseIcon /> Reject
                  </button>
                  <button className="button button-primary" type="button" onClick={() => setConfirming({ approval, action: "approve" })}>
                    <CheckIcon /> Review &amp; approve
                  </button>
                </div>
              </footer>
              <details className="technical-details">
                <summary>Technical details</summary>
                <dl>
                  <div><dt>Approval ID</dt><dd><code>{approval.approval_id}</code></dd></div>
                  <div><dt>Risk level</dt><dd>{approval.risk_level}</dd></div>
                </dl>
              </details>
            </article>
          ))}
        </div>
      )}

      {confirming === null ? null : (
        <Modal title={confirming.action === "approve" ? "Confirm approval" : "Confirm rejection"} onClose={() => setConfirming(null)}>
          <div className="confirmation-body">
            <span className={`confirmation-icon ${confirming.action}`}>
              {confirming.action === "approve" ? <CheckIcon /> : <CloseIcon />}
            </span>
            <p>
              {confirming.action === "approve"
                ? "Approve this exact request for one-time consumption by the original agent? This does not execute the tool."
                : "Reject this request? The agent will not be able to consume this approval."}
            </p>
            <div className="confirmation-target">
              <strong>{confirming.approval.tool_name}</strong>
              <span>{confirming.approval.tenant_id} · {confirming.approval.principal_id}</span>
            </div>
          </div>
          <footer className="modal-actions">
            <button className="button button-secondary" type="button" onClick={() => setConfirming(null)}>Cancel</button>
            <button
              className={`button ${confirming.action === "approve" ? "button-primary" : "button-danger"}`}
              type="button"
              onClick={() => void decide()}
              disabled={deciding}
            >
              {deciding ? "Saving…" : confirming.action === "approve" ? "Approve request" : "Reject request"}
            </button>
          </footer>
        </Modal>
      )}
    </div>
  );
}
