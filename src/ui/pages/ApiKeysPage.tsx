import { useCallback, useState, type FormEvent } from "react";
import { api, ApiError, type ApiKeyMetadata } from "../api";
import {
  CopyButton,
  EmptyState,
  ErrorBanner,
  LoadingBlock,
  Modal,
  PageHeader,
  StatusPill,
  formatTimestamp,
} from "../components";
import { AlertIcon, KeyIcon } from "../icons";
import { useResource } from "../use-resource";

interface CreateKeyForm {
  tenant_id: string;
  label: string;
  daily_ai_limit: string;
}

const EMPTY_FORM: CreateKeyForm = {
  tenant_id: "",
  label: "",
  daily_ai_limit: "100",
};

export function ApiKeysPage({ onUnauthorized }: { onUnauthorized: () => void }) {
  const load = useCallback(() => api.apiKeys(), []);
  const { data, setData, error, setError, loading, refresh } = useResource(load, onUnauthorized);
  const [creating, setCreating] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [form, setForm] = useState<CreateKeyForm>(EMPTY_FORM);
  const [issuedKey, setIssuedKey] = useState<{ raw: string; metadata: ApiKeyMetadata } | null>(null);
  const [revokeTarget, setRevokeTarget] = useState<ApiKeyMetadata | null>(null);

  async function createKey(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const created = await api.createApiKey({
        tenant_id: form.tenant_id,
        label: form.label,
        daily_ai_limit: Number(form.daily_ai_limit),
      });
      setData((current) => ({ api_keys: [created.api_key, ...(current?.api_keys ?? [])] }));
      setForm(EMPTY_FORM);
      setCreating(false);
      setIssuedKey({ raw: created.raw_api_key, metadata: created.api_key });
    } catch (cause) {
      if (cause instanceof ApiError && cause.status === 401) onUnauthorized();
      else setError(cause instanceof Error ? cause.message : "The API key could not be created.");
    } finally {
      setSubmitting(false);
    }
  }

  async function revoke() {
    if (revokeTarget === null) return;
    setSubmitting(true);
    setError(null);
    try {
      const result = await api.revokeApiKey(revokeTarget.key_id);
      setData((current) => current === null ? current : {
        api_keys: current.api_keys.map((item) => item.key_id === result.api_key.key_id ? result.api_key : item),
      });
      setRevokeTarget(null);
    } catch (cause) {
      if (cause instanceof ApiError && cause.status === 401) onUnauthorized();
      else setError(cause instanceof Error ? cause.message : "The API key could not be revoked.");
    } finally {
      setSubmitting(false);
    }
  }

  const keys = data?.api_keys ?? [];

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Tenant credentials"
        title="API keys"
        description="Issue and revoke tenant-bound agent credentials. Raw keys are never stored or shown again."
        actions={<button className="button button-primary" type="button" onClick={() => setCreating(true)}><KeyIcon /> Create key</button>}
      />
      {error === null ? null : <ErrorBanner message={error} />}
      {loading && data === null ? <LoadingBlock label="Loading API keys" /> : keys.length === 0 ? (
        <EmptyState title="No API keys">Create a tenant-bound key when an agent integration is ready.</EmptyState>
      ) : (
        <section className="panel table-panel">
          <div className="table-toolbar">
            <span>{keys.length} credential{keys.length === 1 ? "" : "s"}</span>
            <button className="button button-quiet button-small" type="button" onClick={refresh}>Refresh</button>
          </div>
          <div className="responsive-table">
            <table>
              <thead>
                <tr>
                  <th>Key</th>
                  <th>Tenant</th>
                  <th>Status</th>
                  <th>Daily AI limit</th>
                  <th>Created</th>
                  <th><span className="sr-only">Actions</span></th>
                </tr>
              </thead>
              <tbody>
                {keys.map((key) => (
                  <tr key={key.key_id}>
                    <td data-label="Key">
                      <strong>{key.label}</strong>
                      <code>{key.key_prefix}••••</code>
                      <small>ID {key.key_id}</small>
                    </td>
                    <td data-label="Tenant">{key.tenant_id}</td>
                    <td data-label="Status"><StatusPill value={key.status.toUpperCase()} /></td>
                    <td data-label="Daily AI limit">{key.daily_ai_limit.toLocaleString()}</td>
                    <td data-label="Created">{formatTimestamp(key.created_at)}</td>
                    <td className="table-action">
                      {key.status === "active" ? (
                        <button className="button button-quiet button-small danger-text" type="button" onClick={() => setRevokeTarget(key)}>Revoke</button>
                      ) : <span className="muted">{formatTimestamp(key.revoked_at)}</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {creating ? (
        <Modal title="Create tenant API key" onClose={() => setCreating(false)}>
          <form className="modal-form" onSubmit={(event) => void createKey(event)}>
            <label>
              <span>Label</span>
              <input value={form.label} onChange={(event) => setForm({ ...form, label: event.target.value })} maxLength={200} placeholder="Support agent — preview" required />
            </label>
            <label>
              <span>Tenant</span>
              <input value={form.tenant_id} onChange={(event) => setForm({ ...form, tenant_id: event.target.value.toLowerCase() })} maxLength={128} pattern="[a-z0-9._-]+" placeholder="acme" required />
            </label>
            <label>
              <span>Daily semantic-classifier limit</span>
              <input type="number" min="0" step="1" value={form.daily_ai_limit} onChange={(event) => setForm({ ...form, daily_ai_limit: event.target.value })} required />
            </label>
            <footer className="modal-actions">
              <button className="button button-secondary" type="button" onClick={() => setCreating(false)}>Cancel</button>
              <button className="button button-primary" type="submit" disabled={submitting}>{submitting ? "Creating…" : "Create key"}</button>
            </footer>
          </form>
        </Modal>
      ) : null}

      {issuedKey === null ? null : (
        <Modal title="Copy your API key now" onClose={() => setIssuedKey(null)} wide>
          <div className="one-time-warning">
            <AlertIcon />
            <div><strong>You will not see this key again.</strong><p>Copy it into your secret manager before closing this window.</p></div>
          </div>
          <div className="issued-key">
            <code>{issuedKey.raw}</code>
            <CopyButton value={issuedKey.raw} label="Copy key" />
          </div>
          <p className="modal-help">Issued for <strong>{issuedKey.metadata.label}</strong> in tenant <strong>{issuedKey.metadata.tenant_id}</strong>.</p>
          <footer className="modal-actions">
            <button className="button button-primary" type="button" onClick={() => setIssuedKey(null)}>I have saved the key</button>
          </footer>
        </Modal>
      )}

      {revokeTarget === null ? null : (
        <Modal title="Revoke API key" onClose={() => setRevokeTarget(null)}>
          <div className="confirmation-body">
            <span className="confirmation-icon reject"><AlertIcon /></span>
            <p>Revoke <strong>{revokeTarget.label}</strong>? Requests using this key will be rejected immediately.</p>
          </div>
          <footer className="modal-actions">
            <button className="button button-secondary" type="button" onClick={() => setRevokeTarget(null)}>Cancel</button>
            <button className="button button-danger" type="button" onClick={() => void revoke()} disabled={submitting}>{submitting ? "Revoking…" : "Revoke key"}</button>
          </footer>
        </Modal>
      )}
    </div>
  );
}
