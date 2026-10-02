import { useState, type FormEvent } from "react";
import { api, ApiError } from "./api";
import { ErrorBanner } from "./components";
import { GateIcon, ShieldIcon } from "./icons";

export function OperatorLogin({ onAuthenticated }: { onAuthenticated: () => void }) {
  const [operatorKey, setOperatorKey] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (operatorKey === "") return;
    setSubmitting(true);
    setError(null);
    const transientKey = operatorKey;
    setOperatorKey("");
    try {
      await api.createSession(transientKey);
      onAuthenticated();
    } catch (cause) {
      setError(
        cause instanceof ApiError && cause.status === 401
          ? "That operator key was not accepted."
          : cause instanceof ApiError
            ? cause.message
            : "The operator session could not be created.",
      );
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <main className="login-page">
      <a className="brand login-brand" href="/">
        <span className="brand-mark"><GateIcon /></span>
        <span>Agent Action Gate</span>
      </a>
      <section className="login-panel">
        <span className="login-icon"><ShieldIcon /></span>
        <p className="eyebrow">Operator access</p>
        <h1>Sign in to the control plane</h1>
        <p className="login-description">
          Enter the dedicated operator key once. It is exchanged for a short-lived, signed HttpOnly session and is
          cleared from this form immediately.
        </p>
        {error === null ? null : <ErrorBanner message={error} />}
        <form onSubmit={(event) => void submit(event)}>
          <label htmlFor="operator-credential">Operator key</label>
          <input
            id="operator-credential"
            type="password"
            autoComplete="off"
            autoCapitalize="none"
            spellCheck={false}
            value={operatorKey}
            onChange={(event) => setOperatorKey(event.target.value)}
            placeholder="Paste your operator key"
            required
          />
          <button className="button button-primary button-full" type="submit" disabled={submitting}>
            {submitting ? "Creating secure session…" : "Continue"}
          </button>
        </form>
        <div className="login-note">
          <strong>V0.1 shared operator identity</strong>
          <span>This is a single-operator control, not multi-human production authentication.</span>
        </div>
      </section>
    </main>
  );
}
