import { useEffect, useRef, type ReactNode } from "react";
import { AlertIcon, BlockIcon, CheckIcon, ClockIcon, CloseIcon, CopyIcon } from "./icons";
import { decisionLabel, policyLabel } from "./policy-labels";

export function formatTimestamp(value: number | string | null | undefined): string {
  if (value === null || value === undefined) {
    return "—";
  }
  const date = typeof value === "number" ? new Date(value * 1_000) : new Date(value);
  return Number.isNaN(date.getTime())
    ? "Unknown time"
    : new Intl.DateTimeFormat(undefined, {
        dateStyle: "medium",
        timeStyle: "short",
      }).format(date);
}

export function relativeTime(value: number): string {
  const seconds = value - Math.floor(Date.now() / 1_000);
  const absolute = Math.abs(seconds);
  const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  if (absolute < 60) return formatter.format(seconds, "second");
  if (absolute < 3_600) return formatter.format(Math.round(seconds / 60), "minute");
  if (absolute < 86_400) return formatter.format(Math.round(seconds / 3_600), "hour");
  return formatter.format(Math.round(seconds / 86_400), "day");
}

export function StatusPill({ value }: { value: string | null }) {
  const normalized = value ?? "EVENT";
  const kind =
    normalized === "ALLOW" || normalized === "ACTIVE" || normalized === "APPROVED"
      ? "positive"
      : normalized === "DENY" || normalized === "REJECTED" || normalized === "REVOKED"
        ? "negative"
        : normalized === "REQUIRE_APPROVAL" || normalized === "PENDING"
          ? "warning"
          : "neutral";
  const label =
    normalized === "ALLOW" || normalized === "DENY" || normalized === "REQUIRE_APPROVAL"
      ? decisionLabel(normalized)
      : normalized.replaceAll("_", " ").toLowerCase();
  const Icon = kind === "positive" ? CheckIcon : kind === "negative" ? BlockIcon : ClockIcon;
  return (
    <span className={`status-pill status-${kind}`}>
      <Icon />
      {label}
    </span>
  );
}

export function PolicyReasons({ codes }: { codes: string[] }) {
  if (codes.length === 0) {
    return <span className="muted">No policy flags</span>;
  }
  return (
    <ul className="reason-list">
      {codes.map((code) => (
        <li key={code}>
          <span>{policyLabel(code)}</span>
          <code>{code}</code>
        </li>
      ))}
    </ul>
  );
}

export function EmptyState({
  title,
  children,
}: {
  title: string;
  children: ReactNode;
}) {
  return (
    <div className="empty-state">
      <CheckIcon />
      <h3>{title}</h3>
      <p>{children}</p>
    </div>
  );
}

export function ErrorBanner({ message }: { message: string }) {
  return (
    <div className="error-banner" role="alert">
      <AlertIcon />
      <span>{message}</span>
    </div>
  );
}

export function LoadingBlock({ label = "Loading" }: { label?: string }) {
  return (
    <div className="loading-block" role="status">
      <span className="spinner" aria-hidden="true" />
      <span>{label}</span>
    </div>
  );
}

export function Modal({
  title,
  onClose,
  children,
  wide = false,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  wide?: boolean;
}) {
  const closeRef = useRef<HTMLButtonElement>(null);
  const dialogRef = useRef<HTMLElement>(null);
  useEffect(() => {
    const prior = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    closeRef.current?.focus();
    const handleKeyboard = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        onClose();
        return;
      }
      if (event.key !== "Tab" || dialogRef.current === null) return;
      const focusable = Array.from(
        dialogRef.current.querySelectorAll<HTMLElement>(
          'button:not([disabled]), input:not([disabled]), select:not([disabled]), a[href], [tabindex]:not([tabindex="-1"])',
        ),
      );
      const first = focusable[0];
      const last = focusable.at(-1);
      if (first === undefined || last === undefined) return;
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    window.addEventListener("keydown", handleKeyboard);
    return () => {
      window.removeEventListener("keydown", handleKeyboard);
      prior?.focus();
    };
  }, [onClose]);

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={onClose}>
      <section
        ref={dialogRef}
        className={`modal ${wide ? "modal-wide" : ""}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby="modal-title"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <header>
          <h2 id="modal-title">{title}</h2>
          <button ref={closeRef} className="icon-button" type="button" onClick={onClose} aria-label="Close">
            <CloseIcon />
          </button>
        </header>
        {children}
      </section>
    </div>
  );
}

export function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  async function copy() {
    await navigator.clipboard.writeText(value);
  }
  return (
    <button className="button button-secondary button-small" type="button" onClick={() => void copy()}>
      <CopyIcon />
      {label}
    </button>
  );
}

export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow: string;
  title: string;
  description: string;
  actions?: ReactNode;
}) {
  return (
    <header className="page-header">
      <div>
        <p className="eyebrow">{eyebrow}</p>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {actions === undefined ? null : <div className="page-actions">{actions}</div>}
    </header>
  );
}
