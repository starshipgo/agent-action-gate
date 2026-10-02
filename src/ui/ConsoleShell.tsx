import { useState, type ReactNode } from "react";
import type { ConsoleRoute } from "./routing";
import { routePath } from "./routing";
import {
  ApprovalIcon,
  CloseIcon,
  CodeIcon,
  GateIcon,
  GridIcon,
  KeyIcon,
  LogOutIcon,
  MenuIcon,
  ShieldIcon,
  TimelineIcon,
} from "./icons";

const NAV_ITEMS = [
  { route: "overview" as const, label: "Overview", icon: GridIcon },
  { route: "approvals" as const, label: "Approvals", icon: ApprovalIcon },
  { route: "audit" as const, label: "Audit timeline", icon: TimelineIcon },
  { route: "api-keys" as const, label: "API keys", icon: KeyIcon },
  { route: "policies" as const, label: "Policies", icon: ShieldIcon },
  { route: "integration" as const, label: "Integration", icon: CodeIcon },
];

export function ConsoleShell({
  route,
  onNavigate,
  onLogout,
  children,
}: {
  route: ConsoleRoute;
  onNavigate: (path: string) => void;
  onLogout: () => void;
  children: ReactNode;
}) {
  const [menuOpen, setMenuOpen] = useState(false);

  function navigate(path: string) {
    setMenuOpen(false);
    onNavigate(path);
  }

  return (
    <div className="console-layout">
      <header className="mobile-header">
        <button
          className="icon-button"
          type="button"
          onClick={() => setMenuOpen((value) => !value)}
          aria-label={menuOpen ? "Close navigation" : "Open navigation"}
          aria-expanded={menuOpen}
        >
          {menuOpen ? <CloseIcon /> : <MenuIcon />}
        </button>
        <button className="brand brand-button" type="button" onClick={() => navigate("/console")}>
          <span className="brand-mark"><GateIcon /></span>
          <span>Action Gate</span>
        </button>
        <span className="environment-chip">Preview</span>
      </header>

      <aside className={`sidebar ${menuOpen ? "sidebar-open" : ""}`}>
        <button className="brand brand-button sidebar-brand" type="button" onClick={() => navigate("/")}>
          <span className="brand-mark"><GateIcon /></span>
          <span>Agent Action Gate</span>
        </button>
        <div className="environment-row">
          <span className="environment-chip"><span className="live-dot" /> Preview</span>
          <span>Control plane</span>
        </div>
        <nav className="console-nav" aria-label="Operator console">
          <p>Workspace</p>
          {NAV_ITEMS.map(({ route: itemRoute, label, icon: Icon }) => (
            <a
              href={routePath(itemRoute)}
              className={route === itemRoute ? "active" : ""}
              aria-current={route === itemRoute ? "page" : undefined}
              key={itemRoute}
              onClick={(event) => {
                event.preventDefault();
                navigate(routePath(itemRoute));
              }}
            >
              <Icon />
              <span>{label}</span>
            </a>
          ))}
        </nav>
        <div className="sidebar-footer">
          <div className="operator-avatar">OP</div>
          <div>
            <strong>Operator</strong>
            <span>Secure session</span>
          </div>
          <button className="icon-button" type="button" onClick={onLogout} aria-label="Log out">
            <LogOutIcon />
          </button>
        </div>
      </aside>

      {menuOpen ? <button className="sidebar-scrim" type="button" aria-label="Close navigation" onClick={() => setMenuOpen(false)} /> : null}
      <main className="console-main">{children}</main>
    </div>
  );
}
