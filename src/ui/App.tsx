import { useCallback, useEffect, useState } from "react";
import { api, ApiError } from "./api";
import { ConsoleShell } from "./ConsoleShell";
import { OperatorLogin } from "./Login";
import { ErrorBanner, LoadingBlock } from "./components";
import { GateIcon } from "./icons";
import { ApiKeysPage } from "./pages/ApiKeysPage";
import { ApprovalsPage } from "./pages/ApprovalsPage";
import { AuditPage } from "./pages/AuditPage";
import { IntegrationPage } from "./pages/IntegrationPage";
import { LandingPage } from "./pages/LandingPage";
import { DemoPage } from "./pages/DemoPage";
import { DeveloperQuickstartPage } from "./pages/DeveloperQuickstartPage";
import { OverviewPage } from "./pages/OverviewPage";
import { PoliciesPage } from "./pages/PoliciesPage";
import { resolveRoute, type ConsoleRoute } from "./routing";

type SessionState = "checking" | "authenticated" | "anonymous";

export function App() {
  const [pathname, setPathname] = useState(() => window.location.pathname);
  const [session, setSession] = useState<SessionState>("checking");
  const [logoutError, setLogoutError] = useState<string | null>(null);
  const route = resolveRoute(pathname);

  const navigate = useCallback((path: string) => {
    if (window.location.pathname !== path) window.history.pushState({}, "", path);
    setPathname(path);
    window.scrollTo({ top: 0, behavior: "instant" });
  }, []);

  useEffect(() => {
    const handlePopState = () => setPathname(window.location.pathname);
    window.addEventListener("popstate", handlePopState);
    return () => window.removeEventListener("popstate", handlePopState);
  }, []);

  useEffect(() => {
    if (route === "landing" || route === "demo" || route === "quickstart" || route === "not-found" || session !== "checking") return;
    let active = true;
    void api.overview()
      .then(() => {
        if (active) setSession("authenticated");
      })
      .catch((cause: unknown) => {
        if (!active) return;
        setSession(cause instanceof ApiError && cause.status === 401 ? "anonymous" : "anonymous");
      });
    return () => {
      active = false;
    };
  }, [route, session]);

  async function logout() {
    try {
      setLogoutError(null);
      await api.deleteSession();
      setSession("anonymous");
    } catch (cause) {
      if (cause instanceof ApiError && cause.status === 401) {
        setSession("anonymous");
        return;
      }
      setLogoutError(
        "Logout could not be confirmed. Your console session remains open; try again.",
      );
    }
  }

  if (route === "landing") {
    return <LandingPage onOpenConsole={() => navigate("/console")} onDemo={() => navigate("/demo")} onQuickstart={() => navigate("/quickstart")} />;
  }
  if (route === "demo") return <DemoPage onHome={() => navigate("/")} onQuickstart={() => navigate("/quickstart")} />;
  if (route === "quickstart") return <DeveloperQuickstartPage onHome={() => navigate("/")} onDemo={() => navigate("/demo")} />;

  if (route === "not-found") {
    return (
      <main className="not-found-page">
        <span className="brand-mark"><GateIcon /></span>
        <p className="eyebrow">404 · Not found</p>
        <h1>This route is outside the gate.</h1>
        <p>The page you requested does not exist.</p>
        <button className="button button-primary" type="button" onClick={() => navigate("/")}>Return home</button>
      </main>
    );
  }

  if (session === "checking") {
    return <main className="session-check"><LoadingBlock label="Checking operator session" /></main>;
  }

  if (session === "anonymous") {
    return (
      <OperatorLogin
        onAuthenticated={() => {
          setLogoutError(null);
          setSession("authenticated");
        }}
      />
    );
  }

  const unauthorized = () => {
    setLogoutError(null);
    setSession("anonymous");
  };
  return (
    <ConsoleShell route={route} onNavigate={navigate} onLogout={() => void logout()}>
      {logoutError === null ? null : <ErrorBanner message={logoutError} />}
      <ConsoleRouteView route={route} onUnauthorized={unauthorized} />
    </ConsoleShell>
  );
}

export function ConsoleRouteView({ route, onUnauthorized }: { route: ConsoleRoute; onUnauthorized: () => void }) {
  switch (route) {
    case "overview":
      return <OverviewPage onUnauthorized={onUnauthorized} />;
    case "approvals":
      return <ApprovalsPage onUnauthorized={onUnauthorized} />;
    case "audit":
      return <AuditPage onUnauthorized={onUnauthorized} />;
    case "api-keys":
      return <ApiKeysPage onUnauthorized={onUnauthorized} />;
    case "policies":
      return <PoliciesPage onUnauthorized={onUnauthorized} />;
    case "integration":
      return <IntegrationPage />;
  }
}
