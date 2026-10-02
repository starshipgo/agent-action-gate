import { describe, expect, test } from "bun:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { ConsoleRouteView } from "../src/ui/App";
import { ConsoleShell } from "../src/ui/ConsoleShell";
import { policyLabel } from "../src/ui/policy-labels";
import { resolveRoute, routePath, type ConsoleRoute } from "../src/ui/routing";

const ROOT = `${import.meta.dir}/..`;

async function source(path: string): Promise<string> {
  return Bun.file(`${ROOT}/${path}`).text();
}

describe("operator console routing", () => {
  test("resolves every product route without a router dependency", () => {
    expect(resolveRoute("/")).toBe("landing");
    expect(resolveRoute("/console")).toBe("overview");
    expect(resolveRoute("/console/approvals")).toBe("approvals");
    expect(resolveRoute("/console/audit")).toBe("audit");
    expect(resolveRoute("/console/api-keys")).toBe("api-keys");
    expect(resolveRoute("/console/policies")).toBe("policies");
    expect(resolveRoute("/console/integration")).toBe("integration");
    expect(resolveRoute("/outside")).toBe("not-found");
    expect(routePath("overview")).toBe("/console");
  });

  test("main navigation includes every console route", async () => {
    const shell = await source("src/ui/ConsoleShell.tsx");
    for (const route of ["overview", "approvals", "audit", "api-keys", "policies", "integration"]) {
      expect(shell).toContain(`route: \"${route}\"`);
    }
  });

  test("renders the real console shell and every route view", () => {
    const expectedText: Readonly<Record<ConsoleRoute, string>> = {
      overview: "Overview",
      approvals: "Approval inbox",
      audit: "Audit timeline",
      "api-keys": "API keys",
      policies: "Built-in policies",
      integration: "Put the gate before the tool",
    };

    for (const [route, marker] of Object.entries(expectedText)) {
      const consoleRoute = route as ConsoleRoute;
      const view = createElement(ConsoleRouteView, {
        route: consoleRoute,
        onUnauthorized: () => undefined,
      });
      const markup = renderToStaticMarkup(
        createElement(ConsoleShell, {
          route: consoleRoute,
          onNavigate: () => undefined,
          onLogout: () => undefined,
          children: view,
        }),
      );
      expect(markup).toContain(marker);
      expect(markup).toContain("Operator console");
    }
  });
});

describe("readable security labels", () => {
  test("maps stable policy codes without hiding the underlying code", () => {
    expect(policyLabel("PROMPT_INJECTION_SIGNAL")).toBe("Prompt injection detected");
    expect(policyLabel("DATA_EXFILTRATION_SIGNAL")).toBe("Possible data exfiltration");
    expect(policyLabel("CROSS_TENANT_ACCESS")).toBe("Cross-tenant access blocked");
    expect(policyLabel("OUTBOUND_SEND")).toBe("Outbound send requires approval");
  });
});

describe("browser security regressions", () => {
  test("operator UI never uses persistent browser storage or unsafe HTML", async () => {
    const files = [
      "src/ui/App.tsx",
      "src/ui/Login.tsx",
      "src/ui/ConsoleShell.tsx",
      "src/ui/components.tsx",
      "src/ui/pages/ApiKeysPage.tsx",
      "src/ui/pages/ApprovalsPage.tsx",
      "src/ui/pages/AuditPage.tsx",
      "src/ui/pages/IntegrationPage.tsx",
      "src/ui/pages/LandingPage.tsx",
      "src/ui/pages/OverviewPage.tsx",
      "src/ui/pages/PoliciesPage.tsx",
    ];
    const combined = (await Promise.all(files.map(source))).join("\n");
    expect(combined).not.toContain("local" + "Storage");
    expect(combined).not.toContain("session" + "Storage");
    expect(combined).not.toContain("indexed" + "DB");
    expect(combined).not.toContain("dangerouslySet" + "InnerHTML");
    expect(combined).not.toContain("VITE_" + "OPERATOR");
    expect(combined).not.toContain("style={{");
  });

  test("session client uses same-origin cookies and no bearer credential", async () => {
    const client = await source("src/ui/api.ts");
    expect(client).toContain('credentials: "same-origin"');
    expect(client).toContain('"/v1/operator/session"');
    expect(client).not.toContain('local' + 'Storage');
    expect(client).not.toContain('headers.set("authorization"');
  });

  test("operator key is cleared before the session exchange completes", async () => {
    const login = await source("src/ui/Login.tsx");
    const clearIndex = login.indexOf('setOperatorKey("")');
    const requestIndex = login.indexOf("await api.createSession");
    expect(clearIndex).toBeGreaterThan(-1);
    expect(requestIndex).toBeGreaterThan(clearIndex);
  });

  test("approval presentation applies a second tool-specific allowlist", async () => {
    const approvals = await source("src/ui/pages/ApprovalsPage.tsx");
    expect(approvals).toContain('display.kind === "email_send"');
    expect(approvals).toContain('["recipient", display.recipient]');
    expect(approvals).toContain('["has_attachments", display.has_attachments]');
    expect(approvals).toContain('display.kind === "refund_create"');
    expect(approvals).not.toContain("Object.entries(approval.approval_display)");
    expect(approvals).not.toContain("display.body");
  });

  test("static assets declare restrictive browser headers", async () => {
    const headers = await source("public/_headers");
    expect(headers).toContain("Content-Security-Policy: default-src 'self'");
    expect(headers).toContain("frame-ancestors 'none'");
    expect(headers).toContain("X-Content-Type-Options: nosniff");
  });

  test("failed logout does not pretend the browser session was cleared", async () => {
    const app = await source("src/ui/App.tsx");
    expect(app).toContain("await api.deleteSession()");
    expect(app).toContain("Logout could not be confirmed");
    expect(app).not.toContain("await api.deleteSession();\n    } finally");
  });
});
