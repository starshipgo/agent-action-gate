export type ConsoleRoute =
  | "overview"
  | "approvals"
  | "audit"
  | "api-keys"
  | "policies"
  | "integration";

const CONSOLE_PATHS: Readonly<Record<ConsoleRoute, string>> = {
  overview: "/console",
  approvals: "/console/approvals",
  audit: "/console/audit",
  "api-keys": "/console/api-keys",
  policies: "/console/policies",
  integration: "/console/integration",
};

export function resolveRoute(pathname: string): "landing" | "demo" | "quickstart" | ConsoleRoute | "not-found" {
  if (pathname === "/") {
    return "landing";
  }
  if (pathname === "/demo" || pathname === "/demo/") return "demo";
  if (pathname === "/quickstart" || pathname === "/quickstart/") return "quickstart";
  for (const [route, path] of Object.entries(CONSOLE_PATHS)) {
    if (pathname === path || pathname === `${path}/`) {
      return route as ConsoleRoute;
    }
  }
  return "not-found";
}

export function routePath(route: ConsoleRoute): string {
  return CONSOLE_PATHS[route];
}
