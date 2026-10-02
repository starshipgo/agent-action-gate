export const PRODUCT_EVENTS = ["demo_scenario_run", "developer_quickstart_view", "api_key_created", "first_evaluation", "first_approval_created", "first_approval_consumed"] as const;
export type ProductEvent = (typeof PRODUCT_EVENTS)[number];
export type PublicProductEvent = "demo_scenario_run" | "developer_quickstart_view";
export type Integration = "MCP" | "Dify" | "custom_agent" | "other";
export type VolumeBand = "under_1k" | "1k_to_10k" | "10k_to_100k" | "over_100k";
export interface BetaInterest { email: string; intended_integration: Integration; approximate_monthly_tool_calls: VolumeBand; created_at: number; }
export interface BetaRepository {
  recordPublicEvent(event: PublicProductEvent, dayUtc: string): Promise<void>;
  createInterest(interest: BetaInterest): Promise<void>;
  funnel(): Promise<Record<ProductEvent, number>>;
}
function object(value: unknown): value is Record<string, unknown> { return value !== null && typeof value === "object" && !Array.isArray(value); }
export function parsePublicEvent(value: unknown): PublicProductEvent | null {
  if (!object(value) || Object.keys(value).length !== 1) return null;
  return value.event === "demo_scenario_run" || value.event === "developer_quickstart_view" ? value.event : null;
}
export function parseBetaInterest(value: unknown, createdAt: number): BetaInterest | null {
  if (!object(value) || Object.keys(value).length !== 3 || !["email", "intended_integration", "approximate_monthly_tool_calls"].every((key) => Object.hasOwn(value, key))) return null;
  const email = value.email;
  const integration = value.intended_integration;
  const volume = value.approximate_monthly_tool_calls;
  if (typeof email !== "string" || email.length < 3 || email.length > 254 || email !== email.trim().toLowerCase() || !/^[a-z0-9!#$%&'*+/=?^_`{|}~.-]+@[a-z0-9.-]+$/.test(email)) return null;
  const [local, domain, extra] = email.split("@");
  if (!local || !domain || extra !== undefined || local.length > 64 || local.startsWith(".") || local.endsWith(".") || local.includes("..")) return null;
  const labels = domain.split(".");
  if (labels.length < 2 || !/^[a-z]{2,}$/.test(labels[labels.length - 1]!) || labels.some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) return null;
  if (integration !== "MCP" && integration !== "Dify" && integration !== "custom_agent" && integration !== "other") return null;
  if (volume !== "under_1k" && volume !== "1k_to_10k" && volume !== "10k_to_100k" && volume !== "over_100k") return null;
  return { email, intended_integration: integration, approximate_monthly_tool_calls: volume, created_at: createdAt };
}
