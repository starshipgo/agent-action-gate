/** Best-effort, allowlisted aggregate event. Never includes request content. */
export function recordPublicEvent(event: "demo_scenario_run" | "developer_quickstart_view"): void {
  if (typeof window === "undefined") return;
  void fetch("/v1/product-events", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ event }),
    credentials: "same-origin",
  }).catch(() => undefined);
}
