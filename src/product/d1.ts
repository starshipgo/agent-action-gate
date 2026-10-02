import { PRODUCT_EVENTS, type BetaRepository, type BetaInterest, type ProductEvent, type PublicProductEvent } from "./beta";
type D1Connection = Pick<D1DatabaseSession, "prepare">;
export class D1BetaRepository implements BetaRepository {
  constructor(private readonly database: D1Connection) {}
  async recordPublicEvent(event: PublicProductEvent, dayUtc: string): Promise<void> {
    await this.database.prepare("INSERT INTO product_event_counters (event_name, day_utc, total) VALUES (?1, ?2, 1) ON CONFLICT(event_name, day_utc) DO UPDATE SET total = total + 1").bind(event, dayUtc).run();
  }
  async createInterest(interest: BetaInterest): Promise<void> {
    await this.database.prepare("INSERT INTO beta_interest (email, intended_integration, approximate_monthly_tool_calls, created_at) VALUES (?1, ?2, ?3, ?4) ON CONFLICT(email) DO NOTHING").bind(interest.email, interest.intended_integration, interest.approximate_monthly_tool_calls, interest.created_at).run();
  }
  async funnel(): Promise<Record<ProductEvent, number>> {
    const rows = await this.database.prepare("SELECT event_name, SUM(total) AS total FROM product_event_counters GROUP BY event_name").all<{event_name: string; total: number}>();
    const result = Object.fromEntries(PRODUCT_EVENTS.map((event) => [event, 0])) as Record<ProductEvent, number>;
    for (const row of rows.results) {
      if (!PRODUCT_EVENTS.includes(row.event_name as ProductEvent) || !Number.isSafeInteger(row.total) || row.total < 0) throw new TypeError("invalid beta aggregate");
      result[row.event_name as ProductEvent] = row.total;
    }
    return result;
  }
}
