import type { BurstRateLimiter } from "./types";

export class CloudflareBurstRateLimiter implements BurstRateLimiter {
  constructor(private readonly binding: RateLimit) {}

  async allow(principalId: string): Promise<boolean> {
    const result = await this.binding.limit({
      key: `evaluate:${principalId}`,
    });

    return result.success;
  }
}
