import type { Middleware, RateLimiterBinding } from "../types";
import { blocked, pathMatches } from "../utils/respond";

/**
 * Per-isolate fallback limiter, used when no RATE_LIMITER binding exists
 * (local dev, unit tests). It is NOT shared across Cloudflare's edge, so
 * production deployments should keep the binding in wrangler.toml.
 */
export class MemoryRateLimiter implements RateLimiterBinding {
  private buckets = new Map<string, { count: number; resetAt: number }>();
  constructor(
    private readonly limitPerWindow: number,
    private readonly windowMs: number,
    private readonly now: () => number = Date.now,
  ) {}

  async limit({ key }: { key: string }): Promise<{ success: boolean }> {
    const t = this.now();
    const bucket = this.buckets.get(key);
    if (!bucket || bucket.resetAt <= t) {
      this.buckets.set(key, { count: 1, resetAt: t + this.windowMs });
      if (this.buckets.size > 10_000) this.sweep(t);
      return { success: true };
    }
    bucket.count += 1;
    return { success: bucket.count <= this.limitPerWindow };
  }

  private sweep(t: number) {
    for (const [k, v] of this.buckets) if (v.resetAt <= t) this.buckets.delete(k);
  }
}

let fallback: MemoryRateLimiter | null = null;

export const rateLimit: Middleware = async (ctx, next) => {
  const cfg = ctx.config.rateLimit;
  if (!cfg.enabled) return next();
  if (pathMatches(ctx.url.pathname, cfg.exemptPaths)) return next();

  const limiter =
    ctx.env.RATE_LIMITER ??
    (fallback ??= new MemoryRateLimiter(cfg.requests, cfg.windowSeconds * 1000));

  const key = cfg.keyBy === "ip+path" ? `${ctx.clientIp}|${ctx.url.pathname}` : ctx.clientIp;

  let success = true;
  try {
    ({ success } = await limiter.limit({ key }));
  } catch (err) {
    // Fail open on limiter errors; log so it is visible.
    console.error("rate limiter error", String(err));
    ctx.trail.push({ control: "rate-limit", decision: "allow", reason: "limiter error, failed open" });
    return next();
  }

  if (!success) {
    return blocked(ctx, 429, "rate-limit", "too many requests", {
      "Retry-After": String(cfg.windowSeconds),
    });
  }
  return next();
};

/** Test hook: reset the in-memory fallback between runs. */
export function resetFallbackLimiter(): void {
  fallback = null;
}
