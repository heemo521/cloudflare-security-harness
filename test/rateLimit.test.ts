import { beforeEach, describe, expect, it } from "vitest";
import { MemoryRateLimiter, resetFallbackLimiter } from "../src/middleware/rateLimit";
import { run } from "./helpers";

describe("rate limit", () => {
  beforeEach(() => resetFallbackLimiter());

  it("memory limiter allows N then blocks until the window resets", async () => {
    let now = 1_000_000;
    const limiter = new MemoryRateLimiter(3, 1000, () => now);
    const results: boolean[] = [];
    for (let i = 0; i < 5; i++) results.push((await limiter.limit({ key: "a" })).success);
    expect(results).toEqual([true, true, true, false, false]);
    expect((await limiter.limit({ key: "b" })).success).toBe(true);
    now += 1001;
    expect((await limiter.limit({ key: "a" })).success).toBe(true);
  });

  it("uses the RATE_LIMITER binding when present and returns 429 with Retry-After", async () => {
    const calls: string[] = [];
    const binding = {
      async limit({ key }: { key: string }) {
        calls.push(key);
        return { success: calls.length <= 2 };
      },
    };
    const cfg = { rateLimit: { enabled: true, requests: 2, windowSeconds: 30 } };
    const env = { RATE_LIMITER: binding };

    expect((await run("/", { config: cfg, env })).status).toBe(200);
    expect((await run("/", { config: cfg, env })).status).toBe(200);
    const third = await run("/", { config: cfg, env });
    expect(third.status).toBe(429);
    expect(third.headers.get("Retry-After")).toBe("30");
    expect(calls).toEqual(["203.0.113.10", "203.0.113.10", "203.0.113.10"]);
  });

  it("keys by ip+path when configured", async () => {
    const calls: string[] = [];
    const env = { RATE_LIMITER: { async limit({ key }: { key: string }) { calls.push(key); return { success: true }; } } };
    await run("/a", { config: { rateLimit: { enabled: true, keyBy: "ip+path" } }, env });
    expect(calls[0]).toBe("203.0.113.10|/a");
  });

  it("skips exempt paths", async () => {
    const calls: string[] = [];
    const env = { RATE_LIMITER: { async limit({ key }: { key: string }) { calls.push(key); return { success: false }; } } };
    const res = await run("/healthz", {
      config: { rateLimit: { enabled: true, exemptPaths: ["/healthz"] } },
      env,
    });
    expect(res.status).toBe(200);
    expect(calls).toHaveLength(0);
  });

  it("fails open if the limiter throws", async () => {
    const env = { RATE_LIMITER: { async limit() { throw new Error("boom"); } } };
    const res = await run("/", { config: { rateLimit: { enabled: true } }, env });
    expect(res.status).toBe(200);
  });

  it("falls back to the in-memory limiter without a binding", async () => {
    const cfg = { rateLimit: { enabled: true, requests: 2, windowSeconds: 60 } };
    expect((await run("/", { config: cfg })).status).toBe(200);
    expect((await run("/", { config: cfg })).status).toBe(200);
    expect((await run("/", { config: cfg })).status).toBe(429);
    expect((await run("/", { config: cfg, ip: "198.51.100.1" })).status).toBe(200);
  });
});
