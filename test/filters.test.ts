import { describe, expect, it } from "vitest";
import { json, run } from "./helpers";

describe("ip filter", () => {
  it("blocks denied CIDRs", async () => {
    const res = await run("/", { ip: "198.51.100.7", config: { ipDeny: ["198.51.100.0/24"] } });
    expect(res.status).toBe(403);
    expect(res.headers.get("X-Harness-Block")).toBe("ip-filter");
    expect((await json(res)).control).toBe("ip-filter");
  });

  it("enforces an allow list when present", async () => {
    const blockedRes = await run("/", { ip: "203.0.113.10", config: { ipAllow: ["10.0.0.0/8"] } });
    expect(blockedRes.status).toBe(403);
    const okRes = await run("/", { ip: "10.4.5.6", config: { ipAllow: ["10.0.0.0/8"] } });
    expect(okRes.status).toBe(200);
  });

  it("deny wins over allow", async () => {
    const res = await run("/", {
      ip: "10.4.5.6",
      config: { ipAllow: ["10.0.0.0/8"], ipDeny: ["10.4.5.6"] },
    });
    expect(res.status).toBe(403);
  });
});

describe("geo filter", () => {
  it("blocks listed countries", async () => {
    const res = await run("/", { cf: { country: "KP" }, config: { blockedCountries: ["kp"] } });
    expect(res.status).toBe(403);
    expect(res.headers.get("X-Harness-Block")).toBe("geo-filter");
  });

  it("allow list rejects unknown and unlisted countries", async () => {
    expect((await run("/", { cf: {}, config: { allowedCountries: ["US"] } })).status).toBe(403);
    expect((await run("/", { cf: { country: "DE" }, config: { allowedCountries: ["US"] } })).status).toBe(403);
    expect((await run("/", { cf: { country: "US" }, config: { allowedCountries: ["US"] } })).status).toBe(200);
  });

  it("is a no-op when nothing is configured", async () => {
    expect((await run("/", { cf: {} })).status).toBe(200);
  });
});

describe("request limits", () => {
  it("rejects disallowed methods with an Allow header", async () => {
    const res = await run("/", { method: "DELETE", config: { allowedMethods: ["GET", "HEAD"] } });
    expect(res.status).toBe(405);
    expect(res.headers.get("Allow")).toBe("GET, HEAD");
  });

  it("rejects oversized bodies by content-length", async () => {
    const res = await run("/upload", {
      body: "x",
      headers: { "content-length": "5000000" },
      config: { maxBodyBytes: 1024 },
    });
    expect(res.status).toBe(413);
  });

  it("rejects a malformed content-length", async () => {
    const res = await run("/upload", { body: "x", headers: { "content-length": "abc" } });
    expect(res.status).toBe(400);
  });
});

describe("bot check", () => {
  it("is disabled at threshold 0", async () => {
    const res = await run("/", { cf: { botManagement: { score: 1 } } });
    expect(res.status).toBe(200);
  });

  it("blocks low scores and allows verified bots", async () => {
    const cfg = { bot: { scoreThreshold: 30 } };
    expect((await run("/", { cf: { botManagement: { score: 5 } }, config: cfg })).status).toBe(403);
    expect((await run("/", { cf: { botManagement: { score: 80 } }, config: cfg })).status).toBe(200);
    expect(
      (await run("/", { cf: { botManagement: { score: 1, verifiedBot: true } }, config: cfg })).status,
    ).toBe(200);
  });

  it("allows when no score is available", async () => {
    expect((await run("/", { cf: {}, config: { bot: { scoreThreshold: 30 } } })).status).toBe(200);
  });
});
