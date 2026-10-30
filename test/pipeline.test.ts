import { describe, expect, it, vi } from "vitest";
import { loadConfig, DEFAULT_CONFIG } from "../src/config";
import { handle, getClientIp, forwardToOrigin } from "../src/harness";
import { compose } from "../src/pipeline";
import type { HarnessContext, Middleware } from "../src/types";
import { json, run } from "./helpers";

describe("security headers", () => {
  it("adds hardened headers and strips fingerprints on origin responses", async () => {
    const res = await run("/");
    expect(res.status).toBe(200);
    expect(res.headers.get("Strict-Transport-Security")).toContain("max-age=31536000");
    expect(res.headers.get("Content-Security-Policy")).toContain("default-src 'self'");
    expect(res.headers.get("X-Frame-Options")).toBe("DENY");
    expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
    expect(res.headers.get("Referrer-Policy")).toBe("strict-origin-when-cross-origin");
    expect(res.headers.get("Permissions-Policy")).toContain("camera=()");
    expect(res.headers.get("Server")).toBeNull();
    expect(res.headers.get("X-Powered-By")).toBeNull();
    expect(await res.text()).toBe("origin ok");
  });

  it("also decorates block responses", async () => {
    const res = await run("/.env");
    expect(res.status).toBe(404);
    expect(res.headers.get("Strict-Transport-Security")).toBeTruthy();
    expect(res.headers.get("Cache-Control")).toBe("no-store");
  });

  it("keeps an origin-provided CSP", async () => {
    const res = await run("/", {
      origin: () => new Response("x", { headers: { "Content-Security-Policy": "default-src 'none'" } }),
    });
    expect(res.headers.get("Content-Security-Policy")).toBe("default-src 'none'");
  });
});

describe("cors", () => {
  const cfg = { cors: { enabled: true, origins: ["https://app.example.test"], credentials: true } };

  it("answers preflight for allowed origins and refuses others", async () => {
    const ok = await run("/api", {
      method: "OPTIONS",
      config: cfg,
      headers: { origin: "https://app.example.test", "access-control-request-method": "POST" },
    });
    expect(ok.status).toBe(204);
    expect(ok.headers.get("Access-Control-Allow-Origin")).toBe("https://app.example.test");
    expect(ok.headers.get("Access-Control-Allow-Credentials")).toBe("true");
    expect(ok.headers.get("Access-Control-Allow-Methods")).toContain("POST");

    const no = await run("/api", {
      method: "OPTIONS",
      config: cfg,
      headers: { origin: "https://evil.example", "access-control-request-method": "POST" },
    });
    expect(no.status).toBe(403);
  });

  it("decorates actual responses only for allowed origins", async () => {
    const ok = await run("/api", { config: cfg, headers: { origin: "https://app.example.test" } });
    expect(ok.headers.get("Access-Control-Allow-Origin")).toBe("https://app.example.test");
    expect(ok.headers.get("Vary")).toContain("Origin");
    const no = await run("/api", { config: cfg, headers: { origin: "https://evil.example" } });
    expect(no.status).toBe(200);
    expect(no.headers.get("Access-Control-Allow-Origin")).toBeNull();
  });
});

describe("pipeline", () => {
  it("serves the health endpoint without touching the origin", async () => {
    const origin = vi.fn(() => new Response("should not be called"));
    const res = await run("/__harness/health", { origin });
    expect(res.status).toBe(200);
    const body = await json(res);
    expect(body.ok).toBe(true);
    expect(body.controls).toContain("waf");
    expect(origin).not.toHaveBeenCalled();
  });

  it("fails closed with a 500 if a control throws", async () => {
    const boom: Middleware = async () => {
      throw new Error("kaboom");
    };
    const req = new Request("https://app.example.test/", { headers: { "cf-connecting-ip": "1.1.1.1" } });
    const res = await handle(req, {}, () => {}, { config: DEFAULT_CONFIG, pipeline: [boom], cf: {} });
    expect(res.status).toBe(500);
  });

  it("compose rejects double next()", async () => {
    const bad: Middleware = async (_ctx, next) => {
      await next();
      return next();
    };
    const run2 = compose([bad]);
    await expect(run2({} as HarnessContext, async () => new Response("x"))).rejects.toThrow(/multiple/);
  });

  it("logs a structured audit line", async () => {
    const spy = vi.spyOn(console, "log").mockImplementation(() => {});
    await run("/.git/HEAD");
    const line = spy.mock.calls.map((c) => String(c[0])).find((l) => l.includes("harness.request"));
    spy.mockRestore();
    expect(line).toBeTruthy();
    const ev = JSON.parse(line!);
    expect(ev.control).toBe("waf");
    expect(ev.decision).toBe("block");
    expect(ev.status).toBe(404);
    expect(ev.ip).toBe("203.0.113.10");
  });

  it("writes to the AUDIT analytics binding when present", async () => {
    const writeDataPoint = vi.fn();
    await run("/", { env: { AUDIT: { writeDataPoint } } });
    expect(writeDataPoint).toHaveBeenCalledOnce();
    expect(writeDataPoint.mock.calls[0][0].indexes).toEqual(["pipeline"]);
  });
});

describe("origin forwarding", () => {
  it("prefers cf-connecting-ip and falls back sensibly", () => {
    expect(getClientIp(new Request("https://x/", { headers: { "cf-connecting-ip": "1.2.3.4", "x-forwarded-for": "9.9.9.9" } }))).toBe("1.2.3.4");
    expect(getClientIp(new Request("https://x/", { headers: { "x-forwarded-for": "9.9.9.9, 10.0.0.1" } }))).toBe("9.9.9.9");
    expect(getClientIp(new Request("https://x/"))).toBe("0.0.0.0");
  });

  it("rewrites host to ORIGIN_URL and sets forwarding headers", async () => {
    let captured: Request | undefined;
    const fetcher = (async (input: RequestInfo | URL, init?: RequestInit) => {
      captured = new Request(input as RequestInfo, init);
      return new Response("upstream");
    }) as typeof fetch;
    const request = new Request("https://app.example.test/path?x=1", { headers: { "cf-connecting-ip": "1.1.1.1" } });
    const ctx: HarnessContext = {
      request,
      url: new URL(request.url),
      env: { ORIGIN_URL: "https://origin.internal:8443" },
      config: loadConfig(undefined),
      cf: {},
      clientIp: "1.1.1.1",
      rayId: "ray-1",
      startedAt: Date.now(),
      trail: [],
      responseHooks: [],
      fetcher,
      waitUntil: () => {},
    };
    const res = await forwardToOrigin(ctx);
    expect(await res.text()).toBe("upstream");
    expect(captured!.url).toBe("https://origin.internal:8443/path?x=1");
    expect(captured!.headers.get("X-Forwarded-Host")).toBe("app.example.test");
    expect(captured!.headers.get("X-Forwarded-Proto")).toBe("https");
    expect(captured!.headers.get("X-Harness-Ray")).toBe("ray-1");
  });

  it("uses a service binding when present", async () => {
    const binding = { fetch: vi.fn(async () => new Response("from binding")) };
    const request = new Request("https://app.example.test/");
    const ctx = {
      request,
      url: new URL(request.url),
      env: { ORIGIN: binding as unknown as Fetcher },
      config: DEFAULT_CONFIG,
      cf: {},
      clientIp: "1.1.1.1",
      rayId: "r",
      startedAt: 0,
      trail: [],
      responseHooks: [],
      fetcher: fetch,
      waitUntil: () => {},
    } satisfies HarnessContext;
    expect(await (await forwardToOrigin(ctx)).text()).toBe("from binding");
    expect(binding.fetch).toHaveBeenCalledWith(request);
  });
});

describe("config", () => {
  it("merges partial JSON over defaults and normalises case", () => {
    const cfg = loadConfig(JSON.stringify({ blockedCountries: ["ru"], waf: { blockXss: false }, allowedMethods: ["get"] }));
    expect(cfg.blockedCountries).toEqual(["RU"]);
    expect(cfg.allowedMethods).toEqual(["GET"]);
    expect(cfg.waf.blockXss).toBe(false);
    expect(cfg.waf.blockSqli).toBe(true);
    expect(cfg.rateLimit.requests).toBe(DEFAULT_CONFIG.rateLimit.requests);
  });

  it("falls back to defaults on invalid JSON", () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    expect(loadConfig("{not json")).toBe(DEFAULT_CONFIG);
    spy.mockRestore();
  });
});
