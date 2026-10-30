import { loadConfig, type HarnessConfig } from "./config";
import { applyResponseHooks, compose } from "./pipeline";
import { accessAuth } from "./middleware/accessAuth";
import { bearerAuth } from "./middleware/bearerAuth";
import { botCheck } from "./middleware/botCheck";
import { cors } from "./middleware/cors";
import { geoFilter } from "./middleware/geoFilter";
import { ipFilter } from "./middleware/ipFilter";
import { rateLimit } from "./middleware/rateLimit";
import { requestLimits } from "./middleware/requestLimits";
import { securityHeaders } from "./middleware/securityHeaders";
import { waf } from "./middleware/waf";
import { emitAudit } from "./utils/log";
import type { CfInfo, Env, HarnessContext, Middleware } from "./types";

/**
 * Order matters: cheap, high-confidence rejections first so abusive traffic
 * costs as little as possible; auth before the origin; headers register first
 * so they decorate every response including blocks.
 */
export const DEFAULT_PIPELINE: Middleware[] = [
  securityHeaders,
  ipFilter,
  geoFilter,
  requestLimits,
  botCheck,
  rateLimit,
  waf,
  cors,
  accessAuth,
  bearerAuth,
];

export interface HarnessOptions {
  config?: HarnessConfig;
  pipeline?: Middleware[];
  fetcher?: typeof fetch;
  /** Overrides request.cf (tests). */
  cf?: CfInfo;
  /** Overrides the forwarding step (tests). */
  forward?: (ctx: HarnessContext) => Promise<Response>;
}

export function getClientIp(request: Request): string {
  return (
    request.headers.get("cf-connecting-ip") ??
    request.headers.get("x-real-ip") ??
    request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ??
    "0.0.0.0"
  );
}

/** Forward to the origin: service binding, explicit ORIGIN_URL, or same-host passthrough. */
export async function forwardToOrigin(ctx: HarnessContext): Promise<Response> {
  const { env, request, url } = ctx;

  if (env.ORIGIN) return env.ORIGIN.fetch(request);

  if (env.ORIGIN_URL) {
    const target = new URL(env.ORIGIN_URL);
    const upstream = new URL(url.toString());
    upstream.protocol = target.protocol;
    upstream.host = target.host;
    const headers = new Headers(request.headers);
    headers.set("X-Forwarded-Host", url.host);
    headers.set("X-Forwarded-Proto", url.protocol.replace(":", ""));
    headers.set("X-Harness-Ray", ctx.rayId);
    return ctx.fetcher(new Request(upstream.toString(), { ...requestInit(request), headers }));
  }

  return ctx.fetcher(request);
}

function requestInit(request: Request): RequestInit {
  const init: RequestInit = {
    method: request.method,
    redirect: "manual",
  };
  if (request.method !== "GET" && request.method !== "HEAD") {
    init.body = request.body;
  }
  return init;
}

function healthResponse(ctx: HarnessContext): Response {
  return new Response(
    JSON.stringify({
      ok: true,
      rayId: ctx.rayId,
      colo: ctx.cf.colo ?? null,
      controls: DEFAULT_PIPELINE.map((m) => m.name),
    }),
    { headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } },
  );
}

/** Core entry point, shared by the Worker export and the tests. */
export async function handle(
  request: Request,
  env: Env,
  waitUntil: (p: Promise<unknown>) => void,
  opts: HarnessOptions = {},
): Promise<Response> {
  const config = opts.config ?? loadConfig(env.HARNESS_CONFIG);
  const cf = opts.cf ?? ((request as Request & { cf?: CfInfo }).cf ?? {});
  const url = new URL(request.url);

  const ctx: HarnessContext = {
    request,
    url,
    env,
    config,
    cf,
    clientIp: getClientIp(request),
    rayId: request.headers.get("cf-ray") ?? crypto.randomUUID(),
    startedAt: Date.now(),
    trail: [],
    responseHooks: [],
    // Wrap rather than store the global directly: calling an unbound `fetch`
    // through a property raises "Illegal invocation" in workerd.
    fetcher: opts.fetcher ?? ((input, init) => fetch(input, init)),
    waitUntil,
  };

  const run = compose(opts.pipeline ?? DEFAULT_PIPELINE);
  const forward = opts.forward ?? forwardToOrigin;

  let response: Response;
  try {
    response = await run(ctx, async () => {
      if (url.pathname === "/__harness/health") return healthResponse(ctx);
      return forward(ctx);
    });
  } catch (err) {
    console.error("harness pipeline error", String(err));
    ctx.trail.push({ control: "pipeline", decision: "block", reason: "internal error" });
    response = new Response(JSON.stringify({ error: "internal error", rayId: ctx.rayId }), {
      status: 500,
      headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
    });
  }

  response = applyResponseHooks(ctx, response);
  emitAudit(ctx, response.status);
  return response;
}
