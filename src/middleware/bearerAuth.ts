import type { Middleware } from "../types";
import { blocked, pathMatches } from "../utils/respond";

/** Constant-time string comparison to avoid leaking token prefixes via timing. */
export function timingSafeEqual(a: string, b: string): boolean {
  const enc = new TextEncoder();
  const ab = enc.encode(a);
  const bb = enc.encode(b);
  let diff = ab.length ^ bb.length;
  const len = Math.max(ab.length, bb.length);
  for (let i = 0; i < len; i++) {
    diff |= (ab[i % ab.length] ?? 0) ^ (bb[i % bb.length] ?? 0);
  }
  return diff === 0;
}

/**
 * Static bearer token for machine clients on selected paths. The token lives in
 * the API_TOKEN secret. If the secret is missing while the control is enabled,
 * the paths fail closed.
 */
export const bearerAuth: Middleware = async (ctx, next) => {
  const cfg = ctx.config.bearer;
  if (!cfg.enabled || !pathMatches(ctx.url.pathname, cfg.paths)) return next();

  const expected = ctx.env.API_TOKEN;
  if (!expected) {
    console.error("bearer control enabled but API_TOKEN secret is not set");
    return blocked(ctx, 503, "bearer-auth", "auth not configured");
  }

  const header = ctx.request.headers.get("authorization") ?? "";
  const match = header.match(/^Bearer\s+(.+)$/i);
  if (!match || !timingSafeEqual(match[1].trim(), expected)) {
    return blocked(ctx, 401, "bearer-auth", "invalid or missing bearer token", {
      "WWW-Authenticate": 'Bearer realm="harness"',
    });
  }

  return next();
};
