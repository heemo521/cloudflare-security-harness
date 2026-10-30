import type { Middleware } from "../types";
import type { HarnessConfig } from "../config";

/** Apply hardened response headers and strip server fingerprints. */
export function applySecurityHeaders(res: Response, cfg: HarnessConfig["headers"]): Response {
  const out = new Response(res.body, res);
  const h = out.headers;

  for (const name of cfg.strip) h.delete(name);

  if (cfg.hsts) h.set("Strict-Transport-Security", cfg.hsts);
  if (cfg.csp && !h.has("Content-Security-Policy")) h.set("Content-Security-Policy", cfg.csp);
  if (cfg.frameOptions) h.set("X-Frame-Options", cfg.frameOptions);
  if (cfg.referrerPolicy) h.set("Referrer-Policy", cfg.referrerPolicy);
  if (cfg.permissionsPolicy) h.set("Permissions-Policy", cfg.permissionsPolicy);
  h.set("X-Content-Type-Options", "nosniff");
  h.set("Cross-Origin-Opener-Policy", "same-origin");
  h.set("Cross-Origin-Resource-Policy", "same-origin");
  return out;
}

/**
 * Registers a response hook so headers land on every response, including
 * block responses produced by later controls.
 */
export const securityHeaders: Middleware = async (ctx, next) => {
  ctx.responseHooks.push((res) => applySecurityHeaders(res, ctx.config.headers));
  return next();
};
