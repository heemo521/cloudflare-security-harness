import type { Middleware } from "../types";

/**
 * CORS with an explicit origin allow list. Wildcards are intentionally not
 * supported with credentials; "*" in the list means any origin, no credentials.
 */
export const cors: Middleware = async (ctx, next) => {
  const cfg = ctx.config.cors;
  if (!cfg.enabled) return next();

  const origin = ctx.request.headers.get("origin");
  if (!origin) return next();

  const anyOrigin = cfg.origins.includes("*");
  const allowed = anyOrigin || cfg.origins.includes(origin);

  const apply = (res: Response): Response => {
    if (!allowed) return res;
    const out = new Response(res.body, res);
    out.headers.set("Access-Control-Allow-Origin", anyOrigin ? "*" : origin);
    out.headers.append("Vary", "Origin");
    if (cfg.credentials && !anyOrigin) out.headers.set("Access-Control-Allow-Credentials", "true");
    return out;
  };

  const isPreflight =
    ctx.request.method === "OPTIONS" && ctx.request.headers.has("access-control-request-method");

  if (isPreflight) {
    if (!allowed) {
      ctx.trail.push({ control: "cors", decision: "block", reason: `origin ${origin} not allowed` });
      return new Response(null, { status: 403 });
    }
    const res = new Response(null, { status: 204 });
    res.headers.set("Access-Control-Allow-Methods", cfg.methods.join(", "));
    res.headers.set("Access-Control-Allow-Headers", cfg.headers.join(", "));
    res.headers.set("Access-Control-Max-Age", String(cfg.maxAge));
    return apply(res);
  }

  ctx.responseHooks.push(apply);
  return next();
};
