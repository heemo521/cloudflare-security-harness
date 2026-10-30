import type { Middleware } from "../types";
import { blocked } from "../utils/respond";

/**
 * Method allow list and body size ceiling. Body size is enforced from the
 * declared Content-Length; chunked uploads without one are capped by the WAF
 * body inspector and ultimately by the origin.
 */
export const requestLimits: Middleware = async (ctx, next) => {
  const method = ctx.request.method.toUpperCase();
  if (!ctx.config.allowedMethods.includes(method)) {
    return blocked(ctx, 405, "request-limits", `method ${method} not allowed`, {
      Allow: ctx.config.allowedMethods.join(", "),
    });
  }

  const declared = ctx.request.headers.get("content-length");
  if (declared !== null) {
    const length = Number(declared);
    if (!Number.isFinite(length) || length < 0) {
      return blocked(ctx, 400, "request-limits", "invalid content-length");
    }
    if (length > ctx.config.maxBodyBytes) {
      return blocked(ctx, 413, "request-limits", `body exceeds ${ctx.config.maxBodyBytes} bytes`);
    }
  }

  return next();
};
