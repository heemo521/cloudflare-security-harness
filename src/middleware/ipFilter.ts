import type { Middleware } from "../types";
import { ipInAnyCidr } from "../utils/cidr";
import { blocked } from "../utils/respond";

/**
 * IP allow/deny lists (CIDR or single addresses).
 *  - If the client matches a deny entry, block.
 *  - If an allow list is configured and the client is not on it, block.
 */
export const ipFilter: Middleware = async (ctx, next) => {
  const { ipDeny, ipAllow } = ctx.config;

  const denied = ipInAnyCidr(ctx.clientIp, ipDeny);
  if (denied) return blocked(ctx, 403, "ip-filter", `ip denied by ${denied}`);

  if (ipAllow.length > 0 && !ipInAnyCidr(ctx.clientIp, ipAllow)) {
    return blocked(ctx, 403, "ip-filter", "ip not on allow list");
  }

  return next();
};
