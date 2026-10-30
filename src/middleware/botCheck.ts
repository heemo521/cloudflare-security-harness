import type { Middleware } from "../types";
import { blocked } from "../utils/respond";

/**
 * Bot Management scoring. request.cf.botManagement is populated only on zones
 * with Bot Management (Enterprise) or Super Bot Fight Mode; when the field is
 * absent the control records that and lets the request through.
 */
export const botCheck: Middleware = async (ctx, next) => {
  const { scoreThreshold, allowVerifiedBots } = ctx.config.bot;
  if (scoreThreshold <= 0) return next();

  const bm = ctx.cf.botManagement;
  if (!bm || typeof bm.score !== "number") {
    ctx.trail.push({ control: "bot-check", decision: "allow", reason: "no bot score available" });
    return next();
  }

  if (bm.verifiedBot && allowVerifiedBots) {
    ctx.trail.push({ control: "bot-check", decision: "allow", reason: "verified bot" });
    return next();
  }

  if (bm.score < scoreThreshold) {
    return blocked(ctx, 403, "bot-check", `bot score ${bm.score} below ${scoreThreshold}`);
  }

  return next();
};
