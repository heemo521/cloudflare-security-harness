import type { AuditEvent, HarnessContext } from "../types";

/**
 * Emit one structured audit line per request. Lines go to the Workers log
 * stream (wrangler tail / Logpush / Workers Logs) and, when an Analytics
 * Engine binding named AUDIT exists, to that dataset as well.
 */
export function emitAudit(ctx: HarnessContext, status: number): void {
  const durationMs = Date.now() - ctx.startedAt;
  const finalDecision = ctx.trail.find((t) => t.decision !== "allow");
  const summary: AuditEvent = {
    ts: new Date().toISOString(),
    rayId: ctx.rayId,
    ip: ctx.clientIp,
    country: ctx.cf.country,
    method: ctx.request.method,
    path: ctx.url.pathname,
    control: finalDecision?.control ?? "pipeline",
    decision: finalDecision?.decision ?? "allow",
    reason: finalDecision?.reason,
    status,
    durationMs,
  };
  console.log(JSON.stringify({ type: "harness.request", ...summary, trail: ctx.trail }));

  try {
    ctx.env.AUDIT?.writeDataPoint({
      indexes: [summary.control],
      blobs: [
        summary.decision,
        summary.reason ?? "",
        summary.method,
        summary.path,
        summary.country ?? "",
        summary.ip,
      ],
      doubles: [status, durationMs],
    });
  } catch (err) {
    console.error("audit write failed", String(err));
  }
}
