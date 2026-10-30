import type { HarnessContext } from "../types";

/** Build a block response and record the decision on the context trail. */
export function blocked(
  ctx: HarnessContext,
  status: number,
  control: string,
  reason: string,
  extraHeaders?: HeadersInit,
): Response {
  ctx.trail.push({ control, decision: "block", reason });
  const headers = new Headers(extraHeaders);
  headers.set("Cache-Control", "no-store");
  headers.set("X-Harness-Block", control);
  if (ctx.config.blockFormat === "json") {
    headers.set("Content-Type", "application/json; charset=utf-8");
    return new Response(JSON.stringify({ error: reason, control, rayId: ctx.rayId }), {
      status,
      headers,
    });
  }
  headers.set("Content-Type", "text/plain; charset=utf-8");
  return new Response(`${status} ${reason} (${ctx.rayId})`, { status, headers });
}

/**
 * Prefix match on path segments: "/api" matches "/api" and "/api/users" but
 * not "/apiary".
 */
export function pathMatches(path: string, prefixes: string[]): boolean {
  for (const raw of prefixes) {
    if (!raw) continue;
    const p = raw.endsWith("/") && raw.length > 1 ? raw.slice(0, -1) : raw;
    if (p === "/" || path === p || path.startsWith(p + "/")) return true;
  }
  return false;
}
