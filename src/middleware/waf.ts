import type { HarnessContext, Middleware } from "../types";
import { blocked, pathMatches } from "../utils/respond";

/**
 * Lightweight request inspection. This is a tripwire for obvious attack
 * payloads, not a substitute for Cloudflare's managed WAF rulesets, which
 * should stay enabled on the zone. Patterns are deliberately conservative to
 * keep false positives low.
 */

const SQLI_PATTERNS: RegExp[] = [
  /\bunion\b[\s\S]{0,40}\bselect\b/i,
  /\bselect\b[\s\S]{0,60}\bfrom\b[\s\S]{0,60}\b(information_schema|sysobjects|pg_catalog)\b/i,
  // Tautologies: ' or 1=1, ' OR '1'='1, " and "a"="a
  /('|")\s*(or|and)\s+('|")?\w+('|")?\s*=\s*('|")?\w+/i,
  /\b(sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(/i,
  /;\s*(drop|alter|truncate)\s+(table|database)\b/i,
  /\bload_file\s*\(|\binto\s+(out|dump)file\b/i,
];

const XSS_PATTERNS: RegExp[] = [
  /<\s*script\b/i,
  /\bjavascript\s*:/i,
  /\bon(load|error|click|mouseover|focus|blur|submit)\s*=/i,
  /<\s*(iframe|object|embed|svg)\b[^>]*\bon\w+\s*=/i,
  /\bdocument\.(cookie|location|write)\b/i,
  /\beval\s*\(|\bexpression\s*\(/i,
];

const TRAVERSAL_PATTERNS: RegExp[] = [
  /(^|[\\/])\.\.([\\/]|$)/,
  /%2e%2e(%2f|%5c|\/|\\)/i,
  /\/(etc\/passwd|etc\/shadow|proc\/self|windows\/win\.ini)\b/i,
];

export interface Finding {
  category: "sqli" | "xss" | "traversal";
  location: string;
}

function safeDecode(s: string): string {
  try {
    return decodeURIComponent(s.replace(/\+/g, " "));
  } catch {
    return s;
  }
}

function scan(value: string, patterns: RegExp[]): boolean {
  return patterns.some((p) => p.test(value));
}

/** Inspect one string under every enabled category. */
export function inspectValue(
  value: string,
  location: string,
  cfg: HarnessContext["config"]["waf"],
): Finding | null {
  const decoded = safeDecode(value);
  const candidates = decoded === value ? [value] : [value, decoded];
  for (const c of candidates) {
    if (cfg.blockSqli && scan(c, SQLI_PATTERNS)) return { category: "sqli", location };
    if (cfg.blockXss && scan(c, XSS_PATTERNS)) return { category: "xss", location };
    if (cfg.blockTraversal && scan(c, TRAVERSAL_PATTERNS)) return { category: "traversal", location };
  }
  return null;
}

const INSPECTABLE_TYPES = [
  "application/json",
  "application/x-www-form-urlencoded",
  "text/plain",
  "text/xml",
  "application/xml",
  "multipart/form-data",
];

export const waf: Middleware = async (ctx, next) => {
  const cfg = ctx.config.waf;
  if (!cfg.enabled) return next();

  const path = ctx.url.pathname;
  const decodedPath = safeDecode(path);

  if (pathMatches(decodedPath, cfg.blockedPaths) || pathMatches(path, cfg.blockedPaths)) {
    return blocked(ctx, 404, "waf", "path is blocked");
  }

  let finding = inspectValue(path, "path", cfg);

  if (!finding) {
    for (const [key, value] of ctx.url.searchParams) {
      finding = inspectValue(value, `query:${key}`, cfg) ?? inspectValue(key, "query-key", cfg);
      if (finding) break;
    }
  }

  if (!finding) {
    for (const header of ["user-agent", "referer", "x-forwarded-for"]) {
      const v = ctx.request.headers.get(header);
      if (v) {
        finding = inspectValue(v, `header:${header}`, cfg);
        if (finding) break;
      }
    }
  }

  if (!finding && ctx.request.body && cfg.inspectBodyBytes > 0) {
    const type = (ctx.request.headers.get("content-type") ?? "").toLowerCase();
    const declared = Number(ctx.request.headers.get("content-length") ?? "0");
    if (INSPECTABLE_TYPES.some((t) => type.startsWith(t)) && declared <= cfg.inspectBodyBytes) {
      // Clone so the origin still receives the body.
      const text = await ctx.request.clone().text();
      if (text.length <= cfg.inspectBodyBytes) {
        finding = inspectValue(text, "body", cfg);
      }
    }
  }

  if (finding) {
    return blocked(ctx, 403, "waf", `${finding.category} pattern in ${finding.location}`);
  }

  return next();
};
