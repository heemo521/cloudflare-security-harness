import type { HarnessContext, Middleware } from "../types";
import { blocked, pathMatches } from "../utils/respond";

/**
 * Verifies the Cloudflare Access JWT (Cf-Access-Jwt-Assertion header or
 * CF_Authorization cookie) for protected paths. Access already enforces this
 * at the edge when the hostname is behind an Access application; validating
 * again in the Worker guards against misconfigured routes and direct hits.
 *
 * Verification: RS256 signature against the team's JWKS, plus iss, aud, exp
 * and nbf checks.
 */

interface Jwk {
  kid: string;
  kty: string;
  alg?: string;
  n: string;
  e: string;
}

interface JwksCacheEntry {
  keys: Jwk[];
  fetchedAt: number;
}

const JWKS_TTL_MS = 60 * 60 * 1000;
const jwksCache = new Map<string, JwksCacheEntry>();

function b64urlToBytes(s: string): Uint8Array {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + pad;
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function b64urlToJson<T>(s: string): T {
  return JSON.parse(new TextDecoder().decode(b64urlToBytes(s))) as T;
}

export async function fetchJwks(
  teamDomain: string,
  fetcher: typeof fetch,
  force = false,
): Promise<Jwk[]> {
  const url = `https://${teamDomain}/cdn-cgi/access/certs`;
  const cached = jwksCache.get(url);
  if (!force && cached && Date.now() - cached.fetchedAt < JWKS_TTL_MS) return cached.keys;
  const res = await fetcher(url, { headers: { accept: "application/json" } });
  if (!res.ok) throw new Error(`JWKS fetch failed: ${res.status}`);
  const body = (await res.json()) as { keys: Jwk[] };
  jwksCache.set(url, { keys: body.keys, fetchedAt: Date.now() });
  return body.keys;
}

export interface AccessClaims {
  iss: string;
  aud: string | string[];
  exp: number;
  nbf?: number;
  iat?: number;
  sub?: string;
  email?: string;
  [k: string]: unknown;
}

export type VerifyResult = { ok: true; claims: AccessClaims } | { ok: false; reason: string };

export async function verifyAccessJwt(
  token: string,
  opts: { teamDomain: string; aud: string; fetcher: typeof fetch; now?: number },
): Promise<VerifyResult> {
  const parts = token.split(".");
  if (parts.length !== 3) return { ok: false, reason: "malformed token" };
  const [h, p, s] = parts;

  let header: { alg?: string; kid?: string };
  let claims: AccessClaims;
  try {
    header = b64urlToJson(h);
    claims = b64urlToJson(p);
  } catch {
    return { ok: false, reason: "token not decodable" };
  }
  if (header.alg !== "RS256") return { ok: false, reason: `unsupported alg ${header.alg}` };
  if (!header.kid) return { ok: false, reason: "missing kid" };

  let keys = await fetchJwks(opts.teamDomain, opts.fetcher);
  let jwk = keys.find((k) => k.kid === header.kid);
  if (!jwk) {
    // Key rotation: refresh once before giving up.
    keys = await fetchJwks(opts.teamDomain, opts.fetcher, true);
    jwk = keys.find((k) => k.kid === header.kid);
    if (!jwk) return { ok: false, reason: "unknown signing key" };
  }

  const key = await crypto.subtle.importKey(
    "jwk",
    { kty: "RSA", n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    b64urlToBytes(s),
    new TextEncoder().encode(`${h}.${p}`),
  );
  if (!valid) return { ok: false, reason: "bad signature" };

  const now = Math.floor((opts.now ?? Date.now()) / 1000);
  if (claims.iss !== `https://${opts.teamDomain}`) return { ok: false, reason: "issuer mismatch" };
  const auds = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!auds.includes(opts.aud)) return { ok: false, reason: "audience mismatch" };
  if (typeof claims.exp !== "number" || claims.exp <= now) return { ok: false, reason: "token expired" };
  if (typeof claims.nbf === "number" && claims.nbf > now + 60) return { ok: false, reason: "token not yet valid" };

  return { ok: true, claims };
}

function extractToken(ctx: HarnessContext): string | null {
  const header = ctx.request.headers.get("cf-access-jwt-assertion");
  if (header) return header.trim();
  const cookie = ctx.request.headers.get("cookie") ?? "";
  const m = cookie.match(/(?:^|;\s*)CF_Authorization=([^;]+)/);
  return m ? m[1] : null;
}

export const accessAuth: Middleware = async (ctx, next) => {
  const cfg = ctx.config.access;
  if (!cfg.enabled || !pathMatches(ctx.url.pathname, cfg.paths)) return next();

  if (!cfg.teamDomain || !cfg.aud) {
    console.error("access control enabled but teamDomain/aud not configured");
    return blocked(ctx, 503, "access-auth", "access not configured");
  }

  const token = extractToken(ctx);
  if (!token) return blocked(ctx, 401, "access-auth", "missing access token");

  let result: VerifyResult;
  try {
    result = await verifyAccessJwt(token, {
      teamDomain: cfg.teamDomain,
      aud: cfg.aud,
      fetcher: ctx.fetcher,
    });
  } catch (err) {
    console.error("access verification error", String(err));
    return blocked(ctx, 503, "access-auth", "access verification unavailable");
  }

  if (!result.ok) return blocked(ctx, 401, "access-auth", result.reason);

  ctx.trail.push({ control: "access-auth", decision: "allow", reason: result.claims.email ?? result.claims.sub });
  return next();
};

/** Test hook. */
export function clearJwksCache(): void {
  jwksCache.clear();
}
