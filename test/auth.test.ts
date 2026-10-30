import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { clearJwksCache, verifyAccessJwt } from "../src/middleware/accessAuth";
import { timingSafeEqual } from "../src/middleware/bearerAuth";
import { run } from "./helpers";

const TEAM = "unit.cloudflareaccess.com";
const AUD = "aud-1234567890abcdef";

function b64url(input: ArrayBuffer | Uint8Array | string): string {
  const bytes =
    typeof input === "string" ? new TextEncoder().encode(input) : input instanceof Uint8Array ? input : new Uint8Array(input);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

interface SigningKey {
  privateKey: CryptoKey;
  jwk: { kid: string; kty: string; alg: string; n: string; e: string };
}

async function makeKey(kid: string): Promise<SigningKey> {
  const pair = (await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const pub = (await crypto.subtle.exportKey("jwk", pair.publicKey)) as JsonWebKey;
  return {
    privateKey: pair.privateKey,
    jwk: { kid, kty: "RSA", alg: "RS256", n: pub.n!, e: pub.e! },
  };
}

async function sign(key: SigningKey, claims: Record<string, unknown>, alg = "RS256"): Promise<string> {
  const h = b64url(JSON.stringify({ alg, kid: key.jwk.kid, typ: "JWT" }));
  const p = b64url(JSON.stringify(claims));
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key.privateKey, new TextEncoder().encode(`${h}.${p}`));
  return `${h}.${p}.${b64url(sig)}`;
}

function jwksFetcher(keys: SigningKey[], log: string[] = []): typeof fetch {
  return (async (input: RequestInfo | URL) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    log.push(url);
    if (url === `https://${TEAM}/cdn-cgi/access/certs`) {
      return new Response(JSON.stringify({ keys: keys.map((k) => k.jwk) }), {
        headers: { "content-type": "application/json" },
      });
    }
    return new Response("not found", { status: 404 });
  }) as typeof fetch;
}

let keyA: SigningKey;
let keyB: SigningKey;
const nowSec = () => Math.floor(Date.now() / 1000);
const goodClaims = () => ({
  iss: `https://${TEAM}`,
  aud: [AUD],
  exp: nowSec() + 600,
  iat: nowSec(),
  nbf: nowSec() - 10,
  email: "person@example.test",
  sub: "user-1",
});

beforeAll(async () => {
  keyA = await makeKey("key-a");
  keyB = await makeKey("key-b");
});

beforeEach(() => clearJwksCache());

describe("verifyAccessJwt", () => {
  it("accepts a valid token", async () => {
    const token = await sign(keyA, goodClaims());
    const r = await verifyAccessJwt(token, { teamDomain: TEAM, aud: AUD, fetcher: jwksFetcher([keyA]) });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.claims.email).toBe("person@example.test");
  });

  it("rejects bad signature, wrong aud, wrong iss, expired, and wrong alg", async () => {
    const f = jwksFetcher([keyA]);
    const o = { teamDomain: TEAM, aud: AUD, fetcher: f };

    const forged = await sign({ ...keyB, jwk: { ...keyB.jwk, kid: "key-a" } }, goodClaims());
    expect(await verifyAccessJwt(forged, o)).toMatchObject({ ok: false, reason: "bad signature" });

    expect(await verifyAccessJwt(await sign(keyA, { ...goodClaims(), aud: ["other"] }), o)).toMatchObject({ ok: false, reason: "audience mismatch" });
    expect(await verifyAccessJwt(await sign(keyA, { ...goodClaims(), iss: "https://evil.example" }), o)).toMatchObject({ ok: false, reason: "issuer mismatch" });
    expect(await verifyAccessJwt(await sign(keyA, { ...goodClaims(), exp: nowSec() - 1 }), o)).toMatchObject({ ok: false, reason: "token expired" });
    expect(await verifyAccessJwt(await sign(keyA, goodClaims(), "none"), o)).toMatchObject({ ok: false });
    expect(await verifyAccessJwt("garbage", o)).toMatchObject({ ok: false, reason: "malformed token" });
  });

  it("refetches JWKS once on an unknown kid (key rotation)", async () => {
    const log: string[] = [];
    let served = [keyA];
    const fetcher = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const res = await jwksFetcher(served, log)(input, init);
      served = [keyA, keyB];
      return res;
    }) as typeof fetch;

    await verifyAccessJwt(await sign(keyA, goodClaims()), { teamDomain: TEAM, aud: AUD, fetcher });
    expect(log).toHaveLength(1);
    const r = await verifyAccessJwt(await sign(keyB, goodClaims()), { teamDomain: TEAM, aud: AUD, fetcher });
    expect(r.ok).toBe(true);
    expect(log).toHaveLength(2);
  });
});

describe("access control", () => {
  const cfg = { access: { enabled: true, teamDomain: TEAM, aud: AUD, paths: ["/admin"] } };

  it("ignores unprotected paths", async () => {
    expect((await run("/public", { config: cfg })).status).toBe(200);
  });

  it("requires a token on protected paths", async () => {
    const res = await run("/admin/users", { config: cfg, fetcher: jwksFetcher([keyA]) });
    expect(res.status).toBe(401);
    expect(res.headers.get("X-Harness-Block")).toBe("access-auth");
  });

  it("accepts the header or the CF_Authorization cookie", async () => {
    const token = await sign(keyA, goodClaims());
    const viaHeader = await run("/admin", { config: cfg, fetcher: jwksFetcher([keyA]), headers: { "cf-access-jwt-assertion": token } });
    expect(viaHeader.status).toBe(200);
    const viaCookie = await run("/admin", { config: cfg, fetcher: jwksFetcher([keyA]), headers: { cookie: `a=b; CF_Authorization=${token}` } });
    expect(viaCookie.status).toBe(200);
  });

  it("fails closed when misconfigured or when JWKS is unreachable", async () => {
    const bad = await run("/admin", { config: { access: { enabled: true, teamDomain: "", aud: "", paths: ["/admin"] } } });
    expect(bad.status).toBe(503);
    const token = await sign(keyA, goodClaims());
    const down = await run("/admin", { config: cfg, fetcher: jwksFetcher([]), headers: { "cf-access-jwt-assertion": token } });
    expect(down.status).toBe(401);
    const unreachable = await run("/admin", {
      config: cfg,
      fetcher: (async () => new Response("err", { status: 500 })) as typeof fetch,
      headers: { "cf-access-jwt-assertion": token },
    });
    expect(unreachable.status).toBe(503);
  });
});

describe("bearer control", () => {
  const cfg = { bearer: { enabled: true, paths: ["/api"] } };
  const env = { API_TOKEN: "s3cret-token" };

  it("timingSafeEqual compares correctly", () => {
    expect(timingSafeEqual("abc", "abc")).toBe(true);
    expect(timingSafeEqual("abc", "abd")).toBe(false);
    expect(timingSafeEqual("abc", "abcd")).toBe(false);
    expect(timingSafeEqual("", "")).toBe(true);
  });

  it("requires the right token on protected paths only", async () => {
    expect((await run("/api/things", { config: cfg, env })).status).toBe(401);
    expect((await run("/api/things", { config: cfg, env, headers: { authorization: "Bearer wrong" } })).status).toBe(401);
    expect((await run("/api/things", { config: cfg, env, headers: { authorization: "Bearer s3cret-token" } })).status).toBe(200);
    expect((await run("/apiary", { config: cfg, env })).status).toBe(200);
    expect((await run("/", { config: cfg, env })).status).toBe(200);
  });

  it("fails closed when the secret is missing", async () => {
    const res = await run("/api/things", { config: cfg, headers: { authorization: "Bearer anything" } });
    expect(res.status).toBe(503);
  });
});
