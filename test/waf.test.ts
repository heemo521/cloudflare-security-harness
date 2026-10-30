import { describe, expect, it } from "vitest";
import { json, run } from "./helpers";

describe("waf", () => {
  it("returns 404 for probed paths", async () => {
    for (const p of ["/.env", "/.git/config", "/wp-admin/install.php", "/phpmyadmin"]) {
      const res = await run(p);
      expect(res.status, p).toBe(404);
      expect(res.headers.get("X-Harness-Block")).toBe("waf");
    }
  });

  it("blocks SQL injection in query strings, including encoded", async () => {
    const plain = await run("/search?q=1' OR '1'='1");
    expect(plain.status).toBe(403);
    expect((await json(plain)).error).toMatch(/sqli/);

    const union = await run("/items?id=1%20UNION%20SELECT%20password%20FROM%20users");
    expect(union.status).toBe(403);

    const sleep = await run("/items?id=1;SELECT%20pg_sleep(10)");
    expect(sleep.status).toBe(403);
  });

  it("blocks XSS payloads", async () => {
    expect((await run("/?name=<script>alert(1)</script>")).status).toBe(403);
    expect((await run("/?u=javascript:alert(1)")).status).toBe(403);
    expect((await run("/?x=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E")).status).toBe(403);
  });

  it("blocks path traversal", async () => {
    expect((await run("/static/../../etc/passwd")).status).toBe(403);
    expect((await run("/files?name=..%2F..%2Fetc%2Fpasswd")).status).toBe(403);
    expect((await run("/download?f=%2e%2e%2f%2e%2e%2fwindows%2fwin.ini")).status).toBe(403);
  });

  it("inspects small JSON bodies and preserves them for the origin", async () => {
    let seen = "";
    const origin = async (req: Request) => {
      seen = await req.text();
      return new Response("ok");
    };
    const bad = await run("/api/comments", {
      body: JSON.stringify({ text: "<script>steal()</script>" }),
      headers: { "content-type": "application/json" },
      origin,
    });
    expect(bad.status).toBe(403);

    const good = await run("/api/comments", {
      body: JSON.stringify({ text: "hello world" }),
      headers: { "content-type": "application/json" },
      origin,
    });
    expect(good.status).toBe(200);
    expect(seen).toBe(JSON.stringify({ text: "hello world" }));
  });

  it("does not inspect binary bodies", async () => {
    const res = await run("/upload", {
      body: "<script>in a png?</script>",
      headers: { "content-type": "image/png" },
    });
    expect(res.status).toBe(200);
  });

  it("lets ordinary traffic through", async () => {
    for (const p of [
      "/",
      "/products?category=select+kitchenware&sort=asc",
      "/articles/union-station-history",
      "/search?q=how%20to%20order%20from%20a%20menu",
      "/api/users/42",
    ]) {
      expect((await run(p)).status, p).toBe(200);
    }
  });

  it("can be disabled", async () => {
    const res = await run("/?q=<script>x</script>", { config: { waf: { enabled: false } } });
    expect(res.status).toBe(200);
  });
});
