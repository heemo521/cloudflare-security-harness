import { loadConfig, type DeepPartial, type HarnessConfig } from "../src/config";
import { handle, type HarnessOptions } from "../src/harness";
import type { CfInfo, Env } from "../src/types";

export interface RunOptions {
  config?: DeepPartial<HarnessConfig>;
  env?: Partial<Env>;
  cf?: CfInfo;
  ip?: string;
  headers?: Record<string, string>;
  method?: string;
  body?: string;
  fetcher?: typeof fetch;
  /** What the "origin" returns. Defaults to 200 "origin ok". */
  origin?: (req: Request) => Response | Promise<Response>;
}

export const ORIGIN_OK = () =>
  new Response("origin ok", {
    status: 200,
    headers: { "Content-Type": "text/plain", Server: "nginx/1.25", "X-Powered-By": "PHP" },
  });

/** Run one request through the full harness with a stubbed origin. */
export async function run(path: string, opts: RunOptions = {}): Promise<Response> {
  const headers = new Headers(opts.headers);
  headers.set("cf-connecting-ip", opts.ip ?? "203.0.113.10");
  headers.set("cf-ray", "test-ray");
  if (opts.body !== undefined && !headers.has("content-length")) {
    headers.set("content-length", String(new TextEncoder().encode(opts.body).length));
  }
  const request = new Request(`https://app.example.test${path}`, {
    method: opts.method ?? (opts.body !== undefined ? "POST" : "GET"),
    headers,
    body: opts.body,
  });

  // Rate limiting is on by default in config; most tests should not trip it.
  const config = loadConfig({ rateLimit: { enabled: false }, ...opts.config } as DeepPartial<HarnessConfig>);
  const origin = opts.origin ?? ORIGIN_OK;

  const harnessOpts: HarnessOptions = {
    config,
    cf: opts.cf ?? { country: "US", colo: "SJC" },
    fetcher: opts.fetcher,
    forward: async (ctx) => origin(ctx.request),
  };
  return handle(request, { ...opts.env }, () => {}, harnessOpts);
}

export async function json(res: Response): Promise<Record<string, unknown>> {
  return (await res.json()) as Record<string, unknown>;
}
