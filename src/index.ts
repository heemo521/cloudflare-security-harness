import { handle } from "./harness";
import type { Env } from "./types";

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    return handle(request, env, (p) => ctx.waitUntil(p));
  },
} satisfies ExportedHandler<Env>;

export { handle } from "./harness";
export { loadConfig, DEFAULT_CONFIG } from "./config";
export type { HarnessConfig } from "./config";
export type { Env, Middleware, HarnessContext } from "./types";
