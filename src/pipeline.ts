import type { HarnessContext, Middleware, Next } from "./types";

/** Compose middleware left-to-right into a single handler. */
export function compose(middleware: Middleware[]): (ctx: HarnessContext, final: Next) => Promise<Response> {
  return (ctx, final) => {
    let index = -1;
    const dispatch = (i: number): Promise<Response> => {
      if (i <= index) return Promise.reject(new Error("next() called multiple times"));
      index = i;
      const fn = middleware[i];
      if (!fn) return final();
      return fn(ctx, () => dispatch(i + 1));
    };
    return dispatch(0);
  };
}

/** Run registered response hooks in registration order. */
export function applyResponseHooks(ctx: HarnessContext, res: Response): Response {
  let out = res;
  for (const hook of ctx.responseHooks) out = hook(out);
  return out;
}
