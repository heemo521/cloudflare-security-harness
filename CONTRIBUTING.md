# Contributing

Thanks for helping make this harness better. The bar for merging is simple:
every control stays small, every behaviour has a test, and nothing fails open
on authentication.

## Setup

```bash
git clone <your-fork-url>
cd cloudflare-security-harness
npm install
npm test
```

Tests run on plain Node with vitest and need no Cloudflare account. To run
the Worker locally under the real runtime:

```bash
cp .dev.vars.example .dev.vars
npm run dev
```

On Windows keep the checkout at a short path (see the README limitations).

## Making changes

1. Open an issue first for anything beyond a bug fix, so the design can be
   discussed before you write code.
2. Add or update tests under `test/`. The `run()` helper in
   `test/helpers.ts` executes the full pipeline with a stubbed origin, so most
   controls can be tested end to end in a few lines.
3. Run `npm run typecheck` and `npm test` before opening a pull request. CI
   runs both plus a `wrangler deploy --dry-run`.
4. Keep the default policy conservative. New WAF patterns must come with
   tests for the false positives they could cause, not only the payloads they
   catch.

## Adding a control

A control is a `Middleware`: `(ctx, next) => Promise<Response>`.

- Return `next()` to continue down the pipeline.
- Return `blocked(ctx, status, name, reason)` to stop. This records the
  decision on `ctx.trail` so it shows up in the audit log.
- Push a function onto `ctx.responseHooks` to change the eventual response.
- Add any new configuration to `HarnessConfig` and `DEFAULT_CONFIG` in
  `src/config.ts`, and document it in the README table.
- Register the control in `DEFAULT_PIPELINE` in `src/harness.ts`, keeping the
  order: cheap rejections first, authentication last.

## Reporting security issues

Please do not open public issues for vulnerabilities in the harness itself.
See [SECURITY.md](SECURITY.md).

## License

By contributing you agree that your contributions are licensed under the MIT
License in [LICENSE](LICENSE).
