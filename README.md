# Cloudflare Security Harness

[![CI](https://github.com/heemo521/cloudflare-security-harness/actions/workflows/ci.yml/badge.svg)](https://github.com/heemo521/cloudflare-security-harness/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A Cloudflare Worker that sits in front of an origin and runs every request
through a configurable chain of security controls before it is forwarded.
Each control is a small, independently tested middleware; the whole policy is
one JSON document in `wrangler.toml`. MIT licensed, no account needed to run
the tests, and the free Workers plan is enough to deploy it.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/heemo521/cloudflare-security-harness)

```
client ──> Cloudflare edge ──> [ harness Worker ] ──> origin
                                 │
                                 ├─ security headers   (always; decorates every response)
                                 ├─ ip filter          (CIDR allow / deny)
                                 ├─ geo filter         (country allow / deny)
                                 ├─ request limits     (method allow list, max body size)
                                 ├─ bot check          (Bot Management score threshold)
                                 ├─ rate limit         (Workers Rate Limiting binding)
                                 ├─ waf                (SQLi / XSS / traversal / probe paths)
                                 ├─ cors               (explicit origin allow list)
                                 ├─ access auth        (Cloudflare Access JWT, RS256 + JWKS)
                                 └─ bearer auth        (static API token for machine clients)
```

Every decision is written as one structured JSON log line (and optionally to
an Analytics Engine dataset) with the Ray ID, client IP, country, the control
that decided, and why.

## Quick start

Requirements: Node 20 or newer and a free Cloudflare account for deploying.

```bash
git clone https://github.com/heemo521/cloudflare-security-harness.git
cd cloudflare-security-harness
npm install
npm test            # 55 unit tests, run on Node, no Cloudflare account needed
npm run typecheck
```

Local development against a real origin:

```bash
cp .dev.vars.example .dev.vars        # local secrets
# set ORIGIN_URL in wrangler.toml, or leave empty to pass through
npm run dev                           # http://localhost:8787
curl -i http://localhost:8787/__harness/health
curl -i "http://localhost:8787/?q=<script>x</script>"   # 403 from the waf control
```

Deploy:

```bash
npx wrangler login
npx wrangler secret put API_TOKEN     # only if bearer auth is enabled
npm run deploy
npm run tail                          # live audit stream
```

Then attach the Worker to your hostname: either uncomment `routes` in
`wrangler.toml` (the Worker fetches the same hostname, which Cloudflare routes
to your origin), or set `ORIGIN_URL` to proxy to an explicit upstream, or bind
an origin Worker as a service binding named `ORIGIN`.

## Configuration

All policy lives in the `HARNESS_CONFIG` var in `wrangler.toml`. Every key is
optional and merges over the defaults in `src/config.ts`.

| Key | What it does | Default |
| --- | --- | --- |
| `allowedMethods` | Methods accepted; others get 405 with an `Allow` header | GET HEAD POST PUT PATCH DELETE OPTIONS |
| `maxBodyBytes` | Reject requests whose `Content-Length` exceeds this (413) | 1 MiB |
| `ipDeny` / `ipAllow` | CIDR lists (IPv4 and IPv6). Deny wins; a non-empty allow list blocks everything else | empty |
| `blockedCountries` / `allowedCountries` | ISO country codes from edge geolocation. `T1` is Tor | empty |
| `bot.scoreThreshold` | Block when Bot Management score is below this. `0` disables | 0 |
| `bot.allowVerifiedBots` | Let verified crawlers through regardless of score | true |
| `rateLimit` | `requests` per `windowSeconds`, keyed by `ip` or `ip+path`; `exemptPaths` skip it | 100 / 60s |
| `waf.blockedPaths` | Path prefixes that always 404 (dotfiles, admin panels) | `.env`, `.git`, `wp-admin`, ... |
| `waf.blockSqli` / `blockXss` / `blockTraversal` | Pattern categories applied to path, query, selected headers, and small text bodies | all true |
| `waf.inspectBodyBytes` | Max body size inspected (text content types only) | 64 KiB |
| `access` | Require a valid Cloudflare Access JWT on `paths`; needs `teamDomain` and the app `aud` | disabled |
| `bearer` | Require `Authorization: Bearer <API_TOKEN>` on `paths` | disabled |
| `cors` | Origin allow list, methods, headers, max age, credentials | disabled |
| `headers` | HSTS, CSP, frame options, referrer and permissions policies, plus headers to strip | hardened set |
| `blockFormat` | `json` or `text` block bodies | json |

Path lists match whole segments: `/api` matches `/api` and `/api/users` but not
`/apiary`.

### Bindings

- **`RATE_LIMITER`** (Workers Rate Limiting). Configured in `wrangler.toml`.
  Without it the harness falls back to a per-isolate in-memory limiter, which
  is fine for `wrangler dev` but is not shared across the edge.
- **`AUDIT`** (Analytics Engine, optional). Uncomment in `wrangler.toml` to
  get queryable audit data: index is the deciding control; blobs are decision,
  reason, method, path, country, IP; doubles are status and duration.
- **`ORIGIN`** (service binding, optional). Forward to another Worker directly.

### Secrets

- `API_TOKEN`: the bearer token. Set with `wrangler secret put API_TOKEN`.
  If `bearer.enabled` is true and the secret is missing, protected paths fail
  closed with 503.

## How the controls behave

- **Fail closed on auth, fail open on availability.** Missing or malformed
  tokens, unknown signing keys, and misconfigured auth all block. A rate
  limiter that throws logs the error and lets the request through so a
  binding outage does not take the site down.
- **Block responses** carry `X-Harness-Block: <control>` and a Ray ID so a
  blocked user can quote something supportable and you can grep the logs.
- **Probe paths return 404, not 403**, so scanners learn nothing.
- **Security headers land on every response**, including blocks, and an
  origin-supplied `Content-Security-Policy` is kept rather than overwritten.
- **Access JWTs** are verified against the team JWKS with RS256; `iss`, `aud`,
  `exp` and `nbf` are checked; an unknown `kid` triggers one JWKS refresh to
  handle key rotation. The header `Cf-Access-Jwt-Assertion` and the
  `CF_Authorization` cookie are both accepted.
- **The WAF is a tripwire, not a replacement** for Cloudflare's managed
  rulesets. Keep those enabled on the zone; this layer adds application-aware
  rules you control in code and test in CI.
- **`/__harness/health`** answers from the Worker without touching the origin.

## Adding a control

A control is a function `(ctx, next) => Promise<Response>`. Return `next()`
to continue, return `blocked(ctx, status, name, reason)` to stop, or push a
function onto `ctx.responseHooks` to modify the eventual response. Register it
in `DEFAULT_PIPELINE` in `src/harness.ts` and add a test under `test/`. The
`run()` helper in `test/helpers.ts` executes the full pipeline with a stubbed
origin and injectable `cf` data, IP, headers and config.

## Project layout

```
src/
  index.ts              Worker entry (fetch handler)
  harness.ts            context creation, pipeline order, origin forwarding, health
  pipeline.ts           middleware composition and response hooks
  config.ts             HarnessConfig type, defaults, JSON loader
  types.ts              Env bindings and context types
  middleware/           one file per control
  utils/                CIDR matching, block responses, audit logging
test/                   vitest suite (runs on plain Node)
wrangler.toml           deployment config and policy
```

## Continuous deployment

`.github/workflows/ci.yml` runs typecheck, tests and a dry-run bundle on
every push and pull request. `.github/workflows/deploy.yml` deploys on pushes
to `main` once you set the repository variable `ENABLE_DEPLOY=true` and add
the secrets `CLOUDFLARE_API_TOKEN` (Workers Scripts: Edit) and
`CLOUDFLARE_ACCOUNT_ID`. Forks without those stay test-only.

## Contributing and security

Pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). To report
a bypass or other vulnerability in the harness itself, follow
[SECURITY.md](SECURITY.md) rather than opening a public issue.

## License

[MIT](LICENSE).

## Limitations

- Bot scores require Bot Management or Super Bot Fight Mode on the zone; on
  other plans the bot control records "no score" and allows.
- The body inspector only reads text content types up to `inspectBodyBytes`
  and relies on `Content-Length`; chunked uploads without a length are left to
  the origin.
- On Windows, `wrangler dev` spawns `workerd.exe` from `node_modules`; if the
  project lives at a deep path the full binary path can exceed the 260
  character limit and spawning fails with ENOENT. Keep the project at a short
  path such as `C:\dev\security-harness`.
- Rate limiting via the binding is approximate by design (Cloudflare documents
  it as best-effort per location), which is the right trade-off for abuse
  control but not for billing-grade quotas.
