---
name: Bug report
about: A control blocked something it should not have, or let something through
title: ""
labels: bug
---

**Which control** (ip-filter, geo-filter, request-limits, bot-check, rate-limit, waf, cors, access-auth, bearer-auth, headers):

**Expected**: allowed / blocked

**Actual**: allowed / blocked, status code, `X-Harness-Block` header value

**Request** (method, path, query, relevant headers; redact anything private):

```
```

**HARNESS_CONFIG** (the relevant part):

```json
```

**Audit log line** from `wrangler tail`, if you have it:

```
```
