# Security Policy

## Scope

This project is a security control layer, so bugs in it can have outsized
impact for anyone running it. The following are in scope:

- A request that should be blocked by an enabled control reaching the origin
  (bypass).
- Authentication controls (Access JWT, bearer token) accepting an invalid
  credential, or failing open when misconfigured.
- Denial of service against the Worker itself that a reasonable configuration
  does not mitigate.
- Leaking secrets or audit data to clients.

Out of scope: WAF pattern gaps for novel payloads (please open a normal issue
or pull request with a test), and anything that requires an attacker to
already control the Cloudflare account or wrangler configuration.

## Reporting

Email the maintainer at heemo521@gmail.com with "security-harness" in the
subject, or use GitHub's private vulnerability reporting on the repository if
it is enabled. Include a request that demonstrates the issue and the
`HARNESS_CONFIG` you used.

You can expect an acknowledgement within a few days. Please give a reasonable
window for a fix before disclosing publicly.

## Supported versions

Only the latest commit on the default branch is supported. There are no
backports.
