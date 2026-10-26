# GetPatched domain onboarding and DNS cutover

Status: prepared from public DNS evidence on 26 October 2026. No Cloudflare zone, DNS record, nameserver, or Worker change has been made. Nameserver cutover requires explicit approval after the target zone and exact records are verified.

## Current observations

- RDAP lists `getpatched.dev` as registered through Porkbun on 26 October 2026, with an expiration date of 26 October 2027. This confirms registration, but not which account has registrar access.
- RDAP and public DNS show these four delegated nameservers: `curitiba.ns.porkbun.com`, `fortaleza.ns.porkbun.com`, `maceio.ns.porkbun.com`, and `salvador.ns.porkbun.com`. No DNSSEC DS record was returned.
- Public DNS resolves the apex to Porkbun parking addresses `207.207.210.229` and `207.207.210.107`; no apex AAAA, MX, TXT, or CAA records were returned. `repo.getpatched.dev` and `early.getpatched.dev` are CNAMEs to `pixie.porkbun.com`, which resolves to the same parking service. These public answers do not replace inspection of the authoritative registrar zone.
- An HTTPS request to `https://getpatched.dev/` failed during the TLS handshake. The website and repository endpoints are not live.
- The only Cloudflare credential checked earlier was used for read-only checks against the former `apt.to` zone. No Cloudflare-related token variable surfaced from the current configured shell, Wrangler is not installed, and the available dashboard session is not verified as the intended Diderichsens account. Do not reuse the former zone or credentials scoped to another account.

Evidence was queried on 26 October 2026 from [Google Registry RDAP](https://pubapi.registry.google/rdap/domain/getpatched.dev) and [Google Public DNS](https://dns.google/resolve?name=getpatched.dev&type=A). Separate public DNS lookups cover the apex [AAAA](https://dns.google/resolve?name=getpatched.dev&type=AAAA), [MX](https://dns.google/resolve?name=getpatched.dev&type=MX), [TXT](https://dns.google/resolve?name=getpatched.dev&type=TXT), and [CAA](https://dns.google/resolve?name=getpatched.dev&type=CAA) records and the [DNSSEC DS](https://dns.google/resolve?name=getpatched.dev&type=DS) record. Public DNS evidence also includes the [repository hostname](https://dns.google/resolve?name=repo.getpatched.dev&type=CNAME) and [early hostname](https://dns.google/resolve?name=early.getpatched.dev&type=CNAME).

The TLS observation was a `curl -I --max-time 15 https://getpatched.dev/` probe on 26 October 2026; it failed before receiving an HTTP response, during TLS negotiation. Repeat this probe after DNS cutover.

## Intended routing

`worker/wrangler.jsonc` declares the Worker custom domains `getpatched.dev`, `repo.getpatched.dev`, and `early.getpatched.dev`. The Worker deployment workflow is gated by `APTTO_WORKER_DEPLOY_ENABLED`, a manual confirmation input, and the `aptto-worker-deploy` protected environment. Package staging/publication is separately gated by `APTTO_REPOSITORY_ENABLED` and the signing environment. Keep both controls disabled until their own gates are satisfied.

## Required preparation before approval

1. Obtain access to the intended Cloudflare account and verify its account ID, the active `getpatched.dev` zone ID, and domain ownership. Confirm whether the `aptto-release-staging` bucket exists in that same account and that its jurisdiction and Worker binding match the configuration.
2. Export the full authoritative Porkbun DNS record set and compare it with the public observations above. The apparent parking records are not permission to delete unobserved records. Record all existing mail, verification, and service records; preserve any that are still needed.
3. Add the domain to the verified Cloudflare account and inspect Cloudflare's assigned nameservers and imported DNS records. Do not change registrar delegation yet. Check that Worker custom domains, certificates, and the expected APT routes can be provisioned without touching unrelated services.
4. Prepare an exact change list containing the registrar, current and proposed nameservers, all records to add/replace/remove, expected downtime, and rollback steps. Obtain explicit approval for that specific nameserver cutover before changing delegation.
5. After approved cutover, verify authoritative and public DNS, HTTPS for all three hosts, Worker health, anonymous/sponsor access boundaries, signed APT installation, and the 168-hour promotion flow. Keep the repository and deployment gates disabled until required secrets, environment protection, and independent reviewers are configured.

## Current blocker

The configured task shell and browser do not currently expose verified access to the intended Cloudflare account. Continue with code, package, and hosted GitHub verification; do not guess an account, zone, API credential, or nameserver target.
