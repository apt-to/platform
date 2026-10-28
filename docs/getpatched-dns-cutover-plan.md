# GetPatched Cloudflare and DNS setup

Status checked on 28 October 2026. `getpatched.dev` is already delegated to Cloudflare in the Diderichsen account. No production Worker deployment or DNS records are currently present. The nameserver cutover is complete; do not repeat it.

## Verified account and domain state

- Cloudflare account: Diderichsen (`c2e600736a5bb19e12ab38b0c7efbe71`).
- Cloudflare zone: `getpatched.dev` (`7115be62cf0e3f9e2642b30ab0082183`).
- Cloudflare-assigned authoritative nameservers: `kia.ns.cloudflare.com` and `terin.ns.cloudflare.com`; public delegation matches.
- The authoritative `.dev` RDAP record reports initial registration on 26 October 2026 at 14:54 UTC. This is a newly registered domain, not a transfer of the former `apt.to` zone; no legacy `getpatched.dev` registrar export is expected from before registration.
- Cloudflare DNS currently has zero records. The apex and the `repo` and `early` hostnames therefore have no configured routes.
- Cloudflare Overview reports no Worker connected to the zone. `worker/wrangler.jsonc` declares the intended Worker custom domains `getpatched.dev`, `repo.getpatched.dev`, and `early.getpatched.dev`; declarations do not mean they are deployed.
- R2 bucket `aptto-release-staging` exists in this account, using Standard storage in EEUR. It contains 0 B, has no custom domain, and has its public `r2.dev` endpoint disabled. Its Worker binding still needs verification in the deployed Worker.
- On 28 October 2026 at 06:18 UTC, read-only API calls using the stored GetPatched deployment credential verified the account-scoped token as active (HTTP 200) and listed the account's Worker scripts (HTTP 200). There is no `aptto-release-gateway` script yet; existing Worker scripts were not changed. The credential's recorded scope is account-wide Workers Scripts Write and Account Settings Read plus Workers Routes Write on only the `getpatched.dev` zone. This does not prove permission to create the new Worker.
- The account-wide Domains page confirms `getpatched.dev` is Active and the separate, superseded `apt.to` zone has invalid nameservers. No `getpatched.dev` mail, verification, or service records are currently configured; add such records only if those services become part of this project. Do not copy or alter `apt.to` records as a substitute.
- No production service, HTTPS endpoint, package archive, or sponsor flow has been verified.

## Deployment gates

`.github/workflows/worker-deploy.yml` verifies and deploys the Worker and static site on every push to `main`, including merges. Its `aptto-worker-deploy` environment is limited to `main` and does not require a human reviewer under the maintainer's single-operator policy. Manual dispatch from `main` remains available with `confirm_production=true`. Package publication and signing controls are separate and remain in force.

Before the first deployment:

1. For initial Worker creation, Cloudflare's current [Workers roles guidance](https://developers.cloudflare.com/workers/authorization/workers/) requires product-level Workers `Admin`, plus `Workers Routes Write` limited to the `getpatched.dev` zone for the declared Custom Domains. This temporary product-level permission can affect all Workers in the account; obtain action-time confirmation, store it only as the protected `CLOUDFLARE_BOOTSTRAP_TOKEN` environment secret, and revoke it after the Worker is created. The existing script-write token is not documented to create a new Worker.
2. Routine deployments use `CLOUDFLARE_API_TOKEN` with Workers `Editor` and `Workers Routes Write` limited to `getpatched.dev`. Cloudflare does not currently support per-Worker roles for Custom Domains, so the ongoing Editor role applies across the account. Do not copy credentials into Git, logs or artifacts.
3. Verify the Worker configuration and private R2 binding. Configure runtime secrets only through the intended Cloudflare secret mechanism. Keep package publication and signing gates off until their own protections and credentials are ready.
4. After the initial deployment, verify Cloudflare routes, HTTPS, site and account pages, public/early archive access boundaries, R2 access, and health responses. Save workflow and endpoint evidence in `EVIDENCE.md` and update `STATUS.md`.

## Current blockers and next actions

- A temporary bootstrap credential is needed for the first Worker creation. Its Workers `Admin` permission is account-wide; request confirmation at the time of creation. After bootstrap, routine deployments should use the existing least-privilege deployment token.
- The website can deploy before sponsor OAuth and release runtime credentials are configured; the account page must accurately report unavailable sign-in. The private R2 binding and archive routes still require live verification.
- No DNS records or Worker routes are live yet. Because delegation already points to Cloudflare, no further nameserver change is needed.
- No pre-registration `getpatched.dev` zone export exists to restore. Leave the zone's DNS record set empty until Wrangler deploys the declared custom domains; do not copy records from the former `apt.to` zone or add guessed routes.

Do not enable package publication as part of the Worker setup.
