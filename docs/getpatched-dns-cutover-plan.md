# GetPatched Cloudflare and DNS setup

Status updated on 28 October 2026. `getpatched.dev` is delegated to Cloudflare in the Diderichsen account. The latest production Worker/site deployment, [run 40715152075](https://github.com/getpatched/platform/actions/runs/40715152075), completed from `main` at `5237ca8f0d5a3d907334701fe1508b282ef57116`; its output confirms all three custom domains and the private R2 binding. The nameserver cutover is complete; do not repeat it. Package metadata is not published yet.

## Verified account and domain state

- Cloudflare account: Diderichsen (`c2e600736a5bb19e12ab38b0c7efbe71`).
- Cloudflare zone: `getpatched.dev` (`7115be62cf0e3f9e2642b30ab0082183`).
- Cloudflare-assigned authoritative nameservers: `kia.ns.cloudflare.com` and `terin.ns.cloudflare.com`; public delegation matches.
- The authoritative `.dev` RDAP record reports initial registration on 26 October 2026 at 14:54 UTC. This is a newly registered domain, not a transfer of the former `apt.to` zone; no legacy `getpatched.dev` registrar export is expected from before registration.
- Wrangler provisions the Worker custom domains `getpatched.dev`, `repo.getpatched.dev`, and `early.getpatched.dev`. The live root and `/account` routes passed smoke checks after deployment.
- The public `repo.getpatched.dev/dists/focal/InRelease` route returned HTTP 503 in the latest live check because no signed production repository metadata is published; unauthenticated `early.getpatched.dev/dists/focal/InRelease` returned HTTP 401. This confirms route responses, not a live APT repository or sponsor access.
- R2 bucket `getpatched-release-staging` exists in this account, using Standard storage in EEUR. It contains 0 B, has no custom domain, and has its public `r2.dev` endpoint disabled. Deployment run 40715152075 confirmed its binding in the deployed Worker; no package objects have been uploaded.
- Historical predeployment checks at 06:18 UTC showed no `getpatched-release-gateway` script. The Worker was subsequently created by the initial deployment run and verified by a successful follow-up run using the ongoing deployment token.
- The account-wide Domains page confirms `getpatched.dev` is Active and the separate, superseded `apt.to` zone has invalid nameservers. No `getpatched.dev` mail, verification, or service records are currently configured; add such records only if those services become part of this project. Do not copy or alter `apt.to` records as a substitute.
- The website's HTTPS routes and deployed Worker's private R2 binding are verified live. Package archive publication and sponsor access are not yet verified.

## Deployment gates

`.github/workflows/worker-deploy.yml` verifies and deploys the Worker and static site on every push to `main`, including merges. Its `getpatched-worker-deploy` environment is limited to `main` and does not require a human reviewer under the maintainer's single-operator policy. Manual dispatch from `main` remains available with `confirm_production=true`. Package signing also has no required human reviewer; signed-tag identity checks, build verification, and publication controls remain in force.

Deployment history and continuing checks:

1. Initial Worker creation required product-level Workers `Admin` plus `Workers Routes Write` limited to `getpatched.dev`, according to Cloudflare's current [Workers roles guidance](https://developers.cloudflare.com/workers/authorization/workers/). The temporary seven-day token was used, then revoked; its `CLOUDFLARE_BOOTSTRAP_TOKEN` GitHub secret was deleted. No product-level `Admin` credential remains in CI.
2. Routine deployment uses `CLOUDFLARE_API_TOKEN` with Workers `Editor` and `Workers Routes Write` limited to `getpatched.dev`. Cloudflare does not currently support per-Worker roles for Custom Domains, so the ongoing Editor role applies across the account. Follow-up deployment succeeded using this token alone. Do not copy credentials into Git, logs or artifacts.
3. The deployed Worker has its private R2 binding and expected archive routes. Configure runtime secrets only through the intended Cloudflare secret mechanism. Keep package publication and signing gates off until their own protections and credentials are ready.
4. Website HTTPS routes, site/account pages, and public/early response boundaries have been checked. Continue recording workflow and endpoint evidence in `EVIDENCE.md` and update `STATUS.md`.

## Current blockers and next actions

- Initial Worker bootstrap is complete. The temporary account-level Workers `Admin` token has been revoked and its GitHub environment secret removed; a second successful deployment confirmed the ongoing token works.
- The website can deploy before sponsor OAuth and release runtime credentials are configured; the account page must accurately report unavailable sign-in. The private R2 binding and archive route boundaries are verified, but package publication and sponsor access are not.
- The apex website and `/account` route are live. The public APT metadata route returns HTTP 503 because no signed metadata is published; the unauthenticated early route returns HTTP 401. No further nameserver change is needed.
- No pre-registration `getpatched.dev` zone export exists to restore. Do not copy records from the former `apt.to` zone or add guessed routes.

Do not enable package publication as part of the Worker setup.
