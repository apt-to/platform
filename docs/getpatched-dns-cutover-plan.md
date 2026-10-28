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
- The account-wide Domains page confirms `getpatched.dev` is Active and the separate, superseded `apt.to` zone has invalid nameservers. No `getpatched.dev` mail, verification, or service records are currently configured; add such records only if those services become part of this project. Do not copy or alter `apt.to` records as a substitute.
- No production service, HTTPS endpoint, package archive, or sponsor flow has been verified.

## Deployment gates

The repository keeps production deployment behind `APTTO_WORKER_DEPLOY_ENABLED=true`, the manual `confirm_production` input, and the planned protected GitHub environment `aptto-worker-deploy`, which does not exist yet. The repository publication path has separate controls and must remain disabled until its signing and publication gates pass.

Before enabling deployment:

1. Create the `aptto-worker-deploy` GitHub environment with an independent required reviewer and self-review prevention. Provision a dedicated least-privilege Cloudflare deployment credential for the verified project zone and required Worker resources; store it only as a protected environment secret. Never put credentials in Git or chat.
2. Confirm the workflow's Cloudflare token permissions are least-privilege and the environment reviewer is independent. GitHub currently has no `aptto-worker-deploy` environment, and the deployment enable variable is unset. Keep credentials and account-specific credential metadata out of repository content, build logs, and artifacts.
3. Verify the Worker configuration and private R2 binding. Configure required runtime secrets only through the intended Cloudflare secret mechanism. Keep package publication and signing gates off until their own protections and credentials are ready.
4. Run the existing manual deployment workflow from `main` only after its environment gate is configured, with `confirm_production=true`. The declared Worker custom domains are intended to provision routing and certificates as part of deployment; do not add guessed DNS records manually.
5. Verify Cloudflare routes, HTTPS, site and account pages, public/early archive access boundaries, R2 access, and health responses. Save workflow and endpoint evidence in `EVIDENCE.md` and update `STATUS.md`.

## Current blockers and next actions

- A dedicated least-privilege Cloudflare deployment credential must be provisioned, verified, and configured through the protected GitHub environment before deployment.
- A human must choose an independent GitHub reviewer for `aptto-worker-deploy` and establish the environment's required-reviewer protection.
- Required Worker runtime secrets and the R2 binding need configuration and verification before production deployment.
- No DNS records or Worker routes are live yet. Because delegation already points to Cloudflare, no further nameserver change is needed.
- Review the former registrar DNS export for mail, verification, and service records before deploying custom domains; the active Cloudflare zone currently contains zero records.

Do not enable the deployment variable or run a production deployment until these gates are complete. Do not enable package publication as part of the Worker setup.
