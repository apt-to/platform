# GetPatched Cloudflare and DNS setup

Status checked on 28 October 2026. `getpatched.dev` is already delegated to Cloudflare in the Diderichsen account. No production Worker deployment or DNS records are currently present. The nameserver cutover is complete; do not repeat it.

## Verified account and domain state

- Cloudflare account: Diderichsen (`c2e600736a5bb19e12ab38b0c7efbe71`).
- Cloudflare zone: `getpatched.dev` (`7115be62cf0e3f9e2642b30ab0082183`).
- Cloudflare-assigned authoritative nameservers: `kia.ns.cloudflare.com` and `terin.ns.cloudflare.com`; public delegation matches.
- Cloudflare DNS currently has zero records. The apex and the `repo` and `early` hostnames therefore have no configured routes.
- Cloudflare Overview reports no Worker connected to the zone. `worker/wrangler.jsonc` declares the intended Worker custom domains `getpatched.dev`, `repo.getpatched.dev`, and `early.getpatched.dev`; declarations do not mean they are deployed.
- R2 bucket `aptto-release-staging` exists in this account, using Standard storage in EEUR. It contains 0 B, has no custom domain, and has its public `r2.dev` endpoint disabled. Its Worker binding still needs verification in the deployed Worker.
- The registration and original registrar zone export were not rechecked in this task. Cloudflare delegation proves the active DNS authority, not that all former registrar records were migrated. Recover any required mail, verification, or service records from the registrar before relying on them.
- No production service, HTTPS endpoint, package archive, or sponsor flow has been verified.

## Deployment gates

The repository keeps production deployment behind `APTTO_WORKER_DEPLOY_ENABLED=true`, the manual `confirm_production` input, and the planned protected GitHub environment `aptto-worker-deploy`, which does not exist yet. The repository publication path has separate controls and must remain disabled until its signing and publication gates pass.

Before enabling deployment:

1. Create the `aptto-worker-deploy` GitHub environment with an independent required reviewer and self-review prevention. Add a dedicated Cloudflare Workers deployment API token and the matching account ID as environment secrets. Do not reuse the token previously tested: it returned 401 and is not a verified credential. Store the replacement in the approved local secret store; do not put it in Git or chat.
2. Confirm the workflow's Cloudflare token permissions are least-privilege and the environment reviewer is independent. GitHub currently has no `aptto-worker-deploy` environment, and the deployment enable variable is unset.
3. Verify the Worker configuration and private R2 binding. Configure required runtime secrets only through the intended Cloudflare secret mechanism. Keep package publication and signing gates off until their own protections and credentials are ready.
4. Run the existing manual deployment workflow from `main` only after its environment gate is configured, with `confirm_production=true`. The declared Worker custom domains are intended to provision routing and certificates as part of deployment; do not add guessed DNS records manually.
5. Verify Cloudflare routes, HTTPS, site and account pages, public/early archive access boundaries, R2 access, and health responses. Save workflow and endpoint evidence in `EVIDENCE.md` and update `STATUS.md`.

## Current blockers and next actions

- A new valid, dedicated Cloudflare Workers API token must be created and stored locally; the previously supplied token failed verification with HTTP 401.
- A human must choose an independent GitHub reviewer for `aptto-worker-deploy` and establish the environment's required-reviewer protection.
- Required Worker runtime secrets and the R2 binding need configuration and verification before production deployment.
- No DNS records or Worker routes are live yet. Because delegation already points to Cloudflare, no further nameserver change is needed.

Do not enable the deployment variable or run a production deployment until these gates are complete. Do not enable package publication as part of the Worker setup.
