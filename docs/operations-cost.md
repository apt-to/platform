# GetPatched hosting cost model

Checked 28 October 2026 against the official provider documentation linked below. This is a usage scenario, not an account-specific quote or billing approval. The Cloudflare Worker and website are deployed; the R2 bucket is empty, and production package routes have no published metadata, so actual release traffic, request counts and invoices are not yet available. The estimate assumes the three GetPatched repositories remain public and excludes any pre-existing account charges.

## Current price and limit baseline

- **GitHub Actions:** Standard GitHub-hosted runners are free and unlimited for public repositories. The latest two candidate verification runs took 7m00s and 6m20s, or 13m20s for one package pair; future runtime depends on source/toolchain changes. Larger runners are billed. [Actions billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions) and [public runner details](https://docs.github.com/en/actions/how-tos/write-workflows/choose-where-workflows-run/choose-the-runner-for-a-job).
- **GitHub Releases:** Public release assets have no total release-size or bandwidth quota. Each release allows up to 1,000 assets, and each file must be under 2 GiB. [Release asset quotas](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases#storage-and-bandwidth-quotas).
- **GitHub Actions artifacts:** GitHub Free for Organizations includes 500 MB of shared Actions artifact and GitHub Packages storage; overage is currently $0.25/GB-month. The included 2,000 minutes do not apply to standard runners used by public repositories, which remain free. The latest two package runs retained 9,856,625 bytes (~9.40 MiB) across their source and verification artifacts, with 30-day retention. [Included usage](https://docs.github.com/en/billing/reference/product-usage-included), [Actions billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions), and [Packages storage sharing](https://docs.github.com/en/billing/concepts/product-billing/github-packages).
- **Cloudflare R2 Standard:** Free monthly usage is 10 GB-month, 1 million Class A operations, and 10 million Class B operations; Internet egress is free. Above those allowances, rates are $0.015/GB-month, $4.50/million Class A, and $0.36/million Class B. Cloudflare rounds billable usage up to its billing units. [R2 pricing](https://developers.cloudflare.com/r2/pricing/).
- **Cloudflare Workers:** Free includes 100,000 requests/day and 10 ms CPU per HTTP or Cron invocation. Static asset requests are free and unlimited; dynamic Worker routes and API calls count as requests. Workers Paid starts at $5/month and includes 10 million requests and 30 million CPU milliseconds monthly; overage is $0.30/million requests and $0.02/million CPU milliseconds. On Paid, Cron CPU is limited to 30 seconds for schedules more frequent than hourly. [Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/) and [Workers limits](https://developers.cloudflare.com/workers/platform/limits/).

## Estimated pilot usage

The latest hosted manifests contain 3,375,642 bytes (3.22 MiB) for the libxml2 source-and-binary set and 7,382,524 bytes (7.04 MiB) for libarchive, or 10,758,166 bytes (10.26 MiB) combined per candidate pair. These are manifest totals, not a live bucket measurement; source packages are intended to be public immediately, so counting all source and binary bytes in private storage is conservative.

For an illustrative month with four complete package pairs retained for 30 days, counting every source and binary asset in R2 would total about 41.04 MiB-month, far below R2's 10 GB-month free allowance. This overstates gated storage because sources are public immediately and libarchive is immediate-public; only libxml2's early binaries need sponsor-period storage. A payload-only operation estimate that counts all 11 manifest assets per pair as R2 writes gives 44 Class A operations. Assuming 100 aggregate sponsor binary reads per day during each of four seven-day early windows gives 2,800 Class B reads. Index/control-object operations, retries, range requests, and other traffic are excluded; measure actual operation counts before launch. R2 Standard fits the seven-day window without Infrequent Access's 30-day minimum and retrieval charges.

At this pilot scale, the expected R2 bill is $0/month if actual storage and operations remain within the free tier. Public GitHub Actions builds and Releases are also expected to cost $0. Keep Actions artifacts on bounded 30-day retention and monitor the shared 500 MB allowance. GitHub Releases asset storage and bandwidth are separate from that Actions/Packages artifact pool.

## Worker plan decision

One 15-minute reconciler schedule invokes Cron 96 times/day, within the Free plan's daily request allowance. Its actual CPU time is unknown; the Free plan's 10 ms Cron CPU cap may be too small for sponsor reconciliation. The Worker must be deployed and measured before deciding whether Free is adequate. Workers Paid would start at $5/month, but that is not authorised spending. Do not enable a paid plan without explicit approval. If the Free CPU limit is insufficient, prepare the measured workload and cost before requesting that approval.

The example R2 bills below show standard-tier charges above the free allowances; they are not forecasts:

| Average Standard storage | Class A / month | Class B / month | Estimated R2 charge |
| ---: | ---: | ---: | ---: |
| 8 GB-month | 0.8 million | 8 million | $0 |
| 20 GB-month | 1.5 million | 15 million | about $4.20: 10 GB × $0.015 + 0.5 million × $4.50 + 5 million × $0.36 |
| 100 GB-month | 5 million | 50 million | about $33.75: 90 GB × $0.015 + 4 million × $4.50 + 40 million × $0.36 |

Count actual `.deb`, source, and index sizes, average stored bytes, sponsor downloads, metadata reads, promotion retries, and cleanup operations after deployment. Keep only the private release and bounded recovery copies required by policy. Add budget alerts and inspect actual account usage before changing plans or enabling production publication.
