# GetPatched hosting cost model

Prepared 25 October 2026 from current provider documentation. This is a usage model, not a billing approval or an account-specific quote. It excludes any paid plan already attached to Diderichsens and assumes the three AptTo repositories remain public.

## Expected baseline

- **GitHub Actions builds:** $0 for standard GitHub-hosted runners in public repositories. Larger runners are charged. Current public runs are approximately 7–8 minutes per package build; cadence is a project choice, so total runner time is `runs × 8 minutes × packages`. [GitHub Actions billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions)
- **GitHub Releases:** $0 for release assets; GitHub currently allows up to 1,000 assets per release, each under 2 GiB, with no total release-size or bandwidth quota. [Release quotas](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases#storage-and-bandwidth-quotas)
- **Cloudflare R2 Standard:** $0 while monthly usage stays within 10 GB-month, 1 million Class A operations, and 10 million Class B operations. Internet egress is free. Above those allowances, rates are $0.015/GB-month, $4.50/million Class A and $0.36/million Class B. Deletion is free. [R2 pricing](https://developers.cloudflare.com/r2/pricing/)
- **Cloudflare Workers:** Free tier may suffice for a pilot under its 100,000 requests/day and 10 ms CPU/request limits, subject to account plan and Cron limits. For more headroom, Workers Paid starts at $5/month and includes 10 million requests and 30 million CPU milliseconds monthly; standard overage is $0.30/million requests and $0.02/million CPU milliseconds. [Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/) and [limits](https://developers.cloudflare.com/workers/platform/limits/)

## Example monthly R2 bills

| Average Standard storage | Class A / month | Class B / month | Estimated R2 charge |
| ---: | ---: | ---: | ---: |
| 8 GB-month | 0.8 million | 8 million | $0 |
| 20 GB-month | 1.5 million | 15 million | about $4.20: 10 GB × $0.015 + 0.5 million × $4.50 + 5 million × $0.36 |
| 100 GB-month | 5 million | 50 million | about $33.75: 90 GB × $0.015 + 4 million × $4.50 + 40 million × $0.36 |

Cloudflare rounds billable usage to its documented units; actual charges may be higher around unit boundaries. These examples assume all data uses Standard storage, omit Infrequent Access (which has retrieval charges and a 30-day minimum), and exclude Workers charges.

## Measurement before enabling releases

The two hosted candidate manifests provide a first payload estimate. The libxml2 candidate contains 3,375,642 bytes (about 3.22 MiB) of source and binaries; libarchive contains 7,382,456 bytes (about 7.04 MiB). Together that is about 10.26 MiB per pair. These are candidate manifest sizes, not a live bucket measurement; source packages are intended to be public immediately, so treating the whole payload as private staging is conservative.

For a simple scenario, four complete candidate pairs retained for 30 days would average about 41 MiB-month, far below R2's 10 GB-month free allowance. Even counting 11 uploads per pair and 100 sponsor downloads per day gives only 44 Class A writes and about 3,000 Class B reads per month, before metadata/index requests and retries. Those counts are illustrative assumptions; measure actual requests and retained bytes before launch. R2 Standard has no minimum retention period, while Infrequent Access has a 30-day minimum plus retrieval charges, so Standard is the natural fit for a seven-day private window.

Measure actual `.deb`, source-package and generated-index sizes per release; count average retained sponsor-period bytes, staging retries, authenticated downloads, metadata reads, and promotion/audit operations for a month. Calculate R2 using average daily stored bytes and request counts, and retain only release artifacts needed for the seven-day window and integrity/recovery policy. Public assets should use GitHub Releases after verified promotion. Add budget alerts and inspect current account usage before attaching a paid Workers plan. Do not enable production publishing until R2 lifecycle/cleanup and alerting have been exercised with disposable test releases.

GitHub Free for Organizations currently includes 500 MB of combined Actions artifact and Packages storage; overage is billed at $0.25/GB-month, accrued hourly. Keep workflow artifacts on bounded retention and monitor this shared pool, especially because source packages are public and do not need to remain in private staging. Standard GitHub-hosted runner use for public repositories remains free; the private artifact storage allowance and larger runner charges are separate concerns. [GitHub included usage](https://docs.github.com/en/billing/reference/product-usage-included) and [Actions billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions).

The Workers Free plan allows 100,000 requests/day and 10 ms CPU for both HTTP and Cron invocations. A 15-minute schedule is 96 invocations/day, but the 10 ms Cron CPU cap may be too tight for repository reconciliation. Workers Paid allows 30 seconds per Cron invocation when the schedule is more frequent than hourly; this per-invocation cap does not increase the included monthly CPU pool of 30 million milliseconds. Confirm the real workload with measurement before selecting a plan. [Workers limits](https://developers.cloudflare.com/workers/platform/limits/).

The current implementation has not created a Cloudflare bucket or Worker, and no account-specific usage or invoice is available. The expected provider baseline is $0 for public GitHub builds/releases and R2 Standard while within free allowances. The $5 Workers Paid baseline is not authorised spending; use the Free plan if it meets verified limits, otherwise obtain explicit approval before enabling Paid.
