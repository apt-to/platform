# AptTo hosting cost model

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

Measure actual `.deb`, source-package and generated-index sizes per release; count average retained sponsor-period bytes, staging retries, authenticated downloads, metadata reads, and promotion/audit operations for a month. Calculate R2 using average daily stored bytes and request counts, and retain only release artifacts needed for the seven-day window and integrity/recovery policy. Public assets should use GitHub Releases after verified promotion. Add budget alerts and inspect current account usage before attaching a paid Workers plan. Do not enable production publishing until R2 lifecycle/cleanup and alerting have been exercised with disposable test releases.

The current implementation has not created a Cloudflare bucket or Worker, and no account-specific usage or invoice is available. The $5 Workers Paid baseline is not authorised spending; use the Free plan if it meets the verified limits, otherwise request explicit approval before enabling Paid.
