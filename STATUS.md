# AptTo implementation status

Updated 26 October 2026. This is an evidence ledger; candidate verification is not a public release or live deployment.

## Current state

- Public repositories: [platform](https://github.com/apt-to/platform), [packaging-libxml2](https://github.com/apt-to/packaging-libxml2), [packaging-libarchive](https://github.com/apt-to/packaging-libarchive). Platform PR [#1](https://github.com/apt-to/platform/pull/1) is open and requires independent approval. The reviewed timeout fix is pushed in commit `dad54c4`; hosted platform quality passed in [run 40278841713](https://github.com/apt-to/platform/actions/runs/40278841713).
- Later reruns on the hardened scanner exposed intermittent HTTP 503 responses from `snapshot.ubuntu.com` while retrieving pinned Focal `.deb` files. Focal-compatible bounded APT retries are now in the pushed recipe. Two fresh libarchive verifications [40282741614](https://github.com/apt-to/platform/actions/runs/40282741614) and [40285159539](https://github.com/apt-to/platform/actions/runs/40285159539), and fresh libxml2 verification [40285154915](https://github.com/apt-to/platform/actions/runs/40285154915), passed. The prior libxml2 attempt [40282738950](https://github.com/apt-to/platform/actions/runs/40282738950) hit the old 20-minute Docker build timeout; it did not reach scanner verification.
- Cloudflare read-only checks authenticated to the credential's account and found the existing `apt.to` zone in `pending` state with no DNS records. The project setup names the account **Diderichsens**, while the API display name is **Diderichsen**; the account and zone were matched by ID. Preserve this distinction and select by IDs before any mutation. Public DNS still points to Afternic (`ns1.afternic.com`, `ns2.afternic.com`) and parking addresses. Account inventory showed 12 Workers, four R2 buckets and 10 Pages projects, with no AptTo-named resources. No Cloudflare or DNS state was changed.
- GitHub reports no `apt-to` Sponsors listing. Only `marktopper` is an organization member. Existing `aptto-index-build` and `aptto-signing` environments are branch-limited; signing requires one reviewer and prevents self-review, but has no independent configured reviewer and no environment secrets or variables. Production sponsor authentication, signing, publication, and promotion are not configured or tested.
- Estimated current pilot storage is about 10.26 MiB per two-package candidate pair, or about 41 MiB-month for four pairs retained 30 days. Public GitHub-hosted build/release infrastructure is expected to remain in free public-repository allowances. R2 is estimated free within 10 GB-month, 1M Class A and 10M Class B requests; above those allowances the documented Standard rates are $0.015/GB-month, $4.50/M Class A and $0.36/M Class B, with free internet egress. A paid Workers plan is estimated at $5/month and has not been enabled or authorized. Recheck current pricing and quotas before launch; see [operations-cost.md](docs/operations-cost.md).

## Candidate build evidence

The following are the original successful hosted, isolated focal/amd64 candidate checks, performed before scanner hardening. They are not published packages, signed production releases, or live APT endpoints. Full manifests and verification evidence are in the linked workflow artifacts (GitHub retains them for 30 days).

| Source | Source commit | Source/base version | Candidate version | Policy | Hosted verification |
| --- | --- | --- | --- | --- | --- |
| libxml2 | `5d4f212522dc479290443e9e97d3c42053a689df` | `2.9.10+dfsg-5ubuntu0.20.04.10` | `2.9.10+dfsg-5ubuntu0.20.04.10+aptto1` | 7-day sponsor delay | [40228372770](https://github.com/apt-to/platform/actions/runs/40228372770) |
| libarchive | `bae65a1d9a669caa6aca51ed74ee3ae5b612fe73` | `3.4.0-2ubuntu1.5` | `3.4.0-2ubuntu1.5+aptto1` | Immediate public | [40229030398](https://github.com/apt-to/platform/actions/runs/40229030398) |

libxml2 baseline fixtures reproduced crashes for CVE-2025-49794 and CVE-2025-49796; the patched package rejected both inputs and passed a normal XPath consumer check. libarchive's bounded CVE-2026-4111 RAR5 baseline timed out; the patched package rejected the fixture and upstream tests passed 4/4. The original CVE-2025-5914 scenario was not attempted with an unsafe multi-billion-node allocation; CVE-2026-4111 is the documented pilot substitution. The raw Trivy reports showed zero target findings before and after for both candidates. The custom AptTo advisory scan, not Trivy, detected the baseline target CVEs and found none in the candidate builds. Each run also passed isolated signed focal APT metadata, binary install, and source-fetch checks with temporary test keys. No claim is made that either package is free of other vulnerabilities.

The hardened-scanner libarchive reruns [40282741614](https://github.com/apt-to/platform/actions/runs/40282741614) and [40285159539](https://github.com/apt-to/platform/actions/runs/40285159539) passed for source commit `745615747aa4f5706a4e7ef30d8229a6b331d9af`, producing `3.4.0-2ubuntu1.5+aptto1`. The latest artifact confirms the custom AptTo scan reports CVE-2026-4111 on the exact Focal baseline and no target finding after patching; the bounded baseline RAR5 fixture timed out as expected, while the patched fixture was rejected and the installed consumer regression passed. The AptTo installed-package scan showed two unrelated libxml2 advisories still present; raw Trivy reports contained zero findings in both images, so Trivy alone does not substantiate this target fix. Signed repository smoke checks, source retrieval, and report upload passed. [Latest run artifact](https://github.com/apt-to/platform/actions/runs/40285159539/artifacts/12634332361).

The hardened-scanner libxml2 run [40285154915](https://github.com/apt-to/platform/actions/runs/40285154915) passed for source commit `5d4f212522dc479290443e9e97d3c42053a689df`, producing `2.9.10+dfsg-5ubuntu0.20.04.10+aptto1`. The custom AptTo scan reported CVE-2025-49794 and CVE-2025-49796 on the exact Focal baseline and neither after patching. Both baseline Schematron fixtures reproduced invalid memory reads and SIGSEGV under Valgrind; the patched fixtures completed without memory errors, and the normal XPath consumer regression passed. Raw Trivy reports had zero target findings before and after, so they do not substantiate this target fix. Signed repository smoke checks and source retrieval passed. [Run artifact](https://github.com/apt-to/platform/actions/runs/40285154915/artifacts/12634781538).

The source and binary checksums below are SHA-256 values recorded in the verified source-preflight and binary-manifest evidence. They identify the tested candidate inputs and outputs; they do not imply publication.

| Candidate asset | SHA-256 |
| --- | --- |
| libxml2 source `debian.tar.xz` | `4c6bfe0b654bcad9bfe7ddcc008c61dde73b180a86f12b638e755f4a9363b999` |
| libxml2 source `.dsc` | `5744786df81cce783ed908fbe5fb9f935b2e60c3f4b2e539c27915a2199b240c` |
| libxml2 upstream orig tarball | `65ee7a2f5e100c64ddf7beb92297c9b2a30b994a76cd1fab67470cf22db6b7d0` |
| libxml2 `libxml2-dev` binary | `8ecd3e0260e6809c395b148ff54354c1f82128d0d3902948d06b2d8ffe95af19` |
| libxml2 `libxml2-doc` binary | `b87e6e2b6ce563568004958d9148aeb212262d067c7c98e06a7ba1e2249e4f15` |
| libxml2 `libxml2-utils` binary | `0497283cfce4bbeaa7eec42ca4075b69442f655fc7a2c54cbff66770774d8807` |
| libxml2 `libxml2` binary | `4a78d74c0bd187df0210bf955a89d10d794fca3ecd57f5f32b31f314cd6d4b50` |
| libxml2 `python-libxml2-dbg` binary | `b64b06bffc216ede9b30ba92e5c76a85165983b22fa391d1f9728590eb970e24` |
| libxml2 `python-libxml2` binary | `71e15ebf66f2cd946e4431de565d20fef5cddcf07cd5bdf17625eecceb73dc5a` |
| libxml2 `python3-libxml2-dbg` binary | `1f2b073c5994a6b84b5802fe4fb3d4038dc0cc70024b56deac2f68da6a5fe685` |
| libxml2 `python3-libxml2` binary | `3e7e1fc372f7f0b1add4961c2be99520a2c77a19fc27c2943b95a8180a344615` |
| libarchive source `debian.tar.xz` | `961a77d422943368a0b423813fafc48c20112d5fb87738e11799c067eada2ed7` |
| libarchive source `.dsc` | `c13662651e87ecd9f9a73a5f1982061744161a03eac69bf3de5a0db9ee6b5500` |
| libarchive upstream orig tarball | `8643d50ed40c759f5412a3af4e353cffbce4fdf3b5cf321cb72cacf06b2d825e` |
| libarchive upstream `.asc` signature | `5aa9d657d9d2f2481a8dce1bab4c733cfc18657b451f6551d60f37cce4ca2f57` |
| libarchive `libarchive-dev` binary | `124880a49be7019f5f8492e1839d8a33a1051a0f52641ff743b36df97e708225` |
| libarchive `libarchive-tools` binary | `749c01bf86e5571113b2b0cea32f77233f17d7234e85d75e1f2caf3ef1f5edf6` |
| libarchive `libarchive13` binary | `1d7e1f0b8ddbc4ccd027a926be157be44023fbc381b68d1ac4d1719009261590` |

Temporary local APT smoke-test metadata was signed with disposable test keys, not production keys. For libxml2, Release SHA-256 was `34e96710cb49158dcdc8f47eae32a82f5d3d759330a748d610f627fec23fd882` and InRelease SHA-256 was `41b6f846d67f1e98af356bb2037d6cb40f92e6f5bba0d68c0b12879fadf90d82`. For libarchive, Release SHA-256 was `9fdbc117775c483389d6838b1bae822e0155c1767780f5baf574fb5800b4f9fd` and InRelease SHA-256 was `9e097f1a0f1cf803106a2bfc38b7530c1de3b04ec32e2489fe0f7e45d370dfca`.

## Scanner hardening in this working tree

The advisory scanner now treats an exact reviewed vulnerable baseline as affected, versions at or above a reviewed fixed boundary as clean for that advisory, and unknown versions below those boundaries as unsupported/error rather than clean. This closes a fail-open gap for older or intermediate package revisions. The advisory feed and regression tests were updated. Focused scanner tests passed 10/10; the full Python verification suite passed 61/61 with disposable GPG-agent IPC enabled; hosted platform quality passed; fresh independent reviews found no actionable scanner or retry-recipe findings. The package build recipe preserves the pinned Focal snapshot and package versions, detects partial index updates with Focal-compatible output checks, and applies bounded retries to APT operations.

## Unfulfilled acceptance gates

- Obtain a trusted independent GitHub reviewer and merge PR #1 only after that review and the user's approval.
- Complete GitHub Sponsors enrollment and configure/test the actual tier and entitlement rules.
- Establish least-privilege Cloudflare CI credentials and production signing-key custody, then configure protected release environments. Do not use an account key in GitHub.
- Prepare and approve a DNS routing plan that preserves current services; domain nameservers and records have not been changed.
- Deploy the real website, sponsor portal, signed public and early APT endpoints, private R2 holding, and public GitHub Releases promotion flow.
- Exercise anonymous, valid, invalid, expired and revoked sponsor credentials; test the exact 168-hour boundary, retries, concurrent/missed promotion, failures, tampering, identical-byte promotion, rollback and source downloads against live hosted services.
- Rerun candidate builds and the hardened scanner on hosted packages, verify live client installation and public/sponsor routes, and retain fresh signed release manifests and evidence.

## Next actions

1. Resolve independent GitHub review and Sponsors enrollment; in parallel, prepare exact scoped Cloudflare/signing credential requirements and a DNS preservation plan without changing live DNS.
2. Continue the implementation gates above; do not label candidates released or the platform complete until live acceptance evidence exists.
