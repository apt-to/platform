# Follow-up package candidates — 30 October 2026

These are research candidates for future work, not supported GetPatched targets or release claims. The first targets to assess are public Ubuntu 20.04 (Focal) source packages; never use Ubuntu Pro/ESM source or binaries. Before selection, pin and verify the signed public source index, reproduce each issue on the exact installed baseline package, backport only the necessary upstream fix, and prove the patched package passes the same regression plus package tests and scans.

## Recommended shortlist

| Rank | Package / proposed target | Issue and patch anchor | Why it is promising | Main risk / gate |
|---|---|---|---|---|
| 1 | `libsoup2.4` / Ubuntu Focal amd64 | CVE-2026-102555, upstream `e4f0322`; also assess CVE-2026-1801 (`MR 506`), CVE-2026-1539 (`98c1285`) and CVE-2026-1467 as one target patch set | Current Ubuntu tracker marks Focal vulnerable for 102555; the fix is a bounded data-URI parser bug with a focused regression. The three earlier issues are medium priority and ESM-fixed on Focal. | Confirm exact Focal source contains all affected functions and that the fixes apply cleanly. Test with the upstream parser tests and crafted data-URI/proxy/redirect regressions. CVE-2026-102555 severity/applicability must be checked against Debian and Ubuntu before scope is finalized. |
| 2 | `gnutls28` / Ubuntu Focal amd64 | CVE-2025-32990 upstream `408bed40`; CVE-2025-32988 upstream `6088297`; separately assess CVE-2025-6395 | Two medium-priority fixes have explicit upstream commits and Focal ESM fixes; certtool's template parser has a practical standalone regression path. | GnuTLS is a widely used ABI library. Keep ABI and dependent packages unchanged; run upstream tests and ASAN regressions, and prove the package doesn't pull in ESM inputs. |
| 3 | `cups` / Ubuntu Focal amd64 | CVE-2025-58060 and CVE-2025-58364; upstream CUPS `v2.4.13` release contains both fixes | CVE-2025-58060 is rated high (CVSS 8.0) by Ubuntu; the upstream advisory describes a concrete authentication-bypass request. Both fixes are included in one upstream release. | Service-facing and multi-binary package with configuration interactions. Use an isolated test instance for authentication regression; inspect the release diff and Debian patch stack rather than importing the full upstream release. |

## Why these are only candidates

- Ubuntu's current tracker shows Focal fixes for all three packages as Ubuntu Pro/ESM versions, which makes the public Focal baselines useful candidates for GetPatched's public-source-only rule. That status does not prove the public `.dsc`, patches, exact binary, or regression behavior.
- Debian may already have fixed some issues or package a different upstream version. Add a Debian target only after checking its current signed source index and Debian Security Tracker status for each CVE.
- Do not copy Ubuntu's `+esm` package version, source archive, or build dependencies into a public recipe. Patch the latest public free source version and use a GetPatched Debian revision.
- Do not claim a CVE fixed because the scanner stops reporting it. Require exact installed baseline reproduction, patched regression, upstream/package test results, and a package-aware scan with a pinned database.

## Primary references

- Ubuntu [CVE-2026-102555](https://ubuntu.com/security/CVE-2026-102555) and its upstream fix [`e4f0322`](https://gitlab.gnome.org/GNOME/libsoup/-/commit/e4f0322); Ubuntu [CVE-2026-1801](https://ubuntu.com/security/CVE-2026-1801), [CVE-2026-1539](https://ubuntu.com/security/CVE-2026-1539), and [USN-8780-1](https://ubuntu.com/security/notices/USN-8780-1).
- Ubuntu [CVE-2025-32990](https://ubuntu.com/security/CVE-2025-32990), [CVE-2025-32988](https://ubuntu.com/security/CVE-2025-32988), and [USN-7742-1](https://ubuntu.com/security/notices/USN-7742-1); Debian [CVE-2025-32990](https://security-tracker.debian.org/tracker/CVE-2025-32990).
- Ubuntu [CVE-2025-58060](https://ubuntu.com/security/CVE-2025-58060), [CVE-2025-58364](https://ubuntu.com/security/CVE-2025-58364), and [USN-7745-1](https://ubuntu.com/security/notices/USN-7745-1); upstream [CUPS v2.4.13](https://github.com/OpenPrinting/cups/releases/tag/v2.4.13).

## Next step

Start the next preflight with libsoup2.4: fetch and verify the public Focal source pin, inspect `e4f0322` and related issue fixes against that exact source, then produce baseline regressions before creating a packaging repository. Treat Debian as a separate target rather than reusing Ubuntu's recipe.
