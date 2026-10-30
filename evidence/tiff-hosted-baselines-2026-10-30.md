# Hosted TIFF baseline artifacts — 2026-10-30

These raw workflow artifacts came from the hosted, non-publishing package verification runs using platform branch `debian-snapshot-tls` at `4fcf778b62f1a8a51b57e102341c7042c5bdd081` and packaging recipe commit `fb61911d9d7172591bccbbef8958d9b09956ac25`.

| Target | GitHub Actions run | Retained files |
| --- | --- | --- |
| Ubuntu Focal amd64 | [41134206424](https://github.com/getpatched/platform/actions/runs/41134206424) | `evidence/tiff-hosted-baseline-41134206424/` |
| Debian Bookworm amd64 | [41134218586](https://github.com/getpatched/platform/actions/runs/41134218586) | `evidence/tiff-hosted-baseline-41134218586/` |
| Debian Trixie amd64 | [41134220801](https://github.com/getpatched/platform/actions/runs/41134220801) | `evidence/tiff-hosted-baseline-41134220801/` |

The retained `baseline-regression.json` SHA-256 values are `7f6122333fd5a40482b954501f3251753710b3f4b420c63c434a31f090c78d44` (Focal), `b1919e0d80e2a62fcd5e41909b39b3cdb1551ff0e54616224bda7bbf490c3f7f` (Bookworm), and `3049a34c1c6e8c6e64697f728fff262dfb88c2e7619b908abf8d84a9448caa4b` (Trixie).

Each directory preserves the original baseline regression report, package policy, source provenance, and build-toolchain inventory downloaded from its workflow artifact. The regression reports are failed candidate evidence, not release evidence. All three confirm the installed baseline package version and contain the CVE-2025-61144 Memcheck signature. The exact ordered `tiffcrop` frames are target-specific and are recorded in the packaging repository's `patches/metadata.json`.

CVE-2025-61143 did not reproduce with the original malformed-input fixture in these runs: Valgrind reported zero memory errors. Exact sources are Focal `4.1.0+git191117` (`67e1d045e994adb7144b0cca228d70dd6d520aaf8c75c342064bc0fd601e6e42`), Bookworm `4.5.0` (`638f43d7dea33948d5dee7f39572fc0194d9cc3c74195de9dd26a4388a1f880a`), and Trixie `4.7.0` (`2b8b5c4e79cb2a4651796602e45d6179b7f18bc283feab417b8e881ef7e81862`). Source inspection showed each exits directly on `loadImage` failure before cleanup. The alternate crop-margin probe returned the expected error and `(not opened)` marker on local patched Homebrew 4.7.2, but without an exact vulnerable baseline reproduction or local Valgrind that observation did not establish target applicability. The new exact hosted results and their retained reports are listed below.

## Exact CVE-2025-61143 applicability follow-up

The hosted runs below used platform verifier commit `a499703d3f0313b196cc8ad9a0d3b5aa9c8ae681` and TIFF recipe commit `6cfb968c3fcc5ce245eb3ea98ad53a77a3b60789`, present on each target's declared branch. The `CVE-2025-61143` crop-margin check failed on all three installed baselines because it did not reproduce the invalid read; all Memcheck summaries were zero errors, and none wrote the cleanup completion marker. The independent `CVE-2025-61144` baseline signature passed on all three.

| Target | Run | 61143 baseline | 61144 baseline | Retained report SHA-256 |
| --- | --- | --- | --- | --- |
| Ubuntu Focal amd64 (`4.1.0+git191117-2ubuntu0.20.04.14`) | [41136552298](https://github.com/getpatched/platform/actions/runs/41136552298) | Not reproduced; exit 255, zero Memcheck errors | Reproduced | `caf6fe41c753bbffcef4d2049d04bb8c251d870dacfd7306049748900e77489a` |
| Debian Bookworm amd64 (`4.5.0-6+deb12u4`) | [41136555441](https://github.com/getpatched/platform/actions/runs/41136555441) | Not reproduced; exit 1, zero Memcheck errors | Reproduced | `034b90c51c0e8372222c3819df84668bc2febe37ca68466bc68db2cb5dcb6007` |
| Debian Trixie amd64 (`4.7.0-3+deb13u3`) | [41136558678](https://github.com/getpatched/platform/actions/runs/41136558678) | Not reproduced; exit 1, zero Memcheck errors | Reproduced | `34e13f76f8e72871b2681dde8cfd0b6cf3b15d0a68a213e1a9f4496c4be15e0e` |

Each complete baseline artifact is retained under the matching `evidence/tiff-hosted-baseline-<run>/` directory. These workflow runs stopped before patched builds and scans because the 61143 baseline did not meet its reproduction gate. The 61143 patch is therefore removed from all three active target recipes; this is an applicability exclusion, not a claim of remediation. Run the follow-up candidates with only the reproduced 61144 patch before considering any release.
