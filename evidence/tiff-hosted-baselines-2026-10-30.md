# Hosted TIFF baseline artifacts — 2026-10-30

These raw workflow artifacts came from the hosted, non-publishing package verification runs using platform branch `debian-snapshot-tls` at `4fcf778b62f1a8a51b57e102341c7042c5bdd081` and packaging recipe commit `fb61911d9d7172591bccbbef8958d9b09956ac25`.

| Target | GitHub Actions run | Retained files |
| --- | --- | --- |
| Ubuntu Focal amd64 | [41134206424](https://github.com/getpatched/platform/actions/runs/41134206424) | `evidence/tiff-hosted-baseline-41134206424/` |
| Debian Bookworm amd64 | [41134218586](https://github.com/getpatched/platform/actions/runs/41134218586) | `evidence/tiff-hosted-baseline-41134218586/` |
| Debian Trixie amd64 | [41134220801](https://github.com/getpatched/platform/actions/runs/41134220801) | `evidence/tiff-hosted-baseline-41134220801/` |

The retained `baseline-regression.json` SHA-256 values are `7f6122333fd5a40482b954501f3251753710b3f4b420c63c434a31f090c78d44` (Focal), `b1919e0d80e2a62fcd5e41909b39b3cdb1551ff0e54616224bda7bbf490c3f7f` (Bookworm), and `3049a34c1c6e8c6e64697f728fff262dfb88c2e7619b908abf8d84a9448caa4b` (Trixie).

Each directory preserves the original baseline regression report, package policy, source provenance, and build-toolchain inventory downloaded from its workflow artifact. The regression reports are failed candidate evidence, not release evidence. All three confirm the installed baseline package version and contain the CVE-2025-61144 Memcheck signature. The exact ordered `tiffcrop` frames are target-specific and are recorded in the packaging repository's `patches/metadata.json`.

CVE-2025-61143 did not reproduce in these runs: Valgrind reported zero memory errors on all three targets. The three targets remain ineligible for release until the exact upstream reproducer is established (or the unsupported CVE claim is removed from target policy) and the patched installed regressions pass.
