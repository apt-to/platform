# Hosted TIFF candidate verification — 30 October 2026

The three TIFF targets passed the hosted, non-publishing build and verification workflow. This covers exact source retrieval, backport application, package build and install, paired installed regression runs, target advisory comparison, consumer checks, and signed APT binary/source retrieval by a clean client. Each workflow reports `repository publication enabled=false`; no package repository publication occurred.

| Target | Run | Platform verifier | Packaging recipe | GetPatched package version | Retained evidence |
| --- | --- | --- | --- | --- | --- |
| Ubuntu Focal amd64 | [41139546571](https://github.com/getpatched/platform/actions/runs/41139546571) | `60b2c2b24a3a1cd12b9f3c02beb113a30f2248d2` | `1424643349b442fefdbda9462d1d55e5461a148a` | `4.1.0+git191117-2ubuntu0.20.04.14+getpatched1` | [`tiff-hosted-verify-41139546571/`](tiff-hosted-verify-41139546571/) |
| Debian Bookworm amd64 | [41138824705](https://github.com/getpatched/platform/actions/runs/41138824705) | `f63301016ae0b6ccc7c68c78f25e631793cbf1e1` | `b305dd0011f01ea949b73ae4cad356c01daa229f` | `4.5.0-6+deb12u4+getpatched1` | [`tiff-hosted-verify-41138824705/`](tiff-hosted-verify-41138824705/) |
| Debian Trixie amd64 | [41138827880](https://github.com/getpatched/platform/actions/runs/41138827880) | `f63301016ae0b6ccc7c68c78f25e631793cbf1e1` | `b305dd0011f01ea949b73ae4cad356c01daa229f` | `4.7.0-3+deb13u3+getpatched1` | [`tiff-hosted-verify-41138827880/`](tiff-hosted-verify-41138827880/) |

For all three targets, the exact installed baseline reproduced CVE-2025-61144 in the target-specific `tiffcrop` stack. The patched run passed with that baseline signature absent and no Valgrind invalid read/write; `tiffinfo` consumed the generated image. The GetPatched package-aware advisory scan found CVE-2025-61144 on the baseline image and none on the patched image. Advisory scope is `libtiff-tools`. Focal additionally builds `libtiff5` to satisfy `libtiff-tools`' versioned runtime dependency.

Trivy 0.70 is a separate signal: its Focal report contains no findings, while its Bookworm and Trixie reports still list CVE-2025-61144 against `libtiff-tools` in both baseline and patched images, with no fixed version in that database record. It also lists the CVE against the separate `libtiff6` package. The candidate gate currently uses the exact package-aware advisory scan and installed regression, so the workflow passes despite this Trivy mismatch. Do not describe the Debian images as clean in Trivy; resolve how patch-level status should be represented to generic scanners before public release. Compact counts, target CVE entries, database identities, and raw report hashes are in each `trivy-summary.json`; GitHub Actions retains the complete raw reports for 30 days.

The CVE-2025-61143 probe remains excluded: its baseline did not reproduce on the exact pinned sources, as documented in [`tiff-hosted-baselines-2026-10-30.md`](tiff-hosted-baselines-2026-10-30.md). This evidence supports only the listed amd64 targets and the named CVE. It does not establish arm64 coverage or a published APT repository release.

`SHA256SUMS` in each retained directory covers the copied reports and provenance. Complete source archives are not duplicated here; their exact upstream and distro archive hashes are recorded in `source-provenance.json`.
