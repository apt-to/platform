# Ubuntu Jammy libgit2 hosted verification, run 41165518728

- Workflow: [Package build and installed regressions](https://github.com/getpatched/platform/actions/runs/41165518728)
- Platform source: `7894f7740b094819276a0fa232a1fb30f0a17f0f` on `codex/libgit2-jammy-verified-status`
- Package recipe: `db0dccf3a13fd004c502f18be943c665b9173a8f`
- Target: Ubuntu 22.04 Jammy, amd64
- Baseline: `1.1.0+dfsg.1-4.1ubuntu0.1`
- Candidate: `1.1.0+dfsg.1-4.1ubuntu0.1+getpatched1`
- Workflow conclusion: success; publication disabled.

The exact installed baseline reproduced all three regressions: the pack indexer accepted a declared 100 MiB object, submodule processing created a directory outside the repository worktree, and HTTP redirect handling sent a fixture credential to another host. The candidate rejected the oversized object at the configured 42 MiB limit, rejected the escaping submodule path, and sent no `Authorization` header to the redirected host.

The package-aware advisory scan reported six findings across `libgit2-1.1` and `libgit2-dev` on the baseline and zero on the candidate. A clean Jammy client verified the temporary `InRelease`, `Release.gpg`, and SHA-256 by-hash path, installed both candidate binary packages, and fetched the source package. The temporary repository and signing key were discarded; this is not a public repository release.

**Scanner caveat:** Trivy 0.70.0 still reports all three CVE IDs on both candidate binary packages after the patch (six candidate findings total); its records have no fixed version. The raw reports and database metadata are retained in `verification-artifacts.zip`. Do not describe this candidate as Trivy-clean. The package-aware result is separate evidence, and the raw Trivy findings remain visible.

The run's package policy was still `unverified-development-candidate`, so its report has `verificationChecksPassed: true`, `candidateVerified: false`, and `releaseEligible: false`. No candidate policy promotion or package publication is represented by this run report. GitHub artifact IDs are source `13028539448` (SHA-256 `27048f8d44fa6c48d1007ff800008cf908997ca0013d8518fd846a8b1fb46da5`) and verification `13028524505` (SHA-256 `41cdb5e711510ad202bbfabb28d00ecea76a61340f9d09ea64850af474f4dfbb`); their GitHub retention expires 30 November 2026. Local archives and source files have SHA-256 manifests alongside them.
