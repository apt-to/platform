# Ubuntu Jammy libgit2 hosted verification, run 41163772812

- Workflow: [Package build and installed regressions](https://github.com/getpatched/platform/actions/runs/41163772812)
- Source commit: `a22ac6f462c8e425f5953eb1f6f8f9d5a20f5e35`
- Target: Ubuntu 22.04 Jammy, amd64
- Candidate: `libgit2` `1.1.0+dfsg.1-4.1ubuntu0.1+getpatched1`
- Outcome: build and paired installed regressions passed; the run stopped at the advisory scan gate.

The installed Jammy baseline reproduced the selected CVE-2026-53584 path traversal, CVE-2026-53585 oversized allocation, and CVE-2026-53586 redirected-credential disclosure. The patched installed package passed the corresponding regression checks.

The scan gate failed because the canonical GetPatched advisory feed did not match the package policy on this source commit. The retained `package-policy.json` is the pre-run policy snapshot and says `development-verified-production-release-pending`; that status was premature and has since been downgraded to `unverified-development-candidate`. Preserve the artifact unchanged as run evidence, but do not treat its status field as approval. The current package policy and canonical feed remain unverified until a complete hosted run passes. This run has no completed post-build scan, signed APT client verification, or release eligibility result and must not be counted as a completed candidate verification. No package was published.

The retained `baseline-regression-verified-by-scanner.json` and `patched-regression-verified-by-scanner.json` filenames are workflow artifact names only. In this run they contain regression reports; they do not establish that the scanner step completed successfully.
