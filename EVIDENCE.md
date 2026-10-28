# GetPatched evidence index

This index points to evidence for the pilot described in [`BUILD_SPEC.md`](../BUILD_SPEC.md). Evidence is scoped to the check it records: candidate builds and local tests do not establish package publication, sponsor access, or a live seven-day promotion. The package candidates remain ineligible for release until the real Ubuntu Pro ESM compatibility gate passes.

## Candidate source, patches, builds, and scans

- [`evidence/source-preflight.json`](evidence/source-preflight.json) records source-package preflight metadata; [`evidence/source-signature-verification.json`](evidence/source-signature-verification.json) records source signature verification.
- [libarchive hosted verification, run 40761904628](https://github.com/getpatched/platform/actions/runs/40761904628) and [libxml2 hosted verification, run 40761907579](https://github.com/getpatched/platform/actions/runs/40761907579) built the Focal amd64 candidates, ran vulnerable-baseline and patched regressions, consumer checks, GetPatched before/after scans, and signed temporary APT installation/source-retrieval smoke checks. Their `+esm` APT candidates were synthetic fixtures. Both reports set `releaseEligible: false` and stopped at the authentic Ubuntu Pro ESM compatibility gate; neither run published binaries. Retained workflow artifacts include the reports, source and binary manifests, checksums, provenance, and build logs.
- Local baseline and scanner evidence is under [`evidence/baseline-initial-libxml2/`](evidence/baseline-initial-libxml2/) and [`evidence/baseline-initial-libarchive/`](evidence/baseline-initial-libarchive/). [`evidence/osv-baseline-libxml2.json`](evidence/osv-baseline-libxml2.json), [`evidence/osv-baseline-libarchive.json`](evidence/osv-baseline-libarchive.json), and [`evidence/scanner-database-reference.json`](evidence/scanner-database-reference.json) preserve vendor scan/database context. Raw vendor scan absence is not proof that a backport is fixed.
- Additional build artifacts and logs are grouped under [`evidence/`](evidence/), including per-package baseline and patched regression reports, binary manifests, build provenance, toolchain records, and version-ordering output. Consult the linked run artifacts above for the latest complete hosted comparison; GitHub workflow artifacts have finite retention.

## Signing, deployment, and live routes

- The protected signing-key self-test [run 40761524119](https://github.com/getpatched/platform/actions/runs/40761524119) built and verified a disposable signed Focal repository. It did not publish production metadata.
- The evidence-index change merged as [PR #41](https://github.com/getpatched/platform/pull/41), commit `c63cd61463ee8306c5ad9c3478304dc8c36a7b39`; required quality check [run 40768702711](https://github.com/getpatched/platform/actions/runs/40768702711) passed. Its automatic Worker/site deployment and public route smoke checks [run 40768844058](https://github.com/getpatched/platform/actions/runs/40768844058) also passed. This docs-only PR changed no runtime behavior.
- At 2026-10-28 21:00 UTC, read-only HTTP checks returned 200 for [`getpatched.dev`](https://getpatched.dev/) and [`/account`](https://getpatched.dev/account), 503 for the [public Focal InRelease](https://repo.getpatched.dev/dists/focal/InRelease), and 401 for the [anonymous early Focal InRelease](https://early.getpatched.dev/dists/focal/InRelease). These verify current site reachability and fail-closed archive routes; there is no live signed archive available to install.
- The protected R2 self-test [run 40767240472](https://github.com/getpatched/platform/actions/runs/40767240472) failed before reaching the Worker: Cloudflare returned HTTP 403 with Ray ID `a51cd476f8c9a807-ARN`. The matching Cloudflare Security Event identified Browser Integrity Check. No diagnostic object was created, and the production R2 read/write/delete round trip remains unverified. No WAF setting was changed.

## Website rendering

- Desktop and mobile catalogue captures are in [`evidence/ui/`](evidence/ui/), including `getpatched-catalogue-desktop.png` and `getpatched-catalogue-mobile-390.png`.
- The responsive catalogue/account UI and its local tests verify presentation and interaction states; they do not prove a live sponsor transaction.

## Acceptance still requiring live evidence

- Authentic Canonical Focal ESM package contents and upgrade/ABI compatibility, using a protected Ubuntu Pro entitlement.
- GitHub Sponsors enrollment, actual eligible tier IDs, and live sponsor entitlement/revocation behavior.
- Successful protected production R2 self-test, then isolated private staging and byte-identical promotion to immutable GitHub Releases.
- Production signed public and sponsor APT metadata, fresh-client anonymous and sponsor-authenticated installation/source retrieval, invalid/expired/revoked access tests, and the real 168-hour promotion schedule.
- Fresh independent review of any subsequent code/configuration changes and completion of the remaining operational/key-custody acceptance gates in [`BUILD_SPEC.md`](../BUILD_SPEC.md).

The current checkpoint and exact next actions are in [`STATUS.md`](STATUS.md); operational steps and recovery guidance are in [`docs/operations-runbook.md`](docs/operations-runbook.md).
