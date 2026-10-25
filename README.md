# AptTo

Public source and reproducible packaging, with a signed APT archive for selected maintained packages.

The pilot targets Ubuntu 20.04 (focal), amd64. The initial candidates are libxml2 (seven-day sponsor binary access) and libarchive (immediate public binaries), subject to verified vulnerability and regression preflight. Source remains public from the start. Public binaries will be served from GitHub Releases; private staging will use Cloudflare R2.

This is an implementation in progress. No package is claimed fixed or supported until its release evidence is published.

## Source preflight

`python3 scripts/inspect-ubuntu.py` records the currently published focal source-package metadata from Launchpad, descriptor hashes, and archive checksums/sizes from the source descriptors. It downloads small descriptors, uses no credentials, and does not mutate the archive. Descriptor signatures are not verified by this helper; archive bytes must be verified against the recorded hashes when imported. Its JSON output is suitable for saving as preflight evidence.

## Candidate baseline scans

On a disposable Linux Docker host, run `python3 scripts/run-baseline.py --package libxml2 --output evidence/baseline-libxml2` (or `libarchive`). The helper installs the exact current public candidate, fails if the archive candidate changes, and retains the unfiltered Trivy report, identified packages, database hashes and reusable `scanner-db/` snapshot. It creates and removes its own baseline image and temporary scan directory. Base/scanner images remain available to the disposable runner until that runner is destroyed.

Reuse the snapshot with `--database-snapshot PATH/TO/scanner-db` and a fresh output directory; this disables database updates. Before/after remediation comparisons must use the same snapshot and scanner, and preserve their raw reports. The manual `Candidate baseline scans` workflow stores JSON and database snapshots as separate immutable run artifacts for 30 days; retain the matching snapshot with final release evidence before that expiry. These artifacts contain public baseline reports and public vulnerability databases, never AptTo binary builds.

The raw baseline scan is expected to fail its recognition check when pinned Trivy does not list the target CVE; it still preserves the full vendor report and package inventory. Do not read an empty Trivy target list as evidence of a fix. The package verification workflow performs paired scans of the exact baseline and locally built patched images with the same pinned Trivy database. It also queries Canonical's Ubuntu Pro focal OSV ecosystem for each exact source version and writes `advisory-comparison.json`: the report keeps raw Trivy JSON and Ubuntu's vendor assessment separate, while the AptTo assessment resolves a target only when the vulnerable installed baseline is reproduced, the exact patched package is identified in the after-scan, and its installed regression passes. Ubuntu may continue to list `+aptto` within its own published affected range; AptTo's assessment is a tested backport, not a change to Canonical's advisory data.

## Development package verification

Clone the public `apt-to/packaging-libxml2` or `apt-to/packaging-libarchive` repository and check out its `aptto/focal` branch. With a clean, committed checkout and a disposable Linux Docker host, run `python3 scripts/build-package.py --source /path/to/packaging-checkout --output build/output`.

The build dependencies come from the official Ubuntu archive snapshot recorded in `packages.json`. The base and trust-bundle images are pinned by digest. The helper records the resulting builder image ID, installed toolchain and Debian `.buildinfo`; native package compilation/testing runs with networking disabled. It requires a reproduced installed-baseline regression before building, then installs its own outputs for patched regressions, consumer checks and Debian version comparisons. It assembles the actual `.deb`, `.dsc` and source tarballs into a temporary signed focal archive using an ephemeral test key, then asks a clean pinned focal client to verify `InRelease`/`Release.gpg`, install the exact binary packages, and fetch the source package through `deb-src`. The archive and key are discarded; no test binary is published.

The manual `Package build and installed regressions` workflow performs the paired scanner/advisory verification and signed APT client smoke test as well. Its JSON artifacts include both raw Trivy reports, exact OSV requests/responses, scan identity/database sidecars, the advisory comparison and temporary signed-repository smoke summary. The selected, hash-verified `.deb` files are retained only under the runner's ignored `build/output/binary/` directory for a future protected staging step; the current workflow's public artifact paths exclude that directory. Development backports are not releases: production signing, storage, access and promotion gates must still pass.

## Public catalogue preview

`site/` contains the public package catalogue UI and its policy-backed data. Preview it locally with `python3 -m http.server 8765 --directory site`, then open `http://127.0.0.1:8765/`. The page reports development checks as passed while keeping release verification and production publication explicitly open; it must not expose install commands or binary links until the signed production repository is available. The `Platform quality` workflow checks that catalogue versions, CVEs, target and access delays stay aligned with `packages.json`.

The catalogue source is ready for deployment, but it is not live on `apt.to`. Cloudflare account and zone identity still need to be verified before deployment or DNS changes.

## Release state worker (integration in progress)

`worker/` contains the current R2-backed release-state adapter and a 15-minute Cloudflare Cron Trigger. It uses conditional R2 writes for compare-and-swap state updates, checks a successful package-verification Actions run, binds that run to the exact signed tag and source commit on `aptto/focal`, uploads staged immediate-public assets to draft GitHub Releases, reads them back to check SHA-256, and publishes only when GitHub immutable releases are enabled. The reconciler audits already-published release bytes against the recorded hashes. Configure the R2 bucket binding and Worker secrets `GITHUB_TOKEN` (GitHub App permissions: Actions read on `apt-to/platform`; Contents read/write and Administration read on the two packaging repositories) and `RELEASE_ADMIN_TOKEN` before deployment. Do not put either value in this repository or a public workflow log.

The Worker now has an authenticated, bounded R2 staging upload endpoint that accepts only manifest-listed assets, derives create-only keys, streams bytes to R2 with SHA-256 validation, and supports integrity-checked retries. It also contains code for signed cancellation-webhook intake, scheduled GitHub Sponsors reconciliation against an explicit eligible-tier allowlist, GitHub OAuth with state and PKCE, hashed seven-day sessions, revocable per-device APT credentials, sponsor-only asset serving, and an admin-gated transition that starts the exact 168-hour clock after every private asset passes R2 checksum/metadata readback. These paths have local unit coverage only: no sponsor listing, credentials, webhook, R2 bucket, or Worker deployment is configured, and the implementation is not connected to a protected build workflow. Signed APT metadata/index publication, public repository routing, full sponsorship paid-through semantics, hosted R2/concurrency tests, and production integration remain open. Do not treat local unit tests as production release evidence.

See [`docs/operations-cost.md`](docs/operations-cost.md) for the current usage-based hosting estimate and pricing references. It is a planning model, not approval to enable paid Cloudflare Workers service.
