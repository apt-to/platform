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

The build dependencies come from the official Ubuntu archive snapshot recorded in `packages.json`. The base and trust-bundle images are pinned by digest. The helper records the resulting builder image ID, installed toolchain and Debian `.buildinfo`; native package compilation/testing runs with networking disabled. It requires a reproduced installed-baseline regression before building, then installs its own outputs for patched regressions, consumer checks and Debian version comparisons. Source packages and verification reports are retained; binary outputs remain in the disposable container and are not published by this workflow.

The manual `Package build and installed regressions` workflow performs the paired scanner/advisory verification as well. Its JSON artifacts include both raw Trivy reports, exact OSV requests/responses, scan identity/database sidecars, and the comparison. Development backports are not releases: signed APT, storage, access and promotion gates must still pass.
