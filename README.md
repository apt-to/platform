# AptTo

Public source and reproducible packaging, with a signed APT archive for selected maintained packages.

The pilot targets Ubuntu 20.04 (focal), amd64. The initial candidates are libxml2 (seven-day sponsor binary access) and libarchive (immediate public binaries), subject to verified vulnerability and regression preflight. Source remains public from the start. Public binaries will be served from GitHub Releases; private staging will use Cloudflare R2.

This is an implementation in progress. No package is claimed fixed or supported until its release evidence is published.

## Source preflight

`python3 scripts/inspect-ubuntu.py` records the currently published focal source-package metadata from Launchpad, descriptor hashes, and archive checksums/sizes from the source descriptors. It downloads small descriptors, uses no credentials, and does not mutate the archive. Descriptor signatures are not verified by this helper; archive bytes must be verified against the recorded hashes when imported. Its JSON output is suitable for saving as preflight evidence.

## Candidate baseline scans

On a disposable Linux Docker host, run `python3 scripts/run-baseline.py --package libxml2 --output evidence/baseline-libxml2` (or `libarchive`). The helper installs the exact current public candidate, fails if the archive candidate changes, and retains the unfiltered Trivy report, identified packages, database hashes and reusable `scanner-db/` snapshot. It creates and removes its own baseline image and temporary scan directory. Base/scanner images remain available to the disposable runner until that runner is destroyed.

Reuse the snapshot with `--database-snapshot PATH/TO/scanner-db` and a fresh output directory; this disables database updates. Before/after remediation comparisons must use the same snapshot and scanner, and preserve their raw reports. The manual `Candidate baseline scans` workflow stores JSON and database snapshots as separate immutable run artifacts for 30 days; retain the matching snapshot with final release evidence before that expiry. These artifacts contain public baseline reports and public vulnerability databases, never AptTo binary builds.
