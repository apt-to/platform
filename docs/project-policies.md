# Project policies

This document describes how to contribute to GetPatched, report security issues, handle archive signing keys, and understand the project's support scope. Package-specific licence notices remain authoritative for each source and binary package.

## Contributing

Use the public repositories under [`getpatched`](https://github.com/getpatched). For platform changes, open a pull request against `getpatched/platform`; package changes belong in the corresponding packaging repository. Keep changes focused and include tests or a clear reason tests do not apply. Never put credentials, private signing material, sponsor binaries, or production data in source, commits, CI artifacts, or logs.

Package contributions must preserve upstream and distribution copyright/licence notices, document patches with DEP-3 headers, and include provenance and regression evidence. Do not claim a vulnerability is fixed based only on a version string or an empty scanner result. Releases require maintainer review and the protected verification and signing workflows.

## Security reporting

Please report suspected vulnerabilities privately through GitHub's **Report a vulnerability** feature on the affected `getpatched` repository. As of 28 October 2026, this feature is enabled on `getpatched/platform`, `getpatched/packaging-libxml2`, and `getpatched/packaging-libarchive`; settings are per repository and should be rechecked before use. A separate private contact route has not been published. If private reporting is unavailable on a repository, do not post vulnerability details in a public issue; the maintainers must publish a verified private contact route before inviting confidential reports through another channel. Include the affected repository/package and version, impact, reproduction steps, and any proposed fix. Do not include secrets or real sponsor credentials in a report.

The maintainers will acknowledge reports as capacity permits, coordinate a fix and disclosure timeline with the reporter, and publish a public advisory after a fix or coordinated disclosure decision. GetPatched is a small maintenance project and does not promise a response-time SLA. Reports about upstream packages should also be sent to the relevant upstream security team when appropriate.

## Archive signing keys

The APT archive signing key is separate from package build and publication credentials. Keep its private material only in the protected signing environment; never store it in GitHub source, build artifacts, R2, runner caches, or logs. Signing workflows must accept only bounded, hash-verified metadata and must not parse or build package sources while the private key is available.

The two-year RSA-4096 archive key is held in the protected `getpatched-signing` environment. Its public key and primary fingerprint are published at [`/keys/getpatched-archive-key.asc`](https://getpatched.dev/keys/getpatched-archive-key.asc) and [`/keys/getpatched-archive-key-fingerprint.txt`](https://getpatched.dev/keys/getpatched-archive-key-fingerprint.txt); verify the fingerprint over an independent channel before trusting it. No production snapshot has been signed or published, and no key-rotation drill is claimed. If compromise is suspected, stop signing and publication, revoke or replace the key, publish the revocation/new key instructions, and document affected metadata.

## Support scope

The only currently verified target is Ubuntu 20.04 LTS (focal), amd64, using the latest publicly available (non-ESM) Focal source versions pinned in the catalogue. Ubuntu 20.04 is outside standard support. Ubuntu Pro/ESM and upgrades from GetPatched packages to Canonical ESM packages are outside this pilot and are not tested or supported. Package recipes and platform policy are target-scoped by distribution, release, and architecture so Debian, other Ubuntu releases, and arm64 can be added independently. A target is not supported or publishable until its exact pinned source, builder, scans, regressions, APT client path, and repository Worker/snapshot routing have been tested and the platform policy explicitly enables its repository.

Each release is supported only to the extent documented by its package metadata, source, regression evidence, and publication status. Selected package targets may be sponsor-first for seven days; every active individual GitHub Sponsors tier qualifies, with no tier allowlist or minimum amount. A one-time sponsorship qualifies only while GitHub reports it active. Access ends when GitHub reports the sponsorship inactive. A signed end-of-billing-cycle cancellation webhook immediately invalidates cached early-channel entitlements; active-only reconciliation also runs every 15 minutes, and expired sponsor snapshots fail closed. Organization sponsorships are not yet mapped to an authorized GitHub user and therefore do not grant access; membership alone never grants access. A package shown as a candidate or development build is not a production security fix or support commitment.

## Licensing

GetPatched-authored platform code, schemas, recipes, patches, tests, and documentation are MIT-licensed from day one. Public source remains available, so users may independently build and redistribute under MIT and the applicable upstream and distribution licences. The MIT grant does not replace third-party rights or notices in source and compiled packages. Before downloading official sponsor-first binaries during the early period, a sponsor accepts the early-binary terms: private and commercial use are allowed, redistribution of the official early binaries is prohibited, and access ends when sponsorship becomes inactive. Upon public promotion, the early-channel restriction ends for that target's official binaries. Each package still retains all applicable upstream and distribution licences and notices.
