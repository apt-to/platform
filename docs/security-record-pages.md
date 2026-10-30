# Vulnerability and patch records

The public site serves one page for each listed vulnerability and patch:

| Record | HTML | JSON | Badge |
| --- | --- | --- | --- |
| Vulnerability | `/vulnerabilities/{slug}` | `/vulnerabilities/{slug}.json` | `/vulnerabilities/{slug}/badge.svg` |
| Patch | `/patches/{slug}` | `/patches/{slug}.json` | `/patches/{slug}/badge.svg` |

Vulnerability slugs are lowercase CVE identifiers. Patch slugs come from the patch metadata `id` and must be globally unique across packages. Package catalogue entries list vulnerability summaries and patch metadata in `site/catalogue.json`; the Worker uses that catalogue to render both formats.

Vulnerability JSON includes the CVE identifier, summary, advisory URL, patch state, related patch pages, and affected target versions. Patch JSON includes its id, kind, title, description, SHA-256, patch file URL, upstream reference, regression expectations, CVEs, and target versions. Each target identifies its source package and reports its security-patch coverage. The response shape is described by `schemas/security-record.schema.json`.

`patched: true` and a visible “patched” badge mean a security patch covers every listed target, each target is marked `development-verified-production-release-pending`, and each has a verification link to a GetPatched Platform GitHub Actions run. The Worker does not trust the catalogue's `patched` boolean by itself. Partial coverage is reported per target and uses the `partial-coverage` status; its badge remains empty. Patch badges are calculated from that exact patch's source package, slug, and target; a fix for the same CVE in another package or target cannot activate the badge. Duplicate patch slugs are treated as ambiguous and cannot produce links or badges. A badge does not mean a production binary has been released. The HTML and JSON records include each target's patch status, release status, and verification link. Build-compatibility patches have no CVE association and do not receive a security badge.

A known vulnerability with `patched: false` still has a JSON and HTML page; `status` is `partial-coverage` when some targets are patched, `patch-unverified` when patch metadata exists but no target is verified, and `no-patch` when no patch metadata exists. Its badge is an empty SVG with no `width` or `height`. Unknown badge slugs also return that empty SVG so it can be embedded directly. Public JSON responses allow cross-origin reads for project integrations. Unknown `.json` URLs return status `404`, `application/json`, and `{"error":"not_found"}`. Other unknown record paths return an HTML 404 page.

When adding a catalogue vulnerability, add a unique lowercase slug, its summary and advisory URL, an explicit `patched` boolean, and the related patch slugs. Add each patch's stable slug, metadata, source link, regression expectations, and affected target. The catalogue page links CVEs and patches to these routes.
