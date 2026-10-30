# libgit2 Ubuntu Focal source audit — 30 Oct 2026

## Pinned source

Ubuntu Focal source version `0.28.4+dfsg.1-2ubuntu0.1` was fetched from the public Ubuntu `universe/libg/libgit2` archive. The exact descriptor and archives match the checksums in the signed Ubuntu source-index record `evidence/new-batch-source-index-verification-20261030.json`:

| File | Bytes | SHA-256 |
|---|---:|---|
| `libgit2_0.28.4+dfsg.1-2ubuntu0.1.dsc` | 2,344 | `259c89491dbd17407b738316447c7afb0b7858478d39db3b194c92c40fad47a4` |
| `libgit2_0.28.4+dfsg.1.orig.tar.xz` | 2,798,048 | `758517d1ff5124e732e999e2e50a501cb0d3c8bdcf64d1cec404ced6235c0bb7` |
| `libgit2_0.28.4+dfsg.1-2ubuntu0.1.debian.tar.xz` | 19,016 | `8a3d388a52655ac0eb1437097b9cac150bc5052ac4fa44d98bb6d4d21c2e773d` |

The extracted source files match these hashes:

| File | SHA-256 |
|---|---|
| `src/submodule.c` | `ff67dcbec4e80a027427b3518a8e4d2e39060c006b9419b876ee7c6046708011` |
| `src/delta.c` | `0496cb9bed8143c043145e30ef7702441d1fa919a48edbdc203f50816e33ce94` |
| `src/transports/http.c` | `c9f38f9ace45be366df4716ab6209349574f7735666ae49a2c4b5b2b020066ce` |
| `src/transports/smart_pkt.c` | `85ae97f585e7ab7c9bb723d6838e64f8e33878f703541a3e335f16445f6da64d` |

## Code-path findings

- **CVE-2026-53584:** `load_submodule_names` validates the submodule name at `src/submodule.c:225`, then accepts the configured path (`entry->value`) at `:233` without applying the same traversal check. This matches the upstream path-traversal fix area. The eventual recipe must test a malicious `.gitmodules` path against the Focal build and show that no filesystem entry is created outside the repository.
- **CVE-2026-53585:** `git_delta_apply` parses the declared result size and reaches `GIT_ERROR_CHECK_ALLOC_ADD(&alloc_sz, res_sz, 1)` at `src/delta.c:564` without a package-level maximum-object-size check. The upstream fix adds a configurable bounded maximum. The recipe must demonstrate that an undersized pack with an oversized declared delta cannot trigger unbounded allocation on the baseline and is rejected by the patched build.
- **CVE-2026-53586:** after a redirect updates `t->server.url`, the 401 handler passes `t->owner->url` to the credentials callback at `src/transports/http.c:494`. That keeps the original host as the credential decision context. The fix must bind the callback to the current redirected host; a local HTTP regression should verify that credentials are not sent to an offsite redirect target.
- **CVE-2026-53587:** Focal's `src/transports/smart_pkt.c` hash is recorded above. The audit of that exact pinned file found no `set_data` object-format capability parser or `format_str` path described by the advisory. Canonical's [CVE-2026-53587 record](https://ubuntu.com/security/CVE-2026-53587), last updated 2 September 2026, explicitly lists Ubuntu 20.04 Focal as **Not affected**. This official target status corroborates the source-file audit; do not list 53587 as a Focal target or patch claim.

The source audit supports selecting the three requested CVEs for a Focal development candidate. It does not prove a patch, package build, installed regression, scan, or APT release. No libgit2 binary has been built or published.

## Upstream patch provenance and local draft review

The official libgit2 `v1.8.5...v1.8.6` comparison contains the following security commits, confirmed through the public upstream GitHub API on 30 October 2026:

| CVE | Upstream commit | Subject |
|---|---|---|
| CVE-2026-53584 | `419637d3587396f5d139d6d88480eab3cd81e7a1` | `submodule: check paths for escaping` |
| CVE-2026-53585 | `c1896f06df22cc0ca5658df3a8f6cd7ede4cd6ae` | `settings: introduce GIT_OPT_SET_PACK_MAX_OBJECT_SIZE` |
| CVE-2026-53586 | `c1507abc44647b3acd832a33a5b1c8c9f5ba8821` | `http: give auth callback current host` |

The experimental diff in `/private/tmp/getpatched-libgit2-20261030/libgit2-cves-53584-53585-53586.patch` is not release-ready. Its CVE-2026-53584 hunk passes the configured path to `git_submodule_name_is_valid`. Although that function has a name-oriented API, inspection of the pinned Focal implementation shows it normalizes backslashes and calls `git_path_isvalid` with filesystem-default rejection flags, including traversal rejection. Therefore the previous statement that this call cannot reject `../` traversal was incorrect. The upstream commit uses a dedicated path validator, permits the appropriate path components, and applies checks across more configuration/loading paths; the local draft does not include the upstream regression additions. Its behavior must be tested against the exact baseline and candidate before crediting the fix. The CVE-2026-53585 and CVE-2026-53586 changes likewise need target-version-appropriate regression tests. No tested libgit2 patch or package is currently available.
