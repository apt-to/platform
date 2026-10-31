# Ubuntu Focal libpng1.6 baseline verification, run 41166668036

- Workflow: [Package build and installed regressions](https://github.com/getpatched/platform/actions/runs/41166668036)
- Platform commit: `965cb3458b8a7086c0e31269a0143e88b3bd1694`
- Package recipe commit: `59bc42705b209884df5c335580c36c60c26f313b`
- Target: Ubuntu 20.04 Focal, amd64
- Installed baseline: `1.6.37-2`
- Outcome: baseline gate failed; no candidate build, patched checks, package scan, signed client, or release-eligibility result was produced.

The Python 3.8 classifier failure from run 41166307949 is resolved. This run correctly classified the negative-stride baseline as reproducing CVE-2026-22801: Valgrind reported two invalid reads in `png_image_write_to_file` from the installed libpng library. The padded-stride CVE-2026-22695 baseline check had zero Memcheck errors.

The pinned RGB16 Adam7 input for CVE-2025-65018 still did not reproduce on the exact installed baseline: it returned `result=within-output-buffer`, and Memcheck reported zero errors. The upstream [GHSA advisory](https://github.com/pnggroup/libpng/security/advisories/GHSA-7wv6-48j4-hj3g) describes the affected range and a 32×32 16-bit interlaced case, while upstream [issue #755](https://github.com/pnggroup/libpng/issues/755) documents that the published ImageMagick command can create a 1-bit palette image and that another RGB16 Adam7 image did not reproduce for the reporter. We have no exact CVE-2025-65018 baseline reproducer yet, so this run proves neither that Focal's installed build reproduces that issue nor that the GetPatched candidate fixes it.

The package remains `unverified-development-candidate`. No package was published. The verification artifact is GitHub artifact [13029590424](https://github.com/getpatched/platform/actions/runs/41166668036/artifacts/13029590424), archive SHA-256 `cce0b1a45eb0b8bc749123360db40aaa38c71a93db78b8565800b420d01819c1`; GitHub retention expires 30 November 2026. The baseline report, toolchain, package policy, and source provenance are retained here with a local SHA-256 manifest.
