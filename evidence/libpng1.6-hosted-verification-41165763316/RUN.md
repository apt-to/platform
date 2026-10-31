# Ubuntu Focal libpng1.6 hosted verification, run 41165763316

- Workflow: [Package build and installed regressions](https://github.com/getpatched/platform/actions/runs/41165763316)
- Platform commit: `cb8b3547a65a95f8ff40f18368c23ff9c13dafc6`
- Package recipe commit: `59bc42705b209884df5c335580c36c60c26f313b`
- Target: Ubuntu 20.04 Focal, amd64
- Candidate: `libpng1.6` `1.6.37-2+getpatched1`
- Outcome: failed the installed-baseline gate; no patched phase or package scan completed.

The exact installed Focal baseline returned `result=within-output-buffer` for the pinned 32×32 RGB16 Adam7 input and Valgrind reported zero errors. This does not reproduce CVE-2025-65018, so this run provides no evidence that the target is affected or that the patch fixes it.

The CVE-2026-22801 baseline log contains two `Invalid read of size 2` reports in `png_image_write_to_file` from the installed libpng library. The runner initially marked that check failed because it expected the Valgrind log filename to match the executable, while this baseline invocation names the file by CVE. The classifier correction merged in PR [#93](https://github.com/getpatched/platform/pull/93), and follow-up run [41166668036](https://github.com/getpatched/platform/actions/runs/41166668036) correctly recognized this baseline reproduction. This earlier run itself remains unaccepted. The CVE-2026-22695 padded-stride baseline check completed with zero Memcheck errors.

No patched package regressions, post-build scans, signed APT client checks, or release-eligibility result were produced. The candidate remains `unverified-development-candidate`; no package was published.
