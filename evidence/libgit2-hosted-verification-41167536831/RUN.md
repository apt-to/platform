# libgit2 Ubuntu Jammy policy-aligned verification

- Hosted run: [41167536831](https://github.com/getpatched/platform/actions/runs/41167536831)
- Platform commit: `f4fd7c84bc7854921721a4ecd54a69b3ddbc4984`
- Public packaging recipe commit: `db0dccf3a13fd004c502f18be943c665b9173a8f`
- Target: Ubuntu 22.04 Jammy, amd64
- Base version: `1.1.0+dfsg.1-4.1ubuntu0.1`
- Candidate version: `1.1.0+dfsg.1-4.1ubuntu0.1+getpatched1`

The baseline reproduced the three target CVEs in installed packages. The candidate passed all three installed regressions. The package-aware scan found six baseline findings and zero candidate findings. A disposable Jammy client verified the temporary signed `InRelease`, `Release.gpg`, by-hash SHA-256 metadata, both binary packages, and source retrieval.

The policy-aligned report records `candidateVerified: true` and `verificationChecksPassed: true`. `releaseEligible` remains false because production repository publication is disabled. No package binaries or production metadata were published.

Trivy 0.70.0 still reports all three target CVEs on both candidate binary packages (six findings) and supplies no fixed version. The candidate is not Trivy-clean; the package-aware scan and installed regressions are separate evidence.

The original verification artifact is retained as `verification-artifacts.zip`; its GitHub artifact ID is [13030200521](https://github.com/getpatched/platform/actions/runs/41167536831/artifacts/13030200521), API SHA-256 `ece28f1c1281b721eb21fd25beb98edbdcca55de46a8e9774b8d0a5ed8955549`, and expiry 30 November 2026. The source artifact is [13030125644](https://github.com/getpatched/platform/actions/runs/41167536831/artifacts/13030125644), API SHA-256 `8e5139c94041e3dc58d803bf04874460d6c96aee1cc6407a305b3264ba57c4ab`, with the same expiry. The source files and their manifest are retained in the sibling `libgit2-hosted-source-41167536831` directory.
