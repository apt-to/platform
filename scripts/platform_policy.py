"""Resolve target-specific build, scan, and release policy."""
import base64
import re
from urllib.parse import urlsplit


SUPPORTED_DISTRIBUTIONS = {"Ubuntu", "Debian"}
SUPPORTED_ARCHITECTURES = {"amd64", "arm64"}
TARGET_ID_RE = re.compile(r"^[a-z0-9]+-[a-z0-9][a-z0-9.-]*-(amd64|arm64)$")
SOURCE_BRANCH_RE = re.compile(r"^getpatched/[a-z0-9][a-z0-9._/-]*$")


def target_profile(config, target_id):
    if config.get("schemaVersion") != 2:
        raise ValueError("platform policy must use schemaVersion 2")
    if not isinstance(target_id, str) or not TARGET_ID_RE.fullmatch(target_id):
        raise ValueError("target id must include a distribution, codename, and supported architecture")
    profiles = config.get("targets")
    profile = profiles.get(target_id) if isinstance(profiles, dict) else None
    if not isinstance(profile, dict):
        raise ValueError(f"target is not configured by platform policy: {target_id}")
    distribution = profile.get("distribution")
    codename = profile.get("codename")
    architecture = profile.get("architecture")
    if distribution not in SUPPORTED_DISTRIBUTIONS or architecture not in SUPPORTED_ARCHITECTURES:
        raise ValueError(f"unsupported target distribution or architecture: {target_id}")
    if target_id != f"{distribution.lower()}-{codename}-{architecture}":
        raise ValueError("target id must match its distribution, codename, and architecture")
    if not isinstance(profile.get("releaseVersion"), str) or not profile["releaseVersion"]:
        raise ValueError("target must declare its distribution release version")
    source_branch = profile.get("sourceBranch")
    source_branch_parts = source_branch.split("/") if isinstance(source_branch, str) else []
    if (not isinstance(source_branch, str) or not SOURCE_BRANCH_RE.fullmatch(source_branch)
            or len(source_branch_parts) < 2
            or any(part in ("", ".", "..") or part.endswith(".lock") for part in source_branch_parts)):
        raise ValueError("target must declare a valid getpatched/* source branch")
    if (not isinstance(profile.get("advisoryEcosystem"), str) or not profile["advisoryEcosystem"]
            or not isinstance(profile.get("packageEcosystem"), str) or not profile["packageEcosystem"]):
        raise ValueError("target must declare its package and advisory ecosystems")
    base_image = profile.get("baseImage")
    if not isinstance(base_image, str) or not re.search(r"@sha256:[0-9a-f]{64}$", base_image):
        raise ValueError("target base image must be pinned by a SHA-256 digest")
    build = profile.get("build")
    if not isinstance(build, dict) or build.get("containerPlatform") != f"linux/{architecture}":
        raise ValueError("target container platform must match its package architecture")
    if not isinstance(build.get("runner"), str) or not build["runner"]:
        raise ValueError("target must declare a compatible GitHub Actions runner")
    sources = profile.get("aptSources")
    if not isinstance(sources, list) or not sources:
        raise ValueError("target must pin at least one APT snapshot source")
    snapshot = profile.get("archiveSnapshot")
    if not isinstance(snapshot, str) or not re.fullmatch(r"[0-9]{8}T[0-9]{6}Z", snapshot):
        raise ValueError("target must pin an immutable archive snapshot timestamp")
    allowed_hosts = {
        "Ubuntu": {"snapshot.ubuntu.com"},
        "Debian": {"snapshot.debian.org"},
    }[distribution]
    for source in sources:
        parsed = urlsplit(source.get("uri", "")) if isinstance(source, dict) else None
        if (not isinstance(source, dict)
                or source.get("type") not in ("deb", "deb-src", "both")
                or parsed.scheme != "https"
                or parsed.hostname not in allowed_hosts
                or parsed.username or parsed.password
                or snapshot not in parsed.path
                or not isinstance(source.get("suites"), list) or not source["suites"]
                or not isinstance(source.get("components"), list) or not source["components"]):
            raise ValueError("target APT sources must use pinned HTTPS snapshots for the selected distribution")
    repository = profile.get("repository")
    if not isinstance(repository, dict) or not isinstance(repository.get("enabled"), bool):
        raise ValueError("target must declare whether repository publication supports it")
    if repository.get("enabled") and (
        repository.get("suite") != codename or repository.get("architecture") != architecture
    ):
        raise ValueError("enabled repository suite and architecture must match the target")
    return profile


def target_source_branch(config, target_id):
    return target_profile(config, target_id)["sourceBranch"]


def package_target_policy(config, package, target_id):
    packages = config.get("packages")
    package_record = packages.get(package) if isinstance(packages, dict) else None
    targets = package_record.get("targets") if isinstance(package_record, dict) else None
    policy = targets.get(target_id) if isinstance(targets, dict) else None
    if not isinstance(policy, dict):
        raise ValueError(f"package {package} is not configured for target {target_id}")
    access = policy.get("releaseAccess")
    if (not isinstance(access, dict)
            or access.get("policy") not in ("sponsor-first", "public-after-checks")
            or access.get("sponsorDelayHours") not in (0, 168)
            or (access.get("policy") == "sponsor-first") != (access.get("sponsorDelayHours") == 168)
            or access.get("publicContributionSpdx") != "MIT"
            or (access.get("sponsorDelayHours") == 168 and (
                access.get("sponsorEligibility") != "any-active-individual-github-sponsorship"
                or access.get("earlyBinaryLicenseId") != "LicenseRef-GetPatched-Early-Binary-1.1"
                or access.get("earlyUse") != ["private", "commercial"]
                or access.get("earlyRedistributionAllowed") is not False
                or access.get("publicBinaryLicenseSpdx") != "MIT"
            ))):
        raise ValueError(f"package {package} has an invalid target release or sponsor-access policy")
    return policy


def scanner_config(config):
    scanner = config.get("scanner")
    if (not isinstance(scanner, dict)
            or not isinstance(scanner.get("image"), str)
            or not isinstance(scanner.get("databaseReference"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", scanner.get("databaseSha256", ""))):
        raise ValueError("platform scanner image and database pins are incomplete")
    return scanner


def apt_source_list(profile, *, include_sources=True):
    architecture = profile["architecture"]
    lines = []
    for source in profile["aptSources"]:
        kinds = ("deb", "deb-src") if source["type"] == "both" else (source["type"],)
        if not include_sources:
            kinds = tuple(kind for kind in kinds if kind == "deb")
        components = " ".join(source["components"])
        for suite in source["suites"]:
            for kind in kinds:
                lines.append(f"{kind} [arch={architecture}] {source['uri']} {suite} {components}")
    if not lines:
        raise ValueError("target APT source list would be empty")
    return "\n".join(lines) + "\n"


def apt_source_list_b64(profile, *, include_sources=True):
    return base64.b64encode(apt_source_list(profile, include_sources=include_sources).encode()).decode()
