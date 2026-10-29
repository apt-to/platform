"""Validate and fetch GetPatched's declarative package recipes."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import urllib.parse
import urllib.request

SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))
from debian_versions import debian_version_compare
from platform_policy import package_target_policy, target_profile


MAX_SOURCE_BYTES = 128 * 1024 * 1024
MAX_DESCRIPTOR_BYTES = 16 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def load_json(path):
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"Could not read JSON file {path}: {error}") from error


def recipe_path(root, relative, *, must_exist=True, directory=False):
    if not isinstance(relative, str) or not relative:
        raise RuntimeError("Recipe paths must be non-empty relative strings")
    path = PurePosixPath(relative)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise RuntimeError(f"Unsafe recipe path: {relative}")
    root = root.resolve()
    result = root.joinpath(*path.parts)
    if result.is_symlink():
        raise RuntimeError(f"Recipe path must not be a symlink: {relative}")
    if must_exist:
        correct_type = result.is_dir() if directory else result.is_file()
        resolved = result.resolve()
        if not correct_type or os.path.commonpath((str(resolved), str(root))) != str(root):
            label = "directory" if directory else "file"
            raise RuntimeError(f"Recipe {label} is missing or escapes the checkout: {relative}")
    return result


def validate_hash_file(root, relative, expected_hash):
    path = recipe_path(root, relative)
    if not isinstance(expected_hash, str) or not SHA256_RE.fullmatch(expected_hash):
        raise RuntimeError(f"Invalid SHA-256 for recipe file: {relative}")
    if sha256_bytes(path.read_bytes()) != expected_hash:
        raise RuntimeError(f"SHA-256 mismatch for recipe file: {relative}")
    return path


def validate_source_asset(asset, package, version, *, distribution, descriptor=False):
    if not isinstance(asset, dict):
        raise RuntimeError("Source assets must be JSON objects")
    name = asset.get("name")
    if not isinstance(name, str) or PurePosixPath(name).name != name or name in (".", ".."):
        raise RuntimeError("Source asset name must be a plain filename")
    if not isinstance(asset.get("bytes"), int) or asset["bytes"] <= 0:
        raise RuntimeError(f"Invalid byte length for source asset {name}")
    maximum = MAX_DESCRIPTOR_BYTES if descriptor else MAX_SOURCE_BYTES
    if asset["bytes"] > maximum:
        raise RuntimeError(f"Source asset exceeds the {maximum}-byte build limit: {name}")
    digest = asset.get("sha256")
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        raise RuntimeError(f"Invalid SHA-256 for source asset {name}")
    parsed = urllib.parse.urlparse(asset.get("url", ""))
    approved_hosts = {
        "Ubuntu": {"launchpad.net", "www.launchpad.net"},
        "Debian": {"snapshot.debian.org"},
    }.get(distribution, set())
    if parsed.scheme != "https" or parsed.hostname not in approved_hosts:
        raise RuntimeError(f"Source asset must use an approved HTTPS {distribution} source host: {name}")
    if descriptor and not name.endswith(".dsc"):
        raise RuntimeError("The pinned source descriptor must be a .dsc file")
    if name.endswith(".dsc") and name != f"{package}_{version}.dsc":
        raise RuntimeError("Source descriptor filename does not match package and source version")
    return asset


def patch_applies_to_version(entry, target_id, version):
    if not isinstance(entry, dict) or not isinstance(entry.get("target"), str):
        raise RuntimeError("Patch applicability entries must name a target")
    has_exact = "sourceVersion" in entry
    has_range = "sourceVersionRange" in entry
    if has_exact == has_range:
        raise RuntimeError("Patch applicability must declare one exact version or Debian version range")
    if entry["target"] != target_id:
        return False
    if has_exact:
        if not isinstance(entry["sourceVersion"], str):
            raise RuntimeError("Patch exact source version must be a string")
        return entry["sourceVersion"] == version
    version_range = entry["sourceVersionRange"]
    if not isinstance(version_range, dict):
        raise RuntimeError("Patch sourceVersionRange must be an object")
    lower = version_range.get("minimum")
    upper = version_range.get("maximum")
    if lower is None and upper is None:
        raise RuntimeError("Patch source version range must have at least one bound")
    if lower is not None and (not isinstance(lower, str) or not isinstance(version_range.get("minimumInclusive"), bool)):
        raise RuntimeError("Patch range minimum needs a Debian version and inclusivity flag")
    if upper is not None and (not isinstance(upper, str) or not isinstance(version_range.get("maximumInclusive"), bool)):
        raise RuntimeError("Patch range maximum needs a Debian version and inclusivity flag")
    if lower is not None and upper is not None:
        comparison = debian_version_compare(lower, upper)
        if comparison > 0 or (comparison == 0 and not (
            version_range["minimumInclusive"] and version_range["maximumInclusive"]
        )):
            raise RuntimeError("Patch source version range is empty or reversed")
    if lower is not None:
        comparison = debian_version_compare(version, lower)
        if comparison < 0 or (comparison == 0 and not version_range["minimumInclusive"]):
            return False
    if upper is not None:
        comparison = debian_version_compare(version, upper)
        if comparison > 0 or (comparison == 0 and not version_range["maximumInclusive"]):
            return False
    return True


def load_recipe(root, platform_config, target_id=None):
    root = Path(root).resolve()
    manifest = load_json(root / "package-manifest.json")
    manifest_schema = manifest.get("schemaVersion")
    if manifest_schema not in (1, 2, 3):
        raise RuntimeError("Unsupported package recipe schemaVersion")
    package = manifest.get("package", {}).get("source")
    if not isinstance(package, str):
        raise RuntimeError("Recipe source package is missing")
    if manifest.get("project", {}).get("repository") != f"getpatched/packaging-{package}":
        raise RuntimeError("Recipe repository identity does not match its source package")

    target_refs = manifest.get("targets")
    if not isinstance(target_refs, list) or not target_refs:
        raise RuntimeError("Recipe must define at least one build target")
    if target_id is None:
        if len(target_refs) != 1:
            raise RuntimeError("Select --target when a recipe defines more than one target")
        target_ref = target_refs[0]
    else:
        matches = [item for item in target_refs if isinstance(item, dict) and item.get("id") == target_id]
        if len(matches) != 1:
            raise RuntimeError("Requested target is missing or duplicated in package manifest")
        target_ref = matches[0]
    if not isinstance(target_ref, dict) or not isinstance(target_ref.get("id"), str) or not target_ref["id"]:
        raise RuntimeError("Build target must have an id")
    if manifest_schema == 3:
        target_path = recipe_path(root, target_ref.get("file"))
        target = load_json(target_path)
        if target.get("schemaVersion") != 1 or target.get("id") != target_ref["id"]:
            raise RuntimeError("Referenced target file schema or identity does not match package manifest")
    else:
        target = target_ref

    profile = target_profile(platform_config, target["id"])
    central = package_target_policy(platform_config, package, target["id"])
    base = target.get("base", {})
    source = target.get("source", {})
    version = source.get("version")
    supported_versions = target.get("supportedSourceVersions")
    if (base.get("distribution") != profile["distribution"] or base.get("release") != profile["releaseVersion"]
            or base.get("codename") != profile["codename"]
            or base.get("sourcePocket") != central["sourcePocket"]
            or base.get("architecture") != profile["architecture"]
            or source.get("format") != "3.0 (quilt)"
            or version != central["baselineVersion"]
            or not isinstance(supported_versions, list) or not supported_versions
            or any(not isinstance(item, str) for item in supported_versions)
            or len(set(supported_versions)) != len(supported_versions)
            or version not in supported_versions):
        raise RuntimeError("Recipe base, exact source version, or supported-version declaration differs from target policy")
    package_version = target.get("packageVersion")
    release_serial = target.get("releaseSerial")
    if (package_version != central["packageVersion"]
            or release_serial != central.get("releaseSerial")
            or not isinstance(release_serial, int) or isinstance(release_serial, bool) or release_serial < 1
            or package_version != f"{version}+getpatched{release_serial}"):
        raise RuntimeError("Recipe package version must match the configured GetPatched release serial")
    if target.get("binaryPackages") != central["binaryPackages"]:
        raise RuntimeError("Recipe runtime package list differs from platform verification policy")
    access = target.get("releaseAccess", {})
    configured_access = central.get("releaseAccess", {})
    delay = configured_access.get("sponsorDelayHours")
    expected_policy = "sponsor-first" if delay else "public-after-checks"
    if (access.get("sponsorDelayHours") != delay or access.get("policy") != expected_policy
            or configured_access.get("policy") != expected_policy
            or access.get("sponsorEligibility") != configured_access.get("sponsorEligibility")
            or access.get("earlyBinaryLicenseId") != configured_access.get("earlyBinaryLicenseId")
            or access.get("publicContributionSpdx") != configured_access.get("publicContributionSpdx")):
        raise RuntimeError("Recipe release access policy differs from platform configuration")
    license_policy = platform_config.get("licenses", {})
    public_license = license_policy.get("publicContributions", {})
    early_license = license_policy.get("earlyBinary", {})
    recipe_licensing = manifest.get("licensing", {})
    if (recipe_licensing.get("publicContributionsSpdx") != public_license.get("spdx")
            or recipe_licensing.get("publicContributionsLicenseFile") != public_license.get("licenseFile")
            or recipe_licensing.get("earlyBinaryLicenseId") != early_license.get("licenseId")
            or recipe_licensing.get("earlyBinaryTermsFile") != early_license.get("termsFile")
            or recipe_licensing.get("upstreamLicenses") != "preserve"):
        raise RuntimeError("Recipe licensing declaration differs from platform public and early-binary policy")
    recipe_path(root, recipe_licensing.get("publicContributionsLicenseFile"))
    recipe_path(root, recipe_licensing.get("earlyBinaryTermsFile"))
    recipe_path(root, recipe_licensing.get("upstreamCopyrightFile"))
    changelog = target.get("changelog", {})
    if (changelog.get("distribution") != profile["codename"]
            or changelog.get("urgency") not in ("low", "medium", "high", "critical")
            or not isinstance(changelog.get("maintainer"), str)
            or not isinstance(changelog.get("date"), str)):
        raise RuntimeError("Recipe changelog identity is incomplete or mismatched")

    descriptor = validate_source_asset(source.get("descriptor"), package, version,
                                       distribution=profile["distribution"], descriptor=True)
    assets = source.get("files")
    if not isinstance(assets, list) or not assets:
        raise RuntimeError("Recipe must pin its source archives")
    names = [item.get("name") for item in assets if isinstance(item, dict)]
    if len(names) != len(assets) or len(set(names)) != len(names):
        raise RuntimeError("Source archive names must be unique")
    for item in assets:
        validate_source_asset(item, package, version, distribution=profile["distribution"])
    if not any(".orig.tar." in item["name"] for item in assets):
        raise RuntimeError("Recipe must pin the original upstream source archive")
    if not any(".debian.tar." in item["name"] for item in assets):
        raise RuntimeError("Recipe must pin a Debian packaging archive")
    if not isinstance(source.get("signatureVerification"), dict) or source["signatureVerification"].get("verified") is not False:
        raise RuntimeError("Recipe must report the source signature verification status accurately")

    metadata_file = manifest.get("patchMetadata")
    metadata_path = recipe_path(root, metadata_file)
    metadata = load_json(metadata_path)
    metadata_schema = metadata.get("schemaVersion")
    if metadata_schema not in (1, 2, 3) or not isinstance(metadata.get("patches"), list):
        raise RuntimeError("Unsupported or malformed patch metadata")
    patches = metadata["patches"]
    patch_by_id = {item.get("id"): item for item in patches if isinstance(item, dict)}
    patch_ids = target.get("patches")
    build_patch_ids = target.get("buildPatches", [])
    all_patch_ids = patch_ids + build_patch_ids if isinstance(patch_ids, list) and isinstance(build_patch_ids, list) else []
    if isinstance(build_patch_ids, list) and build_patch_ids and manifest_schema < 2:
        raise RuntimeError("Build patches require package manifest schemaVersion 2")
    if (not isinstance(patch_ids, list) or not patch_ids
            or not isinstance(build_patch_ids, list)
            or any(not isinstance(item, str) for item in all_patch_ids)
            or len(set(all_patch_ids)) != len(all_patch_ids)
            or not set(all_patch_ids).issubset(patch_by_id)
            or len(patch_by_id) != len(patches)):
        raise RuntimeError("Target security and build patch lists must refer to unique patch metadata IDs")
    cves = set()
    fixture_entries = {}
    reference_entries = {}
    for patch_id in all_patch_ids:
        item = patch_by_id[patch_id]
        patch_path = f"patches/{item.get('file', '')}"
        if not item.get("file") or PurePosixPath(item["file"]).name != item["file"]:
            raise RuntimeError(f"Patch file must be a plain filename: {patch_id}")
        validate_hash_file(root, patch_path, item.get("sha256"))
        applicability = item.get("appliesTo")
        if not isinstance(applicability, list) or not applicability:
            raise RuntimeError(f"Patch {patch_id} must declare target and source-version applicability")
        applicable = [entry for entry in applicability if patch_applies_to_version(entry, target["id"], version)]
        if len(applicable) != 1:
            raise RuntimeError(f"Patch {patch_id} is not pinned to exactly this target and source version")
        patch_kind = item.get("kind", "security")
        if metadata_schema >= 2 and ("kind" not in item or patch_kind not in ("security", "build-compatibility")):
            raise RuntimeError(f"Patch {patch_id} has an unsupported patch kind")
        if patch_kind == "build-compatibility" and metadata_schema < 2:
            raise RuntimeError("Build-compatibility patches require patch metadata schemaVersion 2")
        patch_cves = item.get("cves")
        if (not isinstance(patch_cves, list)
                or any(not isinstance(cve, str) or not cve for cve in patch_cves)
                or len(set(patch_cves)) != len(patch_cves)):
            raise RuntimeError(f"Patch {patch_id} must list unique CVE identifiers")
        if patch_id in patch_ids:
            if patch_kind != "security" or not patch_cves:
                raise RuntimeError(f"Security patch {patch_id} must be typed as security and list CVEs")
            upstream = item.get("upstream")
            if (not isinstance(upstream, dict)
                    or not isinstance(upstream.get("repository"), str) or not upstream["repository"]
                    or not isinstance(upstream.get("url"), str) or not upstream["url"]
                    or not isinstance(upstream.get("commit"), str)
                    or not re.fullmatch(r"[0-9a-fA-F]{40}", upstream["commit"])):
                raise RuntimeError(f"Security patch {patch_id} must record its upstream repository, URL, and full commit")
            cves.update(patch_cves)
        elif patch_kind != "build-compatibility" or patch_cves:
            raise RuntimeError(f"Build patch {patch_id} must be build-compatibility-only and list no CVEs")
        tests = item.get("tests")
        if not isinstance(tests, list) or not tests:
            raise RuntimeError(f"Patch {patch_id} must declare regression tests")
        for reference in item.get("referenceFiles", []):
            if not isinstance(reference, dict):
                raise RuntimeError(f"Patch {patch_id} reference files must include path and SHA-256")
            validate_hash_file(root, reference.get("path"), reference.get("sha256"))
            reference_entries[reference["path"]] = reference["sha256"]
        for test in tests:
            for fixture in test.get("fixtures", []):
                if not isinstance(fixture, dict):
                    raise RuntimeError("Regression fixtures must include path and SHA-256")
                fixture_path = fixture.get("path")
                validate_hash_file(root, fixture_path, fixture.get("sha256"))
                fixture_entries[fixture_path] = fixture["sha256"]
    if cves != set(central["targetCves"]):
        raise RuntimeError("Patch CVEs differ from the platform target CVE policy")

    tests_config = manifest.get("regressionTests", {})
    fixtures_dir = tests_config.get("fixturesDirectory")
    if not isinstance(fixtures_dir, str) or not fixture_entries:
        raise RuntimeError("Recipe regression fixture directory or fixture list is missing")
    fixture_root = recipe_path(root, fixtures_dir, directory=True)
    all_recipe_tests = set(fixture_entries) | set(reference_entries)
    if any(not path.startswith(fixtures_dir.rstrip("/") + "/") for path in all_recipe_tests):
        raise RuntimeError("Every declared regression fixture must be inside the recipe fixture directory")
    copyright_path = manifest.get("package", {}).get("copyrightFile")
    recipe_path(root, copyright_path)

    policy = {
        "schemaVersion": 1,
        "source": package,
        "targetId": target["id"],
        "baseVersion": version,
        "version": package_version,
        "releaseSerial": release_serial,
        "targetCve": central["targetCve"],
        "targetCves": central["targetCves"],
        "sponsorDelayHours": delay,
        "release": base["codename"],
        "distribution": base["distribution"],
        "releaseVersion": base["release"],
        "architecture": base["architecture"],
        "advisoryEcosystem": profile["advisoryEcosystem"],
        "releaseAccess": configured_access,
        "publicContributionsSpdx": public_license["spdx"],
        "earlyBinaryLicenseId": early_license["licenseId"] if delay else None,
        "binaryPackages": target["binaryPackages"],
        "ubuntuProEsmCompatibility": central.get("ubuntuProEsmCompatibility", "not-applicable"),
        "patches": patch_ids,
        "buildPatches": build_patch_ids,
    }
    return {"manifest": manifest, "target": target, "metadata": metadata,
            "patchesById": patch_by_id, "policy": policy, "central": central,
            "descriptor": descriptor, "sourceFiles": assets, "fixtureFiles": fixture_entries}


def download_source_assets(recipe, destination):
    """Fetch a recipe's exact .dsc and archives, enforcing size and digest pins."""
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    assets = [recipe["descriptor"], *recipe["sourceFiles"]]
    downloaded = []
    for asset in assets:
        target = destination / asset["name"]
        request = urllib.request.Request(asset["url"], headers={"User-Agent": "getpatched.dev-build/0.2"})
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                content = response.read(asset["bytes"] + 1)
        except Exception as error:
            raise RuntimeError(f"Could not fetch pinned source asset {asset['name']}: {error}") from error
        if len(content) != asset["bytes"] or sha256_bytes(content) != asset["sha256"]:
            raise RuntimeError(f"Pinned source asset size or SHA-256 mismatch: {asset['name']}")
        target.write_bytes(content)
        downloaded.append({"name": asset["name"], "bytes": len(content), "sha256": sha256_bytes(content)})
    return downloaded
