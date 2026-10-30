#!/usr/bin/env python3
"""Scan installed dpkg package records against the GetPatched OSV-compatible feed."""
import argparse
import hashlib
import json
from email.parser import Parser
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from build_getpatched_advisory_feed import PACKAGES, build_feed
from debian_versions import debian_version_compare, debian_version_parts
from platform_policy import package_ecosystem, package_target_policy, target_profile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "verification"))
from regression import (consumer_version_succeeded, libpng_overwrite_reproduced, libpng_stride_read_reproduced,
                        poppler_uaf_reproduced, schematron_baseline_reproduced,
                        tiff_baseline_reproduced)

DEFAULT_FEED = ROOT / "advisories" / "getpatched-osv.json"
MAX_STATUS_BYTES = 16 * 1024 * 1024
MAX_FEED_BYTES = 4 * 1024 * 1024


def parse_status(path):
    path = Path(path)
    if path.stat().st_size > MAX_STATUS_BYTES:
        raise ValueError("dpkg status inventory exceeds the 16 MiB scanner limit")
    return parse_status_text(path.read_text())


def validate_followup_assessment_checks(target, checks, phase):
    if phase != "patched":
        return
    for cve, assessment in target.get("followUpAssessments", {}).items():
        matches = [check for check in checks
                   if check.get("cve") == cve and check.get("testId") == assessment["regressionTestId"]]
        if len(matches) != 1 or matches[0].get("passed") is not True:
            raise ValueError(f"candidate regression report lacks the assessed follow-up check for {cve}")
        if assessment["candidateDisposition"] != "fixed-in-backport":
            raise ValueError(f"patched disposition for follow-up {cve} is not explicitly assessed")


def poppler_patched_checks_succeeded(cve_check, checks):
    return (
        cve_check.get("returncode") == 0
        and not cve_check.get("timedOut")
        and "ERROR SUMMARY: 0 errors" in cve_check.get("memoryLog", "")
        and any(item.get("passed") is True and item.get("command", [None])[0] == "pdfinfo"
                and consumer_version_succeeded(item, "pdfinfo version") for item in checks)
    )


def libgit2_regression_checks_succeeded(cve_checks, phase):
    path_check = cve_checks.get("CVE-2026-53584", {})
    pack_check = cve_checks.get("CVE-2026-53585", {})
    redirect_check = cve_checks.get("CVE-2026-53586", {})
    checks = (
        (path_check, "CVE-2026-53584"),
        (pack_check, "CVE-2026-53585"),
        (redirect_check, "CVE-2026-53586"),
    )
    if any(check.get("cve") != cve or check.get("passed") is not True
           or check.get("returncode") != 0 or check.get("timedOut") is not False
           for check, cve in checks):
        return False
    if phase == "baseline":
        return (
            path_check.get("baselinePathEscapeReproduced") is True
            and path_check.get("outsideDirectoryCreated") is True
            and path_check.get("result") == "result=created:escaped-submodule-directory"
            and pack_check.get("baselineAcceptedLargeObject") is True
            and pack_check.get("result") == "result=accepted:large-object"
            and pack_check.get("declaredObjectSize") == 100 * 1024 * 1024
            and redirect_check.get("baselineUsedOriginalOrigin") is True
            and redirect_check.get("callbackReceivedExpectedOrigin") is True
            and redirect_check.get("callbackOrigin") == redirect_check.get("initialOrigin")
            and redirect_check.get("initialOrigin") != redirect_check.get("redirectedOrigin")
        )
    return (
        path_check.get("patchedPathRejected") is True
        and path_check.get("outsideDirectoryCreated") is False
        and path_check.get("result") == "result=rejected:invalid-submodule-path"
        and pack_check.get("rejectedLargeObject") is True
        and pack_check.get("result") == "result=rejected:overly-large-object"
        and pack_check.get("configuredObjectLimit") == 42 * 1024 * 1024
        and pack_check.get("declaredObjectSize", 0) > pack_check.get("configuredObjectLimit", 0)
        and redirect_check.get("patchedUsedRedirectedOrigin") is True
        and redirect_check.get("callbackReceivedExpectedOrigin") is True
        and redirect_check.get("callbackOrigin") == redirect_check.get("redirectedOrigin")
        and redirect_check.get("initialOrigin") != redirect_check.get("redirectedOrigin")
    )


def parse_status_text(text):
    # Parser returns one message. Split dpkg's RFC822-style control records explicitly.
    packages = {}
    for stanza in re.split(r"\n\s*\n", text.strip()):
        if not stanza.strip():
            continue
        record = Parser().parsestr(stanza)
        package = record.get("Package")
        if not package:
            continue
        architecture = record.get("Architecture")
        identity = (package, architecture)
        if identity in packages:
            raise ValueError(f"duplicate dpkg status record for {package}:{architecture}")
        packages[identity] = {
            "version": record.get("Version"),
            "architecture": record.get("Architecture"),
            "status": record.get("Status", ""),
        }
    return packages


def load_feed(path, verified_candidates=frozenset()):
    path = Path(path)
    if path.stat().st_size > MAX_FEED_BYTES:
        raise ValueError("OSV feed exceeds the 4 MiB scanner limit")
    feed = json.loads(path.read_text())
    if feed.get("schema_version") != "1.6.0" or not isinstance(feed.get("vulns"), list):
        raise ValueError("advisory feed is not a supported OSV schema database")
    seen = set()
    config = json.loads(PACKAGES.read_text())
    canonical_feed = build_feed(config)
    if feed != canonical_feed:
        raise ValueError("canonical advisory feed does not match the reviewed GetPatched package policy")
    expected_feed = build_feed(config, verified_candidates)
    if verified_candidates:
        # Candidate advisories enter this isolated scan only after paired
        # installed baseline and patched regressions have passed.
        feed = expected_feed
    for advisory in feed["vulns"]:
        advisory_id = advisory.get("id")
        if not isinstance(advisory_id, str) or not advisory_id.startswith("CVE-") or advisory_id in seen:
            raise ValueError("advisory IDs must be unique CVE identifiers")
        seen.add(advisory_id)
        if not isinstance(advisory.get("affected"), list) or not advisory["affected"]:
            raise ValueError(f"{advisory_id} has no affected package records")
        for affected in advisory["affected"]:
            package = affected.get("package", {})
            scope = affected.get("ecosystem_specific", {})
            policy = affected.get("database_specific", {})
            fixed = policy.get("fixed_versions")
            source = scope.get("source_package") if isinstance(scope, dict) else None
            target_id = scope.get("target_id") if isinstance(scope, dict) else None
            if (not isinstance(package.get("ecosystem"), str) or not package["ecosystem"]
                    or not isinstance(package.get("name"), str)
                    or not re.fullmatch(r"[a-z0-9][a-z0-9+.-]+", package["name"])
                    or not isinstance(scope, dict) or not isinstance(scope.get("distribution"), str)
                    or not isinstance(scope.get("release"), str) or not isinstance(scope.get("architecture"), str)
                    or not isinstance(target_id, str) or policy.get("target_id") != target_id
                    or not isinstance(source, str) or not isinstance(fixed, list)
                    or not isinstance(affected.get("versions"), list) or not affected["versions"] or affected.get("ranges")):
                raise ValueError(f"{advisory_id} has an invalid target-specific affected package entry")
            try:
                profile = target_profile(config, target_id)
                expected = package_target_policy(config, source, target_id)
            except (KeyError, ValueError) as error:
                raise ValueError(f"{advisory_id} names an unconfigured package target: {error}") from error
            vendor_fixed = expected.get("vendorFixedVersions", [])
            candidate_status = expected.get("candidateStatus", "unverified")
            if (source, target_id) in verified_candidates and not candidate_status.startswith("development-verified"):
                candidate_status = "development-verified-production-release-pending"
            candidate_verified = candidate_status.startswith("development-verified")
            expected_fixed = [expected["packageVersion"], *vendor_fixed] if candidate_verified else vendor_fixed
            if (package["ecosystem"] != package_ecosystem(config, source, target_id)
                    or scope["distribution"] != profile["distribution"] or scope["release"] != profile["codename"]
                    or scope["architecture"] != profile["architecture"]
                    or policy.get("source_package") != source
                    or policy.get("candidate_version") != expected["packageVersion"]
                    or policy.get("candidate_status") != candidate_status
                    or policy.get("getpatched_fixed_version") != (expected["packageVersion"] if candidate_verified else None)
                    or policy.get("vendor_fixed_versions") != vendor_fixed
                    or fixed != expected_fixed
                    or affected["versions"] != [expected["baselineVersion"]]):
                raise ValueError("advisory feed does not match the reviewed GetPatched package policy")
            for version in [*affected["versions"], *fixed]:
                debian_version_parts(version)
            if any(debian_version_compare(fixed_version, affected_version) <= 0
                   for fixed_version in fixed for affected_version in affected["versions"]):
                raise ValueError(f"{advisory_id} fixed versions must sort after every reviewed affected version")
    if feed != expected_feed:
        raise ValueError("advisory feed does not match the reviewed GetPatched package policy")
    return feed


def regression_verified_candidate(directory, scan_images_path, target_id, recipe_directory, policy_path):
    directory = Path(directory)
    scan_images = json.loads(Path(scan_images_path).read_text())
    config = json.loads(PACKAGES.read_text())
    policy = json.loads(Path(policy_path).read_text())
    source = policy.get("source")
    if not isinstance(source, str) or policy.get("targetId") != target_id:
        raise ValueError("candidate build policy does not identify the selected source and target")
    target = package_target_policy(config, source, target_id)
    profile = target_profile(config, target_id)
    runner = ROOT / "verification" / "regression.py"
    report_paths = {}
    verification_id = uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix="getpatched-verified-candidate-") as temporary:
        temp = Path(temporary)
        for phase, image_key, report_phase, version in (
            ("before", "baselineImageId", "baseline", target["baselineVersion"]),
            ("after", "patchedImageId", "patched", target["packageVersion"]),
        ):
            image_id = scan_images.get(image_key)
            if not isinstance(image_id, str) or not image_id:
                raise ValueError("candidate scan image identity is missing")
            inspected = subprocess.run(
                ["docker", "image", "inspect", "--format", "{{.Id}}", image_id],
                capture_output=True, text=True, timeout=60, check=False,
            )
            if inspected.returncode != 0 or inspected.stdout.strip() != image_id:
                raise ValueError("candidate scan image identity does not match a locally inspectable Docker image")
            report_name = report_phase + "-regression-verified-by-scanner.json"
            report_path = temp / report_name
            command = [
                "docker", "run", "--rm", "--network", "none", "--platform", profile["build"]["containerPlatform"],
                "--mount", "type=bind,source=" + str(Path(recipe_directory).resolve()) + ",target=/recipe,readonly",
                "--mount", "type=bind,source=" + str(runner.resolve()) + ",target=/regression.py,readonly",
                "--mount", "type=bind,source=" + str(Path(policy_path).resolve()) + ",target=/policy.json,readonly",
                "--mount", "type=bind,source=" + str(temp.resolve()) + ",target=/proof",
                image_id, "python3", "/regression.py", "--recipe", "/recipe", "--policy", "/policy.json",
                "--phase", report_phase, "--image-id", image_id, "--verification-id", verification_id,
                "--output", "/proof/" + report_name,
            ]
            executed = subprocess.run(command, capture_output=True, text=True, timeout=240, check=False)
            if executed.returncode != 0 or not report_path.is_file():
                raise ValueError("independent installed regression execution failed for the candidate scan images")
            report_paths[report_phase] = report_path
        baseline = json.loads(report_paths["baseline"].read_text())
        patched = json.loads(report_paths["patched"].read_text())
        if (baseline.get("source") != source or patched.get("source") != source
                or baseline.get("targetId") != target_id or patched.get("targetId") != target_id
                or baseline.get("verificationId") != patched.get("verificationId")
                or baseline.get("imageId") != scan_images.get("baselineImageId")
                or patched.get("imageId") != scan_images.get("patchedImageId")):
            raise ValueError("independently executed regressions do not identify the paired candidate images")
        runner_hash = hashlib.sha256(runner.read_bytes()).hexdigest()
    for report, phase, version in (
        (baseline, "baseline", target["baselineVersion"]),
        (patched, "patched", target["packageVersion"]),
    ):
        if (report.get("runner") != "getpatched-platform-regression/1"
                or report.get("runnerSha256") != runner_hash
                or not isinstance(report.get("imageId"), str) or not report["imageId"]
                or not isinstance(report.get("verificationId"), str)
                or not re.fullmatch(r"[0-9a-f]{32}", report["verificationId"])
                or report.get("phase") != phase or report.get("installedVersion") != version
                or report.get("expectedVersion") != version or report.get("passed") is not True
                or report.get("distribution") != profile["distribution"]
                or report.get("release") != profile["codename"]
                or report.get("architecture") != profile["architecture"]
                or not report.get("checks") or any(check.get("passed") is not True for check in report["checks"])):
            raise ValueError("candidate regression reports do not prove passing baseline and patched target checks")
        checks = report["checks"]
        cve_checks = {check.get("cve"): check for check in checks if check.get("cve")}
        if not set(target["targetCves"]).issubset(cve_checks):
            raise ValueError("candidate regression reports do not cover every configured target CVE")
        if source == "libgit2" and any(
            sum(check.get("cve") == cve for check in checks) != 1
            for cve in target["targetCves"]
        ):
            raise ValueError("libgit2 regression reports must contain exactly one result per configured CVE")
        validate_followup_assessment_checks(target, checks, phase)
        if source == "tiff":
            target_checks = [cve_checks[cve] for cve in target["targetCves"]]
            if phase == "baseline":
                if not all(tiff_baseline_reproduced(check) for check in target_checks):
                    raise ValueError("TIFF baseline evidence does not reproduce the configured tiffcrop issue")
            elif (not all(check.get("returncode") in (0, 1) and not check.get("timedOut")
                          and check.get("command", [None])[0] == "tiffcrop" for check in target_checks)
                  or not all("ERROR SUMMARY: 0 errors" in check.get("memoryLog", "")
                             for check in target_checks)
                  or not any(check.get("command", [None])[0] == "tiffinfo"
                             and "Image Width" in check.get("stdout", "") for check in checks)):
                raise ValueError("TIFF patched evidence lacks clean CVE regression and a tiffinfo consumer check")
        elif source == "libxml2":
            target_checks = [cve_checks[cve] for cve in target["targetCves"]]
            if phase == "baseline":
                if not all(schematron_baseline_reproduced(check) for check in target_checks):
                    raise ValueError("libxml2 baseline evidence does not reproduce the configured memory fault")
            elif (not all(check.get("returncode") == 3 and "ERROR SUMMARY: 0 errors" in check.get("memoryLog", "")
                          for check in target_checks)
                  or not any(check.get("command", [None])[0] == "xmllint"
                             and check.get("returncode") == 0 for check in checks)):
                raise ValueError("libxml2 patched evidence lacks clean memory checks and a consumer check")
        elif source == "libarchive":
            check = cve_checks[target["targetCves"][0]]
            if phase == "baseline":
                if check.get("timedOut") is not True:
                    raise ValueError("libarchive baseline evidence does not reproduce the configured bounded timeout")
            elif (check.get("returncode") != 0 or check.get("timedOut")
                  or len([item for item in checks if item.get("passed") is True
                          and item.get("command", [None])[0] == "bsdtar"]) < 2):
                raise ValueError("libarchive patched evidence lacks a clean probe and tar consumer round trip")
        elif source == "libpng1.6":
            target_checks = [cve_checks[cve] for cve in target["targetCves"]]
            if phase == "baseline":
                if (not libpng_overwrite_reproduced(cve_checks.get("CVE-2025-65018", {}))
                        or not libpng_stride_read_reproduced(cve_checks.get("CVE-2026-22801", {}))):
                    raise ValueError("libpng baseline evidence does not reproduce both configured memory-safety issues")
            else:
                if (not all(check.get("returncode") == 0 and not check.get("timedOut")
                            and "ERROR SUMMARY: 0 errors" in check.get("memoryLog", "") for check in target_checks)
                        or not any(check.get("testId") == "CVE-2026-22695-padded-stride"
                                   and check.get("passed") is True for check in checks)
                        or not any(Path(check.get("command", [""])[0]).name == "compare-interlaced-read"
                                   and check.get("returncode") == 0 for check in checks)):
                    raise ValueError("libpng patched evidence lacks clean CVE checks, padded-stride follow-up, or Adam7 pixel comparison")
        elif source == "poppler":
            check = cve_checks["CVE-2025-52885"]
            if phase == "baseline":
                if not poppler_uaf_reproduced(check):
                    raise ValueError("Poppler baseline evidence does not reproduce the configured StructTreeRoot use-after-free")
            elif not poppler_patched_checks_succeeded(check, checks):
                raise ValueError("Poppler patched evidence lacks a clean CVE regression and pdfinfo consumer check")
        elif source == "libgit2":
            if not libgit2_regression_checks_succeeded(cve_checks, phase):
                description = "baseline evidence does not reproduce" if phase == "baseline" else "patched evidence does not prove"
                raise ValueError(f"libgit2 {description} all three configured issues/fixes")
        else:
            raise ValueError("candidate regression runner has no package-specific evidence classifier")
    directory.mkdir(parents=True, exist_ok=True)
    stored = {}
    for phase, report in (("baseline", baseline), ("patched", patched)):
        destination = directory / (phase + "-regression-verified-by-scanner.json")
        destination.write_text(json.dumps(report, indent=2) + "\n")
        stored[phase] = hashlib.sha256(destination.read_bytes()).hexdigest()
    return source, {
        **stored,
        "imageIds": {"baseline": baseline["imageId"], "patched": patched["imageId"]},
    }


def scan(status_path, feed_path, release, architecture, image_id=None, target_id=None, regression_directory=None, regression_phase=None, scan_images_path=None, recipe_directory=None, policy_path=None, effective_feed_output=None):
    verified_candidates = frozenset()
    regression_hashes = None
    if regression_directory is not None:
        if (regression_phase not in ("before", "after") or scan_images_path is None
                or recipe_directory is None or policy_path is None):
            raise ValueError("candidate classification requires a before/after image and paired scan-image identities")
        if target_id is None:
            raise ValueError("--target-id is required with --regression-directory")
        source, regression_hashes = regression_verified_candidate(
            regression_directory, scan_images_path, target_id, recipe_directory, policy_path)
        proof_phase = "baseline" if regression_phase == "before" else "patched"
        if (not image_id or regression_hashes["imageIds"][proof_phase] != image_id):
            raise ValueError("candidate regression proof does not match the scanned image and phase")
        verified_candidates = frozenset({(source, target_id)})
    feed = load_feed(feed_path, verified_candidates)
    if verified_candidates:
        if effective_feed_output is None:
            raise ValueError("candidate verification requires an output path for its exact advisory feed")
        effective_feed_bytes = (json.dumps(feed, indent=2, sort_keys=True) + "\n").encode()
        if len(effective_feed_bytes) > MAX_FEED_BYTES:
            raise ValueError("verification advisory feed exceeds the 4 MiB scanner limit")
        effective_feed_path = Path(effective_feed_output)
        if effective_feed_path.resolve() == Path(feed_path).resolve():
            raise ValueError("candidate verification feed output must not overwrite the canonical advisory feed")
        effective_feed_path.parent.mkdir(parents=True, exist_ok=True)
        effective_feed_path.write_bytes(effective_feed_bytes)
        reported_feed_path = effective_feed_path
        effective_feed_sha256 = hashlib.sha256(effective_feed_bytes).hexdigest()
        feed_mode = "candidate-verification-only"
    else:
        reported_feed_path = Path(feed_path)
        effective_feed_sha256 = hashlib.sha256(reported_feed_path.read_bytes()).hexdigest()
        feed_mode = "canonical"
    candidates = {
        affected.get("ecosystem_specific", {}).get("target_id")
        for advisory in feed["vulns"] for affected in advisory["affected"]
        if affected.get("ecosystem_specific", {}).get("release") == release
        and affected.get("ecosystem_specific", {}).get("architecture") == architecture
    }
    if not candidates:
        raise ValueError(f"advisory feed has no coverage for {release}/{architecture}")
    if target_id is None:
        if len(candidates) != 1:
            raise ValueError(f"select --target-id when {release}/{architecture} maps to multiple targets")
        target_id = next(iter(candidates))
    if target_id not in candidates:
        raise ValueError(f"advisory feed has no coverage for {release}/{architecture}")
    status_path = Path(status_path)
    if status_path.stat().st_size > MAX_STATUS_BYTES:
        raise ValueError("dpkg status inventory exceeds the 16 MiB scanner limit")
    status_bytes = status_path.read_bytes()
    if verified_candidates:
        image_status = subprocess.run(
            ["docker", "run", "--rm", "--network", "none", image_id, "cat", "/var/lib/dpkg/status"],
            capture_output=True, text=True, timeout=60, check=False,
        )
        if image_status.returncode != 0 or len(image_status.stdout.encode()) > MAX_STATUS_BYTES:
            raise ValueError("could not read a bounded dpkg inventory from the verified candidate image")
        image_status_bytes = image_status.stdout.encode()
        if image_status_bytes != status_bytes:
            raise ValueError("supplied package inventory does not match the verified candidate image")
        installed = parse_status_text(image_status.stdout)
    else:
        installed = parse_status(status_path)
    findings = []
    scanned = {}
    for advisory in feed["vulns"]:
        for affected in advisory["affected"]:
            package = affected["package"]["name"]
            record = installed.get((package, architecture))
            if not record or record["status"].split()[-1:] != ["installed"]:
                continue
            scope = affected["ecosystem_specific"]
            if scope["target_id"] != target_id or scope["release"] != release or scope["architecture"] != architecture:
                continue
            if not record["version"]:
                raise ValueError(f"installed package {package} has no version")
            scanned[package] = record["version"]
            package_policy = affected["database_specific"]
            fixed_versions = package_policy["fixed_versions"]
            affected_versions = affected["versions"]
            version = record["version"]
            getpatched_fixed = package_policy["getpatched_fixed_version"]
            candidate_version = package_policy["candidate_version"]
            vendor_fixed = package_policy["vendor_fixed_versions"]
            if any(debian_version_compare(version, candidate) == 0 for candidate in affected_versions):
                findings.append({
                    "id": advisory["id"], "package": package, "version": version,
                    "affected_versions": affected_versions,
                    "fixed_versions": fixed_versions, "severity": advisory["database_specific"]["severity"],
                    "summary": advisory["summary"], "references": [ref["url"] for ref in advisory.get("references", [])],
                })
            elif debian_version_compare(version, candidate_version) == 0 and getpatched_fixed is None:
                raise ValueError(
                    f"installed package {package} candidate version {version} is not verified as fixed for {advisory['id']}"
                )
            elif ("+getpatched" in version and
                  (getpatched_fixed is None or debian_version_compare(version, getpatched_fixed) != 0)):
                raise ValueError(
                    f"installed package {package} version {version} is not an exact reviewed affected or GetPatched fixed "
                    f"version for {advisory['id']}; update the advisory feed before treating it as clean"
                )
            elif ((getpatched_fixed is None or debian_version_compare(version, getpatched_fixed) != 0) and
                  not any(debian_version_compare(version, candidate) >= 0 for candidate in vendor_fixed)):
                raise ValueError(
                    f"installed package {package} version {version} is not an exact reviewed affected or GetPatched fixed "
                    f"version, or a configured vendor fixed version or later, for {advisory['id']}; update the advisory feed "
                    "before treating it as clean"
                )
    findings.sort(key=lambda item: (item["package"], item["id"]))
    return {
        "schemaVersion": 1, "scanner": "getpatched-dpkg-osv/1", "targetId": target_id, "release": release, "architecture": architecture,
        "imageId": image_id,
        "advisoryFeed": str(reported_feed_path), "advisoryFeedMode": feed_mode,
        "advisoryFeedSha256": effective_feed_sha256,
        "packagePolicySha256": hashlib.sha256(PACKAGES.read_bytes()).hexdigest(),
        "statusFileSha256": hashlib.sha256(status_bytes).hexdigest(),
        "scannedPackageVersions": dict(sorted(scanned.items())), "findings": findings,
        "findingsById": sorted({item["id"] for item in findings}),
        "regressionVerifiedCandidate": sorted([{"source": source, "targetId": target} for source, target in verified_candidates]),
        "regressionReportSha256": ({key: value for key, value in regression_hashes.items() if key in ("baseline", "patched")}
                                    if regression_hashes else None),
        "regressionImageIds": regression_hashes.get("imageIds") if regression_hashes else None,
        "assessedFollowUpCves": ([{"id": cve, **assessment}
                                   for cve, assessment in package_target_policy(
                                       json.loads(PACKAGES.read_text()), source, target_id
                                   ).get("followUpAssessments", {}).items()]
                                  if target_id and verified_candidates else []),
        "summary": {"scannedPackages": len(scanned), "vulnerablePackages": len({item["package"] for item in findings}), "findingCount": len(findings)},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--feed", type=Path, default=DEFAULT_FEED)
    parser.add_argument("--status-file", type=Path, default=Path("/var/lib/dpkg/status"))
    parser.add_argument("--release", default="focal", help="target distribution release codename")
    parser.add_argument("--architecture", default="amd64", help="target dpkg architecture")
    parser.add_argument("--target-id", help="exact configured distribution/release/architecture target")
    parser.add_argument("--image-id", help="container image digest or local image ID being scanned")
    parser.add_argument("--regression-directory", type=Path, help="accept a candidate only when matching baseline and patched installed regression reports pass")
    parser.add_argument("--regression-phase", choices=("before", "after"), help="scanned image phase paired with installed regression proof")
    parser.add_argument("--scan-images", type=Path, help="paired baseline and patched image IDs produced by the build runner")
    parser.add_argument("--recipe-directory", type=Path, help="package recipe mounted read-only for independent installed regression execution")
    parser.add_argument("--policy-file", type=Path, help="build policy used by the independent installed regression runner")
    parser.add_argument("--effective-feed-output", type=Path, help="retain the exact candidate-only advisory feed used for installed regression scans")
    args = parser.parse_args()
    try:
        report = scan(args.status_file, args.feed, args.release, args.architecture, args.image_id, args.target_id,
                      args.regression_directory, args.regression_phase, args.scan_images,
                      args.recipe_directory, args.policy_file, args.effective_feed_output)
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError, subprocess.SubprocessError) as error:
        print("GetPatched scan failed: " + str(error), file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2))
    return 1 if report["findings"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
