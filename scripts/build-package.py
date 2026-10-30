#!/usr/bin/env python3
"""Build and test a reviewed target-specific packaging checkout without publishing binaries."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from package_recipe import download_source_assets, load_recipe
from build_environment import runner_ca_bundle
from platform_policy import apt_source_list_b64, package_target_policy, scanner_config, target_profile


def run(command, timeout=1200, **kwargs):
    return subprocess.run(command, check=True, timeout=timeout, **kwargs)


def sha256(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            result.update(block)
    return result.hexdigest()


def persist_release_candidates(selected, binary_manifest, output, package, version, source_commit, target_id, profile):
    if (binary_manifest.get("source") != package or binary_manifest.get("targetId") != target_id
            or binary_manifest.get("version") != version
            or binary_manifest.get("architecture") != profile["architecture"]):
        raise RuntimeError("Binary manifest does not match the selected package target and version")
    entries = {item["name"]: item for item in binary_manifest["packages"]}
    binary_output = output / "binary"
    binary_output.mkdir()
    release_candidates = []
    for source_path in sorted(selected):
        item = entries.get(source_path.name)
        if not item:
            raise RuntimeError("Selected package is missing from the verified binary manifest")
        destination = binary_output / source_path.name
        shutil.copyfile(source_path, destination)
        digest = sha256(destination)
        if digest != item["sha256"]:
            raise RuntimeError("Persisted release candidate differs from the verified binary manifest")
        control = dict(
            line.split(": ", 1)
            for line in item["control"].splitlines()
            if ": " in line
        )
        release_candidates.append({
            "name": destination.name,
            "package": control["Package"],
            "version": control["Version"],
            "architecture": control["Architecture"],
            "bytes": destination.stat().st_size,
            "sha256": digest,
        })
    source_dir = output / "source"
    source_paths = sorted(source_dir.glob("*"))
    if not source_paths or not any(path.suffix == ".dsc" for path in source_paths):
        raise RuntimeError("Complete Debian source package is required for a release candidate")
    source_candidates = []
    source_prefix = f"{package}_{version}"
    for path in source_paths:
        if path.is_symlink() or not path.is_file() or path.parent != source_dir:
            raise RuntimeError("Source package contains a non-regular or nested candidate")
        if not (path.name.endswith(".dsc") or ".orig.tar." in path.name or ".debian.tar." in path.name):
            raise RuntimeError("Unexpected file in the Debian source package candidate")
        is_original = ".orig.tar." in path.name
        is_debian = ".debian.tar." in path.name
        expected_prefix = f"{package}_{version}" if not is_original else f"{package}_"
        if not path.name.startswith(expected_prefix):
            raise RuntimeError("Source package filename does not match the candidate source and version")
        if is_original and not re.fullmatch(re.escape(package) + r"_[A-Za-z0-9.+~:-]+\.orig\.tar\.[A-Za-z0-9]+(?:\.asc)?", path.name):
            raise RuntimeError("Original source tarball filename is invalid")
        if is_debian and not path.name.startswith(source_prefix + ".debian.tar."):
            raise RuntimeError("Debian source tarball filename does not match the candidate version")
        source_candidates.append({
            "name": path.name,
            "bytes": path.stat().st_size,
            "sha256": sha256(path),
        })
    (output / "release-candidates.json").write_text(json.dumps({
        "source": package,
        "sourceVersion": version,
        "sourceCommit": source_commit,
        "targetId": target_id,
        "distribution": profile["codename"],
        "architecture": profile["architecture"],
        "publication": "not published; runner-local candidates for a protected staging job",
        "packages": release_candidates,
        "sourceFiles": source_candidates,
    }, indent=2) + "\n")


def run_getpatched_scan(image, image_id, phase, output, temp, package, expected, recipe_directory):
    status_result = run(["docker", "run", "--rm", "--network", "none", image, "cat", "/var/lib/dpkg/status"], capture_output=True, text=True, timeout=60)
    if len(status_result.stdout.encode()) > 16 * 1024 * 1024:
        raise RuntimeError("Installed dpkg status inventory exceeds the scanner input bound")
    status_path = output / (package + "-getpatched-status-" + phase + ".txt")
    status_path.write_text(status_result.stdout)
    command = [
        sys.executable, str(ROOT / "scripts/getpatched-scan.py"), "--feed", str(ROOT / "advisories/getpatched-osv.json"),
        "--status-file", str(status_path), "--release", expected["codename"],
        "--architecture", expected["architecture"], "--target-id", expected["targetId"], "--image-id", image_id,
    ]
    command.extend(["--regression-directory", str(output), "--regression-phase", phase,
                    "--scan-images", str(output / "scan-images.json"),
                    "--recipe-directory", str(recipe_directory),
                    "--policy-file", str(output / "package-policy.json"),
                    "--effective-feed-output", str(output / (package + "-verification-advisory-osv.json"))])
    # Candidate mode independently reruns both installed regression suites inside
    # the baseline and patched images before classifying either scan.
    scan = subprocess.run(command, capture_output=True, text=True, timeout=900, check=False)
    if scan.returncode not in (0, 1):
        raise RuntimeError("GetPatched advisory scan failed: " + scan.stderr[-2000:])
    report = json.loads(scan.stdout)
    report_path = output / (package + "-getpatched-scan-" + phase + ".json")
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    target_cves = set(expected["targetCves"])
    versions = report.get("scannedPackageVersions", {})
    advisory_packages = set(expected["advisoryPackages"])
    if report.get("imageId") != image_id or not advisory_packages.issubset(versions):
        raise RuntimeError("GetPatched scan did not identify every expected advisory package and image")
    expected_version = expected["baselineVersion"] if phase == "before" else expected["packageVersion"]
    if any(versions[name] != expected_version for name in advisory_packages):
        raise RuntimeError("GetPatched scan identified an unexpected installed package version")
    target_findings = set(report.get("findingsById", [])) & target_cves
    finding_pairs = {(finding.get("id"), finding.get("package")) for finding in report.get("findings", [])}
    expected_pairs = {(cve, binary) for cve in target_cves for binary in advisory_packages}
    if phase == "before" and (not target_cves.issubset(target_findings) or not expected_pairs.issubset(finding_pairs)):
        raise RuntimeError("GetPatched advisory scan did not detect every target CVE for every vulnerable binary on the baseline")
    if phase == "after" and target_findings:
        raise RuntimeError("GetPatched advisory scan reported target findings on the tested patched image")
    return {"report": report_path, "status": status_path}


def rerun_installed_regression(image, image_id, verification_id, container_platform, recipe, policy_path, output, phase):
    """Run the checked-in regression runner in the exact baseline or patched scan image."""
    report_phase = "baseline" if phase == "before" else "patched"
    report_path = output / (report_phase + "-regression.json")
    run([
        "docker", "run", "--rm", "--platform", container_platform, "--network", "none",
        "--mount", "type=bind,source=" + str(recipe) + ",target=/recipe,readonly",
        "--mount", "type=bind,source=" + str(ROOT / "verification") + ",target=/verification,readonly",
        "--mount", "type=bind,source=" + str(policy_path) + ",target=/package-policy.json,readonly",
        "--mount", "type=bind,source=" + str(output) + ",target=/output",
        image, "python3", "/verification/regression.py", "--recipe", "/recipe",
        "--policy", "/package-policy.json", "--phase", report_phase,
        "--image-id", image_id, "--verification-id", verification_id,
        "--output", "/output/" + report_path.name,
    ], timeout=180)


def validate_release_policy(policy, config):
    package = policy["source"]
    profile = target_profile(config, policy["targetId"])
    expected = package_target_policy(config, package, policy["targetId"])
    expected = dict(expected, targetId=policy["targetId"], codename=profile["codename"], architecture=profile["architecture"])
    if (policy["baseVersion"] != expected["baselineVersion"] or
        policy["sponsorDelayHours"] != expected["releaseAccess"]["sponsorDelayHours"] or
        policy["version"] != expected["packageVersion"] or
        policy["releaseSerial"] != expected["releaseSerial"]):
        raise RuntimeError("Packaging policy disagrees with project configuration")
    if (expected["targetCve"] not in policy["targetCves"]
            or policy["targetCves"] != expected["targetCves"]
            or policy["binaryPackages"] != expected["binaryPackages"]
            or policy["architecture"] != profile["architecture"]
            or policy["release"] != profile["codename"]
            or policy["distribution"] != profile["distribution"]
            or policy["releaseVersion"] != profile["releaseVersion"]
            or policy["version"] != expected["packageVersion"]):
        raise RuntimeError("Unexpected pilot backport identity")
    return package, expected, profile


def release_eligibility(policy, verification_checks_passed=False, publication_enabled=False):
    if verification_checks_passed is not True:
        raise RuntimeError("Release candidate is unavailable until all public target verification checks pass")
    return {
        "schemaVersion": 1,
        "source": policy["source"],
        "targetId": policy["targetId"],
        "sourceVersion": policy["version"],
        "releaseSerial": policy["releaseSerial"],
        "supportScope": policy["targetId"],
        "verificationChecksPassed": verification_checks_passed,
        "releaseEligible": publication_enabled,
        "ubuntuProEsmCompatibility": policy.get("ubuntuProEsmCompatibility", "not-applicable"),
        "reason": None if publication_enabled else "repository publication is disabled for this target",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--target", help="exact target id from package-manifest.json; required for multi-target recipes")
    args = parser.parse_args()
    source = args.source.resolve()
    output = args.output.resolve()
    if output.exists() and any(output.iterdir()):
        parser.error("Use an empty output directory to avoid mixed evidence")
    output.mkdir(parents=True, exist_ok=True)
    config = json.loads((ROOT / "packages.json").read_text())
    recipe = load_recipe(source, config, args.target)
    policy = recipe["policy"]
    package, expected, profile = validate_release_policy(policy, config)
    scanner = scanner_config(config)
    ca_secret_args, ca_bundle_sha256, ca_bundle_source = runner_ca_bundle()
    container_platform = profile["build"]["containerPlatform"]
    build_sources = apt_source_list_b64(profile)
    binary_sources = apt_source_list_b64(profile, include_sources=False)
    if run(["git", "-C", str(source), "status", "--porcelain"], capture_output=True, text=True).stdout.strip():
        raise RuntimeError("Commit the reviewed packaging changes before recording build evidence")
    commit = run(["git", "-C", str(source), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise RuntimeError("Recipe checkout did not resolve to a full Git commit")
    output.mkdir(parents=True, exist_ok=True)
    (output / "package-policy.json").write_text(json.dumps(policy, indent=2) + "\n")
    with tempfile.TemporaryDirectory(prefix="getpatched-build-inputs-") as directory:
        temp = Path(directory)
        name = "getpatched-build-" + package + "-" + uuid.uuid4().hex[:12]
        container = name + "-job"
        scan_base = name + "-baseline"
        scan_patched = name + "-patched"
        built = False
        started = False
        scan_images = []
        originals = temp / "originals"
        originals.mkdir()
        downloaded_sources = download_source_assets(recipe, originals)
        source_provenance = {
            "schemaVersion": 1,
            "source": package,
            "targetId": recipe["target"]["id"],
            "baseVersion": policy["baseVersion"],
            "packageVersion": policy["version"],
            "releaseSerial": policy["releaseSerial"],
            "recipeCommit": commit,
            "recipeManifestSha256": sha256(source / "package-manifest.json"),
            "patchMetadataSha256": sha256(source / recipe["manifest"]["patchMetadata"]),
            "platformPolicySha256": sha256(ROOT / "packages.json"),
            "sourcePublication": recipe["target"]["source"]["publication"],
            "sourcePublishedAt": recipe["target"]["source"]["publishedAt"],
            "sourceDescriptor": recipe["descriptor"],
            "sourceFiles": recipe["sourceFiles"],
            "downloadedSources": downloaded_sources,
            "signatureVerification": recipe["target"]["source"]["signatureVerification"],
            "patches": [
                {
                    "id": patch_id,
                    "kind": recipe["patchesById"][patch_id].get("kind", "security"),
                    "file": recipe["patchesById"][patch_id]["file"],
                    "sha256": recipe["patchesById"][patch_id]["sha256"],
                    "cves": recipe["patchesById"][patch_id]["cves"],
                    "upstream": recipe["patchesById"][patch_id].get("upstream"),
                    "sourceVersion": policy["baseVersion"],
                }
                for patch_id in policy["patches"] + policy.get("buildPatches", [])
            ],
        }
        provenance_path = temp / "source-provenance.json"
        provenance_path.write_text(json.dumps(source_provenance, indent=2) + "\n")
        try:
            run([
                "docker", "build", "--no-cache", "--platform", container_platform, "--tag", name,
                "--file", str(ROOT / "build/packaging.Containerfile"),
                "--build-arg", "BASE_IMAGE=" + profile["baseImage"],
                *ca_secret_args,
                "--build-arg", "APT_SOURCES_B64=" + build_sources,
                "--build-arg", "SOURCE_PACKAGE=" + package,
                "--build-arg", "EXPECTED_VERSION=" + policy["baseVersion"],
                str(ROOT),
            ], timeout=2700)
            built = True
            builder = run(["docker", "image", "inspect", name, "--format", "{{.Id}}"], capture_output=True, text=True).stdout.strip()
            started = True
            run([
                "docker", "run", "--name", container, "--platform", container_platform,
                "--network", "none", "--cpus", "2", "--memory", "4g", "--pids-limit", "512",
                "--security-opt", "no-new-privileges:true",
                "--mount", "type=bind,source=" + str(source) + ",target=/recipe,readonly",
                "--mount", "type=bind,source=" + str(originals) + ",target=/originals,readonly",
                "--mount", "type=bind,source=" + str(ROOT / "verification") + ",target=/verification,readonly",
                "--mount", "type=bind,source=" + str(ROOT / "build/package.sh") + ",target=/recipe.sh,readonly",
                "--mount", "type=bind,source=" + str(ROOT / "verification/materialize-package.py") + ",target=/materialize-package.py,readonly",
                "--mount", "type=bind,source=" + str(output / "package-policy.json") + ",target=/package-policy.json,readonly",
                "--mount", "type=bind,source=" + str(provenance_path) + ",target=/source-provenance.json,readonly",
                "--mount", "type=bind,source=" + str(output) + ",target=/output",
                name, "bash", "/recipe.sh", str(os.getuid()), str(os.getgid()),
            ], timeout=2400)
            result = {"source": package, "version": policy["version"], "sourceCommit": commit, "targetId": policy["targetId"], "baseImage": profile["baseImage"], "scannerImage": scanner["image"], "runnerCaBundleSource": ca_bundle_source, "runnerCaBundleSha256": ca_bundle_sha256, "archiveSnapshot": profile["archiveSnapshot"], "builderImageId": builder, "toolchainInventory": "build-toolchain.tsv", "publication": "none; binary outputs remained inside the disposable container"}
            result.update({
                "targetId": recipe["target"]["id"],
                "releaseSerial": policy["releaseSerial"],
                "sourceDescriptor": {"name": recipe["descriptor"]["name"], "sha256": recipe["descriptor"]["sha256"]},
                "downloadedSourceAssets": downloaded_sources,
                "patches": source_provenance["patches"],
                "recipeManifestSha256": source_provenance["recipeManifestSha256"],
            })
            (output / "build-provenance.json").write_text(json.dumps(result, indent=2) + "\n")
            (output / "build-container-id.txt").write_text(run(["docker", "container", "inspect", container, "--format", "{{.Id}}"], capture_output=True, text=True).stdout.strip() + "\n")
            debs = temp / "patched-debs"
            debs.mkdir()
            binary_manifest = json.loads((output / "binary-manifest.json").read_text())
            selected = []
            for item in binary_manifest["packages"]:
                binary_name = item["control"].splitlines()[0].split(": ", 1)[1]
                if binary_name not in expected["binaryPackages"]:
                    continue
                target = debs / item["name"]
                run(["docker", "cp", container + ":/build/" + item["name"], str(target)])
                if sha256(target) != item["sha256"]:
                    raise RuntimeError("Extracted package differs from recorded binary manifest")
                selected.append(target)
            if {p.name.split("_", 1)[0] for p in selected} != set(expected["binaryPackages"]):
                raise RuntimeError("Could not extract every patched runtime package")
            patched_context = temp / "patched-context"
            patched_context.mkdir()
            (patched_context / "getpatched").mkdir()
            for deb in selected:
                shutil.copyfile(deb, patched_context / "getpatched" / deb.name)
            shutil.copyfile(ROOT / "build/patched-scan.Containerfile", patched_context / "Dockerfile")
            scan_args = [
                "docker", "build", "--no-cache", "--platform", container_platform, "--tag", scan_patched,
                "--file", str(patched_context / "Dockerfile"),
                "--build-arg", "BASE_IMAGE=" + profile["baseImage"],
                *ca_secret_args,
                "--build-arg", "SOURCE_PACKAGE=" + package,
                "--build-arg", "BASELINE_VERSION=" + policy["baseVersion"],
                "--build-arg", "EXPECTED_VERSION=" + policy["version"],
                "--build-arg", "APT_SOURCES_B64=" + binary_sources,
                "--build-arg", "BINARY_PACKAGES=" + " ".join(expected["binaryPackages"]),
                str(patched_context),
            ]
            run(scan_args)
            scan_images.append(scan_patched)
            run([
                "docker", "build", "--no-cache", "--platform", container_platform, "--tag", scan_base,
                "--file", str(ROOT / "build/baseline.Containerfile"),
                "--build-arg", "BASE_IMAGE=" + profile["baseImage"],
                *ca_secret_args,
                "--build-arg", "SOURCE_PACKAGE=" + package,
                "--build-arg", "EXPECTED_VERSION=" + policy["baseVersion"],
                "--build-arg", "APT_SOURCES_B64=" + binary_sources,
                str(ROOT),
            ])
            scan_images.append(scan_base)
            scan_identity = {"baselineImageId": run(["docker", "image", "inspect", scan_base, "--format", "{{.Id}}"], capture_output=True, text=True).stdout.strip(), "patchedImageId": run(["docker", "image", "inspect", scan_patched, "--format", "{{.Id}}"], capture_output=True, text=True).stdout.strip()}
            (output / "scan-images.json").write_text(json.dumps(scan_identity, indent=2) + "\n")
            regression_verification_id = uuid.uuid4().hex
            rerun_installed_regression(scan_base, scan_identity["baselineImageId"], regression_verification_id, container_platform, source, output / "package-policy.json", output, "before")
            rerun_installed_regression(scan_patched, scan_identity["patchedImageId"], regression_verification_id, container_platform, source, output / "package-policy.json", output, "after")
            getpatched_scan_paths = {}
            for phase, image, image_id in (("before", scan_base, scan_identity["baselineImageId"]), ("after", scan_patched, scan_identity["patchedImageId"])):
                getpatched_scan_paths[phase] = run_getpatched_scan(
                    image, image_id, phase, output, temp, package, expected, source)
            for phase, image in (("before", scan_base), ("after", scan_patched)):
                image_tar = temp / (phase + ".tar")
                run(["docker", "save", "--output", str(image_tar), image])
                command = [
                    "docker", "run", "--rm", "--platform", container_platform,
                    "--mount", "type=bind,source=" + str(temp) + ",target=/work",
                    "--user", str(os.getuid()) + ":" + str(os.getgid()), scanner["image"],
                    "image", "--input", "/work/" + image_tar.name,
                    "--cache-dir", "/work/trivy-cache", "--db-repository", scanner["databaseReference"],
                    "--scanners", "vuln", "--list-all-pkgs", "--format", "json", "--output", "/work/" + phase + "-trivy.json",
                ]
                if phase == "after":
                    command.append("--skip-db-update")
                run(command)
                shutil.copyfile(temp / (phase + "-trivy.json"), output / (package + "-trivy-" + phase + ".json"))
                image_tar.unlink()
            db_files = list((temp / "trivy-cache/db").glob("trivy.db"))
            if len(db_files) != 1 or sha256(db_files[0]) != scanner["databaseSha256"]:
                raise RuntimeError("Paired scans did not use the configured pinned Trivy database digest")
            database_hash = sha256(db_files[0])
            (output / "trivy-database.json").write_text(json.dumps({"reference": scanner["databaseReference"], "sha256": database_hash}, indent=2) + "\n")
            for phase in ("before", "after"):
                report_path = output / (package + "-trivy-" + phase + ".json")
                image_id = scan_identity["baselineImageId" if phase == "before" else "patchedImageId"]
                (output / (package + "-trivy-" + phase + "-metadata.json")).write_text(json.dumps({"phase": phase, "scannerImage": scanner["image"], "imageId": image_id, "databaseReference": scanner["databaseReference"], "databaseSha256": database_hash, "reportSha256": sha256(report_path)}, indent=2) + "\n")
            osv_evidence = {}
            for phase, version in (("before", policy["baseVersion"]), ("after", policy["version"])):
                request_body = {"package": {"name": package, "ecosystem": policy["advisoryEcosystem"]}, "version": version}
                request = urllib.request.Request("https://api.osv.dev/v1/query", data=json.dumps(request_body).encode(), headers={"Content-Type": "application/json", "User-Agent": "getpatched.dev-advisory-audit/0.1"})
                with urllib.request.urlopen(request, timeout=45) as response:
                    response_body = response.read(16 * 1024 * 1024 + 1)
                if len(response_body) > 16 * 1024 * 1024:
                    raise RuntimeError("OSV response exceeds evidence size bound")
                path = output / (package + "-osv-" + phase + ".json")
                path.write_text(json.dumps({"request": request_body, "endpoint": "https://api.osv.dev/v1/query", "response": json.loads(response_body)}, indent=2) + "\n")
                osv_evidence[phase] = str(path)
            audit_input = {
                "source": package, "targetId": policy["targetId"], "baselineVersion": policy["baseVersion"], "patchedVersion": policy["version"],
                "targetCves": policy["targetCves"], "beforeTrivy": str(output / (package + "-trivy-before.json")),
                "afterTrivy": str(output / (package + "-trivy-after.json")), "beforeOsv": osv_evidence["before"], "afterOsv": osv_evidence["after"],
                "baselineRegression": str(output / "baseline-regression.json"), "patchedRegression": str(output / "patched-regression.json"),
                "buildProvenance": str(output / "build-provenance.json"), "binaryManifest": str(output / "binary-manifest.json"),
                "packagePolicy": str(output / "package-policy.json"), "databaseSha256": database_hash, "sourceCommit": commit,
                "beforeScanMetadata": str(output / (package + "-trivy-before-metadata.json")),
                "afterScanMetadata": str(output / (package + "-trivy-after-metadata.json")), "scanImages": str(output / "scan-images.json"),
                "aptToFeed": str(ROOT / "advisories/getpatched-osv.json"),
                "aptToVerificationFeed": str(output / (package + "-verification-advisory-osv.json")),
                "beforeAptToScan": str(getpatched_scan_paths["before"]["report"]), "afterAptToScan": str(getpatched_scan_paths["after"]["report"]),
                "beforeAptToStatus": str(getpatched_scan_paths["before"]["status"]), "afterAptToStatus": str(getpatched_scan_paths["after"]["status"]),
            }
            audit_input_path = temp / "audit-input.json"
            audit_input_path.write_text(json.dumps(audit_input))
            run(["python3", str(ROOT / "scripts/advisory-audit.py"), "--input", str(audit_input_path), "--output", str(output / "advisory-comparison.json")])
            run(["python3", str(ROOT / "scripts/test-apt-repository.py"), "--recipe", str(source), "--policy", str(output / "package-policy.json"), "--output", str(output),
                 "--work", str(temp), "--builder-image", name, "--base-image", profile["baseImage"],
                 "--apt-sources-b64", build_sources])
            (output / "release-eligibility.json").write_text(json.dumps(release_eligibility(
                policy, verification_checks_passed=True, publication_enabled=profile["repository"]["enabled"]
            ), indent=2) + "\n")
            persist_release_candidates(selected, binary_manifest, output, package, policy["version"], commit, policy["targetId"], profile)
            print(package + ": target " + policy["targetId"] + " build, installed regressions, advisory comparison, consumer checks, and signed APT binary/source install passed; repository publication enabled=" + str(profile["repository"]["enabled"]).lower())
        finally:
            try:
                if started:
                    remaining = run(["docker", "container", "ls", "--all", "--filter", "name=^/" + container + "$", "--format", "{{.ID}}"], timeout=60, capture_output=True, text=True)
                    if remaining.stdout.strip():
                        run(["docker", "container", "rm", "--force", container], timeout=60)
            finally:
                for image in scan_images:
                    run(["docker", "image", "rm", image], timeout=60)
                if built:
                    run(["docker", "image", "rm", name], timeout=60)

if __name__ == "__main__":
    main()
