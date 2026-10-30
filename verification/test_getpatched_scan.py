"""End-to-end contract for GetPatched's OSV-compatible dpkg advisory scanner."""
import json
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "scripts" / "getpatched-scan.py"
FEED = ROOT / "advisories" / "getpatched-osv.json"
import importlib.util
sys.path.insert(0, str(ROOT / "scripts"))
SCANNER_SPEC = importlib.util.spec_from_file_location("getpatched_scan", SCANNER)
SCANNER_MODULE = importlib.util.module_from_spec(SCANNER_SPEC)
SCANNER_SPEC.loader.exec_module(SCANNER_MODULE)


class GetPatchedScannerContract(unittest.TestCase):
    def test_poppler_candidate_accepts_pdfinfo_version_on_stderr(self):
        cve_check = {
            "returncode": 0,
            "timedOut": False,
            "memoryLog": "ERROR SUMMARY: 0 errors\n",
        }
        consumer_check = {
            "command": ["pdfinfo", "-v"],
            "returncode": 0,
            "timedOut": False,
            "stdout": "",
            "stderr": "pdfinfo version 0.86.1\n",
            "passed": True,
        }
        self.assertTrue(SCANNER_MODULE.poppler_patched_checks_succeeded(cve_check, [consumer_check]))

    def test_libgit2_candidate_requires_each_baseline_and_patched_security_result(self):
        baseline = {
            "CVE-2026-53584": {"cve": "CVE-2026-53584", "passed": True, "returncode": 0, "timedOut": False,
                                "baselinePathEscapeReproduced": True, "outsideDirectoryCreated": True,
                                "result": "result=created:escaped-submodule-directory"},
            "CVE-2026-53585": {"cve": "CVE-2026-53585", "passed": True, "returncode": 0, "timedOut": False,
                                "baselineAcceptedLargeObject": True, "result": "result=accepted:large-object",
                                "declaredObjectSize": 100 * 1024 * 1024},
            "CVE-2026-53586": {"cve": "CVE-2026-53586", "passed": True, "returncode": 0, "timedOut": False,
                                "baselineUsedOriginalOrigin": True, "callbackOrigin": "http://127.0.0.1:1001",
                                "callbackReceivedExpectedOrigin": True,
                                "initialOrigin": "http://127.0.0.1:1001", "redirectedOrigin": "http://127.0.0.1:1002"},
        }
        patched = {
            "CVE-2026-53584": {"cve": "CVE-2026-53584", "passed": True, "returncode": 0, "timedOut": False,
                                "patchedPathRejected": True, "outsideDirectoryCreated": False,
                                "result": "result=rejected:invalid-submodule-path"},
            "CVE-2026-53585": {"cve": "CVE-2026-53585", "passed": True, "returncode": 0, "timedOut": False,
                                "rejectedLargeObject": True, "result": "result=rejected:overly-large-object",
                                "declaredObjectSize": 100 * 1024 * 1024, "configuredObjectLimit": 42 * 1024 * 1024},
            "CVE-2026-53586": {"cve": "CVE-2026-53586", "passed": True, "returncode": 0, "timedOut": False,
                                "patchedUsedRedirectedOrigin": True, "callbackOrigin": "http://127.0.0.1:1002",
                                "callbackReceivedExpectedOrigin": True,
                                "initialOrigin": "http://127.0.0.1:1001", "redirectedOrigin": "http://127.0.0.1:1002"},
        }
        self.assertTrue(SCANNER_MODULE.libgit2_regression_checks_succeeded(baseline, "baseline"))
        self.assertTrue(SCANNER_MODULE.libgit2_regression_checks_succeeded(patched, "patched"))
        baseline["CVE-2026-53585"]["baselineAcceptedLargeObject"] = False
        patched["CVE-2026-53586"]["patchedUsedRedirectedOrigin"] = False
        self.assertFalse(SCANNER_MODULE.libgit2_regression_checks_succeeded(baseline, "baseline"))
        self.assertFalse(SCANNER_MODULE.libgit2_regression_checks_succeeded(patched, "patched"))
        patched["CVE-2026-53586"]["patchedUsedRedirectedOrigin"] = True
        patched["CVE-2026-53585"]["cve"] = "CVE-2026-53584"
        self.assertFalse(SCANNER_MODULE.libgit2_regression_checks_succeeded(patched, "patched"))
        patched["CVE-2026-53585"]["cve"] = "CVE-2026-53585"
        patched["CVE-2026-53586"]["callbackReceivedExpectedOrigin"] = False
        self.assertFalse(SCANNER_MODULE.libgit2_regression_checks_succeeded(patched, "patched"))
        patched["CVE-2026-53586"]["callbackReceivedExpectedOrigin"] = True
        patched["CVE-2026-53584"]["timedOut"] = True
        self.assertFalse(SCANNER_MODULE.libgit2_regression_checks_succeeded(patched, "patched"))

    def test_followup_assessment_requires_the_paired_installed_regression(self):
        config = json.loads((ROOT / "packages.json").read_text())
        target = config["packages"]["libpng1.6"]["targets"]["ubuntu-focal-amd64"]
        cve = "CVE-2026-22695"
        check = {"cve": cve, "testId": target["followUpAssessments"][cve]["regressionTestId"], "passed": True}
        # Baseline applicability is an explicit source-history assessment. The installed
        # padded-stride check is required only on the patched candidate image.
        SCANNER_MODULE.validate_followup_assessment_checks(target, [], "baseline")
        SCANNER_MODULE.validate_followup_assessment_checks(target, [check], "patched")
        with self.assertRaisesRegex(ValueError, "lacks the assessed follow-up check"):
            SCANNER_MODULE.validate_followup_assessment_checks(target, [], "patched")

    def scan_packages(self, entries):
        status = "\n\n".join(
            f"Package: {name}\nStatus: install ok installed\nVersion: {version}\nArchitecture: amd64"
            for name, version in entries.items()
        ) + "\n"
        return self.scan(status)

    def scan(self, status_text, feed=FEED, architecture="amd64", target_id=None, regression_directory=None, image_id=None, regression_phase=None, scan_images=None, recipe_directory=None, policy_file=None, docker_stub_dir=None, docker_report_dir=None, docker_status_file=None, effective_feed_output=None):
        with tempfile.TemporaryDirectory(prefix="getpatched-scan-test-") as directory:
            status = Path(directory) / "status"
            status.write_text(status_text)
            command = [sys.executable, str(SCANNER), "--feed", str(feed), "--status-file", str(status), "--architecture", architecture]
            if target_id:
                command.extend(["--target-id", target_id])
            if regression_directory:
                command.extend(["--regression-directory", str(regression_directory)])
            if image_id:
                command.extend(["--image-id", image_id])
            if regression_phase:
                command.extend(["--regression-phase", regression_phase])
            if scan_images:
                command.extend(["--scan-images", str(scan_images)])
            if recipe_directory:
                command.extend(["--recipe-directory", str(recipe_directory)])
            if policy_file:
                command.extend(["--policy-file", str(policy_file)])
            if effective_feed_output:
                command.extend(["--effective-feed-output", str(effective_feed_output)])
            environment = None
            if docker_stub_dir:
                import os
                environment = dict(os.environ, PATH=str(docker_stub_dir) + os.pathsep + os.environ.get("PATH", ""),
                                   GETPATCHED_TEST_REPORTS=str(docker_report_dir),
                                   GETPATCHED_TEST_IMAGE_STATUS=str(docker_status_file or status))
            return subprocess.run(
                command,
                capture_output=True, text=True, check=False, env=environment,
            )

    def docker_stub(self, directory, reports):
        stub = directory / "bin"
        stub.mkdir()
        executable = stub / "docker"
        executable.write_text("#!" + sys.executable + "\n" + '''import json, os, pathlib, sys
args = sys.argv[1:]
if args[:2] == ["image", "inspect"]:
    print(args[-1])
    raise SystemExit(0)
if args[0] == "run" and args[-1] == "/var/lib/dpkg/status":
    print(pathlib.Path(os.environ["GETPATCHED_TEST_IMAGE_STATUS"]).read_text(), end="")
    raise SystemExit(0)
if args[0] != "run":
    raise SystemExit(3)
phase = args[args.index("--phase") + 1]
image_id = args[args.index("--image-id") + 1]
verification_id = args[args.index("--verification-id") + 1]
output_name = args[args.index("--output") + 1].rsplit("/", 1)[-1]
mount = next(item for item in args if item.startswith("type=bind,") and "target=/proof" in item)
output_root = pathlib.Path(next(part[7:] for part in mount.split(",") if part.startswith("source=")))
source = pathlib.Path(os.environ["GETPATCHED_TEST_REPORTS"]) / (phase + "-regression.json")
report = json.loads(source.read_text())
report["imageId"] = image_id
report["verificationId"] = verification_id
(output_root / output_name).write_text(json.dumps(report))
''')
        executable.chmod(0o755)
        return stub

    def test_baselines_are_found_and_tested_backports_are_clean(self):
        baseline = self.scan("""Package: libxml2
Status: install ok installed
Version: 2.9.10+dfsg-5ubuntu0.20.04.10
Architecture: amd64

Package: libxml2-utils
Status: install ok installed
Version: 2.9.10+dfsg-5ubuntu0.20.04.10
Architecture: amd64

Package: libarchive13
Status: install ok installed
Version: 3.4.0-2ubuntu1.5
Architecture: amd64

Package: libarchive-tools
Status: install ok installed
Version: 3.4.0-2ubuntu1.5
Architecture: amd64
""")
        self.assertEqual(baseline.returncode, 1, baseline.stderr)
        before = json.loads(baseline.stdout)
        self.assertEqual(set(before["findingsById"]), {"CVE-2025-49794", "CVE-2025-49796", "CVE-2026-4111"})
        self.assertEqual(before["summary"]["vulnerablePackages"], 4)
        self.assertEqual({(item["id"], item["package"]) for item in before["findings"]}, {
            (cve, package) for cve, packages in (
                ("CVE-2025-49794", {"libxml2", "libxml2-utils"}),
                ("CVE-2025-49796", {"libxml2", "libxml2-utils"}),
                ("CVE-2026-4111", {"libarchive13", "libarchive-tools"}),
            ) for package in packages
        })

        patched = self.scan("""Package: libxml2
Status: install ok installed
Version: 2.9.10+dfsg-5ubuntu0.20.04.10+getpatched1
Architecture: amd64

Package: libxml2-utils
Status: install ok installed
Version: 2.9.10+dfsg-5ubuntu0.20.04.10+getpatched1
Architecture: amd64

Package: libarchive13
Status: install ok installed
Version: 3.4.0-2ubuntu1.5+getpatched1
Architecture: amd64

Package: libarchive-tools
Status: install ok installed
Version: 3.4.0-2ubuntu1.5+getpatched1
Architecture: amd64
""")
        self.assertEqual(patched.returncode, 0, patched.stderr)
        after = json.loads(patched.stdout)
        self.assertEqual(after["findings"], [])
        self.assertEqual(after["summary"]["scannedPackages"], 4)
        self.assertEqual(after["summary"]["vulnerablePackages"], 0)
        self.assertEqual(after["scanner"], "getpatched-dpkg-osv/1")

    def test_uninstalled_and_wrong_architecture_packages_are_not_reported(self):
        result = self.scan("""Package: libarchive13
Status: deinstall ok config-files
Version: 3.4.0-2ubuntu1.5
Architecture: amd64

Package: libarchive-tools
Status: install ok installed
Version: 3.4.0-2ubuntu1.5
Architecture: arm64
""")
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["summary"]["scannedPackages"], 0)

    def test_scan_rejects_architectures_without_advisory_coverage(self):
        result = self.scan("""Package: libarchive13
Status: install ok installed
Version: 3.4.0-2ubuntu1.5
Architecture: arm64
""", architecture="arm64")
        self.assertEqual(result.returncode, 2)
        self.assertIn("no coverage for focal/arm64", result.stderr)

    def test_same_package_can_be_installed_for_multiple_architectures(self):
        result = self.scan("""Package: libxml2
Status: install ok installed
Version: 2.9.10+dfsg-5ubuntu0.20.04.10
Architecture: amd64

Package: libxml2
Status: install ok installed
Version: 2.9.10+dfsg-5ubuntu0.20.04.10
Architecture: i386
""")
        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["scannedPackageVersions"], {"libxml2": "2.9.10+dfsg-5ubuntu0.20.04.10"})
        self.assertEqual(set(report["findingsById"]), {"CVE-2025-49794", "CVE-2025-49796"})

    def test_getpatched_revisions_and_canonical_esm_fixed_versions_are_clean(self):
        result = self.scan_packages({
            "libxml2": "2.9.10+dfsg-5ubuntu0.20.04.10+getpatched1",
            "libxml2-utils": "2.9.10+dfsg-5ubuntu0.20.04.10+esm1",
            "libarchive13": "3.4.0-2ubuntu1.5+getpatched1",
            "libarchive-tools": "3.4.0-2ubuntu1.5+esm1",
        })
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["summary"]["scannedPackages"], 4)

    def test_unverified_libpng_target_is_not_asserted_in_public_advisory_feed(self):
        records = [affected for advisory in json.loads(FEED.read_text())["vulns"]
                   for affected in advisory["affected"]
                   if affected["ecosystem_specific"]["source_package"] == "libpng1.6"]
        self.assertEqual(records, [])

    def test_unverified_candidate_requires_version_match_and_regression_evidence(self):
        candidate = "4.1.0+git191117-2ubuntu0.20.04.14+getpatched1"

        with tempfile.TemporaryDirectory(prefix="getpatched-tiff-regression-proof-") as directory:
            proof = Path(directory)
            verification_feed = proof / "verification-advisory.json"
            for phase, version in (("baseline", "4.1.0+git191117-2ubuntu0.20.04.14"), ("patched", candidate)):
                checks = []
                cve_check = {
                    "command": ["tiffcrop", "-D", "format:txt,level:2,input:fixture", "fixture.tif", "output.tif"],
                    "returncode": 97 if phase == "baseline" else 0, "stdout": "", "stderr": "",
                    "timedOut": False, "cve": "CVE-2025-61144", "passed": True,
                    "memoryLog": "Invalid read of size 8\nat loadImage\n0 bytes after a block of size 64\nStack variable srcbuffs\n" if phase == "baseline" else "ERROR SUMMARY: 0 errors\n",
                }
                checks.append(cve_check)
                if phase == "patched":
                    checks.append({"command": ["tiffinfo", "output.tif"], "returncode": 0,
                                   "stdout": "Image Width: 16\n", "stderr": "", "timedOut": False, "passed": True})
                (proof / f"{phase}-regression.json").write_text(json.dumps({
                    "runner": "getpatched-platform-regression/1",
                    "runnerSha256": hashlib.sha256((ROOT / "verification/regression.py").read_bytes()).hexdigest(),
                    "source": "tiff", "targetId": "ubuntu-focal-amd64",
                    "imageId": "image-baseline" if phase == "baseline" else "image-patched",
                    "verificationId": "a" * 32,
                    "distribution": "Ubuntu", "release": "focal", "architecture": "amd64", "phase": phase,
                    "installedVersion": version, "expectedVersion": version, "passed": True, "checks": checks,
                }))
            scan_images = proof / "scan-images.json"
            scan_images.write_text(json.dumps({"baselineImageId": "image-baseline", "patchedImageId": "image-patched"}))
            policy_file = proof / "package-policy.json"
            policy_file.write_text(json.dumps({"source": "tiff", "targetId": "ubuntu-focal-amd64",
                                               "baseVersion": "4.1.0+git191117-2ubuntu0.20.04.14",
                                               "version": candidate}))
            docker_stub = self.docker_stub(proof, proof)
            image_status_file = proof / "image-status.txt"
            image_status_file.write_text("Package: libtiff-tools\nStatus: install ok installed\nVersion: 4.1.0+git191117-2ubuntu0.20.04.14\nArchitecture: amd64\n")
            patched_status_file = proof / "patched-image-status.txt"
            patched_status_file.write_text("Package: libtiff-tools\nStatus: install ok installed\nVersion: " + candidate + "\nArchitecture: amd64\n")
            baseline_result = self.scan(
                "Package: libtiff-tools\nStatus: install ok installed\nVersion: 4.1.0+git191117-2ubuntu0.20.04.14\nArchitecture: amd64\n",
                target_id="ubuntu-focal-amd64", regression_directory=proof, image_id="image-baseline",
                regression_phase="before", scan_images=scan_images, recipe_directory=proof,
                policy_file=policy_file, docker_stub_dir=docker_stub, docker_report_dir=proof,
                docker_status_file=image_status_file, effective_feed_output=verification_feed,
            )
            result = self.scan(
                "Package: libtiff-tools\nStatus: install ok installed\nVersion: " + candidate + "\nArchitecture: amd64\n",
                target_id="ubuntu-focal-amd64", regression_directory=proof, image_id="image-patched",
                regression_phase="after", scan_images=scan_images, recipe_directory=proof,
                policy_file=policy_file, docker_stub_dir=docker_stub, docker_report_dir=proof,
                docker_status_file=patched_status_file, effective_feed_output=verification_feed,
            )
            mismatched_inventory = self.scan(
                "Package: unrelated\nStatus: install ok installed\nVersion: 1\nArchitecture: amd64\n",
                target_id="ubuntu-focal-amd64", regression_directory=proof, image_id="image-baseline",
                regression_phase="before", scan_images=scan_images, recipe_directory=proof,
                policy_file=policy_file, docker_stub_dir=docker_stub, docker_report_dir=proof,
                docker_status_file=image_status_file, effective_feed_output=verification_feed,
            )
            verification_feed_hash = hashlib.sha256(verification_feed.read_bytes()).hexdigest()
        self.assertEqual(baseline_result.returncode, 1, baseline_result.stderr)
        self.assertEqual(json.loads(baseline_result.stdout)["findingsById"], ["CVE-2025-61144"])
        self.assertEqual(mismatched_inventory.returncode, 2)
        self.assertIn("does not match the verified candidate image", mismatched_inventory.stderr)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["advisoryFeedMode"], "candidate-verification-only")
        self.assertEqual(report["advisoryFeedSha256"], verification_feed_hash)
        self.assertEqual(report["regressionVerifiedCandidate"], [{"source": "tiff", "targetId": "ubuntu-focal-amd64"}])
        self.assertEqual(set(report["regressionReportSha256"]), {"baseline", "patched"})
        self.assertEqual(report["regressionImageIds"], {"baseline": "image-baseline", "patched": "image-patched"})

    def test_candidate_feed_output_cannot_alias_canonical_feed(self):
        with tempfile.TemporaryDirectory(prefix="getpatched-candidate-feed-alias-") as directory:
            canonical = Path(directory) / "canonical.json"
            canonical.write_bytes(FEED.read_bytes())
            (Path(directory) / "images.json").write_text(json.dumps({"baselineImageId": "image-baseline", "patchedImageId": "image-patched"}))
            (Path(directory) / "policy.json").write_text(json.dumps({"source": "tiff", "targetId": "ubuntu-focal-amd64"}))
            (Path(directory) / "status").write_text("Package: libtiff-tools\nStatus: install ok installed\nVersion: 4.1.0+git191117-2ubuntu0.20.04.14+getpatched1\nArchitecture: amd64\n")
            for phase, version, code, log in (("baseline", "4.1.0+git191117-2ubuntu0.20.04.14", 97,
                                               "Invalid read of size 8\n0 bytes after a block of size 64\nloadImage\nStack variable srcbuffs\n"),
                                              ("patched", "4.1.0+git191117-2ubuntu0.20.04.14+getpatched1", 0,
                                               "ERROR SUMMARY: 0 errors\n")):
                checks = [{"cve": "CVE-2025-61144", "passed": True, "returncode": code, "timedOut": False,
                           "command": ["tiffcrop", "-D", "format:txt,level:2", "multisample.tif"], "memoryLog": log}]
                if phase == "patched":
                    checks.append({"command": ["tiffinfo", "fixture.tif"], "returncode": 0,
                                   "stdout": "Image Width: 16\n", "timedOut": False, "passed": True})
                (Path(directory) / f"{phase}-regression.json").write_text(json.dumps({
                    "runner": "getpatched-platform-regression/1",
                    "runnerSha256": hashlib.sha256((ROOT / "verification/regression.py").read_bytes()).hexdigest(),
                    "source": "tiff", "targetId": "ubuntu-focal-amd64",
                    "imageId": "image-baseline" if phase == "baseline" else "image-patched",
                    "verificationId": "e" * 32, "distribution": "Ubuntu", "release": "focal",
                    "architecture": "amd64", "phase": phase, "installedVersion": version,
                    "expectedVersion": version, "passed": True, "checks": checks,
                }))
            before = hashlib.sha256(canonical.read_bytes()).hexdigest()
            stub = Path(directory) / "bin"
            stub.mkdir()
            docker = stub / "docker"
            docker.write_text("#!" + sys.executable + "\n" + '''import json, os, pathlib, sys
args=sys.argv[1:]
if args[:2] == ["image", "inspect"]:
    print(args[-1]); raise SystemExit(0)
if args[0] == "run" and args[-1] == "/var/lib/dpkg/status":
    print(pathlib.Path(os.environ["GETPATCHED_TEST_IMAGE_STATUS"]).read_text(), end=""); raise SystemExit(0)
if args[0] == "run":
    phase=args[args.index("--phase") + 1]
    image=args[args.index("--image-id") + 1]
    verification=args[args.index("--verification-id") + 1]
    out=args[args.index("--output") + 1].rsplit("/",1)[-1]
    mount=next(item for item in args if item.startswith("type=bind,") and "target=/proof" in item)
    root=pathlib.Path(next(part[7:] for part in mount.split(",") if part.startswith("source=")))
    report=json.loads((pathlib.Path(os.environ["GETPATCHED_TEST_REPORTS"]) / (phase + "-regression.json")).read_text())
    report["imageId"]=image; report["verificationId"]=verification
    (root/out).write_text(json.dumps(report)); raise SystemExit(0)
raise SystemExit(3)
''')
            docker.chmod(0o755)
            result = self.scan("", feed=canonical, target_id="ubuntu-focal-amd64",
                               regression_directory=directory, image_id="image-patched",
                               regression_phase="after", scan_images=Path(directory) / "images.json",
                               recipe_directory=directory, policy_file=Path(directory) / "policy.json",
                               effective_feed_output=canonical, docker_stub_dir=stub,
                               docker_report_dir=directory, docker_status_file=Path(directory) / "status")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must not overwrite the canonical advisory feed", result.stderr)
            self.assertEqual(hashlib.sha256(canonical.read_bytes()).hexdigest(), before)

    def test_candidate_generic_passing_reports_without_target_cve_proof_are_rejected(self):
        with tempfile.TemporaryDirectory(prefix="getpatched-tiff-regression-proof-") as directory:
            proof = Path(directory)
            for phase, version in (("baseline", "4.1.0+git191117-2ubuntu0.20.04.14"), ("patched", "4.1.0+git191117-2ubuntu0.20.04.14+getpatched1")):
                (proof / f"{phase}-regression.json").write_text(json.dumps({
                    "runner": "getpatched-platform-regression/1",
                    "runnerSha256": hashlib.sha256((ROOT / "verification/regression.py").read_bytes()).hexdigest(),
                    "source": "tiff", "targetId": "ubuntu-focal-amd64",
                    "imageId": "image-baseline" if phase == "baseline" else "image-patched",
                    "verificationId": "b" * 32,
                    "distribution": "Ubuntu", "release": "focal", "architecture": "amd64", "phase": phase,
                    "installedVersion": version, "expectedVersion": version, "passed": True,
                    "checks": [{"command": ["true"], "returncode": 0, "timedOut": False, "passed": True}],
                }))
            scan_images = proof / "scan-images.json"
            scan_images.write_text(json.dumps({"baselineImageId": "image-baseline", "patchedImageId": "image-patched"}))
            policy_file = proof / "package-policy.json"
            policy_file.write_text(json.dumps({"source": "tiff", "targetId": "ubuntu-focal-amd64",
                                               "baseVersion": "4.1.0+git191117-2ubuntu0.20.04.14",
                                               "version": "4.1.0+git191117-2ubuntu0.20.04.14+getpatched1"}))
            docker_stub = self.docker_stub(proof, proof)
            result = self.scan(
                "Package: libtiff-tools\nStatus: install ok installed\nVersion: 4.1.0+git191117-2ubuntu0.20.04.14+getpatched1\nArchitecture: amd64\n",
                target_id="ubuntu-focal-amd64", regression_directory=proof, image_id="image-patched",
                regression_phase="after", scan_images=scan_images, recipe_directory=proof,
                policy_file=policy_file, docker_stub_dir=docker_stub, docker_report_dir=proof,
            )
        self.assertEqual(result.returncode, 2)
        self.assertIn("do not cover every configured target CVE", result.stderr)

    def test_candidate_scan_requires_retained_exact_feed_path(self):
        with tempfile.TemporaryDirectory(prefix="getpatched-candidate-feed-required-") as directory:
            proof = Path(directory)
            for phase, version in (("baseline", "4.1.0+git191117-2ubuntu0.20.04.14"), ("patched", "4.1.0+git191117-2ubuntu0.20.04.14+getpatched1")):
                checks = [{"cve": "CVE-2025-61144", "passed": True, "returncode": 97 if phase == "baseline" else 0,
                           "timedOut": False, "command": ["tiffcrop", "-D", "format:txt,level:2", "multisample.tif"],
                           "memoryLog": ("Invalid read of size 8\n0 bytes after a block of size 64\nloadImage\nStack variable srcbuffs\n" if phase == "baseline" else "ERROR SUMMARY: 0 errors\n")}]
                if phase == "patched":
                    checks.append({"command": ["tiffinfo", "fixture.tif"], "returncode": 0,
                                   "stdout": "Image Width: 16\n", "timedOut": False, "passed": True})
                (proof / f"{phase}-regression.json").write_text(json.dumps({
                    "runner": "getpatched-platform-regression/1",
                    "runnerSha256": hashlib.sha256((ROOT / "verification/regression.py").read_bytes()).hexdigest(),
                    "source": "tiff", "targetId": "ubuntu-focal-amd64",
                    "imageId": "image-baseline" if phase == "baseline" else "image-patched",
                    "verificationId": "d" * 32, "distribution": "Ubuntu", "release": "focal",
                    "architecture": "amd64", "phase": phase, "installedVersion": version,
                    "expectedVersion": version, "passed": True, "checks": checks,
                }))
            (Path(directory) / "baseline-regression.json").write_bytes((proof / "baseline-regression.json").read_bytes())
            (Path(directory) / "patched-regression.json").write_bytes((proof / "patched-regression.json").read_bytes())
            (proof / "scan-images.json").write_text(json.dumps({"baselineImageId": "image-baseline", "patchedImageId": "image-patched"}))
            (proof / "package-policy.json").write_text(json.dumps({"source": "tiff", "targetId": "ubuntu-focal-amd64",
                "baseVersion": "4.1.0+git191117-2ubuntu0.20.04.14", "version": "4.1.0+git191117-2ubuntu0.20.04.14+getpatched1"}))
            (proof / "patched-status.txt").write_text("Package: libtiff-tools\nStatus: install ok installed\nVersion: 4.1.0+git191117-2ubuntu0.20.04.14+getpatched1\nArchitecture: amd64\n")
            stub = proof / "bin"
            stub.mkdir()
            docker = stub / "docker"
            docker.write_text("#!" + sys.executable + "\n" + '''import json, os, pathlib, sys
args=sys.argv[1:]
if args[:2] == ["image", "inspect"]:
    print(args[-1]); raise SystemExit(0)
if args[0] == "run":
    if args[-1] == "/var/lib/dpkg/status":
        print(os.environ["GETPATCHED_TEST_IMAGE_STATUS"], end=""); raise SystemExit(0)
    if "python3" in args and "/regression.py" in args:
        phase=args[args.index("--phase") + 1]
        image=args[args.index("--image-id") + 1]
        verification=args[args.index("--verification-id") + 1]
        out=args[args.index("--output") + 1].rsplit("/",1)[-1]
        mount=next(item for item in args if item.startswith("type=bind,") and "target=/proof" in item)
        root=pathlib.Path(next(part[7:] for part in mount.split(",") if part.startswith("source=")))
        report=json.loads((pathlib.Path(os.environ["GETPATCHED_TEST_REPORTS"]) / (phase + "-regression.json")).read_text())
        report["imageId"]=image; report["verificationId"]=verification
        (root/out).write_text(json.dumps(report))
        raise SystemExit(0)
    phase=args[args.index("--phase") + 1]
    image=args[args.index("--image-id") + 1]
    verification=args[args.index("--verification-id") + 1]
    out=args[args.index("--output") + 1].rsplit("/",1)[-1]
    mount=next(item for item in args if item.startswith("type=bind,") and "target=/proof" in item)
    root=pathlib.Path(next(part[7:] for part in mount.split(",") if part.startswith("source=")))
    report=json.loads((pathlib.Path(os.environ["GETPATCHED_TEST_REPORTS"]) / (phase + "-regression.json")).read_text())
    report["imageId"]=image; report["verificationId"]=verification
    (root/out).write_text(json.dumps(report))
    raise SystemExit(0)
raise SystemExit(3)
''')
            docker.chmod(0o755)
            result = self.scan(
                "Package: libtiff-tools\nStatus: install ok installed\nVersion: 4.1.0+git191117-2ubuntu0.20.04.14+getpatched1\nArchitecture: amd64\n",
                target_id="ubuntu-focal-amd64", regression_directory=proof, image_id="image-patched",
                regression_phase="after", scan_images=proof / "scan-images.json", recipe_directory=proof,
                policy_file=proof / "package-policy.json", docker_stub_dir=stub, docker_report_dir=proof,
                docker_status_file=proof / "patched-status.txt",
            )
        self.assertEqual(result.returncode, 2)
        self.assertIn("requires an output path for its exact advisory feed", result.stderr)

    def test_caller_supplied_passing_reports_cannot_replace_execution_in_scan_images(self):
        with tempfile.TemporaryDirectory(prefix="getpatched-forged-regression-proof-") as directory:
            proof = Path(directory)
            for phase, version in (("baseline", "4.1.0+git191117-2ubuntu0.20.04.14"),
                                   ("patched", "4.1.0+git191117-2ubuntu0.20.04.14+getpatched1")):
                (proof / f"{phase}-regression.json").write_text(json.dumps({
                    "runner": "getpatched-platform-regression/1",
                    "runnerSha256": hashlib.sha256((ROOT / "verification/regression.py").read_bytes()).hexdigest(),
                    "source": "tiff", "targetId": "ubuntu-focal-amd64",
                    "imageId": "invented-" + phase, "verificationId": "c" * 32,
                    "distribution": "Ubuntu", "release": "focal", "architecture": "amd64", "phase": phase,
                    "installedVersion": version, "expectedVersion": version, "passed": True,
                    "checks": [
                        {"command": ["tiffcrop"], "returncode": 0, "passed": True, "cve": "CVE-2025-61144",
                         "memoryLog": "ERROR SUMMARY: 0 errors\n"},
                        {"command": ["tiffinfo"], "returncode": 0, "passed": True, "stdout": "Image Width: 16\n"},
                    ],
                }))
            scan_images = proof / "scan-images.json"
            scan_images.write_text(json.dumps({"baselineImageId": "invented-baseline", "patchedImageId": "invented-patched"}))
            policy_file = proof / "package-policy.json"
            policy_file.write_text(json.dumps({"source": "tiff", "targetId": "ubuntu-focal-amd64",
                                               "baseVersion": "4.1.0+git191117-2ubuntu0.20.04.14",
                                               "version": "4.1.0+git191117-2ubuntu0.20.04.14+getpatched1"}))
            stub = proof / "bin"
            stub.mkdir()
            docker = stub / "docker"
            docker.write_text("#!" + sys.executable + "\nraise SystemExit(1)\n")
            docker.chmod(0o755)
            result = self.scan(
                "Package: libtiff-tools\nStatus: install ok installed\nVersion: 4.1.0+git191117-2ubuntu0.20.04.14+getpatched1\nArchitecture: amd64\n",
                target_id="ubuntu-focal-amd64", regression_directory=proof, image_id="invented-patched",
                regression_phase="after", scan_images=scan_images, recipe_directory=proof,
                policy_file=policy_file, docker_stub_dir=stub,
            )
        self.assertEqual(result.returncode, 2)
        self.assertIn("not match a locally inspectable Docker image", result.stderr)

    def test_later_ubuntu_pro_fixed_versions_are_clean(self):
        result = self.scan_packages({
            "libarchive13": "3.4.0-2ubuntu1.5+esm2",
            "libarchive-tools": "3.4.0-2ubuntu1.5+esm2",
        })
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["findings"], [])

    def test_exact_reviewed_baseline_version_is_asserted_affected(self):
        result = self.scan_packages({"libarchive13": "3.4.0-2ubuntu1.5"})
        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual([(item["package"], item["id"]) for item in report["findings"]], [("libarchive13", "CVE-2026-4111")])

    def test_unreviewed_older_versions_fail_closed(self):
        result = self.scan_packages({"libarchive13": "3.4.0-2ubuntu1.4"})
        self.assertEqual(result.returncode, 2)
        self.assertIn("not an exact reviewed affected or GetPatched fixed version", result.stderr)

    def test_unreviewed_versions_between_baseline_and_fixed_boundary_fail_closed(self):
        result = self.scan_packages({"libarchive13": "3.4.0-2ubuntu1.5+getpatched0"})
        self.assertEqual(result.returncode, 2)
        self.assertIn("not an exact reviewed affected or GetPatched fixed version", result.stderr)

    def test_unreviewed_versions_after_fixed_boundary_fail_closed(self):
        result = self.scan_packages({"libarchive13": "3.4.0-2ubuntu1.5+getpatched3"})
        self.assertEqual(result.returncode, 2)
        self.assertIn("not an exact reviewed affected or GetPatched fixed version", result.stderr)

    def test_feed_generation_is_reproducible_and_has_exact_binary_identities(self):
        with tempfile.TemporaryDirectory(prefix="getpatched-feed-test-") as directory:
            output = Path(directory) / "feed.json"
            subprocess.run([sys.executable, str(ROOT / "scripts" / "build_getpatched_advisory_feed.py"), "--output", str(output)], check=True, capture_output=True, text=True)
            generated = json.loads(output.read_text())
        committed = json.loads(FEED.read_text())
        self.assertEqual(generated, committed)
        self.assertEqual({item["id"] for item in committed["vulns"]}, {
            "CVE-2025-49794", "CVE-2025-49796", "CVE-2026-4111",
        })
        ecosystems = {
            (affected["ecosystem_specific"]["source_package"], affected["ecosystem_specific"]["target_id"]): affected["package"]["ecosystem"]
            for item in committed["vulns"] for affected in item["affected"]
        }
        self.assertEqual(ecosystems[("libxml2", "ubuntu-focal-amd64")], "Ubuntu:Pro:20.04:LTS")
        self.assertEqual(ecosystems[("libarchive", "ubuntu-focal-amd64")], "Ubuntu:Pro:20.04:LTS")
        self.assertFalse(any(affected["ecosystem_specific"]["source_package"] in {"libpng1.6", "libgit2", "tiff", "poppler"}
                             for item in committed["vulns"] for affected in item["affected"]))
        self.assertTrue(all("ranges" not in affected for item in committed["vulns"] for affected in item["affected"]))

    def test_scanner_rejects_feed_that_disagrees_with_reviewed_package_policy(self):
        with tempfile.TemporaryDirectory(prefix="getpatched-feed-tamper-") as directory:
            tampered = Path(directory) / "tampered.json"
            document = json.loads(FEED.read_text())
            document["vulns"][0]["affected"][0]["database_specific"]["fixed_versions"][0] += "0"
            tampered.write_text(json.dumps(document))
            # Invoke the public CLI with the tampered feed and a real dpkg-status stanza.
            result = self.scan("Package: libarchive13\nStatus: install ok installed\nVersion: 3.4.0-2ubuntu1.5\nArchitecture: amd64\n", tampered)
        self.assertEqual(result.returncode, 2)
        self.assertIn("does not match the reviewed GetPatched package policy", result.stderr)


if __name__ == "__main__":
    unittest.main()
