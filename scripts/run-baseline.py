#!/usr/bin/env python3
"""Build a clean public focal baseline and retain an unfiltered pinned Trivy report.

This is a candidate selection check, not proof of remediation. It deliberately
uploads no package binary to GitHub artifacts. Run on a disposable Linux runner.
"""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]


def run(arguments, **kwargs):
    return subprocess.run(arguments, check=True, timeout=1200, **kwargs)


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            result.update(block)
    return result.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", required=True, choices=("libxml2", "libarchive"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--database-snapshot", type=Path, help="Reuse an earlier scanner-db directory without updating it")
    args = parser.parse_args()
    config = json.loads((ROOT / "packages.json").read_text())
    package = config["packages"][args.package]
    args.output.mkdir(parents=True, exist_ok=True)
    output = args.output.resolve()
    if (output / "scanner-db").exists():
        parser.error("Output already contains scanner-db; use a fresh evidence directory")
    if args.database_snapshot and not (args.database_snapshot / "trivy.db").is_file():
        parser.error("Database snapshot must contain trivy.db")
    name = "getpatched-baseline-" + args.package + "-" + uuid.uuid4().hex[:12]
    scanner_name = name + "-scanner"
    built = False
    scan_started = False
    with tempfile.TemporaryDirectory(prefix="getpatched-baseline-") as directory:
        temp = Path(directory)
        try:
            database_flags = []
            if args.database_snapshot:
                shutil.copytree(args.database_snapshot, temp / "cache/db")
                database_flags = ["--skip-db-update"]
            run([
                "docker", "build", "--no-cache", "--platform", "linux/amd64", "--tag", name,
                "--file", str(ROOT / "build/baseline.Containerfile"),
                "--build-arg", "BASE_IMAGE=" + config["baseImage"],
                "--build-arg", "TRUST_IMAGE=" + config["scannerImage"],
                "--build-arg", "SOURCE_PACKAGE=" + args.package,
                "--build-arg", "EXPECTED_VERSION=" + package["baselineVersion"],
                "--build-arg", "ARCHIVE_SNAPSHOT=" + config["archiveSnapshot"],
                str(ROOT),
            ])
            built = True
            run(["docker", "save", "--output", str(temp / "baseline.tar"), name])
            scan_started = True
            run([
                "docker", "run", "--rm", "--platform", "linux/amd64",
                "--name", scanner_name,
                "--user", str(os.getuid()) + ":" + str(os.getgid()),
                "--mount", "type=bind,source=" + str(temp) + ",target=/work",
                config["scannerImage"], "image", "--input", "/work/baseline.tar",
                "--cache-dir", "/work/cache", "--scanners", "vuln",
                "--list-all-pkgs", "--format", "json", "--output", "/work/report.json",
                "--db-repository", config["scannerDatabaseReference"],
                *database_flags,
            ])
            report = json.loads((temp / "report.json").read_text())
            findings = []
            packages = []
            for section in report.get("Results", []):
                packages.extend(p for p in section.get("Packages", []) if p.get("Name") in package["binaryPackages"])
                findings.extend(v for v in section.get("Vulnerabilities", []) if v["VulnerabilityID"] == package["targetCve"] and v["PkgName"] in package["binaryPackages"])
            shutil.copyfile(temp / "report.json", output / (args.package + "-trivy.json"))
            metadata = {
                "checkedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "purpose": "baseline candidate selection; no remediation claimed",
                "sourcePackage": args.package,
                "baselineVersion": package["baselineVersion"],
                "targetCve": package["targetCve"],
                "baseImage": config["baseImage"],
                "scannerImage": config["scannerImage"],
                "identifiedPackages": [{k: p.get(k) for k in ("Name", "Version", "SrcName", "SrcVersion")} for p in packages],
                "findings": [{k: v.get(k) for k in ("VulnerabilityID", "PkgName", "InstalledVersion", "FixedVersion", "Severity", "Status", "DataSource")} for v in findings],
                "databaseFiles": {},
                "reportSha256": digest(temp / "report.json"),
            }
            for path in sorted((temp / "cache/db").glob("*")):
                if path.is_file():
                    metadata["databaseFiles"][path.name] = {"sha256": digest(path), "bytes": path.stat().st_size}
            if "trivy.db" not in metadata["databaseFiles"]:
                raise RuntimeError("Scanner database missing; cannot preserve a repeatable comparison")
            shutil.move(str(temp / "cache/db"), str(output / "scanner-db"))
            (output / (args.package + "-baseline.json")).write_text(json.dumps(metadata, indent=2) + "\n")
            if not packages:
                raise RuntimeError("Scanner did not identify candidate packages; report preserved")
            if not args.database_snapshot and metadata["databaseFiles"]["trivy.db"]["sha256"] != config["scannerDatabaseSha256"]:
                raise RuntimeError("Scanner database digest differs from the pinned reference")
            if not findings:
                raise RuntimeError("Target CVE absent from raw baseline Trivy report; preserve report but do not treat this baseline scan as a passing recognition check")
            print(args.package + ": " + package["targetCve"] + " detected; severity=" + ",".join(sorted({v["Severity"] for v in findings})))
        finally:
            try:
                if scan_started:
                    remaining = subprocess.run([
                        "docker", "container", "ls", "--all", "--filter",
                        "name=^/" + scanner_name + "$", "--format", "{{.ID}}",
                    ], check=True, capture_output=True, text=True, timeout=60)
                    if remaining.stdout.strip():
                        subprocess.run(["docker", "container", "rm", "--force", scanner_name], check=True, timeout=60)
            finally:
                if built:
                    subprocess.run(["docker", "image", "rm", name], check=True, timeout=60)


if __name__ == "__main__":
    main()
