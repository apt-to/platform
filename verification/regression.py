#!/usr/bin/env python3
"""Verify bounded regressions against installed focal packages, before and after."""
import argparse
import binascii
import json
from pathlib import Path
import signal
import subprocess
import tempfile


def execute(command, timeout=30):
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        return {"command": command, "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr, "timedOut": False}
    except subprocess.TimeoutExpired:
        return {"command": command, "returncode": None, "stdout": "", "stderr": "", "timedOut": True}


def schematron_baseline_reproduced(check):
    log = check.get("memoryLog", "")
    return (
        not check["timedOut"]
        and check["returncode"] in (97, -signal.SIGSEGV)
        and "Invalid read" in log
        and "xmlSchematronValidateDoc" in log
        and "libxml2.so." in log
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--phase", choices=("baseline", "patched"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    policy = json.loads((args.source / "debian/aptto/release-policy.json").read_text())
    package = policy["source"]
    fixtures = args.source / "debian/tests/fixtures"
    expected = policy["baseVersion"] if args.phase == "baseline" else policy["version"]
    installed_name = "libxml2" if package == "libxml2" else "libarchive13"
    installed = subprocess.check_output(["dpkg-query", "-W", "-f=${Version}", installed_name], text=True)
    if installed != expected:
        raise RuntimeError("Installed version mismatch: " + installed + " != " + expected)
    checks = []
    with tempfile.TemporaryDirectory(prefix="getpatched-regression-") as directory:
        temp = Path(directory)
        if package == "libxml2":
            for cve in ("CVE-2025-49794", "CVE-2025-49796"):
                stem = cve.lower()
                log = temp / (stem + ".valgrind")
                check = execute([
                    "valgrind", "--tool=memcheck", "--error-exitcode=97", "--leak-check=no",
                    "--log-file=" + str(log), "xmllint", "--nonet", "--schematron",
                    str(fixtures / (stem + ".sct")), str(fixtures / (stem + "_0.xml")),
                ])
                check["cve"] = cve
                check["memoryLog"] = log.read_text() if log.exists() else ""
                check["passed"] = not check["timedOut"] and (
                    schematron_baseline_reproduced(check)
                    if args.phase == "baseline" else
                    check["returncode"] == 3 and "ERROR SUMMARY: 0 errors" in check["memoryLog"]
                )
                checks.append(check)
            if args.phase == "patched":
                normal = temp / "normal.xml"
                normal.write_text("<document><item>compatible</item></document>\n")
                check = execute(["xmllint", "--nonet", "--xpath", "string(/document/item)", str(normal)])
                check["passed"] = check["returncode"] == 0 and check["stdout"] == "compatible\n"
                checks.append(check)
        elif package == "libarchive":
            lines = (fixtures / "test_read_format_rar5_loop_bug.rar.uu").read_bytes().splitlines()
            start = next(i for i, line in enumerate(lines) if line.startswith(b"begin "))
            data = bytearray()
            for line in lines[start + 1:]:
                if line == b"end": break
                data.extend(binascii.a2b_uu(line))
            if not 0 < len(data) < 1024 * 1024:
                raise RuntimeError("Fixture exceeds regression resource bound")
            fixture = temp / "loop.rar"
            fixture.write_bytes(data)
            probe = temp / "archive-probe"
            subprocess.run(["cc", "-std=c99", "-Wall", "-Wextra", "-Werror", str(Path(__file__).with_name("archive-probe.c")), "-larchive", "-o", str(probe)], check=True, timeout=30)
            check = execute([str(probe), str(fixture)], timeout=5)
            check["cve"] = "CVE-2026-4111"
            check["passed"] = check["timedOut"] if args.phase == "baseline" else not check["timedOut"] and check["returncode"] == 0
            checks.append(check)
            if args.phase == "patched":
                item = temp / "consumer.txt"
                item.write_text("consumer round trip\n")
                archive = temp / "consumer.tar.gz"
                create = execute(["bsdtar", "-czf", str(archive), "-C", str(temp), item.name])
                extract = execute(["bsdtar", "-xOf", str(archive), item.name])
                create["passed"] = create["returncode"] == 0
                extract["passed"] = extract["returncode"] == 0 and extract["stdout"] == item.read_text()
                checks.extend([create, extract])
        else:
            raise RuntimeError("Unsupported source package")
    report = {"source": package, "phase": args.phase, "installedVersion": installed, "expectedVersion": expected, "checks": checks, "passed": bool(checks) and all(c["passed"] for c in checks)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(package, args.phase, "PASS" if report["passed"] else "FAIL")
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
