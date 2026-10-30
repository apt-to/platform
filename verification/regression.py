#!/usr/bin/env python3
"""Verify bounded regressions against installed focal packages, before and after."""
import argparse
import binascii
import hashlib
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


def tiff_baseline_reproduced(check):
    log = check.get("memoryLog", "")
    return (
        not check.get("timedOut", False)
        and check.get("returncode") == 97
        and "Invalid read of size 8" in log
        and "0 bytes after a block of size 64" in log
        and "loadImage" in log
        and ("srcbuffs" in log or "combineSeparateSamplesBytes" in log)
    )


def tiff_null_output_baseline_reproduced(check):
    log = check.get("memoryLog", "")
    return (
        not check.get("timedOut", False)
        and check.get("returncode") == 97
        and "Invalid read" in log
        and ("Address 0x8" in log or "Address 0x0" in log)
    )


def tiffdither_overrun_baseline_reproduced(check):
    log = check.get("memoryLog", "")
    return (
        not check.get("timedOut", False)
        and check.get("returncode") == 97
        and ("Invalid write" in log or "Invalid read" in log)
        and ("fsdither" in log or "tiffdither" in log)
    )


def libpng_overwrite_reproduced(check):
    log = check.get("memoryLog", "")
    return (not check.get("timedOut", False) and check.get("returncode") == 97
            and "Invalid write" in log and "png_image_finish_read" in log
            and "libpng16.so." in log)


def libpng_stride_read_reproduced(check):
    log = check.get("memoryLog", "")
    return (not check.get("timedOut", False) and check.get("returncode") == 97
            and "Invalid read" in log and "png_image_write_to_file" in log
            and "libpng16.so." in log)


def libpng_followup_read_is_clean(check):
    log = check.get("memoryLog", "")
    return (not check.get("timedOut", False) and check.get("returncode") == 0
            and "ERROR SUMMARY: 0 errors" in log)


def poppler_uaf_reproduced(check):
    log = check.get("memoryLog", "")
    return (not check.get("timedOut", False) and check.get("returncode") == 97
            and any(error in log for error in ("Invalid read", "Invalid write", "Invalid free"))
            and "StructTreeRoot" in log and "parentTreeAdd" in log)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--recipe", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--phase", choices=("baseline", "patched"), required=True)
    parser.add_argument("--image-id", help="image digest or ID containing the installed package")
    parser.add_argument("--verification-id", help="unique identifier pairing the baseline and patched image checks")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads((args.recipe / "package-manifest.json").read_text())
    policy = json.loads(args.policy.read_text())
    package = policy["source"]
    fixtures = args.recipe / manifest["regressionTests"]["fixturesDirectory"]
    expected = policy["baseVersion"] if args.phase == "baseline" else policy["version"]
    installed_name = {
        "libxml2": "libxml2",
        "libarchive": "libarchive13",
        "tiff": "libtiff-tools",
        "libpng1.6": "libpng16-16",
        "poppler": "libpoppler97",
    }.get(package)
    if installed_name is None:
        raise RuntimeError("Unsupported source package")
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
                    "--read-var-info=yes",
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
        elif package == "tiff":
            fixture = fixtures / "multisample.tif"
            if not fixture.is_file() or not 0 < fixture.stat().st_size < 1024 * 1024:
                raise RuntimeError("TIFF regression fixture is missing or exceeds its size bound")
            dump_prefix = temp / "tiffcrop-debug"
            output = temp / "tiffcrop-output.tif"
            missing_output = temp / "missing-output-parent" / "output.tif"
            null_command = [
                "tiffcrop", "-D", f"format:txt,level:2,input:{dump_prefix}",
                str(fixture), str(missing_output),
            ]
            null_log = temp / "tiffcrop-null-output.valgrind"
            null_check = execute([
                "valgrind", "--tool=memcheck", "--error-exitcode=97", "--leak-check=no",
                "--read-var-info=yes", "--log-file=" + str(null_log), *null_command,
            ])
            null_check["memoryLog"] = null_log.read_text() if null_log.exists() else ""
            null_check["cve"] = "CVE-2025-61143"
            null_check["testId"] = "tiffcrop-null-output-debug-log"
            null_check["passed"] = (
                tiff_null_output_baseline_reproduced(null_check)
                if args.phase == "baseline"
                else null_check["returncode"] in (0, 1) and "ERROR SUMMARY: 0 errors" in null_check["memoryLog"]
            )
            checks.append(null_check)

            command = [
                "tiffcrop", "-D", f"format:txt,level:2,input:{dump_prefix}",
                str(fixture), str(output),
            ]
            memory_log = temp / "tiffcrop.valgrind"
            check = execute([
                "valgrind", "--tool=memcheck", "--error-exitcode=97", "--leak-check=no",
                "--read-var-info=yes", "--log-file=" + str(memory_log), *command,
            ])
            check["memoryLog"] = memory_log.read_text() if memory_log.exists() else ""
            check["cve"] = "CVE-2025-61144"
            check["passed"] = (
                tiff_baseline_reproduced(check)
                if args.phase == "baseline"
                else check["returncode"] == 0 and "ERROR SUMMARY: 0 errors" in check["memoryLog"]
                and output.is_file() and output.stat().st_size > 0
            )
            checks.append(check)

            dither_fixture = fixtures / "subscanline.tif"
            if not dither_fixture.is_file() or not 0 < dither_fixture.stat().st_size < 1024 * 1024:
                raise RuntimeError("TIFF dither regression fixture is missing or exceeds its size bound")
            dither_output = temp / "dither-output.tif"
            dither_memory_log = temp / "tiffdither.valgrind"
            dither_check = execute([
                "valgrind", "--tool=memcheck", "--error-exitcode=97", "--leak-check=no",
                "--read-var-info=yes", "--log-file=" + str(dither_memory_log),
                "tiffdither", str(dither_fixture), str(dither_output),
            ])
            dither_check["memoryLog"] = dither_memory_log.read_text() if dither_memory_log.exists() else ""
            dither_check["testId"] = "tiffdither-scanline-width-bound"
            dither_check["passed"] = (
                tiffdither_overrun_baseline_reproduced(dither_check)
                if args.phase == "baseline"
                else dither_check["returncode"] in (0, 1)
                and "ERROR SUMMARY: 0 errors" in dither_check["memoryLog"]
            )
            checks.append(dither_check)

            if args.phase == "patched":
                consumer = execute(["tiffinfo", str(output)])
                consumer["passed"] = consumer["returncode"] == 0 and "Image Width" in consumer["stdout"]
                checks.append(consumer)
        elif package == "libpng1.6":
            cflags = []
            libs = ["-lpng16", "-lz"]
            def compile_probe(name):
                binary = temp / name.removesuffix(".c")
                subprocess.run(["cc", "-std=c99", "-Wall", "-Wextra", "-Werror",
                                *cflags, str(fixtures.parent / name), *libs, "-o", str(binary)],
                               check=True, timeout=30)
                return binary

            adam7 = temp / "adam7.png"
            flat = temp / "flat.png"
            generator = fixtures.parent / "generate-adam7-rgb16.py"
            subprocess.run(["python3", str(generator), str(adam7)], check=True, timeout=10)
            subprocess.run(["python3", str(generator), str(flat), "--flat"], check=True, timeout=10)
            if args.phase == "baseline":
                for cve, source, expected in (
                    ("CVE-2025-65018", "read-interlaced-rgba.c", "Invalid write"),
                    ("CVE-2026-22801", "write-negative-stride.c", "Invalid read"),
                ):
                    binary = compile_probe(source)
                    log = temp / (cve + ".valgrind")
                    check = execute(["valgrind", "--tool=memcheck", "--error-exitcode=97",
                                     "--leak-check=no", "--read-var-info=yes", "--log-file=" + str(log),
                                     str(binary), *([str(adam7)] if cve == "CVE-2025-65018" else [])])
                    check["memoryLog"] = log.read_text() if log.exists() else ""
                    check["cve"] = cve
                    check["passed"] = (libpng_overwrite_reproduced(check) if expected == "Invalid write"
                                       else libpng_stride_read_reproduced(check))
                    checks.append(check)
                binary = compile_probe("read-padded-stride.c")
                log = temp / "CVE-2026-22695.valgrind"
                check = execute(["valgrind", "--tool=memcheck", "--error-exitcode=97",
                                 "--leak-check=no", "--read-var-info=yes", "--log-file=" + str(log),
                                 str(binary), str(adam7)])
                check["memoryLog"] = log.read_text() if log.exists() else ""
                check["cve"] = "CVE-2026-22695"
                check["testId"] = "CVE-2026-22695-padded-stride-follow-up"
                check["passed"] = libpng_followup_read_is_clean(check)
                checks.append(check)
            else:
                for name, args_for_probe in (
                    ("read-interlaced-rgba.c", [str(adam7)]),
                    ("read-padded-stride.c", [str(adam7)]),
                    ("write-negative-stride.c", []),
                ):
                    binary = compile_probe(name)
                    log = temp / (binary.name + ".valgrind")
                    check = execute(["valgrind", "--tool=memcheck", "--error-exitcode=97",
                                     "--leak-check=no", "--read-var-info=yes", "--log-file=" + str(log),
                                     str(binary), *args_for_probe])
                    check["memoryLog"] = log.read_text() if log.exists() else ""
                    check["passed"] = (libpng_followup_read_is_clean(check)
                                       if name == "read-padded-stride.c"
                                       else not check.get("timedOut") and check.get("returncode") == 0
                                       and "ERROR SUMMARY: 0 errors" in check["memoryLog"])
                    check["testId"] = name
                    checks.append(check)
                checks[0]["cve"] = "CVE-2025-65018"
                checks[2]["cve"] = "CVE-2026-22801"
                comparison = compile_probe("compare-interlaced-read.c")
                check = execute([str(comparison), str(adam7), str(flat)])
                check["passed"] = check["returncode"] == 0 and "differing channels: 0 / 3072" in check["stdout"]
                checks.append(check)
                checks[1]["cve"] = "CVE-2026-22695"
                checks[1]["testId"] = "CVE-2026-22695-padded-stride-follow-up"
        elif package == "poppler":
            fixture = fixtures / "bug.pdf"
            if not fixture.is_file() or not 0 < fixture.stat().st_size < 1024 * 1024:
                raise RuntimeError("Poppler CVE regression fixture is missing or exceeds its size bound")
            memory_log = temp / "pdfinfo.valgrind"
            check = execute([
                "valgrind", "--tool=memcheck", "--error-exitcode=97", "--leak-check=no",
                "--read-var-info=yes", "--log-file=" + str(memory_log),
                "pdfinfo", "-struct", str(fixture),
            ])
            check["memoryLog"] = memory_log.read_text() if memory_log.exists() else ""
            check["cve"] = "CVE-2025-52885"
            check["testId"] = "CVE-2025-52885-structtree-uaf"
            check["passed"] = (
                poppler_uaf_reproduced(check)
                if args.phase == "baseline"
                else not check.get("timedOut") and check.get("returncode") == 0
                and "ERROR SUMMARY: 0 errors" in check["memoryLog"]
            )
            checks.append(check)
            if args.phase == "patched":
                consumer = execute(["pdfinfo", "-v"])
                consumer["passed"] = consumer.get("returncode") == 0 and "pdfinfo version" in consumer.get("stdout", "")
                checks.append(consumer)
        else:
            raise RuntimeError("Unsupported source package")
    report = {
        "runner": "getpatched-platform-regression/1",
        "runnerSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "imageId": args.image_id,
        "verificationId": args.verification_id,
        "source": package, "targetId": policy["targetId"], "distribution": policy["distribution"],
        "release": policy["release"], "architecture": policy["architecture"],
        "phase": args.phase, "installedVersion": installed, "expectedVersion": expected,
        "checks": checks, "passed": bool(checks) and all(c["passed"] for c in checks),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(package, args.phase, "PASS" if report["passed"] else "FAIL")
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
