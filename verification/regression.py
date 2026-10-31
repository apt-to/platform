#!/usr/bin/env python3
"""Verify bounded regressions against installed focal packages, before and after."""
import argparse
import base64
import binascii
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import threading
import tempfile
from urllib.parse import urlsplit

LIBPNG_CVE_2025_65018_FIXTURE = "cve-2025-65018-advisory-adam7-rgb16.png"
LIBPNG_CVE_2025_65018_FIXTURE_SHA256 = "9deb34ada9b550df50181e4cd8c947303fd7b2881f61f3f16efa249d845e9905"


def execute(command, timeout=30, env=None):
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, env=env)
        return {"command": command, "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr, "timedOut": False}
    except subprocess.TimeoutExpired as error:
        def partial_output(value):
            if isinstance(value, bytes):
                return value.decode("utf-8", errors="replace")
            if value is None:
                return ""
            return str(value)

        return {
            "command": command,
            "returncode": None,
            "stdout": partial_output(error.stdout),
            "stderr": partial_output(error.stderr),
            "timedOut": True,
        }


def schematron_baseline_reproduced(check):
    log = check.get("memoryLog", "")
    return (
        not check["timedOut"]
        and check["returncode"] in (97, -signal.SIGSEGV)
        and "Invalid read" in log
        and "xmlSchematronValidateDoc" in log
        and "libxml2.so." in log
    )


def valid_tiff_baseline_stack_signature(expected_stack_frames):
    return (
        isinstance(expected_stack_frames, list)
        and len(expected_stack_frames) == 3
        and all(isinstance(offset, str) and re.fullmatch(r"0x[0-9a-fA-F]{1,16}", offset)
                for offset in expected_stack_frames)
        and len(set(expected_stack_frames)) == 3
    )


def tiff_baseline_reproduced(check, expected_stack_frames):
    log = check.get("memoryLog", "")
    command = check.get("command", [])
    debug_dump = next((command[i + 1] for i, arg in enumerate(command[:-1]) if arg == "-D"), "")
    memcheck_options = ("--tool=memcheck", "--error-exitcode=97", "--read-var-info=yes")
    exact_probe = (
        command
        and Path(command[0]).name == "valgrind"
        and all(option in command for option in memcheck_options)
        and "tiffcrop" in command
        and "format:txt" in debug_dump
        and "level:2" in debug_dump
        and any(Path(arg).name == "multisample.tif" for arg in command)
    )
    if (check.get("timedOut", False) or check.get("returncode") != 97 or not exact_probe
            or not valid_tiff_baseline_stack_signature(expected_stack_frames)):
        return False

    error_blocks = re.finditer(
        r"(?ms)^==\d+== Use of uninitialised value of size 8\n(?P<body>.*?)(?=^==\d+== "
        r"(?:Invalid |Use of |Conditional |Syscall param |ERROR SUMMARY)|\Z)",
        log,
    )
    def matches_expected_stack(block):
        frames = re.findall(r"(?m)^==\d+==\s+(?:at|by) .*?$", block.group("body"))
        return len(frames) >= len(expected_stack_frames) and all(
            re.match(
                rf"^==\d+==\s+(?:at|by) {re.escape(offset)}:.*\(in /usr/bin/tiffcrop\)$",
                frame,
            )
            for frame, offset in zip(frames, expected_stack_frames)
        )

    has_expected_tiffcrop_stack = any(matches_expected_stack(block) for block in error_blocks)
    has_memcheck_errors = re.search(r"(?m)^==\d+== ERROR SUMMARY: [1-9]\d* errors?", log)
    return has_expected_tiffcrop_stack and bool(has_memcheck_errors)


def tiff_patched_regression_succeeded(check):
    command = check.get("command", [])
    log = check.get("memoryLog", "")
    expected_stack_frames = check.get("baselineStackFrames")
    error_summary = re.search(r"(?m)^==\d+== ERROR SUMMARY: (\d+) errors?", log)
    vulnerable_stack_present = False
    if valid_tiff_baseline_stack_signature(expected_stack_frames):
        error_blocks = re.finditer(
            r"(?ms)^==\d+== Use of uninitialised value of size 8\n(?P<body>.*?)(?=^==\d+== "
            r"(?:Invalid |Use of |Conditional |Syscall param |ERROR SUMMARY)|\Z)",
            log,
        )
        for block in error_blocks:
            frames = re.findall(r"(?m)^==\d+==\s+(?:at|by) .*?$", block.group("body"))
            if len(frames) >= len(expected_stack_frames) and all(
                re.match(
                    rf"^==\d+==\s+(?:at|by) {re.escape(offset)}:.*\(in /usr/bin/tiffcrop\)$",
                    frame,
                )
                for frame, offset in zip(frames, expected_stack_frames)
            ):
                vulnerable_stack_present = True
                break
    return (
        not check.get("timedOut", False)
        and check.get("returncode") in (0, 97)
        and command
        and Path(command[0]).name == "valgrind"
        and "--tool=memcheck" in command
        and "tiffcrop" in [Path(argument).name for argument in command]
        and any(argument.startswith("format:txt,level:2,input:") for argument in command)
        and any(Path(argument).name == "multisample.tif" for argument in command)
        and valid_tiff_baseline_stack_signature(expected_stack_frames)
        and not vulnerable_stack_present
        and not valgrind_invalid_access_blocks(log)
        and error_summary is not None
        and ((check["returncode"] == 0 and error_summary.group(1) == "0")
             or (check["returncode"] == 97 and int(error_summary.group(1)) > 0))
    )


def tiff_cve_required(policy, cve):
    configured = policy.get("targetCves") if isinstance(policy, dict) else None
    return isinstance(configured, list) and cve in configured


def valgrind_invalid_access_blocks(log):
    pattern = re.compile(
        r"(?ms)^==\d+== (?P<kind>Invalid (?:read|write) of size \d+)\n"
        r"(?P<body>.*?)(?=^==\d+== (?:Invalid |Use of |Conditional |Syscall param |ERROR SUMMARY)|\Z)"
    )
    return list(pattern.finditer(log))


def memcheck_log_path_matches(check, command):
    memory_log_path = check.get("memoryLogPath")
    return (
        isinstance(memory_log_path, str) and bool(memory_log_path)
        and len(command) > 5
        and command[5] == "--log-file=" + memory_log_path
    )


def tiff_null_output_baseline_reproduced(check):
    command = check.get("command", [])
    log = check.get("memoryLog", "")
    output = Path(command[-1]) if command else Path("/")
    debug_dump = next((command[i + 1] for i, arg in enumerate(command[:-1]) if arg == "-D"), "")
    exact_probe = (
        len(command) == 15
        and Path(command[0]).name == "valgrind"
        and command[1:5] == ["--tool=memcheck", "--error-exitcode=97", "--leak-check=no", "--read-var-info=yes"]
        and memcheck_log_path_matches(check, command)
        and Path(command[6]).name == "tiffcrop"
        and command[7:11] == ["-U", "px", "-m", "0,2,0,2"]
        and command[11] == "-D"
        and debug_dump.startswith("format:txt,level:2,output:")
        and Path(command[13]).name == "multisample.tif"
        and Path(output).name == "tiffcrop-output.tif"
    )
    expected_fault = any(
        block.group("kind") == "Invalid read of size 8"
        and "Address 0x0 is not stack'd, malloc'd or (recently) free'd" in block.group("body")
        and re.search(r"(?m)^==\d+==\s+at .*TIFFFileName \(in /usr/lib(?:/[^ )]+)?/libtiff(?:xx)?\.so(?:\.[0-9]+)*\)", block.group("body"))
        for block in valgrind_invalid_access_blocks(log)
    )
    return (
        not check.get("timedOut", False)
        and check.get("returncode") == 97
        and exact_probe
        and expected_fault
        and re.search(r"(?m)^==\d+== ERROR SUMMARY: [1-9]\d* errors?", log)
    )


def tiff_null_output_patched_succeeded(check):
    command = check.get("command", [])
    log = check.get("memoryLog", "")
    output_text = check.get("stdout", "") + check.get("stderr", "")
    output_path = command[-1] if command else ""
    debug_output_path = check.get("debugOutputPath", "")
    debug_option = command[12] if len(command) > 12 else ""
    debug_prefix = debug_option.removeprefix("format:txt,level:2,output:")
    expected_debug_output = debug_prefix + "-write-001.txt"
    return (
        not check.get("timedOut", False)
        and check.get("returncode") == 1
        and len(command) == 15
        and Path(command[0]).name == "valgrind"
        and command[1:5] == ["--tool=memcheck", "--error-exitcode=97", "--leak-check=no", "--read-var-info=yes"]
        and memcheck_log_path_matches(check, command)
        and Path(command[6]).name == "tiffcrop"
        and command[7:11] == ["-U", "px", "-m", "0,2,0,2"]
        and command[11] == "-D"
        and debug_option.startswith("format:txt,level:2,output:")
        and bool(debug_prefix)
        and "," not in debug_prefix
        and Path(debug_prefix).is_absolute()
        and Path(command[13]).name == "multisample.tif"
        and Path(output_path).name == "tiffcrop-output.tif"
        and Path(debug_prefix).parent.resolve() == Path(output_path).parent.resolve()
        and isinstance(debug_output_path, str)
        and Path(debug_output_path).is_absolute()
        and Path(debug_output_path).resolve() == Path(expected_debug_output).resolve()
        and Path(expected_debug_output).parent.resolve() == Path(output_path).parent.resolve()
        and "Unable to define crop regions" in output_text
        and "Combined left and right margins exceed image width" in output_text
        and Path(debug_output_path).name in check.get("debugOutputFiles", [])
        and "Completed run for (not opened)" in check.get("debugOutput", "")
        and "ERROR SUMMARY: 0 errors" in log
    )


def consumer_version_succeeded(check, expected_banner):
    output = check.get("stdout", "") + check.get("stderr", "")
    return not check.get("timedOut", False) and check.get("returncode") == 0 and expected_banner in output


def libpng_probe_command_matches(check, test_id, executable, arguments):
    command = check.get("command")
    prefix = ["valgrind", "--tool=memcheck", "--error-exitcode=97", "--leak-check=no", "--read-var-info=yes"]
    if (check.get("testId") != test_id or not isinstance(command, list)
            or command[:5] != prefix or len(command) != 7 + len(arguments)
            or not command[5].startswith("--log-file=")):
        return False
    binary = Path(command[6])
    log = Path(command[5].split("=", 1)[1])
    allowed_log_names = {binary.name + ".valgrind"}
    cve = check.get("cve")
    if isinstance(cve, str) and cve.startswith("CVE-"):
        allowed_log_names.add(cve + ".valgrind")
    if (binary.name != executable or log.parent != binary.parent
            or log.name not in allowed_log_names):
        return False
    return all(
        Path(argument).name == expected and Path(argument).parent == binary.parent
        for argument, expected in zip(command[7:], arguments, strict=True)
    )


def memcheck_has_no_errors(log):
    summaries = re.findall(r"(?m)^.*ERROR SUMMARY:\s*(.*?)\s*$", log)
    return (len(summaries) == 1
            and re.fullmatch(r"0 errors(?: from \d+ contexts)?(?: \(suppressed: \d+ from \d+\))?", summaries[0]) is not None)


def libpng_output_buffer_result(check, expected_result):
    log = check.get("memoryLog", "")
    return (check.get("cve") == "CVE-2025-65018"
            and libpng_probe_command_matches(check, "read-interlaced-rgba.c", "read-interlaced-rgba", [LIBPNG_CVE_2025_65018_FIXTURE])
            and not check.get("timedOut", False) and check.get("returncode") == 0
            and check.get("stdout", "").strip() == expected_result
            and memcheck_has_no_errors(log))


def libpng_overwrite_reproduced(check):
    return libpng_output_buffer_result(check, "result=overrun:output-buffer")


def libpng_stride_read_reproduced(check):
    log = check.get("memoryLog", "")
    return (check.get("cve") == "CVE-2026-22801"
            and libpng_probe_command_matches(check, "write-negative-stride.c", "write-negative-stride", [])
            and not check.get("timedOut", False) and check.get("returncode") == 97
            and "Invalid read" in log and "png_image_write_to_file" in log
            and "libpng16.so." in log)


def libpng_followup_read_is_clean(check):
    log = check.get("memoryLog", "")
    return (not check.get("timedOut", False) and check.get("returncode") == 0
            and memcheck_has_no_errors(log))


def libpng_patched_checks_succeeded(checks):
    expected = {
        "CVE-2025-65018": ("read-interlaced-rgba.c", "read-interlaced-rgba", [LIBPNG_CVE_2025_65018_FIXTURE]),
        "CVE-2026-22695": ("CVE-2026-22695-padded-stride-follow-up", "read-padded-stride", ["adam7.png"]),
        "CVE-2026-22801": ("write-negative-stride.c", "write-negative-stride", []),
    }
    by_cve = {}
    for cve in expected:
        matches = [check for check in checks if check.get("cve") == cve]
        if len(matches) != 1:
            return False
        by_cve[cve] = matches[0]
    for cve, (test_id, executable, arguments) in expected.items():
        check = by_cve[cve]
        if (check.get("passed") is not True
                or not libpng_probe_command_matches(check, test_id, executable, arguments)
                or check.get("timedOut") is not False
                or check.get("returncode") != 0
                or not memcheck_has_no_errors(check.get("memoryLog", ""))):
            return False
        if cve == "CVE-2025-65018" and check.get("stdout", "").strip() != "result=within-output-buffer":
            return False
    comparisons = [check for check in checks if check.get("testId") == "adam7-pixel-equality"]
    if len(comparisons) != 1:
        return False
    comparison = comparisons[0]
    command = comparison.get("command", [])
    return (
        comparison.get("passed") is True
        and not comparison.get("timedOut", False)
        and comparison.get("returncode") == 0
        and isinstance(command, list) and len(command) == 3
        and Path(command[0]).name == "compare-interlaced-read"
        and [Path(argument).name for argument in command[1:]] == ["adam7.png", "flat.png"]
        and Path(command[0]).parent == Path(command[1]).parent == Path(command[2]).parent
        and "differing channels: 0 / 3072" in comparison.get("stdout", "")
    )


def poppler_uaf_reproduced(check):
    log = check.get("memoryLog", "")
    return (not check.get("timedOut", False) and check.get("returncode") == 97
            and any(error in log for error in ("Invalid read", "Invalid write", "Invalid free"))
            and "StructTreeRoot" in log and "parentTreeAdd" in log)


def compile_libgit2_probe(source, binary, patched):
    flags = shlex.split(subprocess.check_output(
        ["pkg-config", "--cflags", "--libs", "libgit2"], text=True
    ))
    command = ["cc", "-std=c99", "-Wall", "-Wextra", "-Werror", "-Wno-missing-field-initializers"]
    if patched:
        command.append("-DGETPATCHED_PATCHED=1")
    command.extend([str(source), *flags, "-o", str(binary)])
    subprocess.run(command, check=True, timeout=30)
    return binary


def parse_callback_urls(stdout):
    prefix = "callback_url="
    return [line[len(prefix):] for line in stdout.splitlines() if line.startswith(prefix)]


def parse_callback_url(stdout):
    urls = parse_callback_urls(stdout)
    return urls[0] if len(urls) == 1 else None


def libgit2_redirect_reproduced(check, phase):
    if check.get("timedOut") or check.get("returncode") != 0:
        return False
    callback_urls = check.get("callbackUrls", [])
    if not callback_urls:
        return False
    expected_origin = check.get("initialOrigin") if phase == "baseline" else check.get("redirectedOrigin")
    callback_origins = []
    for callback_url in callback_urls:
        parsed = urlsplit(callback_url)
        callback_origins.append(f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else None)
    if any(origin != expected_origin for origin in callback_origins):
        return False
    if phase == "baseline":
        return check.get("redirectedHostReceivedFixtureCredential") is True
    return check.get("redirectedHostAuthorizationHeaderPresent") is False


def run_libgit2_redirect_regression(binary, temp, phase):
    fixture_credential = "Basic " + base64.b64encode(b"getpatched-test:fixture-only-credential").decode("ascii")
    target_state = {"authorizationHeaderPresent": False, "fixtureCredentialReceived": False}

    class RedirectHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", target_origin + self.path)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, _format, *_args):
            pass

    class UnauthorizedHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            authorization = self.headers.get("Authorization")
            target_state["authorizationHeaderPresent"] |= authorization is not None
            target_state["fixtureCredentialReceived"] |= authorization == fixture_credential
            if authorization == fixture_credential:
                # End the baseline request after observing the dummy credential.
                # An empty Git advertisement makes libgit2 return promptly instead
                # of repeating the challenged request until the timeout.
                self.send_response(200)
                self.send_header("Content-Type", "application/x-git-upload-pack-advertisement")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="getpatched-test"')
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, _format, *_args):
            pass

    initial_server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
    target_server = ThreadingHTTPServer(("127.0.0.1", 0), UnauthorizedHandler)
    initial_server.daemon_threads = True
    target_server.daemon_threads = True
    target_origin = f"http://127.0.0.1:{target_server.server_address[1]}"
    initial_origin = f"http://127.0.0.1:{initial_server.server_address[1]}"
    servers = (initial_server, target_server)
    threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in servers]
    try:
        for thread in threads:
            thread.start()
        environment = {
            key: value for key, value in os.environ.items()
            if key.lower() not in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}
        }
        environment["NO_PROXY"] = "127.0.0.1,localhost"
        environment["no_proxy"] = environment["NO_PROXY"]
        environment["GETPATCHED_TRUSTED_ORIGIN"] = initial_origin
        result = execute([
            str(binary), initial_origin + "/repository", str(temp / "redirect-clone"),
        ], timeout=30, env=environment)
        result["callbackUrls"] = parse_callback_urls(result["stdout"])
        result["redirectedHostAuthorizationHeaderPresent"] = target_state["authorizationHeaderPresent"]
        result["redirectedHostReceivedFixtureCredential"] = target_state["fixtureCredentialReceived"]
        return result, initial_origin, target_origin
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=2)


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
    tiff_baseline_stack_frames = None
    if package == "tiff":
        patch_metadata = json.loads((args.recipe / "patches/metadata.json").read_text())
        regression = next((test for patch in patch_metadata.get("patches", [])
                           for test in patch.get("tests", [])
                           if test.get("id") == "tiffcrop-debug-sample-bounds"), None)
        tiff_baseline_stack_frames = (regression or {}).get("baselineStackSignatures", {}).get(policy["targetId"])
    fixtures = args.recipe / manifest["regressionTests"]["fixturesDirectory"]
    expected = policy["baseVersion"] if args.phase == "baseline" else policy["version"]
    binary_packages = policy.get("binaryPackages")
    if not isinstance(binary_packages, list) or not binary_packages or not all(
        isinstance(name, str) and name for name in binary_packages
    ):
        raise RuntimeError("Package policy has no installed binary package for version verification")
    installed_name = binary_packages[0]
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
            output = temp / "tiffcrop-output.tif"
            if tiff_cve_required(policy, "CVE-2025-61143"):
                null_dump_prefix = temp / "tiffcrop-null-output"
                null_log = temp / "tiffcrop-null-output.valgrind"
                null_check = execute([
                    "valgrind", "--tool=memcheck", "--error-exitcode=97", "--leak-check=no",
                    "--read-var-info=yes", "--log-file=" + str(null_log),
                    "tiffcrop", "-U", "px", "-m", "0,2,0,2", "-D",
                    f"format:txt,level:2,output:{null_dump_prefix}", str(fixture), str(output),
                ])
                null_check["memoryLog"] = null_log.read_text() if null_log.exists() else ""
                null_check["memoryLogPath"] = str(null_log)
                debug_path = Path(str(null_dump_prefix) + "-write-001.txt")
                null_check["debugOutputPath"] = str(debug_path)
                null_check["debugOutputFiles"] = [path.name for path in sorted(temp.glob("tiffcrop-null-output-write-*.txt"))]
                null_check["debugOutput"] = (
                    debug_path.read_text() if debug_path.is_file() and debug_path.stat().st_size <= 1024 * 1024 else ""
                )
                null_check["cve"] = "CVE-2025-61143"
                null_check["testId"] = "tiffcrop-null-output-debug-log"
                null_check["passed"] = (
                    tiff_null_output_baseline_reproduced(null_check)
                    if args.phase == "baseline"
                    else tiff_null_output_patched_succeeded(null_check)
                )
                checks.append(null_check)

            if tiff_cve_required(policy, "CVE-2025-61144"):
                dump_prefix = temp / "tiffcrop-debug"
                command = [
                    "tiffcrop", "-D", f"format:txt,level:2,input:{dump_prefix}",
                    str(fixture), str(output),
                ]
                memory_log = temp / "tiffcrop-valgrind.log"
                check = execute([
                    "valgrind", "--tool=memcheck", "--error-exitcode=97", "--leak-check=no",
                    "--read-var-info=yes", "--log-file=" + str(memory_log), *command,
                ])
                check["memoryLog"] = memory_log.read_text() if memory_log.exists() else ""
                check["memoryLogPath"] = str(memory_log)
                check["cve"] = "CVE-2025-61144"
                check["testId"] = "tiffcrop-debug-sample-bounds"
                check["baselineStackFrames"] = tiff_baseline_stack_frames
                check["passed"] = (
                    tiff_baseline_reproduced(check, tiff_baseline_stack_frames)
                    if args.phase == "baseline"
                    else tiff_patched_regression_succeeded(check)
                    and output.is_file() and output.stat().st_size > 0
                )
                checks.append(check)

            if args.phase == "patched":
                consumer = execute(["tiffinfo", str(output)])
                consumer["passed"] = consumer["returncode"] == 0 and "Image Width" in consumer["stdout"]
                checks.append(consumer)
        elif package == "libpng1.6":
            cflags = []
            libs = ["-lpng16", "-lz"]
            cve_fixture_source = fixtures / LIBPNG_CVE_2025_65018_FIXTURE
            if not cve_fixture_source.is_file():
                raise RuntimeError("the CVE-2025-65018 RGB16 Adam7 fixture is missing")
            cve_fixture_data = cve_fixture_source.read_bytes()
            if hashlib.sha256(cve_fixture_data).hexdigest() != LIBPNG_CVE_2025_65018_FIXTURE_SHA256:
                raise RuntimeError("the CVE-2025-65018 RGB16 Adam7 fixture hash does not match metadata")
            cve_fixture = temp / LIBPNG_CVE_2025_65018_FIXTURE
            cve_fixture.write_bytes(cve_fixture_data)

            def compile_probe(name):
                binary = temp / Path(name).stem
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
                for cve, source in (
                    ("CVE-2025-65018", "read-interlaced-rgba.c"),
                    ("CVE-2026-22801", "write-negative-stride.c"),
                ):
                    binary = compile_probe(source)
                    log = temp / (cve + ".valgrind")
                    check = execute(["valgrind", "--tool=memcheck", "--error-exitcode=97",
                                     "--leak-check=no", "--read-var-info=yes", "--log-file=" + str(log),
                                     str(binary), *([str(cve_fixture)] if cve == "CVE-2025-65018" else [])])
                    check["memoryLog"] = log.read_text() if log.exists() else ""
                    check["cve"] = cve
                    check["testId"] = source
                    check["passed"] = (libpng_overwrite_reproduced(check) if cve == "CVE-2025-65018"
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
                for cve, name, args_for_probe in (
                    ("CVE-2025-65018", "read-interlaced-rgba.c", [str(cve_fixture)]),
                    ("CVE-2026-22695", "read-padded-stride.c", [str(adam7)]),
                    ("CVE-2026-22801", "write-negative-stride.c", []),
                ):
                    binary = compile_probe(name)
                    log = temp / (binary.name + ".valgrind")
                    check = execute(["valgrind", "--tool=memcheck", "--error-exitcode=97",
                                     "--leak-check=no", "--read-var-info=yes", "--log-file=" + str(log),
                                     str(binary), *args_for_probe])
                    check["memoryLog"] = log.read_text() if log.exists() else ""
                    check["cve"] = cve
                    check["testId"] = name
                    if cve == "CVE-2025-65018":
                        check["passed"] = libpng_output_buffer_result(check, "result=within-output-buffer")
                    elif cve == "CVE-2026-22695":
                        check["passed"] = libpng_followup_read_is_clean(check)
                    else:
                        check["passed"] = (not check.get("timedOut") and check.get("returncode") == 0
                                           and memcheck_has_no_errors(check["memoryLog"]))
                    checks.append(check)
                comparison = compile_probe("compare-interlaced-read.c")
                check = execute([str(comparison), str(adam7), str(flat)])
                check["passed"] = check["returncode"] == 0 and "differing channels: 0 / 3072" in check["stdout"]
                check["testId"] = "adam7-pixel-equality"
                checks.append(check)
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
                consumer["passed"] = consumer_version_succeeded(consumer, "pdfinfo version")
                checks.append(consumer)
        elif package == "libgit2":
            patched = args.phase == "patched"
            pack_probe = compile_libgit2_probe(
                fixtures / "pack-size-limit.c", temp / "pack-size-limit", patched
            )
            pack_work = temp / "pack-indexer"
            pack_work.mkdir()
            pack_check = execute([
                str(pack_probe), str(fixtures / "delta_100mb.pack"), str(pack_work)
            ], timeout=45)
            pack_check["cve"] = "CVE-2026-53585"
            pack_check["declaredObjectSize"] = 100 * 1024 * 1024
            pack_check["configuredObjectLimit"] = 42 * 1024 * 1024 if patched else None
            pack_check["result"] = pack_check["stdout"].strip()
            pack_check["rejectedLargeObject"] = patched and pack_check["result"] == "result=rejected:overly-large-object"
            pack_check["baselineAcceptedLargeObject"] = not patched and pack_check["result"] == "result=accepted:large-object"
            pack_check["passed"] = pack_check["returncode"] == 0 and not pack_check["timedOut"]
            checks.append(pack_check)

            submodule_probe = compile_libgit2_probe(
                fixtures / "submodule-path.c", temp / "submodule-path", patched
            )
            repo_parent = temp / "submodule-workspace"
            repo_parent.mkdir()
            repo_path = repo_parent / "repo"
            escaped_path = repo_parent / "escape-target"
            submodule_check = execute([str(submodule_probe), str(repo_path)], timeout=20)
            submodule_check["cve"] = "CVE-2026-53584"
            submodule_check["outsideDirectoryCreated"] = escaped_path.is_dir()
            submodule_check["result"] = submodule_check["stdout"].strip()
            submodule_check["baselinePathEscapeReproduced"] = (
                not patched and submodule_check["returncode"] == 0
                and submodule_check["outsideDirectoryCreated"]
                and submodule_check["result"] == "result=created:escaped-submodule-directory"
            )
            submodule_check["patchedPathRejected"] = (
                patched and submodule_check["returncode"] == 0
                and not submodule_check["outsideDirectoryCreated"]
                and submodule_check["result"] == "result=rejected:invalid-submodule-path"
            )
            submodule_check["passed"] = (
                submodule_check["baselinePathEscapeReproduced"] if not patched
                else submodule_check["patchedPathRejected"]
            )
            checks.append(submodule_check)

            redirect_probe = compile_libgit2_probe(
                fixtures / "redirect-auth.c", temp / "redirect-auth", patched
            )
            redirect_result, initial_origin, target_origin = run_libgit2_redirect_regression(
                redirect_probe, temp, args.phase
            )
            redirect_result["cve"] = "CVE-2026-53586"
            redirect_result["initialOrigin"] = initial_origin
            redirect_result["redirectedOrigin"] = target_origin
            redirect_result["initialOrigin"] = initial_origin
            redirect_result["redirectedOrigin"] = target_origin
            redirect_result["callbackOrigin"] = []
            for callback_url in redirect_result["callbackUrls"]:
                callback = urlsplit(callback_url)
                redirect_result["callbackOrigin"].append(
                    f"{callback.scheme}://{callback.netloc}" if callback.scheme and callback.netloc else None
                )
            redirect_result["baselineCredentialLeakReproduced"] = (
                not patched and libgit2_redirect_reproduced(redirect_result, "baseline")
            )
            redirect_result["patchedCredentialLeakPrevented"] = (
                patched and libgit2_redirect_reproduced(redirect_result, "patched")
            )
            redirect_result["passed"] = libgit2_redirect_reproduced(redirect_result, args.phase)
            checks.append(redirect_result)
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
