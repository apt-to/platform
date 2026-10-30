"""Protect classification of the real focal Schematron baseline crash."""
import json
from pathlib import Path
import signal
import unittest

from regression import (libpng_followup_read_is_clean, libpng_overwrite_reproduced, libpng_stride_read_reproduced,
                        consumer_version_succeeded, poppler_uaf_reproduced, schematron_baseline_reproduced,
                        tiff_baseline_reproduced, parse_callback_url, libgit2_redirect_reproduced)


class BaselineClassification(unittest.TestCase):
    def test_recorded_native_crashes_are_reproductions(self):
        fixture = Path(__file__).resolve().parents[1] / "evidence/build-first-libxml2/baseline-regression.json"
        report = json.loads(fixture.read_text())
        self.assertEqual(len(report["checks"]), 2)
        for check in report["checks"]:
            self.assertEqual(check["returncode"], -11)
            self.assertTrue(schematron_baseline_reproduced(check))

    def test_unrelated_crash_is_not_a_reproduction(self):
        self.assertFalse(schematron_baseline_reproduced({"returncode": -11, "timedOut": False, "memoryLog": "Invalid read in unrelated library"}))

    def test_timeout_cannot_be_accepted_as_schematron_proof(self):
        self.assertFalse(schematron_baseline_reproduced({"returncode": None, "timedOut": True, "memoryLog": "Invalid read xmlSchematronValidateDoc libxml2.so.2"}))


class TiffBaselineClassification(unittest.TestCase):
    def test_generic_tiffcrop_debug_dump_sigsegv_is_not_proof(self):
        check = {
            "command": ["valgrind", "--tool=memcheck", "tiffcrop", "-D", "format:txt,level:2,input:/tmp/debug", "/fixture/multisample.tif", "/tmp/out.tif"],
            "returncode": -signal.SIGSEGV,
            "timedOut": False,
        }
        self.assertFalse(tiff_baseline_reproduced(check))

    def test_sigsegv_outside_exact_tiffcrop_debug_dump_is_not_a_reproduction(self):
        unrelated_command = {
            "command": ["tiffinfo", "/fixture/multisample.tif"],
            "returncode": -signal.SIGSEGV,
            "timedOut": False,
        }
        wrong_debug_level = {
            "command": ["tiffcrop", "-D", "format:txt,level:1,input:/tmp/debug", "/fixture/multisample.tif", "/tmp/out.tif"],
            "returncode": -signal.SIGSEGV,
            "timedOut": False,
        }
        self.assertFalse(tiff_baseline_reproduced(unrelated_command))
        self.assertFalse(tiff_baseline_reproduced(wrong_debug_level))

    def test_specific_out_of_bounds_sample_pointer_read_is_a_reproduction(self):
        check = {
            "command": ["valgrind", "--tool=memcheck", "tiffcrop", "-D", "format:txt,level:2,input:/tmp/debug", "/fixture/multisample.tif", "/tmp/out.tif"],
            "returncode": 97,
            "timedOut": False,
            "memoryLog": "==123== Invalid read of size 8\n==123==    at 0x123: loadImage (tools/tiffcrop.c:5493)\n==123== Address 0x... is 0 bytes after a block of size 64 alloc'd\n==123== Stack variable srcbuffs\n==123== ERROR SUMMARY: 1 errors\n",
        }
        self.assertTrue(tiff_baseline_reproduced(check))

    def test_evidence_from_separate_errors_cannot_be_combined(self):
        check = {
            "command": ["valgrind", "--tool=memcheck", "tiffcrop", "-D", "format:txt,level:2,input:/tmp/debug", "/fixture/multisample.tif", "/tmp/out.tif"],
            "returncode": 97,
            "timedOut": False,
            "memoryLog": (
                "==123== Invalid read of size 8\n"
                "==123==    at 0x123: unrelated_function (other.c:10)\n"
                "==123== Address 0x... is 0 bytes after a block of size 64 alloc'd\n\n"
                "==123== Invalid read of size 4\n"
                "==123==    at 0x456: loadImage (tools/tiffcrop.c:5493)\n"
                "==123== Stack variable srcbuffs\n"
                "==123== ERROR SUMMARY: 2 errors\n"
            ),
        }
        self.assertFalse(tiff_baseline_reproduced(check))

    def test_unrelated_stack_read_size_does_not_match_the_sample_pointer_array(self):
        check = {
            "returncode": 97,
            "timedOut": False,
            "memoryLog": "Invalid read of size 8\nat 0x123: unrelated_function (other.c:10)\nAddress 0x... is 0 bytes after a block of size 64 alloc'd\n",
        }
        self.assertFalse(tiff_baseline_reproduced(check))

    def test_tiffcrop_unrelated_read_is_not_a_reproduction(self):
        check = {
            "returncode": 97,
            "timedOut": False,
            "memoryLog": "Invalid read of size 8\nat 0x123: TIFFReadDirectory (tif_dirread.c:10)\nAddress 0x... is 0 bytes after a block of size 64 alloc'd\n",
        }
        self.assertFalse(tiff_baseline_reproduced(check))

    def test_other_loadimage_read_boundary_is_not_a_reproduction(self):
        check = {
            "returncode": 97,
            "timedOut": False,
            "memoryLog": "Invalid read of size 8\nat 0x123: loadImage (tools/tiffcrop.c:5000)\nAddress 0x... is 8 bytes after a block of size 64 alloc'd\n",
        }
        self.assertFalse(tiff_baseline_reproduced(check))

    def test_generic_loadimage_read_without_sample_pointer_context_is_not_a_reproduction(self):
        check = {
            "returncode": 97,
            "timedOut": False,
            "memoryLog": "Invalid read of size 8\nat 0x123: loadImage (tools/tiffcrop.c:5000)\nAddress 0x... is 0 bytes after a block of size 64 alloc'd\n",
        }
        self.assertFalse(tiff_baseline_reproduced(check))

    def test_generic_crash_warning_and_timeout_are_not_reproductions(self):
        warning_only = {
            "returncode": -11,
            "timedOut": False,
            "stderr": "Sum of Photometric type-related color channels",
        }
        timed_out = {
            "returncode": None,
            "timedOut": True,
            "memoryLog": "Invalid read of size 8\n0 bytes after a block of size 64 alloc'd",
        }
        self.assertFalse(tiff_baseline_reproduced(warning_only))
        self.assertFalse(tiff_baseline_reproduced(timed_out))

class LibpngBaselineClassification(unittest.TestCase):
    def test_padded_stride_followup_requires_a_clean_memcheck_result(self):
        clean = {"returncode": 0, "timedOut": False, "memoryLog": "ERROR SUMMARY: 0 errors"}
        error = {"returncode": 97, "timedOut": False, "memoryLog": "ERROR SUMMARY: 1 errors"}
        self.assertTrue(libpng_followup_read_is_clean(clean))
        self.assertFalse(libpng_followup_read_is_clean(error))

    def test_specific_simplified_read_overwrite_is_a_reproduction(self):
        check = {"returncode": 97, "timedOut": False,
                 "memoryLog": "Invalid write of size 4\nat png_image_finish_read\nlibpng16.so.16"}
        self.assertTrue(libpng_overwrite_reproduced(check))

    def test_unrelated_write_does_not_match(self):
        check = {"returncode": 97, "timedOut": False,
                 "memoryLog": "Invalid write of size 4\nat unrelated\nlibpng16.so.16"}
        self.assertFalse(libpng_overwrite_reproduced(check))

    def test_specific_negative_stride_read_is_a_reproduction(self):
        check = {"returncode": 97, "timedOut": False,
                 "memoryLog": "Invalid read of size 4\nat png_image_write_to_file\nlibpng16.so.16"}
        self.assertTrue(libpng_stride_read_reproduced(check))

    def test_passing_exit_cannot_be_counted_as_baseline_reproduction(self):
        check = {"returncode": 0, "timedOut": False,
                 "memoryLog": "Invalid read png_image_write_to_file libpng16.so.16"}
        self.assertFalse(libpng_stride_read_reproduced(check))


class PopplerBaselineClassification(unittest.TestCase):
    def test_structtree_parent_uaf_is_a_reproduction(self):
        check = {
            "returncode": 97,
            "timedOut": False,
            "memoryLog": "Invalid write of size 8\nAddress is 0 bytes inside a freed block\nStructTreeRoot::parentTreeAdd\n",
        }
        self.assertTrue(poppler_uaf_reproduced(check))

    def test_unrelated_invalid_access_is_not_a_poppler_reproduction(self):
        check = {"returncode": 97, "timedOut": False,
                 "memoryLog": "Invalid write of size 8\nUnrelatedFunction\n"}
        self.assertFalse(poppler_uaf_reproduced(check))

    def test_timeout_or_success_is_not_a_baseline_reproduction(self):
        timed_out = {"returncode": None, "timedOut": True,
                     "memoryLog": "Invalid write StructTreeRoot::parentTreeAdd"}
        success = {"returncode": 0, "timedOut": False,
                   "memoryLog": "Invalid write StructTreeRoot::parentTreeAdd"}
        self.assertFalse(poppler_uaf_reproduced(timed_out))
        self.assertFalse(poppler_uaf_reproduced(success))


class ConsumerVersionCheck(unittest.TestCase):
    def test_version_banner_on_stdout_or_stderr_is_accepted(self):
        self.assertTrue(consumer_version_succeeded(
            {"returncode": 0, "timedOut": False, "stderr": "pdfinfo version 0.86.1"},
            "pdfinfo version"))
        self.assertTrue(consumer_version_succeeded(
            {"returncode": 0, "timedOut": False, "stdout": "pdfinfo version 0.86.1"},
            "pdfinfo version"))

    def test_missing_banner_failure_and_timeout_are_rejected(self):
        self.assertFalse(consumer_version_succeeded(
            {"returncode": 0, "timedOut": False, "stdout": "no version here"}, "pdfinfo version"))
        self.assertFalse(consumer_version_succeeded(
            {"returncode": 1, "timedOut": False, "stderr": "pdfinfo version 0.86.1"}, "pdfinfo version"))
        self.assertFalse(consumer_version_succeeded(
            {"returncode": None, "timedOut": True, "stderr": "pdfinfo version 0.86.1"}, "pdfinfo version"))


class CallbackUrlParsing(unittest.TestCase):
    def test_extracts_single_callback_line_without_python_39_string_methods(self):
        self.assertEqual(parse_callback_url("other output\ncallback_url=http://127.0.0.1:8080/repo\n"),
                         "http://127.0.0.1:8080/repo")

    def test_rejects_missing_or_ambiguous_callback_lines(self):
        self.assertIsNone(parse_callback_url("no callback"))
        self.assertIsNone(parse_callback_url("callback_url=first\ncallback_url=second\n"))


class Libgit2RedirectEvidence(unittest.TestCase):
    def test_baseline_requires_fixture_credential_to_reach_redirected_origin(self):
        check = {
            "returncode": 0, "timedOut": False,
            "initialOrigin": "http://127.0.0.1:8001",
            "redirectedOrigin": "http://127.0.0.1:8002",
            "callbackUrls": ["http://127.0.0.1:8001/repository"],
            "redirectedHostReceivedFixtureCredential": True,
        }
        self.assertTrue(libgit2_redirect_reproduced(check, "baseline"))
        check["redirectedHostReceivedFixtureCredential"] = False
        self.assertFalse(libgit2_redirect_reproduced(check, "baseline"))

    def test_patched_run_requires_redirect_origin_and_no_authorization_header(self):
        check = {
            "returncode": 0, "timedOut": False,
            "initialOrigin": "http://127.0.0.1:8001",
            "redirectedOrigin": "http://127.0.0.1:8002",
            "callbackUrls": ["http://127.0.0.1:8002/repository"],
            "redirectedHostAuthorizationHeaderPresent": False,
        }
        self.assertTrue(libgit2_redirect_reproduced(check, "patched"))
        check["redirectedHostAuthorizationHeaderPresent"] = True
        self.assertFalse(libgit2_redirect_reproduced(check, "patched"))

    def test_wrong_callback_origin_and_timeout_are_not_evidence(self):
        check = {
            "returncode": 0, "timedOut": False,
            "initialOrigin": "http://127.0.0.1:8001",
            "redirectedOrigin": "http://127.0.0.1:8002",
            "callbackUrls": ["http://127.0.0.1:8003/repository"],
            "redirectedHostReceivedFixtureCredential": True,
        }
        self.assertFalse(libgit2_redirect_reproduced(check, "baseline"))
        check["callbackUrls"] = ["http://127.0.0.1:8002/repository"]
        check["redirectedHostAuthorizationHeaderPresent"] = False
        check["timedOut"] = True
        self.assertFalse(libgit2_redirect_reproduced(check, "patched"))


if __name__ == "__main__":
    unittest.main()
