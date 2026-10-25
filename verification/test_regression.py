"""Protect classification of the real focal Schematron baseline crash."""
import json
from pathlib import Path
import unittest

from regression import schematron_baseline_reproduced


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


if __name__ == "__main__":
    unittest.main()
