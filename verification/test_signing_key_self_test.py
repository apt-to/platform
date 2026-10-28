import importlib.util
from pathlib import Path
import unittest

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "verify-signing-key.py"
SPEC = importlib.util.spec_from_file_location("verify_signing_key", SCRIPT_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class SigningKeyIdentity(unittest.TestCase):
    def test_primary_keys_are_separated_from_signing_subkeys(self):
        fingerprints = """sec:u:4096:1:ABCDEF0123456789:1700000000::u:::scESC:
fpr:::::::::AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:
grp:::::::::primary-key-grip:
uid:u::::1700000000::uid-hash::GetPatched Signing Key:
ssb:u:4096:1:0123456789ABCDEF:1700000000:::::s:
fpr:::::::::BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:
grp:::::::::subkey-grip:
sec:u:4096:1:9876543210ABCDEF:1700000000::u:::scESC:
fpr:::::::::CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC:
grp:::::::::second-primary-key-grip:
"""
        self.assertEqual(
            MODULE.parse_secret_primary_fingerprints(fingerprints),
            ["A" * 40, "C" * 40],
        )


if __name__ == "__main__":
    unittest.main()
