import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/build-package.py"
SPEC = importlib.util.spec_from_file_location("aptto_build_package", SCRIPT)
BUILD_PACKAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD_PACKAGE)


class ReleaseCandidateOutput(unittest.TestCase):
    def test_only_verified_selected_binaries_are_persisted_with_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            build = root / "build"
            output = root / "output"
            build.mkdir()
            output.mkdir()
            source = output / "source"
            source.mkdir()
            binary = build / "libarchive13_3.4.0-2ubuntu1.5+aptto1_amd64.deb"
            binary.write_bytes(b"verified package bytes")
            source_files = {
                "libarchive_3.4.0-2ubuntu1.5+aptto1.dsc": b"source descriptor",
                "libarchive_3.4.0.orig.tar.gz": b"upstream source",
                "libarchive_3.4.0.orig.tar.gz.asc": b"upstream source signature",
                "libarchive_3.4.0-2ubuntu1.5+aptto1.debian.tar.xz": b"debian source",
            }
            for name, content in source_files.items():
                (source / name).write_bytes(content)
            digest = BUILD_PACKAGE.sha256(binary)
            manifest = {"packages": [{
                "name": binary.name,
                "sha256": digest,
                "control": "Package: libarchive13\nVersion: 3.4.0-2ubuntu1.5+aptto1\nArchitecture: amd64\nDepends: libc6\n",
            }]}

            BUILD_PACKAGE.persist_release_candidates(
                [binary], manifest, output, "libarchive", "3.4.0-2ubuntu1.5+aptto1", "a" * 40,
            )

            saved = output / "binary" / binary.name
            self.assertEqual(saved.read_bytes(), binary.read_bytes())
            report = json.loads((output / "release-candidates.json").read_text())
            self.assertEqual(report["publication"], "not published; runner-local candidates for a protected staging job")
            self.assertEqual(report["sourceCommit"], "a" * 40)
            self.assertEqual(report["sourceFiles"], [{
                "name": name,
                "bytes": len(content),
                "sha256": BUILD_PACKAGE.sha256(source / name),
            } for name, content in sorted(source_files.items())])
            self.assertEqual(report["packages"], [{
                "name": binary.name,
                "package": "libarchive13",
                "version": "3.4.0-2ubuntu1.5+aptto1",
                "architecture": "amd64",
                "bytes": len(b"verified package bytes"),
                "sha256": digest,
            }])

    def test_candidate_copy_is_rejected_when_it_differs_from_build_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            build = root / "build"
            output = root / "output"
            build.mkdir()
            output.mkdir()
            source = output / "source"
            source.mkdir()
            (source / "libxml2_2.9.10+aptto1.dsc").write_bytes(b"descriptor")
            binary = build / "libxml2_2.9.10+aptto1_amd64.deb"
            binary.write_bytes(b"tampered package")
            manifest = {"packages": [{
                "name": binary.name,
                "sha256": "0" * 64,
                "control": "Package: libxml2\nVersion: 2.9.10+aptto1\nArchitecture: amd64\n",
            }]}
            with self.assertRaisesRegex(RuntimeError, "verified binary manifest"):
                BUILD_PACKAGE.persist_release_candidates(
                    [binary], manifest, output, "libxml2", "2.9.10+aptto1", "b" * 40,
                )


if __name__ == "__main__":
    unittest.main()
