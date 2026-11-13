"""Hardware-free release packaging tests; part of the normal unittest suite."""

import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("build_release", ROOT / "scripts" / "build_release.py")
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


class ReleasePackagingTests(unittest.TestCase):
    def test_current_repo_can_build_complete_verified_zip(self):
        tag = "v" + release.module_version(ROOT / release.VERSION_FILE)
        with tempfile.TemporaryDirectory() as temporary:
            archive_path, checksum_path = release.build_archive(
                tag, repository_root=ROOT, output_dir=Path(temporary)
            )
            self.assertTrue(archive_path.exists())
            self.assertEqual(archive_path.name, f"wcopy_reader_package_{tag}.zip")
            self.assertTrue(checksum_path.exists())
            with ZipFile(archive_path) as archive:
                root = f"wcopy_reader_package_{tag}/"
                self.assertEqual(
                    archive.namelist(),
                    [root + path for path in release.PACKAGE_FILES],
                )
                self.assertIsNone(archive.testzip())
                self.assertIn(b"__version__", archive.read(root + release.VERSION_FILE))
                self.assertNotIn("original_exe/", "\n".join(archive.namelist()))
                self.assertNotIn("tests_and_other/", "\n".join(archive.namelist()))
            checksum = hashlib.sha256(archive_path.read_bytes()).hexdigest()
            self.assertEqual(
                checksum_path.read_text(encoding="ascii"),
                f"{checksum}  {archive_path.name}\n",
            )

    def test_tag_must_be_exact_semver_and_match_library_version(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            for bad in (
                "v1.8", "v1.8.0.0", "v1.8.0-rc1", "v01.8.0", "x1.8.0",
                "v1.8.0;rm -rf /", "v9.9.9", "",
            ):
                with self.subTest(tag=bad), self.assertRaises(ValueError):
                    release.build_archive(bad, repository_root=ROOT, output_dir=output)
            self.assertEqual(list(output.iterdir()), [])

    def test_missing_file_refuses_incomplete_release(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            version_file = root / release.VERSION_FILE
            version_file.parent.mkdir(parents=True)
            version_file.write_text('__version__ = "1.8.0"\n', encoding="utf-8")
            with self.assertRaises(FileNotFoundError):
                release.build_archive(
                    "v1.8.0", repository_root=root, output_dir=Path(temporary) / "dist"
                )
            self.assertFalse((Path(temporary) / "dist").exists())

    def test_version_reader_does_not_import_hid_library(self):
        version = release.module_version(ROOT / release.VERSION_FILE)
        self.assertRegex(version, r"^\d+\.\d+\.\d+$")


if __name__ == "__main__":
    unittest.main()
