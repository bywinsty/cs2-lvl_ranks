#!/usr/bin/env python3
import json
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import validate_package as validator


class PackageValidatorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "package"
        self.root.mkdir()
        self.binary = "addons/vip_modules/test.so"
        self.vdf = "addons/metamod/test.vdf"
        self.config = "addons/configs/vip/test.ini"
        (self.root / self.binary).parent.mkdir(parents=True)
        (self.root / self.vdf).parent.mkdir(parents=True)
        (self.root / self.config).parent.mkdir(parents=True)
        elf = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8
        elf += b"\x02\0" + (62).to_bytes(2, "little") + b"\0" * 32
        (self.root / self.binary).write_bytes(elf)
        (self.root / self.vdf).write_text(
            '"Metamod Plugin"\n{\n\t"file"\t"addons/vip_modules/test"\n}\n',
            encoding="utf-8",
        )
        (self.root / self.config).write_text("enabled = 1\n", encoding="utf-8")
        self.manifest = Path(self.temp.name) / "manifest.json"
        self.manifest.write_text(json.dumps({
            "packages": {
                "test": {
                    "files": [self.binary, self.vdf, self.config],
                    "binary": self.binary,
                    "vdf": self.vdf,
                }
            }
        }), encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def test_directory_passes(self):
        validator.validate_package(self.manifest, "test", self.root)

    def test_missing_and_extra_files_fail(self):
        (self.root / self.config).unlink()
        with self.assertRaises(validator.ValidationError):
            validator.validate_package(self.manifest, "test", self.root)
        (self.root / self.config).write_text("enabled = 1\n", encoding="utf-8")
        (self.root / "addons/extra.txt").write_text("bad\n", encoding="utf-8")
        with self.assertRaises(validator.ValidationError):
            validator.validate_package(self.manifest, "test", self.root)

    def test_bad_vdf_and_bad_elf_fail(self):
        (self.root / self.vdf).write_text('"file" "addons/wrong"\n', encoding="utf-8")
        with self.assertRaises(validator.ValidationError):
            validator.validate_package(self.manifest, "test", self.root)
        (self.root / self.vdf).write_text(
            '"file" "addons/vip_modules/test"\n', encoding="utf-8"
        )
        (self.root / self.binary).write_bytes(b"not an elf")
        with self.assertRaises(validator.ValidationError):
            validator.validate_package(self.manifest, "test", self.root)

    def _write_zip(self, path):
        with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as handle:
            for file in self.root.rglob("*"):
                if file.is_file():
                    handle.write(file, file.relative_to(self.root).as_posix())

    def _write_tar(self, path):
        with tarfile.open(path, "w:gz") as handle:
            handle.add(self.root / "addons", arcname="addons")

    def test_zip_and_tar_pass(self):
        zip_path = Path(self.temp.name) / "package.zip"
        tar_path = Path(self.temp.name) / "package.tar.gz"
        self._write_zip(zip_path)
        self._write_tar(tar_path)
        validator.validate_package(
            self.manifest, "test", archive=zip_path, archive_format="zip"
        )
        validator.validate_package(
            self.manifest, "test", archive=tar_path, archive_format="tar.gz"
        )

    def test_invalid_archives_fail(self):
        invalid_zip = Path(self.temp.name) / "invalid.zip"
        invalid_zip.write_bytes(b"not a zip")
        with self.assertRaises(validator.ValidationError):
            validator.validate_package(
                self.manifest, "test", archive=invalid_zip, archive_format="zip"
            )
        invalid_tar = Path(self.temp.name) / "invalid.tar.gz"
        invalid_tar.write_bytes(b"not a tar")
        with self.assertRaises(validator.ValidationError):
            validator.validate_package(
                self.manifest, "test", archive=invalid_tar, archive_format="tar.gz"
            )


if __name__ == "__main__":
    unittest.main()

