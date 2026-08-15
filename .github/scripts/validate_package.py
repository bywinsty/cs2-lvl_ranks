#!/usr/bin/env python3
import argparse
import hashlib
import json
import posixpath
import re
import stat
import sys
import tarfile
import zipfile
from pathlib import Path


class ValidationError(Exception):
    pass


def normalize_path(name):
    name = name.replace("\\", "/")
    if name.startswith("/") or name.startswith("../") or "/../" in name:
        raise ValidationError(f"unsafe archive path: {name}")
    normalized = posixpath.normpath(name).lstrip("./")
    if normalized in ("", ".") or normalized == ".." or normalized.startswith("../"):
        raise ValidationError(f"unsafe archive path: {name}")
    return normalized.rstrip("/")


def expected_directories(expected):
    directories = set()
    for name in expected:
        parts = name.split("/")
        for index in range(1, len(parts)):
            directories.add("/".join(parts[:index]))
    return directories


def validate_elf(data, label):
    if len(data) < 20 or data[:4] != b"\x7fELF":
        raise ValidationError(f"{label}: not an ELF file")
    if data[4] != 2:
        raise ValidationError(f"{label}: ELF is not 64-bit")
    if data[5] != 1:
        raise ValidationError(f"{label}: ELF is not little-endian")
    machine = int.from_bytes(data[18:20], "little")
    if machine != 62:
        raise ValidationError(f"{label}: ELF machine is {machine}, expected x86-64")


def validate_vdf(data, binary_path, label):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValidationError(f"{label}: VDF is not UTF-8") from exc
    matches = re.findall(r'["\']file["\']\s+["\']([^"\']+)["\']', text)
    if len(matches) != 1:
        raise ValidationError(f"{label}: expected exactly one file entry")
    reference = normalize_path(matches[0])
    allowed = {binary_path}
    if binary_path.endswith(".so"):
        allowed.add(binary_path[:-3])
    if reference not in allowed:
        raise ValidationError(
            f"{label}: file entry {reference!r} does not reference {binary_path!r}"
        )


def validate_file_set(root, expected, binary_path, vdf_path):
    if not root.is_dir():
        raise ValidationError(f"package root does not exist: {root}")

    actual = set()
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise ValidationError(f"symlink is not allowed: {relative}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValidationError(f"special file is not allowed: {relative}")
        actual.add(relative)

    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ValidationError(f"package file set mismatch; missing={missing}, extra={extra}")

    for relative in sorted(expected):
        path = root / Path(relative)
        if path.stat().st_size == 0:
            raise ValidationError(f"empty package file: {relative}")

    validate_elf((root / Path(binary_path)).read_bytes(), binary_path)
    validate_vdf((root / Path(vdf_path)).read_bytes(), binary_path, vdf_path)


def validate_archive(archive, archive_format, expected, binary_path, vdf_path):
    if not archive.is_file() or archive.stat().st_size == 0:
        raise ValidationError(f"archive is missing or empty: {archive}")

    archive_files = set()
    archive_data = {}
    allowed_dirs = expected_directories(expected)

    if archive_format == "zip":
        try:
            with zipfile.ZipFile(archive) as handle:
                bad = handle.testzip()
                if bad is not None:
                    raise ValidationError(f"ZIP CRC check failed for {bad}")
                for info in handle.infolist():
                    name = normalize_path(info.filename)
                    if info.is_dir():
                        if name not in allowed_dirs:
                            raise ValidationError(f"unexpected ZIP directory: {name}")
                        continue
                    mode = (info.external_attr >> 16) & 0o170000
                    if mode == stat.S_IFLNK:
                        raise ValidationError(f"ZIP symlink is not allowed: {name}")
                    archive_files.add(name)
                if archive_files != expected:
                    raise ValidationError(
                        f"ZIP file set mismatch; missing={sorted(expected - archive_files)}, "
                        f"extra={sorted(archive_files - expected)}"
                    )
                archive_data[binary_path] = handle.read(binary_path)
                archive_data[vdf_path] = handle.read(vdf_path)
        except zipfile.BadZipFile as exc:
            raise ValidationError(f"invalid ZIP archive: {archive}") from exc
    elif archive_format == "tar.gz":
        try:
            with tarfile.open(archive, "r:gz") as handle:
                members = handle.getmembers()
                for member in members:
                    name = normalize_path(member.name)
                    if member.isdir():
                        if name not in allowed_dirs:
                            raise ValidationError(f"unexpected TAR directory: {name}")
                        continue
                    if not member.isfile():
                        raise ValidationError(f"non-regular TAR member is not allowed: {name}")
                    archive_files.add(name)
                if archive_files != expected:
                    raise ValidationError(
                        f"TAR file set mismatch; missing={sorted(expected - archive_files)}, "
                        f"extra={sorted(archive_files - expected)}"
                    )
                for member in members:
                    name = normalize_path(member.name)
                    if name in (binary_path, vdf_path):
                        extracted = handle.extractfile(member)
                        if extracted is None:
                            raise ValidationError(f"cannot read TAR member: {name}")
                        archive_data[name] = extracted.read()
        except (tarfile.ReadError, EOFError) as exc:
            raise ValidationError(f"invalid TAR archive: {archive}") from exc
    else:
        raise ValidationError(f"unsupported archive format: {archive_format}")

    validate_elf(archive_data[binary_path], f"{archive}:{binary_path}")
    validate_vdf(archive_data[vdf_path], binary_path, f"{archive}:{vdf_path}")


def validate_package(manifest_path, package_key, package_root=None, archive=None, archive_format=None):
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    package = manifest.get("packages", {}).get(package_key)
    if package is None:
        raise ValidationError(f"package key not found in manifest: {package_key}")

    expected = set(package["files"])
    binary_path = package["binary"]
    vdf_path = package["vdf"]
    if binary_path not in expected or vdf_path not in expected:
        raise ValidationError("manifest binary/vdf must be included in files")

    if package_root is not None:
        validate_file_set(package_root, expected, binary_path, vdf_path)
    if archive is not None:
        if archive_format is None:
            raise ValidationError("--archive-format is required with --archive")
        validate_archive(archive, archive_format, expected, binary_path, vdf_path)

    if package_root is None and archive is None:
        raise ValidationError("provide --package-root, --archive, or both")


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main(argv=None):
    parser = argparse.ArgumentParser(description="Validate a CS2 plugin package")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--package-root", type=Path)
    parser.add_argument("--package-key", required=True)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--archive-format", choices=("zip", "tar.gz"))
    args = parser.parse_args(argv)

    try:
        validate_package(
            args.manifest,
            args.package_key,
            args.package_root,
            args.archive,
            args.archive_format,
        )
        if args.archive is not None:
            print(f"sha256={sha256(args.archive)}  {args.archive}")
        print(f"package validation passed: {args.package_key}")
        return 0
    except (ValidationError, OSError, json.JSONDecodeError, KeyError) as exc:
        print(f"package validation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

