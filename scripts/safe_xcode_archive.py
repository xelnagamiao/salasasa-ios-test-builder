#!/usr/bin/env python3
"""Validate and unpack a Windows Unity export without trusting ZIP paths/modes."""
import argparse
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import sys
import unicodedata
import zipfile

GIB = 1024 ** 3
MAX_UNPACKED = 12 * GIB
FREE_BUILD_MARGIN = 3 * GIB
EXECUTABLE_MAGIC = {
    b"\x7fELF", b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca",
}


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_member(info):
    raw = info.orig_filename
    if "\x00" in raw or any(ord(ch) < 32 for ch in raw):
        raise ValueError("Archive contains a control character in a path")
    normalized = raw.replace("\\", "/")
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
        raise ValueError("Archive contains an absolute path")
    parts = normalized.rstrip("/").split("/")
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise ValueError("Archive contains an ambiguous or traversing path")
    if any(part.endswith((".", " ")) or ":" in part for part in parts):
        raise ValueError("Archive contains a path that changes meaning across platforms")
    mode = info.external_attr >> 16
    kind = stat.S_IFMT(mode)
    if kind not in (0, stat.S_IFREG, stat.S_IFDIR):
        raise ValueError("Archive contains a symlink or special file")
    if info.flag_bits & 1:
        raise ValueError("Encrypted ZIP entries are not supported")
    is_dir = normalized.endswith("/")
    if kind == stat.S_IFDIR and not is_dir:
        raise ValueError("Archive contains inconsistent directory metadata")
    if kind == stat.S_IFREG and is_dir:
        raise ValueError("Archive contains inconsistent file metadata")
    return PurePosixPath(*parts), is_dir, mode


def extract_project(archive, destination, expected_sha256, free_margin=FREE_BUILD_MARGIN):
    if not re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256):
        raise ValueError("Expected SHA-256 must contain exactly 64 hexadecimal characters")
    if sha256_file(archive) != expected_sha256.lower():
        raise ValueError("Xcode ZIP SHA-256 does not match the requested export")
    root = Path(destination).resolve()
    if root.exists():
        raise ValueError("Extraction directory must not already exist")
    root.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as bundle:
        infos = bundle.infolist()
        if len(infos) > 100000:
            raise ValueError("Archive has too many entries")
        total_size = sum(info.file_size for info in infos)
        if total_size > MAX_UNPACKED:
            raise ValueError("Archive exceeds the 12 GiB unpacked limit")
        if total_size + free_margin > shutil.disk_usage(root.parent).free:
            raise ValueError("Insufficient disk space for extraction and the Xcode build margin")
        members = []
        seen = set()
        file_paths = set()
        for info in infos:
            relative, is_dir, mode = safe_member(info)
            key = unicodedata.normalize("NFC", str(relative)).casefold()
            if key in seen:
                raise ValueError("Archive has duplicate or case-colliding paths")
            seen.add(key)
            if not is_dir:
                file_paths.add(key)
            members.append((info, relative, is_dir, mode))
        for _, relative, _, _ in members:
            for parent in relative.parents:
                key = unicodedata.normalize("NFC", str(parent)).casefold()
                if key in file_paths:
                    raise ValueError("Archive uses the same path as both a file and directory")
        root.mkdir(mode=0o700)
        executable_count = 0
        for info, relative, is_dir, source_mode in members:
            target = root.joinpath(*relative.parts)
            # All paths were checked before any extraction; no symlinks are created.
            if not target.resolve().is_relative_to(root):
                raise ValueError("Archive path leaves the extraction directory")
            if is_dir:
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with bundle.open(info) as source, target.open("xb") as output:
                shutil.copyfileobj(source, output, 1024 * 1024)
            with target.open("rb") as source:
                header = source.read(4)
            executable = bool(source_mode & 0o111) or header in EXECUTABLE_MAGIC or header.startswith(b"#!")
            target.chmod(0o700 if executable else 0o600)
            executable_count += int(executable)
    projects = [p.parent.parent for p in root.rglob("Unity-iPhone.xcodeproj/project.pbxproj")]
    if len(projects) != 1:
        raise ValueError("Archive must contain exactly one Unity-iPhone Xcode project")
    project = projects[0]
    if not (project / "Info.plist").is_file() or not (project / "salasasa-export-result.json").is_file():
        raise ValueError("Xcode project is missing Info.plist or the validated Unity export receipt")
    print(f"Verified and extracted Xcode export; restored executable permissions on {executable_count} files.")
    return project


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--destination", required=True, type=Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()
    project = extract_project(args.archive, args.destination, args.sha256)
    if args.github_output:
        with args.github_output.open("a", encoding="utf-8") as stream:
            stream.write(f"project_dir={project}\n")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, zipfile.BadZipFile, RuntimeError) as exc:
        # Do not print exported source contents into the public workflow log.
        print(f"Xcode export validation failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)
