#!/usr/bin/env python3

from __future__ import annotations

import argparse
import shutil
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_ROOT = SCRIPT_DIR
DEFAULT_BACKUP_ROOT = Path("/mnt/sdb/hjr/HouseFuzz/data/corpus_equafl/backups/http/results")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Copy the firmware tar.gz file in each firmware directory under "
            "the replay root into all of its direct subdirectories."
        ),
    )
    parser.add_argument(
        "root",
        nargs="?",
        type=Path,
        default=DEFAULT_ROOT,
        help=f"Replay root directory (default: {DEFAULT_ROOT})",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite existing tar.gz files in subdirectories.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print planned copy operations without writing files.",
    )
    parser.add_argument(
        "--backup-root",
        type=Path,
        default=DEFAULT_BACKUP_ROOT,
        help=f"Backup tar.gz directory (default: {DEFAULT_BACKUP_ROOT})",
    )
    return parser


def ensure_tarball(firmware_dir: Path, backup_root: Path, dry_run: bool) -> Path | None:
    tarballs = sorted(
        path
        for path in firmware_dir.glob("*.tar.gz")
        if path.is_file()
    )
    if len(tarballs) == 1:
        return tarballs[0]

    if len(tarballs) == 0:
        firmware_name = firmware_dir.name.removesuffix(".zip")
        backup_tarball = backup_root / f"{firmware_name}.tar.gz"
        target_tarball = firmware_dir / backup_tarball.name

        if not backup_tarball.is_file():
            print(f"[WARN] No tar.gz found in {firmware_dir} and missing backup {backup_tarball}")
            return None

        if dry_run:
            print(f"[DRY-RUN] {backup_tarball} -> {target_tarball}")
            return target_tarball

        shutil.copy2(backup_tarball, target_tarball)
        print(f"[OK] {backup_tarball} -> {target_tarball}")
        return target_tarball

    else:
        print(f"[WARN] Multiple tar.gz files found in {firmware_dir}, skip")
    return None


def iter_firmware_dirs(root: Path) -> list[Path]:
    return [
        path
        for path in sorted(root.iterdir())
        if path.is_dir() and not path.name.startswith("__")
    ]


def copy_tar_to_subdirs(
    firmware_dir: Path,
    backup_root: Path,
    overwrite: bool,
    dry_run: bool,
) -> tuple[int, int]:
    tarball = ensure_tarball(firmware_dir, backup_root=backup_root, dry_run=dry_run)
    if tarball is None:
        return 0, 0

    copied = 0
    skipped = 0
    for subdir in sorted(path for path in firmware_dir.iterdir() if path.is_dir()):
        dest = subdir / tarball.name
        if dest.exists() and not overwrite:
            skipped += 1
            print(f"[SKIP] {dest} already exists")
            continue

        if dry_run:
            copied += 1
            print(f"[DRY-RUN] {tarball} -> {dest}")
            continue

        shutil.copy2(tarball, dest)
        copied += 1
        print(f"[OK] {tarball} -> {dest}")

    if copied == 0 and skipped == 0:
        print(f"[WARN] No subdirectories found in {firmware_dir}")
    return copied, skipped


def main() -> int:
    args = build_parser().parse_args()
    root = args.root.resolve()
    backup_root = args.backup_root.resolve()

    if not root.is_dir():
        print(f"[ERROR] Root directory does not exist: {root}")
        return 2
    if not backup_root.is_dir():
        print(f"[ERROR] Backup directory does not exist: {backup_root}")
        return 2

    total_copied = 0
    total_skipped = 0
    firmware_count = 0

    for firmware_dir in iter_firmware_dirs(root):
        firmware_count += 1
        copied, skipped = copy_tar_to_subdirs(
            firmware_dir=firmware_dir,
            backup_root=backup_root,
            overwrite=args.overwrite,
            dry_run=args.dry_run,
        )
        total_copied += copied
        total_skipped += skipped

    print(
        f"[DONE] firmware_dirs={firmware_count}, copied={total_copied}, skipped={total_skipped}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
