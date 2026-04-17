#!/usr/bin/env python3

from __future__ import annotations

import argparse
import os
import shutil
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
HOUSEFUZZ_DEAL_ROOT = Path(
    os.environ.get("HOUSEFUZZ_DEAL_ROOT", "/mnt/sdb/hjr/HouseFuzz/deal")
).expanduser()
DEFAULT_ROOT = SCRIPT_DIR
DEFAULT_ANALYZE_TRACE_ROOT = HOUSEFUZZ_DEAL_ROOT / "analyzeTrace"
DEFAULT_ARCHIVE_ROOT = Path(
    os.environ.get(
        "HOUSEFUZZ_RESULTS_ROOT",
        "/mnt/sdb/hjr/HouseFuzz/data/corpus_equafl/backups/http/results",
    )
).expanduser()
SPECIAL_TARBALL_SOURCES = {
    "r8500-v1.0.2.160-1.0.107": Path(
        "/mnt/sdb/hjr/PoC/0412PoC/r8500-v1.0.2.160-1.0.107.zip/"
        "r8500-v1.0.2.160-1.0.107.tar.gz"
    ),
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Ensure each firmware directory under the current PoC root has "
            "its firmware tar.gz file in the firmware root."
        ),
    )
    parser.add_argument(
        "root",
        nargs="?",
        type=Path,
        default=DEFAULT_ROOT,
        help=f"PoC root directory (default: {DEFAULT_ROOT})",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite existing tar.gz files in firmware directories.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print planned copy operations without writing files.",
    )
    parser.add_argument(
        "--archive-root",
        "--backup-root",
        dest="archive_root",
        type=Path,
        default=DEFAULT_ARCHIVE_ROOT,
        help=f"Archive tar.gz directory (default: {DEFAULT_ARCHIVE_ROOT})",
    )
    parser.add_argument(
        "--analyze-trace-root",
        type=Path,
        default=DEFAULT_ANALYZE_TRACE_ROOT,
        help=f"AnalyzeTrace source directory (default: {DEFAULT_ANALYZE_TRACE_ROOT})",
    )
    return parser


def ensure_tarball(
    firmware_dir: Path,
    archive_root: Path,
    analyze_trace_root: Path,
    dry_run: bool,
) -> Path | None:
    tarballs = sorted(
        path
        for path in firmware_dir.glob("*.tar.gz")
        if path.is_file()
    )
    if len(tarballs) == 1:
        return tarballs[0]

    if len(tarballs) == 0:
        firmware_name = firmware_dir.name.removesuffix(".zip")
        analyze_trace_dir = analyze_trace_root / firmware_name
        source_tarball = SPECIAL_TARBALL_SOURCES.get(
            firmware_name,
            archive_root / f"{firmware_name}.tar.gz",
        )
        target_tarball = firmware_dir / source_tarball.name

        if not analyze_trace_dir.is_dir():
            print(f"[WARN] Missing analyzeTrace source dir {analyze_trace_dir}")

        if not source_tarball.is_file():
            print(f"[WARN] No tar.gz found in {firmware_dir} and missing source {source_tarball}")
            return None

        if dry_run:
            print(f"[DRY-RUN] {source_tarball} -> {target_tarball}")
            return target_tarball

        shutil.copy2(source_tarball, target_tarball)
        print(f"[OK] {source_tarball} -> {target_tarball}")
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
    archive_root: Path,
    analyze_trace_root: Path,
    overwrite: bool,
    dry_run: bool,
) -> tuple[int, int]:
    tarballs = sorted(
        path
        for path in firmware_dir.glob("*.tar.gz")
        if path.is_file()
    )
    if tarballs and not overwrite:
        print(f"[SKIP] {firmware_dir} already has root tar.gz")
        return 0, 1

    tarball = ensure_tarball(
        firmware_dir,
        archive_root=archive_root,
        analyze_trace_root=analyze_trace_root,
        dry_run=dry_run,
    )
    if tarball is None:
        return 0, 0

    return 1, 0


def main() -> int:
    args = build_parser().parse_args()
    root = args.root.resolve()
    archive_root = args.archive_root.resolve()
    analyze_trace_root = args.analyze_trace_root.resolve()

    if not root.is_dir():
        print(f"[ERROR] Root directory does not exist: {root}")
        return 2
    if not archive_root.is_dir():
        print(f"[ERROR] Archive directory does not exist: {archive_root}")
        return 2
    if not analyze_trace_root.is_dir():
        print(f"[ERROR] AnalyzeTrace directory does not exist: {analyze_trace_root}")
        return 2

    total_copied = 0
    total_skipped = 0
    firmware_count = 0

    for firmware_dir in iter_firmware_dirs(root):
        firmware_count += 1
        copied, skipped = copy_tar_to_subdirs(
            firmware_dir=firmware_dir,
            archive_root=archive_root,
            analyze_trace_root=analyze_trace_root,
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
