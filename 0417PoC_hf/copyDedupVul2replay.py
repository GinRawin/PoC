#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
HOUSEFUZZ_DEAL_ROOT = Path(
    os.environ.get("HOUSEFUZZ_DEAL_ROOT", "/mnt/sdb/hjr/HouseFuzz/deal")
).expanduser()
DEFAULT_DEDUP_ROOT = HOUSEFUZZ_DEAL_ROOT / "dedupVul"
DEFAULT_REPLAY_FIRMWARE_ROOT = HOUSEFUZZ_DEAL_ROOT / "replayFirmware"
DEFAULT_TARGET_ROOT = SCRIPT_DIR
DEFAULT_DEDUP_SUBDIR = "去重后漏洞"
DEFAULT_MANIFEST_NAME = ".dedup_selection.json"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Copy deduplicated vulnerability markdown files and matching "
            "*.request.raw files into the current PoC directory."
        ),
    )
    parser.add_argument(
        "firmware_name_or_path",
        nargs="*",
        help=(
            "Optional firmware names or absolute paths under the dedup root. "
            "Defaults to all firmware directories that contain 去重后漏洞."
        ),
    )
    parser.add_argument(
        "--dedup-root",
        type=Path,
        default=DEFAULT_DEDUP_ROOT,
        help=f"Dedup root directory (default: {DEFAULT_DEDUP_ROOT})",
    )
    parser.add_argument(
        "--replay-firmware-root",
        type=Path,
        default=DEFAULT_REPLAY_FIRMWARE_ROOT,
        help=f"Replay firmware root directory (default: {DEFAULT_REPLAY_FIRMWARE_ROOT})",
    )
    parser.add_argument(
        "--target-root",
        type=Path,
        default=DEFAULT_TARGET_ROOT,
        help=f"Replay target root directory (default: {DEFAULT_TARGET_ROOT})",
    )
    parser.add_argument(
        "--dedup-subdir",
        default=DEFAULT_DEDUP_SUBDIR,
        help=f"Dedup markdown subdirectory name (default: {DEFAULT_DEDUP_SUBDIR})",
    )
    parser.add_argument(
        "--manifest-name",
        default=DEFAULT_MANIFEST_NAME,
        help=f"Selection manifest filename (default: {DEFAULT_MANIFEST_NAME})",
    )
    parser.add_argument(
        "--requests-only",
        action="store_true",
        help="Only copy *.request.raw files and do not copy or overwrite markdown files.",
    )
    return parser


def resolve_firmware_dir(dedup_root: Path, raw: str, dedup_subdir: str) -> Path:
    raw_path = Path(raw)
    if raw_path.is_dir() and (raw_path / dedup_subdir).is_dir():
        return raw_path.resolve()

    candidate = (dedup_root / raw).resolve()
    if candidate.is_dir() and (candidate / dedup_subdir).is_dir():
        return candidate

    raise FileNotFoundError(f"firmware directory not found: {raw}")


def collect_all_firmware_dirs(dedup_root: Path, dedup_subdir: str) -> list[Path]:
    firmware_dirs: list[Path] = []
    for path in sorted(dedup_root.iterdir()):
        if not path.is_dir():
            continue
        if not (path / dedup_subdir).is_dir():
            continue
        firmware_dirs.append(path.resolve())
    return firmware_dirs


def load_manifest(manifest_path: Path) -> dict:
    try:
        return json.loads(manifest_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"missing manifest: {manifest_path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON in {manifest_path}: {exc}") from exc


def collect_zero_day_markdowns(
    firmware_dir: Path,
    dedup_subdir: str,
    manifest_name: str,
) -> list[Path]:
    manifest_path = firmware_dir / manifest_name
    payload = load_manifest(manifest_path)

    firmware_name = payload.get("firmware")
    if firmware_name is not None and firmware_name != firmware_dir.name:
        raise ValueError(
            f"{manifest_path}: firmware field mismatch, expected {firmware_dir.name}, got {firmware_name}",
        )

    selected_reports = payload.get("selected_reports")
    if not isinstance(selected_reports, list):
        raise ValueError(f"{manifest_path}: selected_reports must be a list")

    markdown_paths: list[Path] = []
    seen_names: set[str] = set()
    for index, entry in enumerate(selected_reports):
        if not isinstance(entry, dict):
            raise ValueError(f"{manifest_path}: selected_reports[{index}] must be an object")

        source = entry.get("source")
        if not isinstance(source, str) or not source.strip():
            raise ValueError(f"{manifest_path}: selected_reports[{index}].source must be a non-empty string")
        if entry.get("0-day") != 1:
            continue
        source_rel = Path(source)
        if source_rel.is_absolute():
            raise ValueError(f"{manifest_path}: selected_reports[{index}].source must be relative: {source}")

        resolved = (firmware_dir / source_rel).resolve()
        try:
            relative_to_firmware = resolved.relative_to(firmware_dir)
        except ValueError as exc:
            raise ValueError(f"{manifest_path}: source escapes firmware dir: {source}") from exc

        if not resolved.is_file():
            raise ValueError(f"{manifest_path}: source file does not exist: {source}")
        if not relative_to_firmware.parts or relative_to_firmware.parts[0] != "确认漏洞":
            raise ValueError(f"{manifest_path}: source must stay under 确认漏洞/: {source}")
        if resolved.suffix.lower() != ".md":
            raise ValueError(f"{manifest_path}: source must be a .md file: {source}")

        target_markdown = firmware_dir / dedup_subdir / resolved.name
        if not target_markdown.is_file():
            raise ValueError(
                f"{manifest_path}: missing matching markdown in {dedup_subdir}/ for {resolved.name}",
            )
        if target_markdown.name in seen_names:
            raise ValueError(f"{manifest_path}: duplicate selected target filename: {target_markdown.name}")

        seen_names.add(target_markdown.name)
        markdown_paths.append(target_markdown)

    return sorted(markdown_paths)


def copy_matching_request_files(source_dir: Path, target_dir: Path) -> int:
    copied = 0
    for request_file in sorted(source_dir.glob("*.request.raw")):
        shutil.copy2(request_file, target_dir / request_file.name)
        copied += 1
    return copied


def normalize_case_name(name: str) -> str:
    return re.sub(r"[^0-9A-Za-z]+", "_", name).strip("_")


def resolve_target_case_dir(target_firmware_dir: Path, case_name: str) -> tuple[Path, bool]:
    exact_dir = target_firmware_dir / case_name
    if exact_dir.is_dir():
        return exact_dir, False

    normalized_case_name = normalize_case_name(case_name)
    matched_dirs = [
        path
        for path in target_firmware_dir.iterdir()
        if path.is_dir() and normalize_case_name(path.name) == normalized_case_name
    ]
    if len(matched_dirs) == 1:
        return matched_dirs[0], False

    return exact_dir, len(matched_dirs) > 1


def sync_one_firmware(
    firmware_dir: Path,
    replay_firmware_root: Path,
    target_root: Path,
    dedup_subdir: str,
    manifest_name: str,
    requests_only: bool,
) -> tuple[int, int, int]:
    firmware_name = firmware_dir.name
    target_firmware_dir = target_root / firmware_name
    target_firmware_dir.mkdir(parents=True, exist_ok=True)

    replay_firmware_dir = replay_firmware_root / firmware_name

    markdown_count = 0
    request_count = 0
    warning_count = 0

    for markdown_path in collect_zero_day_markdowns(
        firmware_dir=firmware_dir,
        dedup_subdir=dedup_subdir,
        manifest_name=manifest_name,
    ):
        case_name = markdown_path.stem
        target_case_dir, ambiguous_match = resolve_target_case_dir(target_firmware_dir, case_name)
        if ambiguous_match:
            warning_count += 1
            print(
                f"[WARN] {firmware_name}/{case_name}: multiple renamed target dirs match; "
                f"fall back to {target_case_dir}"
            )
        target_case_dir.mkdir(parents=True, exist_ok=True)

        source_case_dir = replay_firmware_dir / case_name
        if source_case_dir.is_dir():
            copied_requests = copy_matching_request_files(source_case_dir, target_case_dir)
            request_count += copied_requests
            if copied_requests == 0:
                warning_count += 1
                print(f"[WARN] {firmware_name}/{case_name}: no *.request.raw files found")
        else:
            warning_count += 1
            print(f"[WARN] {firmware_name}/{case_name}: missing replay source dir {source_case_dir}")

        if not requests_only:
            shutil.copy2(markdown_path, target_case_dir / markdown_path.name)
            markdown_count += 1

    return markdown_count, request_count, warning_count


def main() -> int:
    args = build_parser().parse_args()
    dedup_root = args.dedup_root.resolve()
    replay_firmware_root = args.replay_firmware_root.resolve()
    target_root = args.target_root.resolve()

    if not dedup_root.is_dir():
        print(f"[ERROR] dedup root does not exist: {dedup_root}")
        return 2
    if not replay_firmware_root.is_dir():
        print(f"[ERROR] replay firmware root does not exist: {replay_firmware_root}")
        return 2

    target_root.mkdir(parents=True, exist_ok=True)

    if args.firmware_name_or_path:
        try:
            firmware_dirs = [
                resolve_firmware_dir(dedup_root, raw, args.dedup_subdir)
                for raw in args.firmware_name_or_path
            ]
        except FileNotFoundError as exc:
            print(f"[ERROR] {exc}")
            return 2
    else:
        firmware_dirs = collect_all_firmware_dirs(dedup_root, args.dedup_subdir)

    if not firmware_dirs:
        print(f"[ERROR] no firmware directories found under: {dedup_root}")
        return 2

    total_markdown = 0
    total_requests = 0
    total_warnings = 0
    had_error = False

    for firmware_dir in firmware_dirs:
        try:
            markdown_count, request_count, warning_count = sync_one_firmware(
                firmware_dir=firmware_dir,
                replay_firmware_root=replay_firmware_root,
                target_root=target_root,
                dedup_subdir=args.dedup_subdir,
                manifest_name=args.manifest_name,
                requests_only=args.requests_only,
            )
        except (FileNotFoundError, ValueError) as exc:
            had_error = True
            print(f"[ERROR] {firmware_dir.name}: {exc}")
            continue
        total_markdown += markdown_count
        total_requests += request_count
        total_warnings += warning_count
        print(
            f"[OK] {firmware_dir.name}: markdown={markdown_count} "
            f"request_raw={request_count} warnings={warning_count}"
        )

    print(
        f"[SUMMARY] firmware={len(firmware_dirs)} markdown={total_markdown} "
        f"request_raw={total_requests} warnings={total_warnings}"
    )
    return 1 if had_error else 0


if __name__ == "__main__":
    raise SystemExit(main())
