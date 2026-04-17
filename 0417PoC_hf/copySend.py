#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shutil
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Copy send.py into every case subdirectory under the current PoC root.",
    )
    parser.add_argument(
        "root",
        nargs="?",
        type=Path,
        default=SCRIPT_DIR,
        help=f"PoC root directory (default: {SCRIPT_DIR})",
    )
    parser.add_argument(
        "--source",
        type=Path,
        default=SCRIPT_DIR / "send.py",
        help=f"Source send.py path (default: {SCRIPT_DIR / 'send.py'})",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    source = args.source.resolve()
    base_dir = args.root.resolve()

    # 检查源文件
    if not source.is_file():
        print(f"错误：源文件不存在 - {source}")
        return 1

    # 检查基础目录
    if not base_dir.is_dir():
        print(f"错误：基础目录不存在 - {base_dir}")
        return 1

    # 获取所有一级子目录（即各个固件目录）
    try:
        entries = list(base_dir.iterdir())
    except PermissionError:
        print(f"错误：无权限访问目录 - {base_dir}")
        return 1

    firmware_dirs = [
        entry for entry in entries
        if entry.is_dir() and not entry.name.startswith("__")
    ]

    if not firmware_dirs:
        print("基础目录下没有找到任何固件子目录。")
        return 0

    # 遍历每个固件目录
    for fw_dir in firmware_dirs:
        fw_path = fw_dir
        print(f"\n处理固件目录: {fw_path}")

        # 获取该固件目录下的所有子文件夹（即需要复制send.py的目标位置）
        try:
            sub_entries = list(fw_path.iterdir())
        except PermissionError:
            print(f"  警告：无权限访问 {fw_path}，跳过")
            continue

        subdirs = [
            sub for sub in sub_entries
            if sub.is_dir()
        ]

        if not subdirs:
            print(f"  该固件目录下没有子文件夹，跳过")
            continue

        # 将 send.py 复制到每个子文件夹
        for sub in subdirs:
            dest_dir = sub
            dest_file = dest_dir / source.name
            try:
                shutil.copy2(source, dest_file)
                print(f"  已复制: {dest_file}")
            except Exception as e:
                print(f"  复制失败 {dest_file}: {e}")

    print("\n所有固件目录处理完成。")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
