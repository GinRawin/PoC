#!/usr/bin/env python3
import shutil
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent

def main():
    source = SCRIPT_DIR / "send.py"
    base_dir = SCRIPT_DIR

    # 检查源文件
    if not source.is_file():
        print(f"错误：源文件不存在 - {source}")
        sys.exit(1)

    # 检查基础目录
    if not base_dir.is_dir():
        print(f"错误：基础目录不存在 - {base_dir}")
        sys.exit(1)

    # 获取所有一级子目录（即各个固件目录）
    try:
        entries = list(base_dir.iterdir())
    except PermissionError:
        print(f"错误：无权限访问目录 - {base_dir}")
        sys.exit(1)

    firmware_dirs = [
        entry for entry in entries
        if entry.is_dir() and not entry.name.startswith("__")
    ]

    if not firmware_dirs:
        print("基础目录下没有找到任何固件子目录。")
        return

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

if __name__ == "__main__":
    main()
