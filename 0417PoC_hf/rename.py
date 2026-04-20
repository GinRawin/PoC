#!/usr/bin/env python3

from pathlib import Path


def sanitize_name(name: str) -> str:
    return name.replace(",", "_").replace(":", "_")


def rename_markdown_files(directory: Path) -> None:
    for child_path in sorted(directory.iterdir()):
        is_markdown = child_path.is_file() and child_path.suffix.lower() in {
            ".md",
            ".markdown",
        }
        if not is_markdown:
            continue

        sanitized_name = sanitize_name(child_path.name)
        new_path = child_path.with_name(sanitized_name)
        if new_path.exists() and new_path != child_path:
            print(f"skip: {child_path} -> {new_path} (target exists)")
            continue

        if new_path != child_path:
            child_path.rename(new_path)
            print(f"renamed: {child_path.name} -> {new_path.name}")


def main() -> None:
    root = Path(__file__).resolve().parent

    for firmware_dir in sorted(root.iterdir()):
        if not firmware_dir.is_dir():
            continue

        for child_path in sorted(firmware_dir.iterdir()):
            is_markdown = child_path.is_file() and child_path.suffix.lower() in {
                ".md",
                ".markdown",
            }
            if not child_path.is_dir() and not is_markdown:
                continue

            sanitized_name = sanitize_name(child_path.name)
            new_path = child_path.with_name(sanitized_name)
            if new_path.exists() and new_path != child_path:
                print(f"skip: {child_path} -> {new_path} (target exists)")
                continue

            current_path = child_path
            if new_path != child_path:
                child_path.rename(new_path)
                print(f"renamed: {child_path.name} -> {new_path.name}")
                current_path = new_path

            if current_path.is_dir():
                rename_markdown_files(current_path)


if __name__ == "__main__":
    main()
