#!/usr/bin/env python3
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent

def fix_content_length_in_http_request(content: bytes) -> bytes:
    """
    解析 HTTP 请求，修正 Content-Length 头部。
    返回修正后的完整请求字节串。
    """
    # 分离头部和 body
    if b"\r\n\r\n" in content:
        header_part, body = content.split(b"\r\n\r\n", 1)
        line_sep = b"\r\n"
    elif b"\n\n" in content:
        header_part, body = content.split(b"\n\n", 1)
        line_sep = b"\n"
    else:
        # 没有空行，视为没有 body
        return content

    headers = header_part.split(line_sep)
    if not headers:
        return content

    body_len = len(body)
    new_headers = []
    content_length_found = False

    for line in headers:
        if line.lower().startswith(b"content-length:"):
            new_headers.append(f"Content-Length: {body_len}".encode())
            content_length_found = True
        else:
            new_headers.append(line)

    if not content_length_found and body_len > 0:
        new_headers.append(f"Content-Length: {body_len}".encode())

    normalized_header = line_sep.join(new_headers)
    normalized_content = normalized_header + line_sep + line_sep + body
    return normalized_content

def process_directory(root_dir: Path):
    """
    递归遍历 root_dir，找到所有 .request.raw 文件并修正 Content-Length。
    """
    raw_files = list(root_dir.rglob("*.request.raw"))
    if not raw_files:
        print(f"在 {root_dir} 下未找到任何 .request.raw 文件")
        return

    for raw_file in raw_files:
        print(f"处理: {raw_file.relative_to(root_dir)}")
        original = raw_file.read_bytes()
        fixed = fix_content_length_in_http_request(original)
        if fixed != original:
            raw_file.write_bytes(fixed)
            print("  已更新 Content-Length")
        else:
            print("  无需修改")

if __name__ == "__main__":
    if len(sys.argv) > 2:
        print(f"用法: python {Path(__file__).name} [目录路径]")
        sys.exit(1)

    target_dir = Path(sys.argv[1]).resolve() if len(sys.argv) == 2 else SCRIPT_DIR
    if not target_dir.is_dir():
        print(f"错误: '{target_dir}' 不是一个目录")
        sys.exit(1)

    process_directory(target_dir)
