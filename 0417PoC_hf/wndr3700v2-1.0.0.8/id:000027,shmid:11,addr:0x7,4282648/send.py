#!/usr/bin/env python3
from __future__ import annotations

import argparse
import http.client
import json
import socket
from pathlib import Path

import requests

# 启用详细日志
http.client.HTTPConnection.debuglevel = 1


SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_TARGET = "127.0.0.1:80"


def resolve_seed_path(raw_path: str) -> Path:
    seed_path = Path(raw_path).expanduser()
    if seed_path.is_absolute():
        return seed_path

    cwd_candidate = seed_path.resolve()
    if cwd_candidate.exists():
        return cwd_candidate

    return (SCRIPT_DIR / seed_path).resolve()


def send_json(ip_port: str, seed_path: Path) -> None:
    default_request = {
        "method": "POST",
        "prefix": "/",
        "handler_name": "",
        "version": "1.1",
    }
    default_header = {
        "Content-Type": "application/json",
    }
    default_body = {}

    try:
        file_content = seed_path.read_bytes()
    except FileNotFoundError:
        print(f"Error: File not found at {seed_path}")
        return

    json_data = None
    for encoding in ("utf-8", "latin1"):
        try:
            json_data = json.loads(file_content.decode(encoding))
            break
        except UnicodeDecodeError:
            continue
        except json.JSONDecodeError:
            print(f"Error: Invalid JSON format in file {seed_path}")
            return

    if json_data is None:
        print("Error: Unable to decode file content using UTF-8 or Latin-1")
        return

    request_info = json_data.get("request", {})
    method = request_info.get("method", default_request["method"])
    prefix = request_info.get("prefix", default_request["prefix"])
    handler_name = request_info.get("handler_name", default_request["handler_name"])
    version = request_info.get("version", default_request["version"])

    headers = json_data.get("header", default_header)
    body = json_data.get("body", default_body)

    url = f"http://{ip_port}{prefix}{handler_name}"

    print(f"Sending {method} request to {url} (HTTP/{version})")
    print(f"Headers: {headers}")
    print(f"Body: {body}")

    response = None
    try:
        if method.upper() == "POST":
            response = requests.post(url, headers=headers, data=body)
        elif method.upper() == "GET":
            response = requests.get(url, headers=headers, params=body)
        else:
            print(f"Error: Unsupported method {method}")
            return
    except requests.exceptions.RequestException as exc:
        print(f"Error: {exc}")
        return

    print("Response Status Code:", response.status_code)
    print("Response Content:", response.text)


def send(ip_port: str, seed_path: Path, timeout: float) -> None:
    if seed_path.suffix.lower() != ".raw":
        send_json(ip_port, seed_path)
        return

    host, port_text = ip_port.split(":")
    port = int(port_text)
    response_chunks = []

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect((host, port))
        data = seed_path.read_bytes()
        print(data)
        sock.sendall(data)
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response_chunks.append(chunk)
        except socket.timeout:
            if not response_chunks:
                print("No response received before timeout.")

    response = b"".join(response_chunks)
    if response:
        print(response.decode("utf-8", errors="ignore"))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Send a *.request.raw file or a JSON request description. "
            "Relative paths are resolved from the current directory first, "
            "then from the script directory."
        ),
    )
    parser.add_argument("seed_path", help="Path to the request file")
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"Target host:port (default: {DEFAULT_TARGET})",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Socket timeout in seconds for raw requests (default: 5.0)",
    )
    return parser


if __name__ == "__main__":
    args = build_parser().parse_args()
    send(args.target, resolve_seed_path(args.seed_path), args.timeout)
