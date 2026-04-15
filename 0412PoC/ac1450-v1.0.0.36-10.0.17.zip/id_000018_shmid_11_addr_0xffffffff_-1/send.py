import os
import shutil
import socket
import requests
import json
import sys
# 启用详细日志
import http.client
http.client.HTTPConnection.debuglevel = 1


def normalize_raw_http_request(data: bytes):
    separator = None
    line_sep = None

    if b"\r\n\r\n" in data:
        separator = b"\r\n\r\n"
        line_sep = b"\r\n"
    elif b"\n\n" in data:
        separator = b"\n\n"
        line_sep = b"\n"
    else:
        return data, None, None

    header_bytes, body = data.split(separator, 1)
    header_lines = header_bytes.split(line_sep)
    if not header_lines:
        return data, None, None

    # 如果是 chunked 请求，就不要再改 Content-Length。
    for line in header_lines[1:]:
        lower_line = line.lower()
        if lower_line.startswith(b"transfer-encoding:") and b"chunked" in lower_line:
            normalized_headers = b"\r\n".join(header_lines)
            return normalized_headers + b"\r\n\r\n" + body, None, len(body)

    body_length = len(body)
    old_content_length = None
    updated_header_lines = [header_lines[0]]
    content_length_found = False

    for line in header_lines[1:]:
        if line.lower().startswith(b"content-length:"):
            content_length_found = True
            try:
                old_content_length = int(line.split(b":", 1)[1].strip())
            except ValueError:
                old_content_length = None
            updated_header_lines.append(f"Content-Length: {body_length}".encode())
        else:
            updated_header_lines.append(line)

    if body_length > 0 and not content_length_found:
        updated_header_lines.append(f"Content-Length: {body_length}".encode())

    normalized_headers = b"\r\n".join(updated_header_lines)
    normalized_data = normalized_headers + b"\r\n\r\n" + body
    return normalized_data, old_content_length, body_length

def send_json(ip_port: str, seed_path: str):
    default_request = {
        "method": "POST",
        "prefix": "/",
        "handler_name": "",
        "version": "1.1"
    }
    default_header = {
        "Content-Type": "application/json"
    }
    default_body = {}

    # 从文件中读取内容，使用 'rb' 模式
    try:
        with open(seed_path, 'rb') as file:
            file_content = file.read()
            # 尝试解码为 UTF-8，如果失败，尝试其他编码
            try:
                json_data = json.loads(file_content.decode('utf-8'))
            except UnicodeDecodeError:
                try:
                    json_data = json.loads(file_content.decode('latin1'))
                except UnicodeDecodeError:
                    print(f"Error: Unable to decode file content using UTF-8 or Latin-1")
                    return
    except FileNotFoundError:
        print(f"Error: File not found at {seed_path}")
        return
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON format in file {seed_path}")
        return

    # 提取请求信息，使用默认值填充缺失的部分
    request_info = json_data.get("request", {})
    method = request_info.get("method", default_request["method"])
    prefix = request_info.get("prefix", default_request["prefix"])
    handler_name = request_info.get("handler_name", default_request["handler_name"])
    version = request_info.get("version", default_request["version"])

    headers = json_data.get("header", default_header)
    body = json_data.get("body", default_body)

    # 构造完整的 URL
    url = f"http://{ip_port}{prefix}{handler_name}"

    # 打印请求信息
    print(f"Sending {method} request to {url}")
    print(f"Headers: {headers}")
    print(f"Body: {body}")

    response = ''
    # 发送请求
    try:
        if method.upper() == "POST":
            response = requests.post(url, headers=headers, data=body)
        elif method.upper() == "GET":
            response = requests.get(url, headers=headers, params=body)
        # else:
        #     raise ValueError(f"Unsupported method: {method}")
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return

    # 打印响应
    if(response != ''):
        print("Response Status Code:", response.status_code)
        print("Response Content:", response.text)


def send(ip_port: str, seed_path: str):
    if(not seed_path.endswith('.raw')):
        send_json(ip_port, seed_path)
        return
    host, port = ip_port.split(":")
    port = int(port)
    file = None
    s = None
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5.0)
    s.connect((host, port))
    file = open(seed_path, "rb")
    data = file.read()
    data, old_content_length, body_length = normalize_raw_http_request(data)
    if old_content_length is not None and old_content_length != body_length:
        print(f"Adjusted Content-Length: {old_content_length} -> {body_length}")
    elif old_content_length is None and body_length is not None and body_length > 0:
        print(f"Set Content-Length: {body_length}")
    print(data)
    s.sendall(data)
    response_chunks = []
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response_chunks.append(chunk)
    except socket.timeout:
        if not response_chunks:
            print("No response received before timeout.")

    response = b"".join(response_chunks)
    if response:
        print(response.decode('utf-8', errors='ignore'))
    if file:
        file.close()
    if s:
        s.close()
    return


if __name__ == '__main__':
    send("127.0.0.1:80", sys.argv[1])
