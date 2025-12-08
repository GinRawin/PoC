import os
import shutil
import socket
import requests
import json
import sys
# 启用详细日志
import http.client
http.client.HTTPConnection.debuglevel = 1

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
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    file = open(seed_path, "rb")
    data = file.read()
    s.sendall(data)
    file.close()
    s.close()
    return


if __name__ == '__main__':
    send("127.0.0.1:80", sys.argv[1])
