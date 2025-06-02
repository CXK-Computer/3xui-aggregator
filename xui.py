# -*- coding: utf-8 -*-

# @Author  : wzdnzd
# @Time    : 2024-07-05
# @Description: base on https://blog-next-js.pages.dev/blog/%E6%89%AB%E6%8F%8F%E7%BB%93%E6%9E%9C
# @Author  : cxk-computer
# @Time    : 2025-05-17
# @Update  : 2025-06-01 (Read all lines from credential files, Cartesian product, UI updates by Gemini)

import argparse
import base64
import gzip
import json
import os
import socket
import ssl
import sys
import threading
import time
import traceback
import typing
import urllib
import urllib.parse
import urllib.request
from collections import defaultdict
from concurrent import futures
from dataclasses import dataclass
from http.client import HTTPResponse
from urllib import parse

# --- PySide6 imports for GUI ---
from PySide6.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout,
                               QWidget, QLabel, QLineEdit, QPushButton, QFileDialog,
                               QSpinBox, QCheckBox, QTextEdit, QProgressBar, QGroupBox,
                               QFormLayout, QMessageBox)
from PySide6.QtCore import QObject, QThread, Signal, Slot, Qt, QStandardPaths
from PySide6.QtGui import QAction, QIcon
# -------------------------------


from geoip2 import database
# from tqdm import tqdm # tqdm is not used in GUI version effectively

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

FILE_LOCK = threading.Lock()

DEFAULT_WORKSPACE = QStandardPaths.writableLocation(QStandardPaths.AppDataLocation) or os.path.abspath(os.path.dirname(__file__))
if not DEFAULT_WORKSPACE:
    DEFAULT_WORKSPACE = os.path.abspath(os.path.dirname(__file__))


USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

class QTextEditLogger(QObject):
    message_written = Signal(str)

    def write(self, text):
        self.message_written.emit(str(text))

    def flush(self):
        # sys.__stdout__.flush() # Original stdout flush, if needed
        pass


def http_post(url: str, headers: dict = None, params: dict = {}, retry: int = 3, timeout: float = 6) -> HTTPResponse:
    if params is None or type(params) != dict:
        return None

    timeout, retry = max(timeout, 1), retry - 1
    try:
        data = b""
        if params and isinstance(params, dict):
            data = urllib.parse.urlencode(params).encode(encoding="utf8")

        request = urllib.request.Request(url=url, data=data, headers=headers, method="POST")
        return urllib.request.urlopen(request, timeout=timeout, context=CTX)
    except urllib.error.HTTPError as e:
        if retry < 0 or e.code in [400, 401, 405]:
            return None
        time.sleep(1)
        return http_post(url=url, headers=headers, params=params, retry=retry, timeout=timeout)
    except (TimeoutError, urllib.error.URLError) as e:
        return None
    except Exception as e:
        if retry < 0:
            return None
        time.sleep(1)
        return http_post(url=url, headers=headers, params=params, retry=retry, timeout=timeout)


def read_response(response: HTTPResponse, expected: int = 200, deserialize: bool = False, key: str = "") -> typing.Any:
    if not response or not isinstance(response, HTTPResponse):
        return None

    success = expected <= 0 or expected == response.getcode()
    if not success:
        return None

    try:
        text = response.read()
    except Exception as e:
        return None

    try:
        content = text.decode(encoding="UTF8")
    except UnicodeDecodeError:
        try:
            content = gzip.decompress(text).decode("UTF8")
        except Exception as e:
            content = ""
    except Exception as e:
        content = ""

    if not deserialize:
        return content

    if not content:
        return None
    try:
        data = json.loads(content)
        return data if not key else data.get(key, None)
    except Exception as e:
        return None


def trim(text: str) -> str:
    if not text or type(text) != str:
        return ""
    return text.strip()


def write_file(filename: str, lines: str | list, overwrite: bool = True, log_callback: typing.Callable[[str], None] = None) -> None:
    if not filename or (not lines and not isinstance(lines, list) and not isinstance(lines, str)): # Allow empty string or empty list
        if isinstance(lines, list) and not lines: # Allow writing an empty list to clear a file
            pass
        elif isinstance(lines, str) and lines == "": # Allow writing an empty string to clear a file
             pass
        else:
            return


    try:
        if not isinstance(lines, str):
            lines = "\n".join(lines)

        filepath = os.path.abspath(os.path.dirname(filename))
        os.makedirs(filepath, exist_ok=True)
        mode = "w" if overwrite else "a"

        if not FILE_LOCK.acquire(timeout=30):
             msg = f"获取文件锁 {filename} 超时"
             if log_callback:
                 log_callback(msg)
             else:
                print(msg)
             return

        try:
            with open(filename, mode, encoding="UTF8") as f:
                f.write(lines + ("\n" if lines else ""))
                f.flush()
        finally:
            FILE_LOCK.release()

    except Exception as e:
        msg = f"写入文件 {filename} 失败: {e}"
        if log_callback:
            log_callback(msg)
        else:
            print(msg)


def get_cookies(url: str, username: str = "admin", password: str = "admin") -> dict:
    url = trim(url)
    if not url:
        return None

    # Do not trim username and password here, they are already processed by ScanWorker
    # username = trim(username) or "admin"
    # password = password or "admin"

    data = {"username": username, "password": password}
    headers = {
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Origin": url,
        "Referer": url,
        "User-Agent": USER_AGENT,
    }
    
    parsed_origin_url = urllib.parse.urlparse(url)
    headers["Origin"] = f"{parsed_origin_url.scheme}://{parsed_origin_url.netloc}"

    response = http_post(url=f"{url}/login", headers=headers, params=data)
    success = read_response(response=response, expected=200, deserialize=True, key="success")
    if not success:
        return None

    cookies = response.getheader("Set-Cookie")
    if not cookies:
        return None

    headers["Cookie"] = cookies
    return headers


def send_quest(url: str, subpath: str, headers: dict) -> dict:
    url = trim(url)
    if not url or not headers or not isinstance(headers, dict):
        return None

    subpath = trim(subpath)
    if subpath:
        url = parse.urljoin(url, subpath)

    response = http_post(url=url, headers=headers, params={})
    return read_response(response=response, expected=200, deserialize=True)


def get_server_status(url: str, headers: dict) -> dict:
    return send_quest(url=url, subpath="/server/status", headers=headers)


def get_inbound_list(url: str, headers: dict) -> dict:
    return send_quest(url=url, subpath="/xui/inbound/list", headers=headers)


def convert_bytes_to_readable_unit(num: int) -> str:
    TB = 1099511627776
    GB = 1073741824
    MB = 1048576

    if num is None:
        return "未知"
    if not isinstance(num, (int, float)):
        return "未知"

    if num >= TB:
        return f"{num / TB:.2f} TB"
    elif num >= GB:
        return f"{num / GB:.2f} GB"
    elif num >= MB:
        return f"{num / MB:.2f} MB"
    elif num >= 0:
        return f"{num / 1024:.2f} KB" if num >=1024 else f"{num} Bytes"
    else:
        return "未知"


def download_mmdb(repo: str, target: str, directory: str, retry: int = 3, log_callback: typing.Callable[[str], None] = None):
    repo = trim(text=repo)
    if not repo or len(repo.split("/", maxsplit=1)) != 2:
        msg = f"无效的Github仓库名称: {repo}"
        if log_callback: log_callback(msg)
        raise ValueError(msg)

    target = trim(target)
    if not target:
        msg = "无效的下载目标 (文件名)"
        if log_callback: log_callback(msg)
        raise ValueError(msg)

    if not directory:
        msg = "无效的下载目录"
        if log_callback: log_callback(msg)
        raise ValueError(msg)

    filepath = os.path.join(directory, target)
    os.makedirs(directory, exist_ok=True)

    release_api = f"https://api.github.com/repos/{repo}/releases/latest"
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/vnd.github.v3+json",
    }

    count, response = 0, None
    while count < retry:
        try:
            if log_callback: log_callback(f"尝试 {count+1}/{retry}: 获取 {repo} 的发布信息...")
            request = urllib.request.Request(url=release_api, headers=headers)
            response = urllib.request.urlopen(request, timeout=10, context=CTX)
            break
        except Exception as e:
            if log_callback: log_callback(f"尝试 {count+1}/{retry} 失败: {e}")
            count += 1
            time.sleep(2)

    if response is None:
        msg = f"{retry} 次尝试后获取 {repo} 的发布信息失败。"
        if log_callback: log_callback(msg)
        raise Exception(msg)

    assets = read_response(response=response, expected=200, deserialize=True, key="assets")
    if not assets or not isinstance(assets, list):
        msg = "在Github发布中未找到资源"
        if log_callback: log_callback(msg)
        raise Exception(msg)

    download_url = ""
    for asset in assets:
        if asset.get("name", "") == target:
            download_url = asset.get("browser_download_url", "")
            break

    if not download_url:
        msg = f"在Github发布中未找到资源 '{target}' 的下载链接"
        if log_callback: log_callback(msg)
        raise Exception(msg)

    download(download_url, directory, target, retry, log_callback)


def download(url: str, directory: str, filename: str, retry: int = 3, log_callback: typing.Callable[[str], None] = None) -> None:
    if retry < 0:
        msg = "已达到最大下载重试次数"
        if log_callback: log_callback(msg)
        raise Exception(msg)

    url = trim(url)
    if not url:
        msg = "无效的下载链接"
        if log_callback: log_callback(msg)
        raise ValueError(msg)

    directory = trim(directory)
    if not directory:
        msg = "无效的保存目录"
        if log_callback: log_callback(msg)
        raise ValueError(msg)

    filename = trim(filename)
    if not filename:
        msg = "无效的保存文件名"
        if log_callback: log_callback(msg)
        raise ValueError(msg)

    if not os.path.exists(directory) or not os.path.isdir(directory):
        os.makedirs(directory)

    fullpath = os.path.join(directory, filename)
    if os.path.exists(fullpath) and os.path.isfile(fullpath):
        try:
            os.remove(fullpath)
            if log_callback: log_callback(f"已删除已存在文件: {fullpath}")
        except Exception as e:
             if log_callback: log_callback(f"警告: 无法删除已存在文件 {fullpath}: {e}")

    try:
        if log_callback: log_callback(f"正在从 {url} 下载 {filename} 到 {fullpath}...")
        urllib.request.urlretrieve(url=url, filename=fullpath)
        if log_callback: log_callback(f"下载成功: {fullpath}")
    except Exception as e:
        msg = f"下载 {url} 失败: {e}"
        if log_callback: log_callback(msg)
        time.sleep(1)
        return download(url, directory, filename, retry - 1, log_callback)


def load_mmdb(
    directory: str, repo: str = "alecthw/mmdb_china_ip_list", filename: str = "Country.mmdb", update: bool = False, log_callback: typing.Callable[[str], None] = None
) -> database.Reader:
    filepath = os.path.join(directory, filename)
    if update or not os.path.exists(filepath) or not os.path.isfile(filepath):
        try:
            if log_callback: log_callback(f"尝试下载/更新MMDB文件: {filename}...")
            download_mmdb(repo, filename, directory, log_callback=log_callback)
            if not os.path.exists(filepath) or not os.path.isfile(filepath):
                 msg = f"下载尝试后MMDB文件 {filepath} 未找到。"
                 if log_callback: log_callback(msg)
                 return None
        except Exception as e:
            if log_callback: log_callback(f"下载MMDB文件失败: {e}")
            return None

    try:
        if log_callback: log_callback(f"正在从 {filepath} 加载MMDB数据库...")
        reader = database.Reader(filepath)
        if log_callback: log_callback("MMDB数据库加载成功。")
        return reader
    except FileNotFoundError:
        msg = f"MMDB文件 {filepath} 未找到。请确保文件存在或启用更新。"
        if log_callback: log_callback(msg)
        return None
    except Exception as e:
        msg = f"从 {filepath} 加载MMDB数据库失败: {e}"
        if log_callback: log_callback(msg)
        return None


@dataclass
class RunningState(object):
    url: str = "unknown"
    sent: str = "unknown"
    recv: str = "unknown"
    state: str = "unknown"
    version: str = "unknown"
    uptime: int = 0
    links: list[tuple[str, int, int]] = None


def get_running_state(data: dict, url: str) -> RunningState:
    if not data or not isinstance(data, dict) or "obj" not in data:
        return RunningState(url=url)

    uptime, sent, recv, state, version = 0, "unknown", "unknown", "unknown", "unknown"
    obj_data = data.get("obj", {})
    if not isinstance(obj_data, dict):
        obj_data = {}

    if "uptime" in obj_data:
        uptime = obj_data["uptime"]
    if "netTraffic" in obj_data:
        net_traffic_data = obj_data.get("netTraffic", {})
        if not isinstance(net_traffic_data, dict): net_traffic_data = {}
        sent = convert_bytes_to_readable_unit(net_traffic_data.get("sent", 0))
        recv = convert_bytes_to_readable_unit(net_traffic_data.get("recv", 0))
    if "xray" in obj_data:
        xray_data = obj_data.get("xray", {})
        if not isinstance(xray_data, dict): xray_data = {}
        state = xray_data.get("state", "unknown")
        version = xray_data.get("version", "unknown")

    return RunningState(url=url, sent=sent, recv=recv, state=state, version=version, uptime=uptime)


def generate_subscription_links(data: dict, address: str, reader: database.Reader, log_callback: typing.Callable[[str], None] = None) -> list[tuple[str, int, int]]:
    if not data or not isinstance(data, dict) or not data.get("success", False) or not address:
        return []

    result = list()
    items = data.get("obj", [])
    if not isinstance(items, list):
         if log_callback: log_callback("警告: get_inbound_list响应中的'obj'不是列表。")
         return []

    ip = None
    country = ""
    if reader:
        try:
            ip = socket.gethostbyname(address)
            response = reader.country(ip)
            country = response.country.names.get("zh-CN", "")
        except socket.gaierror:
            if log_callback: log_callback(f"警告: 无法解析主机名 {address} 进行GeoIP查询。")
        except Exception as e:
            if log_callback: log_callback(f"警告: {address} ({ip if ip else 'N/A'}) 的GeoIP查询失败: {e}")

    for item in items:
        if not item or not isinstance(item, dict) or not item.get("enable", False):
            continue

        protocol, port = item.get("protocol"), item.get("port")
        if not protocol or not port:
             if log_callback: log_callback(f"警告: 跳过缺少协议或端口的入站规则: {item.get('tag', 'N/A')}")
             continue

        link = ""
        remark = trim(item.get("remark", "")) or item.get("tag", "")

        current_country = country
        
        if reader and ip:
            if current_country == "中国":
                continue

            if current_country and current_country != remark:
                 remark = f"{current_country} - {remark}" if remark else current_country

        try:
            if protocol == "vless":
                settings = json.loads(item.get("settings", "{}"))
                clients = settings.get("clients")
                if not clients or not isinstance(clients, list) or not clients[0].get("id"):
                    if log_callback: log_callback(f"警告: 跳过缺少客户端ID的VLESS入站规则: {item.get('tag', 'N/A')}")
                    continue
                client_id = clients[0]["id"]
                flow = clients[0].get("flow", "")

                stream_settings_str = item.get("streamSettings", "{}")
                if not stream_settings_str: stream_settings_str = "{}"
                stream_settings = json.loads(stream_settings_str)

                network = stream_settings.get("network")
                security = stream_settings.get("security", "none")
                if network == "ws":
                    ws_settings = stream_settings.get("wsSettings", {})
                    path = ws_settings.get("path", "/")
                    query_params = {"type": network, "security": security, "path": path}
                    host = ws_settings.get("headers", {}).get("Host")
                    if host:
                        query_params["host"] = host
                    if flow and flow in ["xtls-rprx-vision", "xtls-rprx-vless", "xtls-rprx-splice", "xtls-rprx-direct"]:
                        query_params["flow"] = flow
                    elif flow:
                        if log_callback: log_callback(f"警告: VLESS入站规则 {item.get('tag', 'N/A')} (网络 'ws') 存在不支持的flow: {flow}。已忽略flow。")
                    
                    link = f"{protocol}://{client_id}@{address}:{port}?{urllib.parse.urlencode(query_params, quote_via=urllib.parse.quote)}"

                elif network == "tcp" and security in ["tls", "xtls"]:
                     query_params = {"type": network, "security": security}
                     if flow and flow in ["xtls-rprx-vision", "xtls-rprx-vless", "xtls-rprx-splice", "xtls-rprx-direct"]:
                         query_params["flow"] = flow
                     elif flow:
                         if log_callback: log_callback(f"警告: VLESS入站规则 {item.get('tag', 'N/A')} (网络 'tcp', 安全 '{security}') 存在不支持的flow: {flow}。已忽略flow。")
                     tls_settings = stream_settings.get(f"{security}Settings", {})
                     sni = tls_settings.get("serverName")
                     if sni:
                         query_params["sni"] = sni
                     alpn = tls_settings.get("alpn")
                     if alpn and isinstance(alpn, list):
                         query_params["alpn"] = ",".join(alpn)

                     link = f"{protocol}://{client_id}@{address}:{port}?{urllib.parse.urlencode(query_params, quote_via=urllib.parse.quote)}"
                
                elif network == "grpc":
                    grpc_settings = stream_settings.get("grpcSettings", {})
                    service_name = grpc_settings.get("serviceName", "")
                    query_params = {"type": network, "security": security, "serviceName": service_name}
                    if security != "none":
                        tls_settings = stream_settings.get(f"{security}Settings", {})
                        sni = tls_settings.get("serverName")
                        if sni: query_params["sni"] = sni
                    link = f"{protocol}://{client_id}@{address}:{port}?{urllib.parse.urlencode(query_params, quote_via=urllib.parse.quote)}"
                else:
                    if flow:
                        if log_callback: log_callback(f"警告: 跳过VLESS入站规则 {item.get('tag', 'N/A')}，其网络/flow组合不受支持: {network}/{flow}")
                        continue
                    if log_callback: log_callback(f"警告: 跳过VLESS入站规则 {item.get('tag', 'N/A')}，其网络为 '{network}'。仅完全解析 'ws', 'tcp' (带 tls/xtls 安全和flow), 以及 'grpc'。")
                    continue

            elif protocol == "vmess":
                settings = json.loads(item.get("settings", "{}"))
                clients = settings.get("clients")
                if not clients or not isinstance(clients, list) or not clients[0].get("id"):
                    if log_callback: log_callback(f"警告: 跳过缺少客户端ID的VMESS入站规则: {item.get('tag', 'N/A')}")
                    continue
                client_id = clients[0]["id"]
                alter_id = clients[0].get("alterId", 0)

                stream_settings_str = item.get("streamSettings", "{}")
                if not stream_settings_str: stream_settings_str = "{}"
                stream_settings = json.loads(stream_settings_str)
                network = stream_settings.get("network")
                vmess_security_link_param = stream_settings.get("security", "none")
                if vmess_security_link_param == "none": vmess_security_link_param = ""

                vmess_config = {
                    "v": "2", "ps": remark, "add": address, "port": str(item["port"]),
                    "id": client_id, "aid": str(alter_id), "net": network, "type": "none",
                    "host": "", "path": "", "tls": vmess_security_link_param, 
                }

                if network == "ws":
                    ws_settings = stream_settings.get("wsSettings", {})
                    vmess_config["path"] = ws_settings.get("path", "/")
                    host = ws_settings.get("headers", {}).get("Host")
                    if host: vmess_config["host"] = host
                elif network == "tcp":
                    tcp_settings = stream_settings.get("tcpSettings", {})
                    header_settings = tcp_settings.get("header", {})
                    vmess_config["type"] = header_settings.get("type", "none")
                    if vmess_config["type"] == "http":
                        request_settings = header_settings.get("request", {})
                        host_headers = request_settings.get("headers", {}).get("Host")
                        if isinstance(host_headers, list) and host_headers:
                            vmess_config["host"] = host_headers[0]
                        elif isinstance(host_headers, str):
                             vmess_config["host"] = host_headers
                elif network == "grpc":
                    grpc_settings = stream_settings.get("grpcSettings", {})
                    vmess_config["path"] = grpc_settings.get("serviceName", "")
                
                if vmess_security_link_param in ["tls", "xtls"]:
                    tls_settings_key = f"{vmess_security_link_param}Settings"
                    tls_settings = stream_settings.get(tls_settings_key, {})
                    sni = tls_settings.get("serverName")
                    if sni:
                         if network != 'ws' or not vmess_config.get('host'):
                             vmess_config["host"] = sni

                vmess_json = json.dumps(vmess_config, separators=(',', ':')).encode()
                link = f"vmess://{base64.b64encode(vmess_json).decode()}"

            elif protocol == "trojan":
                settings = json.loads(item.get("settings", "{}"))
                clients = settings.get("clients")
                if not clients or not isinstance(clients, list) or not clients[0].get("password"):
                    if log_callback: log_callback(f"警告: 跳过缺少密码的TROJAN入站规则: {item.get('tag', 'N/A')}")
                    continue
                password_val = clients[0]["password"]
                
                link = f"trojan://{password_val}@{address}:{port}"
                query_params = {}

                stream_settings_str = item.get("streamSettings", "{}")
                if not stream_settings_str: stream_settings_str = "{}"
                stream_settings = json.loads(stream_settings_str)
                security = stream_settings.get("security", "none")

                if security in ["tls", "xtls"]:
                    sec_settings_key = f"{security}Settings"
                    sec_settings = stream_settings.get(sec_settings_key, {})
                    sni = sec_settings.get("serverName")
                    if sni: query_params["sni"] = sni
                    alpn = sec_settings.get("alpn")
                    if alpn and isinstance(alpn, list):
                        query_params["alpn"] = ",".join(alpn)

                network = stream_settings.get("network")
                if network and network != "tcp":
                    query_params["type"] = network
                    if network == "ws":
                        ws_settings = stream_settings.get("wsSettings", {})
                        path = ws_settings.get("path", "/")
                        if path and path != "/": query_params["path"] = path
                        host = ws_settings.get("headers", {}).get("Host")
                        if host: query_params["host"] = host
                    elif network == "grpc":
                        grpc_settings = stream_settings.get("grpcSettings", {})
                        service_name = grpc_settings.get("serviceName")
                        if service_name: query_params["serviceName"] = service_name
                
                flow = clients[0].get("flow", "")
                if flow and flow.startswith("xtls-rprx-"):
                    query_params["flow"] = flow

                if query_params:
                    link += "?" + parse.urlencode(query_params, doseq=True, quote_via=parse.quote)

            elif protocol == "shadowsocks":
                settings_str = item.get("settings", "{}")
                if not settings_str: settings_str = "{}"
                settings = json.loads(settings_str)

                method = settings.get("method")
                password_ss = settings.get("password")
                if not method or not password_ss:
                     if log_callback: log_callback(f"警告: 跳过缺少方法或密码的SHADOWSOCKS入站规则: {item.get('tag', 'N/A')}")
                     continue
                
                user_info = f"{method}:{password_ss}"
                encoded_user_info = base64.urlsafe_b64encode(user_info.encode()).decode().rstrip('=')
                link = f"ss://{encoded_user_info}@{address}:{port}"

        except json.JSONDecodeError:
            if log_callback: log_callback(f"解码入站规则 {item.get('tag', 'N/A')} 的JSON时出错。跳过。")
            continue
        except Exception as e:
            if log_callback: log_callback(f"为入站规则 {item.get('tag', 'N/A')} 生成链接时出错: {e}。跳过。")
            if log_callback: log_callback(traceback.format_exc())
            continue

        if link:
            if remark and protocol != "vmess":
                link += f"#{parse.quote(remark)}"

            expiry_time = item.get("expiryTime", 0)
            total_limit = item.get("total", 0)
            result.append((link, expiry_time, total_limit))
    return result


def check(url: str, filepath: str, reader: database.Reader, username: str, password: str, log_callback: typing.Callable[[str], None] = None) -> RunningState | None:
    try:
        original_url = url
        if not url.startswith("http://") and not url.startswith("https://"):
             url_with_http = f"http://{url}"
             url_with_https = f"https://{url}"
        else:
             if url.startswith("http://"):
                 url_with_http = url
                 url_with_https = url.replace("http://", "https://", 1)
             else:
                 url_with_https = url
                 url_with_http = url.replace("https://", "http://", 1)
        
        current_url_to_try = url_with_https
        # Log attempt with current credentials (username only for security)
        # if log_callback: log_callback(f"尝试使用账号 '{username}' 登录 {current_url_to_try}...")
        headers = get_cookies(url=current_url_to_try, username=username, password=password)
        
        if not headers:
            # if log_callback: log_callback(f"HTTPS登录 {current_url_to_try} 失败，尝试HTTP...")
            current_url_to_try = url_with_http
            headers = get_cookies(url=current_url_to_try, username=username, password=password)
            if not headers:
                # No need to log here, ScanWorker will handle iterating credentials
                # if log_callback: log_callback(f"{original_url} 使用账号 '{username}' 登录失败 (尝试了HTTPS和HTTP)。")
                return None
        
        login_successful_url = current_url_to_try
        if log_callback: log_callback(f"成功使用账号 '{username}' 登录到 {login_successful_url} (原始: {original_url})")

        parsed_url = parse.urlparse(url=login_successful_url)
        address = parsed_url.hostname
        if not address:
            if log_callback: log_callback(f"跳过: 无法从成功的登录URL解析主机名: {login_successful_url}")
            return None
        
        # Writing to availables.txt only the URL. If credentials are needed, this part needs adjustment.
        # For now, multiple successful credential pairs for the same URL will write the URL multiple times.
        write_file(filename=filepath, lines=login_successful_url, overwrite=False, log_callback=log_callback)
        # if log_callback: log_callback(f"已将可用的面板URL {login_successful_url} 保存到 {filepath}") # A bit verbose per credential

        status = get_server_status(login_successful_url, headers)
        if not status:
            if log_callback: log_callback(f"获取 {login_successful_url} (账号: {username}) 的服务器状态失败。跳过。")
            return RunningState(url=login_successful_url, state="登录成功, API错误") 

        running_state = get_running_state(data=status, url=login_successful_url)
        # if log_callback: log_callback(f"获取到 {login_successful_url} 的状态: 状态={running_state.state}, 版本={running_state.version}, 运行时间={running_state.uptime}s")

        obj_data = status.get("obj", {})
        if not isinstance(obj_data, dict): obj_data = {}

        if "appStats" not in obj_data:
            # if log_callback: log_callback(f"正在为 {login_successful_url} 获取入站列表...")
            inbounds = get_inbound_list(login_successful_url, headers)
            if inbounds:
                running_state.links = generate_subscription_links(data=inbounds, address=address, reader=reader, log_callback=log_callback)
                # if log_callback: log_callback(f"为 {login_successful_url} 找到 {len(running_state.links) if running_state.links else 0} 个链接。")
            else:
                 # if log_callback: log_callback(f"获取 {login_successful_url} 的入站列表失败。")
                 running_state.links = []
        else:
            # if log_callback: log_callback(f"为 {login_successful_url} 找到 'appStats'。假设是较新版XUI，除非逻辑需要，否则不获取单独的入站列表。")
            running_state.links = []

        return running_state # This state is for one successful (URL, user, pass)
    except Exception as e:
        if log_callback: log_callback(f"检查 {original_url if 'original_url' in locals() else url} (账号: {username}) 时发生错误: {e}")
        # if log_callback: log_callback(traceback.format_exc()) # Can be too verbose
        return None


def extract_domain(url: str, include_protocol: bool = True) -> str:
    if not url or not isinstance(url, str):
        return ""

    if not url.startswith("http://") and not url.startswith("https://"):
        url_with_scheme = f"http://{url}"
    else:
        url_with_scheme = url

    try:
        parsed_url = parse.urlparse(url_with_scheme)
        domain_part = parsed_url.netloc
        if not domain_part:
            return ""

        if include_protocol:
            scheme_to_use = parsed_url.scheme if parsed_url.scheme and url.startswith(parsed_url.scheme) else \
                            ('https' if url.lower().startswith("https://") else 'http')
            return f"{scheme_to_use}://{domain_part}"
        else:
            return domain_part.split(':')[0]
    except Exception:
        return ""


def dedup(filepath: str, log_callback: typing.Callable[[str], None] = None) -> None:
    def include_subpath(url_to_check: str) -> bool:
        url_to_check = trim(url_to_check).lower()
        if not url_to_check.startswith("http://") and not url_to_check.startswith("https://"):
            url_with_scheme = f"http://{url_to_check}"
        else:
            url_with_scheme = url_to_check
        parsed = parse.urlparse(url_with_scheme)
        return bool(parsed.path and parsed.path != '/')

    def cmp_key(url_to_sort: str) -> tuple[int, int, str]:
        has_subpath = 2 if include_subpath(url_to_sort) else 0 
        is_https = 1 if url_to_sort.lower().startswith("https://") else 0
        return (has_subpath, is_https, url_to_sort.lower()) 

    if not os.path.exists(filepath) or not os.path.isfile(filepath):
        if log_callback: log_callback(f"去重跳过: 文件 {filepath} 不存在")
        return

    lines_read = []
    try:
        with open(filepath, "r", encoding="utf8") as f:
            lines_read = f.readlines()
    except Exception as e:
        if log_callback: log_callback(f"读取文件 {filepath} 进行去重时出错: {e}")
        return

    groups = defaultdict(list)
    valid_lines_count = 0
    for line_content in lines_read:
        line_content = trim(line_content)
        if not line_content or line_content.startswith("#") or line_content.startswith(";"):
            continue
        valid_lines_count += 1

        normalized_line_for_key = line_content
        if not normalized_line_for_key.lower().startswith("http://") and \
           not normalized_line_for_key.lower().startswith("https://"):
            normalized_line_for_key = f"http://{normalized_line_for_key}"
        
        domain_key = extract_domain(url=normalized_line_for_key, include_protocol=False).lower()
        if domain_key:
             groups[domain_key].append(line_content)

    deduped_links = []
    for domain_name, urls_in_group in groups.items():
        if not urls_in_group:
            continue
        if len(urls_in_group) > 1:
            urls_in_group.sort(key=cmp_key, reverse=True)
        deduped_links.append(urls_in_group[0])
    
    deduped_links.sort()

    total_read, remain = valid_lines_count, len(deduped_links)
    if log_callback:
        log_callback(f"[去重] 文件: {filepath} 完成, 有效行数: {total_read}, 去重后剩余: {remain}, 丢弃: {total_read-remain}")

    if deduped_links or (total_read > 0 and not deduped_links) :
        try:
            write_file(filename=filepath, lines=deduped_links, overwrite=True, log_callback=log_callback)
            if log_callback: log_callback(f"去重列表已保存到 {filepath}")
        except Exception as e:
            if log_callback: log_callback(f"写入去重列表到 {filepath} 时出错: {e}")


def generate_markdown(items: list[RunningState], filepath: str, log_callback: typing.Callable[[str], None] = None) -> None:
    if not filepath:
        if log_callback: log_callback("跳过Markdown生成: 无效的文件路径。")
        return

    # Filter out items that might indicate a failure or are not RunningState instances
    valid_items_dict = {} # Use dict to store only one entry per URL (e.g. first successful)
    for item in items:
        if isinstance(item, RunningState) and \
           (item.links or (item.state not in ["unknown", "Login OK, API Error", "Offline/API Error"])):
            if item.url not in valid_items_dict: # Keep first successful state for a URL
                 valid_items_dict[item.url] = item
    
    valid_items = list(valid_items_dict.values())


    if not valid_items:
         if log_callback: log_callback("跳过Markdown生成: 未找到有效项目或确认状态。")
         if os.path.exists(filepath):
            write_file(filename=filepath, lines=[], overwrite=True, log_callback=log_callback)
         return

    headers = ["URL", "XRay状态", "XRay版本", "运行时间 (s)", "上行总流量", "下行总流量", "订阅链接数", "示例链接"]
    table_lines = []
    table_lines.append("| " + " | ".join(headers) + " |")
    table_lines.append("| " + " | ".join(["---"] * len(headers)) + " |")

    for item in valid_items:
        display_url = item.url
        if len(display_url) > 50:
             display_url = display_url[:47] + "..."
        uptime_str = str(item.uptime) if item.uptime is not None else "未知"
        links_count_str = "0"
        example_link_str = "N/A"

        if item.links and isinstance(item.links, list):
            links_count_str = str(len(item.links))
            if item.links:
                example_link_str = f"`{item.links[0][0][:60]}{'...' if len(item.links[0][0]) > 60 else ''}`"
        else:
            links_count_str = "0"
            if item.state not in ["unknown", "Login OK, API Error", "Offline/API Error"]:
                example_link_str = "(无定义/启用的链接)"
            else:
                example_link_str = "(面板错误)"

        row_data = [
            display_url, item.state, item.version, uptime_str,
            item.sent, item.recv, links_count_str, example_link_str,
        ]
        escaped_row_data = [str(cell).replace('|', '\\|') for cell in row_data]
        table_lines.append("| " + " | ".join(escaped_row_data) + " |")

    write_file(filename=filepath, lines=table_lines, overwrite=True, log_callback=log_callback)
    if log_callback: log_callback(f"Markdown表格已生成并保存到 {filepath}")


# --- Worker Class for the Scan Logic ---
class ScanWorker(QObject):
    finished = Signal()
    error = Signal(str)
    progress = Signal(int) 
    status_message = Signal(str)
    scan_completed = Signal(list) # List of RunningState objects for successfully checked panels
    links_generated = Signal(list) # List of all link strings from all successful panels

    def __init__(self, config: dict):
        super().__init__()
        self.config = config
        self._is_canceled = False

    def cancel(self):
        self._is_canceled = True
        self.status_message.emit("取消标志已设置。")

    def run(self):
        try:
            self.status_message.emit("扫描工作线程已启动。")

            workspace = self.config.get("workspace")
            domain_file_path_config = self.config.get("domain_file") # This is just the filename part
            available_file_config = self.config.get("available_file")
            link_file_config = self.config.get("link_file")
            markdown_file_config = self.config.get("markdown_file")
            num_threads = self.config.get("thread_count")
            update_mmdb = self.config.get("update_mmdb")
            
            # Credentials
            default_username = self.config.get("username", "admin")
            default_password = self.config.get("password", "admin")
            username_file = self.config.get("username_file") # Path or None
            password_file = self.config.get("password_file") # Path or None
            
            source_path = domain_file_path_config # Already resolved to full path in MainWindow
            available_path = os.path.join(workspace, available_file_config)
            link_path = os.path.join(workspace, link_file_config)
            markdown_path = os.path.join(workspace, markdown_file_config)

            if not os.path.exists(source_path) or not os.path.isfile(source_path):
                raise FileNotFoundError(f"域名列表文件未找到: {source_path}")

            self.status_message.emit(f"正在去重输入文件: {source_path}")
            dedup(filepath=source_path, log_callback=self.status_message.emit)

            domains = []
            try:
                with open(source_path, "r", encoding="utf8") as f:
                    domains = [trim(x) for x in f.readlines() if trim(x) and not trim(x).startswith("#") and not trim(x).startswith(";")]
            except Exception as e:
                 raise IOError(f"读取域名列表文件 {source_path} 错误: {e}")

            if not domains:
                self.status_message.emit("去重后列表中未找到有效域名。扫描将不会继续。")
                self.scan_completed.emit([]) 
                self.links_generated.emit([]) 
                self.progress.emit(100)
                self.finished.emit()
                return
            self.status_message.emit(f"加载了 {len(domains)} 个唯一域名用于扫描。")

            # --- Credential List Generation ---
            usernames_to_use = []
            if username_file:
                try:
                    with open(username_file, 'r', encoding='utf-8') as f:
                        usernames_to_use = [line.strip() for line in f if line.strip()]
                    if not usernames_to_use:
                        self.status_message.emit(f"警告: 账号文件 '{os.path.basename(username_file)}' 为空。")
                except Exception as e:
                    self.status_message.emit(f"错误: 读取账号文件 '{os.path.basename(username_file)}' 失败: {e}。")
            
            if not usernames_to_use: # Fallback if file not specified, empty, or error
                usernames_to_use.append(default_username)
                if username_file: # If a file was specified but failed/empty
                     self.status_message.emit(f"将使用输入框中的账号 '{default_username}'。")


            passwords_to_use = []
            if password_file:
                try:
                    with open(password_file, 'r', encoding='utf-8') as f:
                        passwords_to_use = [line.strip() for line in f if line.strip()]
                    if not passwords_to_use:
                        self.status_message.emit(f"警告: 密码文件 '{os.path.basename(password_file)}' 为空。")
                except Exception as e:
                    self.status_message.emit(f"错误: 读取密码文件 '{os.path.basename(password_file)}' 失败: {e}。")

            if not passwords_to_use: # Fallback
                passwords_to_use.append(default_password)
                if password_file: # If a file was specified but failed/empty
                    self.status_message.emit(f"将使用输入框中的密码。")


            credentials_list = []
            for u in usernames_to_use:
                for p in passwords_to_use:
                    credentials_list.append((u, p))

            if not credentials_list:
                self.status_message.emit("错误: 未能生成任何有效凭据对。请检查输入和文件。")
                self.error.emit("未能生成任何有效凭据对。")
                self.finished.emit()
                return
            
            self.status_message.emit(f"将使用 {len(set(usernames_to_use))} 个唯一账号和 {len(set(passwords_to_use))} 个唯一密码，构成 {len(credentials_list)} 对凭据组合。")
            # --- End Credential List Generation ---

            mmdb_dir = os.path.join(workspace, "mmdb") 
            self.status_message.emit(f"正在加载MMDB数据库 (更新: {update_mmdb})...")
            reader = load_mmdb(directory=mmdb_dir, update=update_mmdb, log_callback=self.status_message.emit)
            if reader is None:
                 self.status_message.emit("警告: MMDB阅读器未能加载。GeoIP功能将被禁用。")

            tasks = []
            for domain_url in domains:
                for user, passwd in credentials_list:
                    tasks.append([domain_url, available_path, reader, user, passwd, self.status_message.emit])
            
            if not tasks:
                self.status_message.emit("未生成扫描任务。请检查域名列表和凭据设置。")
                self.scan_completed.emit([]) 
                self.links_generated.emit([])
                self.progress.emit(100) # Indicate completion of setup
                self.finished.emit()
                return

            self.status_message.emit(f"开始对 {len(tasks)} 个任务 (域名/凭据组合) 进行检查，使用 {num_threads} 个线程。")
            
            all_results_for_markdown = [] # Collect all RunningState for markdown, will be deduped by URL later
            completed_tasks_count = 0
            total_tasks_count = len(tasks) # Total tasks to run

            with futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
                active_futures = {executor.submit(check, *task_args): task_args for task_args in tasks}
                for future in futures.as_completed(active_futures):
                    if self._is_canceled:
                         self.status_message.emit("扫描取消请求已检测到。正在停止进一步处理。")
                         for f_act in active_futures:
                             if not f_act.done():
                                 f_act.cancel()
                         break 
                    
                    task_args_processed = active_futures[future] # [url, available_path, reader, user, password, log_fn]
                    url_processed = task_args_processed[0]
                    user_processed = task_args_processed[3]

                    try:
                        result_item = future.result() # This is a RunningState object or None
                        if result_item: 
                             all_results_for_markdown.append(result_item)
                    except futures.CancelledError:
                        self.status_message.emit(f"任务 {url_processed} (账号: {user_processed}) 已被取消。")
                    except Exception as e:
                        self.status_message.emit(f"处理任务 {url_processed} (账号: {user_processed}) 时出错: {e}") # Removed traceback for brevity in GUI
                    
                    completed_tasks_count += 1
                    if total_tasks_count > 0:
                        current_progress = int((completed_tasks_count / total_tasks_count) * 100)
                        self.progress.emit(current_progress)

            if self._is_canceled:
                 self.status_message.emit("扫描已被用户取消。")
                 # Emit partial results if any
                 self.scan_completed.emit(all_results_for_markdown)
                 temp_links = []
                 for res in all_results_for_markdown:
                     if res.links: temp_links.extend([link_tuple[0] for link_tuple in res.links])
                 self.links_generated.emit(list(set(temp_links))) # Dedup links
                 self.progress.emit(0) # Reset progress
                 self.finished.emit()
                 return

            self.status_message.emit("所有检查已处理完毕。")
            self.progress.emit(100)

            # Process results for links - deduped by link string
            all_links_collected = []
            if all_results_for_markdown:
                for item in all_results_for_markdown: # item is RunningState
                    if item.links:
                        all_links_collected.extend([link_tuple[0] for link_tuple in item.links])
            
            unique_links = sorted(list(set(all_links_collected)))

            if unique_links:
                self.status_message.emit(f"共找到 {len(unique_links)} 条唯一的有效订阅链接。")
                try:
                    link_content = base64.b64encode("\n".join(unique_links).encode(encoding="utf8")).decode(encoding="utf8")
                    write_file(filename=link_path, lines=link_content, overwrite=True, log_callback=self.status_message.emit)
                    self.links_generated.emit(unique_links)
                except Exception as e:
                    self.status_message.emit(f"编码或写入链接文件时出错: {e}")
                    self.links_generated.emit([])
            else:
                self.status_message.emit("未找到有效订阅链接。")
                self.links_generated.emit([]) 
                if os.path.exists(link_path): # Clear file if it exists
                     write_file(filename=link_path, lines="", overwrite=True, log_callback=self.status_message.emit)

            # Generate markdown based on all_results_for_markdown (will be deduped by URL inside generate_markdown)
            if all_results_for_markdown:
                 # generate_markdown will pick one entry per URL for the table
                 generate_markdown(items=all_results_for_markdown, filepath=markdown_path, log_callback=self.status_message.emit)
            else:
                 self.status_message.emit("未找到可响应面板来生成Markdown表格。")
                 if os.path.exists(markdown_path): # Clear file
                      write_file(filename=markdown_path, lines="", overwrite=True, log_callback=self.status_message.emit)
            
            self.scan_completed.emit(all_results_for_markdown) # Send all results, GUI can dedup for display if needed

            self.status_message.emit("扫描进程成功完成。")
            self.finished.emit()

        except FileNotFoundError as e:
             self.error.emit(f"文件错误: {e}")
             self.status_message.emit(f"扫描因文件错误失败: {e}")
             self.progress.emit(0) 
             self.finished.emit()
        except IOError as e:
            self.error.emit(f"输入输出错误: {e}")
            self.status_message.emit(f"扫描因输入输出错误失败: {e}")
            self.progress.emit(0)
            self.finished.emit()
        except Exception as e:
            self.error.emit(f"工作线程发生意外错误: {e}\n{traceback.format_exc()}")
            self.status_message.emit(f"扫描因意外错误失败: {e}")
            self.progress.emit(0)
            self.finished.emit()


# --- GUI Main Window ---
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("XUI 面板扫描器")
        self.setGeometry(100, 100, 850, 750) # Increased height slightly for new labels

        self.worker = None
        self.worker_thread = None

        # Paths for selected credential files
        self.username_file_path = None
        self.password_file_path = None

        self.setup_ui()
        self.connect_signals()

        self.stdout_logger = QTextEditLogger()
        self.stdout_logger.message_written.connect(self.append_log)
        sys.stdout = self.stdout_logger
        sys.stderr = self.stdout_logger 

    def setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        input_group = QGroupBox("输入文件和工作目录")
        input_layout = QFormLayout(input_group)

        self.domain_file_edit = QLineEdit("domains.txt")
        self.browse_domain_button = QPushButton("浏览")
        domain_file_layout = QHBoxLayout()
        domain_file_layout.addWidget(self.domain_file_edit)
        domain_file_layout.addWidget(self.browse_domain_button)
        input_layout.addRow("域名列表文件:", domain_file_layout)

        self.workspace_edit = QLineEdit(DEFAULT_WORKSPACE)
        self.browse_workspace_button = QPushButton("浏览")
        workspace_layout = QHBoxLayout()
        workspace_layout.addWidget(self.workspace_edit)
        workspace_layout.addWidget(self.browse_workspace_button)
        input_layout.addRow("工作目录:", workspace_layout)
        main_layout.addWidget(input_group)

        output_group = QGroupBox("输出文件")
        output_layout = QFormLayout(output_group)
        self.available_file_edit = QLineEdit("availables.txt")
        output_layout.addRow("可用面板文件:", self.available_file_edit)
        self.link_file_edit = QLineEdit("links.txt")
        output_layout.addRow("订阅链接文件:", self.link_file_edit)
        self.markdown_file_edit = QLineEdit("table.md")
        output_layout.addRow("Markdown结果文件:", self.markdown_file_edit)
        main_layout.addWidget(output_group)

        settings_group = QGroupBox("扫描设置")
        settings_layout = QFormLayout(settings_group)

        # Username
        self.username_edit = QLineEdit("admin")
        username_browse_layout = QHBoxLayout()
        username_browse_layout.addWidget(self.username_edit, 1) # Give more space to QLineEdit
        self.browse_username_button = QPushButton("从文件选择")
        username_browse_layout.addWidget(self.browse_username_button)
        self.clear_username_file_button = QPushButton("清除")
        username_browse_layout.addWidget(self.clear_username_file_button)
        settings_layout.addRow("账号:", username_browse_layout)
        self.username_file_label = QLabel("账号来源: 输入框")
        settings_layout.addRow("", self.username_file_label)


        # Password
        self.password_edit = QLineEdit("admin")
        self.password_edit.setEchoMode(QLineEdit.Password)
        password_browse_layout = QHBoxLayout()
        password_browse_layout.addWidget(self.password_edit, 1)
        self.browse_password_button = QPushButton("从文件选择")
        password_browse_layout.addWidget(self.browse_password_button)
        self.clear_password_file_button = QPushButton("清除")
        password_browse_layout.addWidget(self.clear_password_file_button)
        settings_layout.addRow("密码:", password_browse_layout)
        self.password_file_label = QLabel("密码来源: 输入框")
        settings_layout.addRow("", self.password_file_label)


        self.thread_spinbox = QSpinBox()
        self.thread_spinbox.setMinimum(1)
        default_threads = (os.cpu_count() or 1) * 2
        self.thread_spinbox.setValue(min(default_threads, 128))
        self.thread_spinbox.setMaximum(10000000)
        settings_layout.addRow("并发线程数:", self.thread_spinbox)

        self.update_mmdb_checkbox = QCheckBox("更新IP数据库 (GeoLite2)")
        self.update_mmdb_checkbox.setChecked(False)
        settings_layout.addRow("IP数据库:", self.update_mmdb_checkbox)
        main_layout.addWidget(settings_group)

        control_layout = QHBoxLayout()
        self.start_button = QPushButton("开始扫描")
        self.cancel_button = QPushButton("取消扫描")
        self.cancel_button.setEnabled(False) 
        control_layout.addWidget(self.start_button)
        control_layout.addWidget(self.cancel_button)
        main_layout.addLayout(control_layout)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        main_layout.addWidget(self.progress_bar)

        log_group = QGroupBox("日志输出")
        log_layout = QVBoxLayout(log_group)
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        log_layout.addWidget(self.log_output)
        main_layout.addWidget(log_group, 1) 

        self.statusBar()

    def connect_signals(self):
        self.browse_domain_button.clicked.connect(self.browse_domain_file)
        self.browse_workspace_button.clicked.connect(self.browse_workspace)
        
        self.browse_username_button.clicked.connect(self.browse_username_credential_file)
        self.clear_username_file_button.clicked.connect(self.clear_username_file_selection)
        
        self.browse_password_button.clicked.connect(self.browse_password_credential_file)
        self.clear_password_file_button.clicked.connect(self.clear_password_file_selection)
        
        self.start_button.clicked.connect(self.start_scan)
        self.cancel_button.clicked.connect(self.cancel_scan)

    @Slot()
    def browse_username_credential_file(self):
        filename, _ = QFileDialog.getOpenFileName(self, "选择账号文件", self.workspace_edit.text(), "文本文件 (*.txt);;所有文件 (*)")
        if filename:
            self.username_file_path = filename
            self.username_file_label.setText(f"账号来源: 文件 ({os.path.basename(filename)})")
            self.username_file_label.setToolTip(filename)
            self.append_log(f"账号将从文件 '{filename}' 加载。")
            
    @Slot()
    def clear_username_file_selection(self):
        self.username_file_path = None
        self.username_file_label.setText("账号来源: 输入框")
        self.username_file_label.setToolTip("")
        self.append_log("已清除选择的账号文件，将使用输入框中的账号。")

    @Slot()
    def browse_password_credential_file(self):
        filename, _ = QFileDialog.getOpenFileName(self, "选择密码文件", self.workspace_edit.text(), "文本文件 (*.txt);;所有文件 (*)")
        if filename:
            self.password_file_path = filename
            self.password_file_label.setText(f"密码来源: 文件 ({os.path.basename(filename)})")
            self.password_file_label.setToolTip(filename)
            self.append_log(f"密码将从文件 '{filename}' 加载。")

    @Slot()
    def clear_password_file_selection(self):
        self.password_file_path = None
        self.password_file_label.setText("密码来源: 输入框")
        self.password_file_label.setToolTip("")
        self.append_log("已清除选择的密码文件，将使用输入框中的密码。")


    @Slot()
    def browse_domain_file(self):
        # If domain_file_edit contains an absolute path, use its directory as initial
        current_domain_path = self.domain_file_edit.text()
        initial_dir = self.workspace_edit.text()
        if os.path.isabs(current_domain_path):
            initial_dir = os.path.dirname(current_domain_path)
        
        filename, _ = QFileDialog.getOpenFileName(self, "选择域名列表文件", initial_dir, "文本文件 (*.txt);;所有文件 (*)")
        if filename:
            # Store absolute path always for domain file for simplicity in worker
            self.domain_file_edit.setText(filename)


    @Slot()
    def browse_workspace(self):
        directory = QFileDialog.getExistingDirectory(self, "选择工作目录", self.workspace_edit.text() or QStandardPaths.writableLocation(QStandardPaths.HomeLocation))
        if directory:
            self.workspace_edit.setText(directory)

    @Slot()
    def start_scan(self):
        self.start_button.setEnabled(False)
        self.cancel_button.setEnabled(True)
        self.log_output.clear()
        self.progress_bar.setValue(0)
        self.statusBar().clearMessage()

        # Resolve domain file path: if not absolute, join with workspace
        domain_file_input = trim(self.domain_file_edit.text())
        workspace_input = trim(self.workspace_edit.text())

        resolved_domain_file_path = domain_file_input
        if not os.path.isabs(domain_file_input):
            resolved_domain_file_path = os.path.join(workspace_input, domain_file_input)


        if not workspace_input or not os.path.isdir(workspace_input):
             QMessageBox.warning(self, "输入错误", "请输入有效的工作目录。")
             self.reset_ui_after_scan()
             return
        if not domain_file_input: # Check original entry
            QMessageBox.warning(self, "输入错误", "请输入域名列表文件名或路径。")
            self.reset_ui_after_scan()
            return
        if not os.path.exists(resolved_domain_file_path) or not os.path.isfile(resolved_domain_file_path):
            QMessageBox.warning(self, "输入错误", f"域名列表文件未找到: {resolved_domain_file_path}")
            self.reset_ui_after_scan()
            return
        
        available_f = trim(self.available_file_edit.text())
        link_f = trim(self.link_file_edit.text())
        markdown_f = trim(self.markdown_file_edit.text())

        if not available_f or not link_f or not markdown_f:
             QMessageBox.warning(self, "输入错误", "请输入所有输出文件名。")
             self.reset_ui_after_scan()
             return

        config = {
            "workspace": workspace_input,
            "domain_file": resolved_domain_file_path, # Pass the resolved full path
            "available_file": available_f,
            "link_file": link_f,
            "markdown_file": markdown_f,
            "thread_count": self.thread_spinbox.value(),
            "update_mmdb": self.update_mmdb_checkbox.isChecked(),
            "username": self.username_edit.text(),  # Default username from QLineEdit
            "password": self.password_edit.text(),  # Default password from QLineEdit
            "username_file": self.username_file_path, # Path to username file, or None
            "password_file": self.password_file_path, # Path to password file, or None
        }

        self.worker_thread = QThread()
        self.worker = ScanWorker(config)
        self.worker.moveToThread(self.worker_thread)

        self.worker_thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.scan_finished_actions)
        
        self.worker.error.connect(self.handle_error)
        self.worker.progress.connect(self.progress_bar.setValue)
        self.worker.status_message.connect(self.append_log)
        self.worker.scan_completed.connect(self.show_scan_summary) # list of RunningState
        self.worker.links_generated.connect(self.show_links_summary) # list of link strings

        self.worker_thread.start()
        self.statusBar().showMessage("扫描已启动...")
        self.append_log("扫描进程已初始化...")

    @Slot()
    def cancel_scan(self):
        if self.worker and self.worker_thread and self.worker_thread.isRunning():
            self.append_log("正在请求取消扫描...")
            self.statusBar().showMessage("正在取消扫描...")
            self.cancel_button.setEnabled(False)
            self.worker.cancel() 

    @Slot()
    def scan_finished_actions(self):
        self.append_log("扫描线程已发出完成信号。")
        current_status_msg = self.statusBar().currentMessage()

        if self.worker and self.worker._is_canceled:
             self.statusBar().showMessage("扫描被用户取消。")
        elif self.progress_bar.value() == 100 and not self.start_button.isEnabled(): # Scan completed normally
             self.statusBar().showMessage("扫描进程已完成。")
        elif current_status_msg not in ["扫描被用户取消。", "扫描进程已完成。"]: # Error or other interruption
             self.statusBar().showMessage("扫描结束，可能存在错误或被中断。")
        
        if self.worker_thread:
            self.worker_thread.quit()
            self.worker_thread.wait(2000)
            if self.worker:
                self.worker.deleteLater()
            self.worker_thread.deleteLater()
            self.worker_thread = None
            self.worker = None
        
        self.reset_ui_after_scan()

    def reset_ui_after_scan(self):
        self.start_button.setEnabled(True)
        self.cancel_button.setEnabled(False)

    @Slot(str)
    def handle_error(self, error_message):
        QMessageBox.critical(self, "扫描错误", error_message)
        self.append_log(f"错误: {error_message}")

    @Slot(str)
    def append_log(self, text):
        if self.log_output:
             clean_text = text.strip()
             if clean_text:
                self.log_output.append(clean_text)

    @Slot(list) # list of RunningState objects
    def show_scan_summary(self, all_results: list):
        # Count unique responsive panels by URL
        successful_urls = set()
        for item in all_results:
            if isinstance(item, RunningState) and \
               (item.links or (item.state not in ["unknown", "Login OK, API Error", "Offline/API Error"])):
                successful_urls.add(item.url)
        count = len(successful_urls)
        self.append_log(f"扫描摘要: 找到 {count} 个可响应面板 (基于URL去重)。")

    @Slot(list) # list of unique link strings
    def show_links_summary(self, unique_links: list):
         count = len(unique_links) if unique_links else 0
         self.append_log(f"链接摘要: 共生成 {count} 条唯一的订阅链接。")

    def closeEvent(self, event):
        if self.worker_thread and self.worker_thread.isRunning():
            reply = QMessageBox.question(self, "扫描进行中",
                                         "扫描正在运行。您要取消并退出吗？",
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.Yes:
                self.cancel_scan()
                if self.worker_thread:
                    if not self.worker_thread.wait(3000):
                        self.append_log("扫描线程在取消请求后未正常结束。强制终止。")
                        self.worker_thread.terminate() 
                        self.worker_thread.wait(500) 
                sys.stdout = sys.__stdout__ # Restore stdout/stderr
                sys.stderr = sys.__stderr__
                event.accept()
            else:
                event.ignore()
        else:
            sys.stdout = sys.__stdout__ # Restore stdout/stderr
            sys.stderr = sys.__stderr__
            event.accept()

if __name__ == "__main__":
    # Ensure sys.__stdout__ is the original before any redirection
    # This is mainly for robustness if script is run multiple times in some environments
    if not hasattr(sys, '__stdout__'): 
        sys.__stdout__ = sys.stdout
    if not hasattr(sys, '__stderr__'):
        sys.__stderr__ = sys.stderr
        
    app = QApplication(sys.argv)
    main_window = MainWindow()
    main_window.show()
    sys.exit(app.exec())