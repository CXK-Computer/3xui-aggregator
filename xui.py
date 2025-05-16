# -*- coding: utf-8 -*-

# @Author  : wzdnzd
# @Time    : 2024-07-05
# @Description: base on https://blog-next-js.pages.dev/blog/%E6%89%AB%E6%8F%8F%E7%BB%93%E6%9E%9C
# @Author  : cxk-computer
# @Time    : 2025-05-17

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
from tqdm import tqdm

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

FILE_LOCK = threading.Lock()

# Use a more standard way to get a potential default user data path
# Fallback to script path if QStandardPaths fails or is not available
DEFAULT_WORKSPACE = QStandardPaths.writableLocation(QStandardPaths.AppDataLocation) or os.path.abspath(os.path.dirname(__file__))
if not DEFAULT_WORKSPACE: # Further fallback if AppDataLocation is None (e.g. very minimal systems)
    DEFAULT_WORKSPACE = os.path.abspath(os.path.dirname(__file__))


USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

# --- Custom Stream for redirecting stdout to GUI ---
class QTextEditLogger(QObject):
    message_written = Signal(str)

    def write(self, text):
        self.message_written.emit(str(text))
        # Also call original stdout write to keep console logging if needed
        # sys.__stdout__.write(text)

    def flush(self):
        sys.__stdout__.flush()

# Replace sys.stdout with our custom logger
# stdout_logger = QTextEditLogger()
# sys.stdout = stdout_logger
# --- End Custom Stream ---


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
        # print(f"HTTP Error {e.code} for {url}: {e.reason}") # Redirect this print
        if retry < 0 or e.code in [400, 401, 405]: # 401 Unauthorized, 400 Bad Request, 405 Method Not Allowed - often non-retryable for login
            return None
        time.sleep(1) # wait a bit before retry
        return http_post(url=url, headers=headers, params=params, retry=retry, timeout=timeout)
    except (TimeoutError, urllib.error.URLError) as e:
        # print(f"URL Error for {url}: {e}") # Redirect this print
        return None
    except Exception as e:
        # print(f"Unexpected error for {url}: {e}\n{traceback.format_exc()}") # Redirect this print
        if retry < 0:
            return None
        time.sleep(1) # wait a bit before retry
        return http_post(url=url, headers=headers, params=params, retry=retry, timeout=timeout)


def read_response(response: HTTPResponse, expected: int = 200, deserialize: bool = False, key: str = "") -> typing.Any:
    if not response or not isinstance(response, HTTPResponse):
        return None

    success = expected <= 0 or expected == response.getcode()
    if not success:
        # print(f"Expected status {expected}, got {response.getcode()}") # Redirect this print
        return None

    try:
        text = response.read()
    except Exception as e:
        # print(f"Error reading response: {e}") # Redirect this print
        return None

    try:
        content = text.decode(encoding="UTF8")
    except UnicodeDecodeError:
        try:
            content = gzip.decompress(text).decode("UTF8")
        except Exception as e:
            # print(f"Error decompressing gzip or decoding UTF8: {e}") # Redirect this print
            content = ""
    except Exception as e:
        # print(f"Error decoding response: {e}") # Redirect this print
        content = ""

    if not deserialize:
        return content

    if not content:
        return None
    try:
        data = json.loads(content)
        return data if not key else data.get(key, None)
    except Exception as e:
        # print(f"Error deserializing JSON: {e}") # Redirect this print
        return None


def trim(text: str) -> str:
    if not text or type(text) != str:
        return ""
    return text.strip()


def write_file(filename: str, lines: str | list, overwrite: bool = True, log_callback: typing.Callable[[str], None] = None) -> None:
    if not filename or not lines or type(lines) not in [str, list]: # allow empty list for clearing file
        if isinstance(lines, list) and not lines: # Allow writing an empty list to clear a file
            pass
        else:
            return


    try:
        if not isinstance(lines, str):
            lines = "\n".join(lines)

        filepath = os.path.abspath(os.path.dirname(filename))
        os.makedirs(filepath, exist_ok=True)
        mode = "w" if overwrite else "a"

        # waitting for lock
        # Use a timeout for acquire to prevent potential deadlocks in GUI context
        if not FILE_LOCK.acquire(timeout=30):
             if log_callback:
                 log_callback(f"Timeout acquiring lock for {filename}")
             else:
                print(f"Timeout acquiring lock for {filename}")
             return

        try:
            with open(filename, mode, encoding="UTF8") as f:
                f.write(lines + ("\n" if lines else "")) # Add newline only if content exists
                f.flush()
        finally:
            # release lock
            FILE_LOCK.release()

    except Exception as e:
        msg = f"write to file {filename} failed: {e}"
        if log_callback:
            log_callback(msg)
        else:
            print(msg)


def get_cookies(url: str, username: str = "admin", password: str = "admin") -> dict:
    url = trim(url)
    if not url:
        return None

    username = trim(username) or "admin"
    password = password or "admin" # Passwords might intentionally have leading/trailing spaces, usually not for 'admin'

    data = {"username": username, "password": password}
    headers = {
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Origin": url, # Origin should be just the scheme + hostname + port
        "Referer": url,
        "User-Agent": USER_AGENT,
    }
    
    parsed_origin_url = urllib.parse.urlparse(url)
    headers["Origin"] = f"{parsed_origin_url.scheme}://{parsed_origin_url.netloc}"


    response = http_post(url=f"{url}/login", headers=headers, params=data)
    success = read_response(response=response, expected=200, deserialize=True, key="success")
    if not success:
        # print(f"Login failed for {url}") # Redirect this print
        return None

    cookies = response.getheader("Set-Cookie")
    if not cookies:
        # print(f"No cookies received after login for {url}") # Redirect this print
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

    if num is None: # Handle None input
        return "unknown"
    if not isinstance(num, (int, float)): # Handle non-numeric input
        return "unknown"


    if num >= TB:
        return f"{num / TB:.2f} TB"
    elif num >= GB:
        return f"{num / GB:.2f} GB"
    # Added check for positive number before MB calculation
    elif num >= MB:
        return f"{num / MB:.2f} MB"
    elif num >= 0: # Handle small positive numbers and zero
        return f"{num / 1024:.2f} KB" if num >=1024 else f"{num} Bytes"
    else: # Negative numbers or other unexpected cases
        return "unknown"


def download_mmdb(repo: str, target: str, directory: str, retry: int = 3, log_callback: typing.Callable[[str], None] = None):
    """
    Download GeoLite2-City.mmdb or Country.mmdb from github release
    """
    repo = trim(text=repo)
    if not repo or len(repo.split("/", maxsplit=1)) != 2:
        msg = f"invalid github repo name: {repo}"
        if log_callback: log_callback(msg)
        raise ValueError(msg)

    target = trim(target)
    if not target:
        msg = "invalid download target (filename)"
        if log_callback: log_callback(msg)
        raise ValueError(msg)

    if not directory:
        msg = "invalid download directory"
        if log_callback: log_callback(msg)
        raise ValueError(msg)

    filepath = os.path.join(directory, target)
    os.makedirs(directory, exist_ok=True)

    # extract download url from github release page
    release_api = f"https://api.github.com/repos/{repo}/releases/latest" # Use latest, not per_page=1 which might be unstable
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/vnd.github.v3+json", # Recommended Accept header for GitHub API
    }

    count, response = 0, None
    while count < retry:
        try:
            if log_callback: log_callback(f"Attempt {count+1}/{retry}: Fetching release info for {repo}...")
            request = urllib.request.Request(url=release_api, headers=headers)
            response = urllib.request.urlopen(request, timeout=10, context=CTX)
            break # Success
        except Exception as e:
            if log_callback: log_callback(f"Attempt {count+1}/{retry} failed: {e}")
            count += 1
            time.sleep(2) # Wait before retrying

    if response is None:
        msg = f"Failed to fetch release info for {repo} after {retry} retries."
        if log_callback: log_callback(msg)
        raise Exception(msg)

    assets = read_response(response=response, expected=200, deserialize=True, key="assets")
    if not assets or not isinstance(assets, list):
        msg = "no assets found in github release"
        if log_callback: log_callback(msg)
        raise Exception(msg)

    download_url = ""
    for asset in assets:
        if asset.get("name", "") == target:
            download_url = asset.get("browser_download_url", "")
            break

    if not download_url:
        msg = f"no download url found for asset '{target}' in github release"
        if log_callback: log_callback(msg)
        raise Exception(msg)

    download(download_url, directory, target, retry, log_callback)


def download(url: str, directory: str, filename: str, retry: int = 3, log_callback: typing.Callable[[str], None] = None) -> None:
    """Download file from url to filepath with filename"""

    if retry < 0:
        msg = "achieved max retry count for download"
        if log_callback: log_callback(msg)
        raise Exception(msg)

    url = trim(url)
    if not url:
        msg = "invalid download url"
        if log_callback: log_callback(msg)
        raise ValueError(msg)

    directory = trim(directory)
    if not directory:
        msg = "invalid save directory"
        if log_callback: log_callback(msg)
        raise ValueError(msg)

    filename = trim(filename)
    if not filename:
        msg = "invalid save filename"
        if log_callback: log_callback(msg)
        raise ValueError(msg)

    if not os.path.exists(directory) or not os.path.isdir(directory):
        os.makedirs(directory)

    fullpath = os.path.join(directory, filename)
    if os.path.exists(fullpath) and os.path.isfile(fullpath):
        try:
            os.remove(fullpath)
            if log_callback: log_callback(f"Removed existing file: {fullpath}")
        except Exception as e:
             if log_callback: log_callback(f"Warning: Could not remove existing file {fullpath}: {e}")


    # download target file
    try:
        if log_callback: log_callback(f"Downloading {filename} from {url} to {fullpath}...")
        urllib.request.urlretrieve(url=url, filename=fullpath)
        if log_callback: log_callback(f"Download successful: {fullpath}")
    except Exception as e:
        msg = f"Download failed for {url}: {e}"
        if log_callback: log_callback(msg)
        # Recursively call download with decreased retry count
        time.sleep(1) # Wait before retrying download
        return download(url, directory, filename, retry - 1, log_callback)


def load_mmdb(
    directory: str, repo: str = "alecthw/mmdb_china_ip_list", filename: str = "Country.mmdb", update: bool = False, log_callback: typing.Callable[[str], None] = None
) -> database.Reader:
    filepath = os.path.join(directory, filename)
    if update or not os.path.exists(filepath) or not os.path.isfile(filepath):
        try:
            if log_callback: log_callback(f"Attempting to download/update MMDB file: {filename}...")
            download_mmdb(repo, filename, directory, log_callback=log_callback)
            if not os.path.exists(filepath) or not os.path.isfile(filepath):
                 msg = f"MMDB file {filepath} not found after download attempt."
                 if log_callback: log_callback(msg)
                 return None # Download failed silently or path was wrong
        except Exception as e:
            if log_callback: log_callback(f"Failed to download MMDB file: {e}")
            return None # Download failed

    try:
        if log_callback: log_callback(f"Loading MMDB database from {filepath}...")
        reader = database.Reader(filepath)
        if log_callback: log_callback("MMDB database loaded successfully.")
        return reader
    except FileNotFoundError:
        msg = f"MMDB file not found at {filepath}. Please ensure it exists or enable update."
        if log_callback: log_callback(msg)
        return None
    except Exception as e:
        msg = f"Failed to load MMDB database from {filepath}: {e}"
        if log_callback: log_callback(msg)
        return None


@dataclass
class RunningState(object):
    url: str = "unknown" # Added URL to state for context
    # 上传总流量
    sent: str = "unknown"
    # 下载总流量
    recv: str = "unknown"
    # 运行状态
    state: str = "unknown"
    # xui 版本
    version: str = "unknown"
    # 运行时间 (seconds)
    uptime: int = 0
    # 连接: list of tuples (link_string, expiry_time, total_limit)
    links: list[tuple[str, int, int]] = None


def get_running_state(data: dict, url: str) -> RunningState:
    if not data or not isinstance(data, dict) or "obj" not in data:
        return RunningState(url=url) # Return partial state with URL

    uptime, sent, recv, state, version = 0, "unknown", "unknown", "unknown", "unknown"
    obj_data = data.get("obj", {})
    if not isinstance(obj_data, dict): # Ensure obj_data is a dict
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
         if log_callback: log_callback("Warning: 'obj' is not a list in get_inbound_list response.")
         return []

    # Cache IP lookup if reader is available
    ip = None
    country = ""
    if reader:
        try:
            ip = socket.gethostbyname(address)
            response = reader.country(ip)
            country = response.country.names.get("zh-CN", "")
        except socket.gaierror:
            if log_callback: log_callback(f"Warning: Could not resolve hostname {address} for GeoIP lookup.")
            # Do not disable reader globally, just for this call
        except Exception as e:
            if log_callback: log_callback(f"Warning: GeoIP lookup failed for {address} ({ip if ip else 'N/A'}): {e}")
            # Do not disable reader globally


    for item in items:
        if not item or not isinstance(item, dict) or not item.get("enable", False):
            continue

        protocol, port = item.get("protocol"), item.get("port")
        if not protocol or not port:
             if log_callback: log_callback(f"Warning: Skipping inbound missing protocol or port: {item.get('tag', 'N/A')}")
             continue # Skip malformed inbound

        link = ""
        remark = trim(item.get("remark", "")) or item.get("tag", "") # Use tag as fallback

        current_country = country # Use cached country
        
        # GeoIP check and remark update
        if reader and ip: # Only proceed if reader is valid and IP was resolved
            if current_country == "中国":
                # if log_callback: log_callback(f"Skipping inbound for {address} due to GeoIP check (China).")
                continue # Skip mainland China IPs

            # Prepend country to remark if available
            if current_country and current_country != remark: # Avoid double-prepending or adding if remark is already the country
                 remark = f"{current_country} - {remark}" if remark else current_country


        try:
            if protocol == "vless":
                settings = json.loads(item.get("settings", "{}"))
                clients = settings.get("clients")
                if not clients or not isinstance(clients, list) or not clients[0].get("id"):
                    if log_callback: log_callback(f"Warning: Skipping VLESS inbound missing client ID: {item.get('tag', 'N/A')}")
                    continue
                client_id = clients[0]["id"]
                flow = clients[0].get("flow", "")

                stream_settings_str = item.get("streamSettings", "{}")
                if not stream_settings_str: stream_settings_str = "{}" # Ensure it's a string for json.loads
                stream_settings = json.loads(stream_settings_str)

                network = stream_settings.get("network")
                security = stream_settings.get("security", "none") # security is optional but common
                if network == "ws":
                    ws_settings = stream_settings.get("wsSettings", {})
                    path = ws_settings.get("path", "/")
                    query_params = {"type": network, "security": security, "path": path}
                    # Add host if present in wsSettings' headers
                    host = ws_settings.get("headers", {}).get("Host")
                    if host:
                        query_params["host"] = host
                    # Add flow if present and valid for VLESS
                    if flow and flow in ["xtls-rprx-vision", "xtls-rprx-vless", "xtls-rprx-splice", "xtls-rprx-direct"]: # Valid VLESS flows
                        query_params["flow"] = flow
                    elif flow: # Log unsupported flow
                        if log_callback: log_callback(f"Warning: VLESS inbound {item.get('tag', 'N/A')} with network 'ws' has unsupported flow: {flow}. Ignoring flow.")
                    
                    link = f"{protocol}://{client_id}@{address}:{port}?{urllib.parse.urlencode(query_params, quote_via=urllib.parse.quote)}"

                elif network == "tcp" and security in ["tls", "xtls"]: # TCP with TLS/XTLS usually implies some flow for VLESS
                     query_params = {"type": network, "security": security}
                     if flow and flow in ["xtls-rprx-vision", "xtls-rprx-vless", "xtls-rprx-splice", "xtls-rprx-direct"]:
                         query_params["flow"] = flow
                     elif flow:
                         if log_callback: log_callback(f"Warning: VLESS inbound {item.get('tag', 'N/A')} with network 'tcp' and security '{security}' has unsupported flow: {flow}. Ignoring flow.")
                     # SNI for TLS/XTLS
                     tls_settings = stream_settings.get(f"{security}Settings", {})
                     sni = tls_settings.get("serverName")
                     if sni:
                         query_params["sni"] = sni
                     # ALPN for TLS/XTLS
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
                    if flow: # Naked VLESS usually doesn't use flow.
                        if log_callback: log_callback(f"Warning: Skipping VLESS inbound {item.get('tag', 'N/A')} with unsupported network/flow combination: {network}/{flow}")
                        continue
                    # Plain VLESS TCP (no TLS, no flow) or other networks might be supported by some clients without query params
                    # link = f"{protocol}://{client_id}@{address}:{port}" # Simplest form if no other params
                    # For now, skip if not WS or TCP/TLS/XTLS with known flow or GRPC for clarity
                    if log_callback: log_callback(f"Warning: Skipping VLESS inbound {item.get('tag', 'N/A')} with network '{network}'. Only 'ws', 'tcp' (with tls/xtls security and flow), and 'grpc' are fully parsed.")
                    continue

            elif protocol == "vmess":
                settings = json.loads(item.get("settings", "{}"))
                clients = settings.get("clients")
                if not clients or not isinstance(clients, list) or not clients[0].get("id"):
                    if log_callback: log_callback(f"Warning: Skipping VMESS inbound missing client ID: {item.get('tag', 'N/A')}")
                    continue
                client_id = clients[0]["id"]
                alter_id = clients[0].get("alterId", 0) # Get alterId

                stream_settings_str = item.get("streamSettings", "{}")
                if not stream_settings_str: stream_settings_str = "{}"
                stream_settings = json.loads(stream_settings_str)

                network = stream_settings.get("network")
                
                # Security field in VMESS might be empty or "none" or specific ciphers like "auto", "aes-128-gcm"
                # For link generation, often "tls", "xtls" or "" (none) is derived from streamSettings.security
                vmess_security_link_param = stream_settings.get("security", "none")
                if vmess_security_link_param == "none": vmess_security_link_param = ""


                vmess_config = {
                    "v": "2",
                    "ps": remark, # Use the remark directly here
                    "add": address,
                    "port": str(item["port"]), # Port should be string in config
                    "id": client_id,
                    "aid": str(alter_id), # AlterId should be string in config
                    "net": network,
                    "type": "none", # Default, will be overridden for certain networks like TCP HTTP Obfuscation
                    "host": "", # Default host
                    "path": "", # Default path
                    "tls": vmess_security_link_param, 
                }

                # Handle specific network settings
                if network == "ws":
                    ws_settings = stream_settings.get("wsSettings", {})
                    vmess_config["path"] = ws_settings.get("path", "/")
                    host = ws_settings.get("headers", {}).get("Host")
                    if host:
                        vmess_config["host"] = host
                elif network == "tcp":
                    tcp_settings = stream_settings.get("tcpSettings", {})
                    header_settings = tcp_settings.get("header", {})
                    vmess_config["type"] = header_settings.get("type", "none") # e.g., "http" for http obfuscation
                    if vmess_config["type"] == "http":
                        # Host for TCP HTTP Obfuscation is typically in request.Host array
                        request_settings = header_settings.get("request", {})
                        host_headers = request_settings.get("headers", {}).get("Host")
                        if isinstance(host_headers, list) and host_headers:
                            vmess_config["host"] = host_headers[0]
                        elif isinstance(host_headers, str):
                             vmess_config["host"] = host_headers
                elif network == "grpc":
                    grpc_settings = stream_settings.get("grpcSettings", {})
                    vmess_config["path"] = grpc_settings.get("serviceName", "") # serviceName maps to 'path' in some clients
                    vmess_config["type"] = grpc_settings.get("multiMode", False) # 'multi' or 'gun' (for multiMode) not std, usually "none"
                # Other networks (kcp, httpupgrade, etc.) might need more specific handling
                
                if vmess_security_link_param in ["tls", "xtls"]:
                    tls_settings_key = f"{vmess_security_link_param}Settings" # "tlsSettings" or "xtlsSettings"
                    tls_settings = stream_settings.get(tls_settings_key, {})
                    sni = tls_settings.get("serverName")
                    if sni:
                         # For VMESS links, SNI is often put in 'host' if 'tls' is set and network is not ws (ws uses wsSettings.host)
                         if network != 'ws' or not vmess_config.get('host'): # Prioritize wsSettings host if available
                             vmess_config["host"] = sni # SNI often populates 'host' if 'tls' is true
                    # ALPN is not typically part of the standard VMESS JSON link format, but good to be aware of.
                    # alpn = tls_settings.get("alpn")


                # Encode VMESS config
                vmess_json = json.dumps(vmess_config, separators=(',', ':')).encode() # Use compact separators
                link = f"vmess://{base64.b64encode(vmess_json).decode()}"


            elif protocol == "trojan":
                settings = json.loads(item.get("settings", "{}"))
                clients = settings.get("clients")
                if not clients or not isinstance(clients, list) or not clients[0].get("password"):
                    if log_callback: log_callback(f"Warning: Skipping TROJAN inbound missing password: {item.get('tag', 'N/A')}")
                    continue
                password_val = clients[0]["password"]
                
                # Base Trojan link
                link = f"trojan://{password_val}@{address}:{port}"
                
                query_params = {}

                # Stream settings for Trojan (often TLS related, or WS/gRPC transport)
                stream_settings_str = item.get("streamSettings", "{}")
                if not stream_settings_str: stream_settings_str = "{}"
                stream_settings = json.loads(stream_settings_str)
                
                # Security setting (e.g., "tls", "xtls") - Trojan inherently uses TLS-like security.
                # The 'security' field in streamSettings is important for SNI, ALPN etc.
                security = stream_settings.get("security", "none") # "tls" is common for Trojan stream settings

                if security in ["tls", "xtls"]: # For Trojan, this means TLS parameters for the underlying transport
                    sec_settings_key = f"{security}Settings" # e.g. "tlsSettings"
                    sec_settings = stream_settings.get(sec_settings_key, {})
                    sni = sec_settings.get("serverName")
                    if sni: query_params["sni"] = sni
                    
                    alpn = sec_settings.get("alpn")
                    if alpn and isinstance(alpn, list):
                        query_params["alpn"] = ",".join(alpn) # Comma-separated for URL

                # Network type (e.g., "ws", "grpc")
                network = stream_settings.get("network")
                if network and network != "tcp": # "tcp" is default for base Trojan
                    query_params["type"] = network
                    if network == "ws":
                        ws_settings = stream_settings.get("wsSettings", {})
                        path = ws_settings.get("path", "/")
                        if path and path != "/": query_params["path"] = path # Some clients assume "/" if omitted
                        
                        host = ws_settings.get("headers", {}).get("Host")
                        if host: query_params["host"] = host # host for WS

                    elif network == "grpc":
                        grpc_settings = stream_settings.get("grpcSettings", {})
                        service_name = grpc_settings.get("serviceName")
                        if service_name: query_params["serviceName"] = service_name
                        # mode = grpc_settings.get("multiMode", False) # Usually 'gun' or 'multi' if supported in link
                        # if mode: query_params["mode"] = "multi" if mode else "gun"


                # Other common Trojan query params: peer, headerType, flow
                # 'flow' for Trojan (from client settings in XUI)
                flow = clients[0].get("flow", "")
                if flow and flow.startswith("xtls-rprx-"): # Vision flow, etc.
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
                     if log_callback: log_callback(f"Warning: Skipping SHADOWSOCKS inbound missing method or password: {item.get('tag', 'N/A')}")
                     continue
                
                # Format: ss://method:password@host:port#remark
                # Base64 encode "method:password" for SIP002 compatibility:
                user_info = f"{method}:{password_ss}"
                encoded_user_info = base64.urlsafe_b64encode(user_info.encode()).decode().rstrip('=')
                link = f"ss://{encoded_user_info}@{address}:{port}"
                
                # Shadowsocks plugins (e.g., v2ray-plugin) might be in streamSettings
                # This is complex as SIP003 (plugins) has its own format.
                # For now, we'll stick to basic SS links or simple plugin parameters if obvious.
                # Example for v2ray-plugin: plugin=v2ray-plugin;tls;host=example.com;path=/ws
                # stream_settings_str = item.get("streamSettings", "{}")
                # ... parse streamSettings for plugin info ...

            # Other protocols if needed.
        except json.JSONDecodeError:
            if log_callback: log_callback(f"Error decoding JSON for inbound {item.get('tag', 'N/A')}. Skipping.")
            continue
        except Exception as e:
            if log_callback: log_callback(f"Error generating link for inbound {item.get('tag', 'N/A')}: {e}. Skipping.")
            if log_callback: log_callback(traceback.format_exc()) # Log traceback for debugging
            continue

        if link:
            # Append remark for all protocols except VMESS (where it's inside the base64)
            if remark and protocol != "vmess":
                link += f"#{parse.quote(remark)}"

            expiry_time = item.get("expiryTime", 0)
            total_limit = item.get("total", 0)

            result.append((link, expiry_time, total_limit))

    return result


def check(url: str, filepath: str, reader: database.Reader, username: str, password: str, log_callback: typing.Callable[[str], None] = None) -> RunningState | None:
    """Checks a single URL (potential XUI panel)"""
    try:
        original_url = url # Keep original for messages if scheme modification fails
        # Ensure URL has a scheme, default to http if none
        if not url.startswith("http://") and not url.startswith("https://"):
             url_with_http = f"http://{url}"
             url_with_https = f"https://{url}"
        else:
             # Determine the alternative scheme
             if url.startswith("http://"):
                 url_with_http = url
                 url_with_https = url.replace("http://", "https://", 1)
             else: # url.startswith("https://")
                 url_with_https = url
                 url_with_http = url.replace("https://", "http://", 1)
        
        current_url_to_try = url_with_https # Prefer HTTPS first
        headers = get_cookies(url=current_url_to_try, username=username, password=password)
        
        if not headers:
            current_url_to_try = url_with_http # Fallback to HTTP
            headers = get_cookies(url=current_url_to_try, username=username, password=password)
            if not headers:
                if log_callback: log_callback(f"Login failed for {original_url} (tried HTTPS and HTTP). Skipping.")
                return None
        
        # At this point, login was successful with current_url_to_try
        login_successful_url = current_url_to_try
        if log_callback: log_callback(f"Successfully logged into {login_successful_url} (original: {original_url})")

        parsed_url = parse.urlparse(url=login_successful_url)
        address = parsed_url.hostname
        if not address:
            if log_callback: log_callback(f"Skipping: could not parse hostname from successful login URL: {login_successful_url}")
            return None
        
        # Save the successful URL (the one that worked for login) to availables.txt
        write_file(filename=filepath, lines=login_successful_url, overwrite=False, log_callback=log_callback)
        if log_callback: log_callback(f"Saved working panel URL {login_successful_url} to {filepath}")


        status = get_server_status(login_successful_url, headers)
        if not status:
            if log_callback: log_callback(f"Failed to get server status for {login_successful_url}. Skipping.")
            # Return state indicating login worked but API failed
            return RunningState(url=login_successful_url, state="Login OK, API Error") 

        running_state = get_running_state(data=status, url=login_successful_url)
        if log_callback: log_callback(f"Got status for {login_successful_url}: State={running_state.state}, Version={running_state.version}, Uptime={running_state.uptime}s")

        # Check if 'appStats' key exists to decide if we need inbound list (newer vs older XUI)
        # If 'obj' is missing or not a dict, .get('appStats', ...) will handle it gracefully
        obj_data = status.get("obj", {})
        if not isinstance(obj_data, dict): obj_data = {}

        if "appStats" not in obj_data: # Older XUI versions might not have appStats, or require inbound list explicitly
            if log_callback: log_callback(f"Fetching inbound list for {login_successful_url}...")
            inbounds = get_inbound_list(login_successful_url, headers)
            if inbounds:
                running_state.links = generate_subscription_links(data=inbounds, address=address, reader=reader, log_callback=log_callback)
                if log_callback: log_callback(f"Found {len(running_state.links) if running_state.links else 0} links for {login_successful_url}.")
            else:
                 if log_callback: log_callback(f"Failed to get inbound list for {login_successful_url}.")
                 running_state.links = [] # Ensure links is a list even if fetch fails
        else:
            # For newer XUI with appStats, links might not be directly fetchable or handled differently.
            # Assuming no links if appStats is present and we don't explicitly fetch inbounds.
            # Or, if you always want to try fetching links, remove this else block and always call get_inbound_list.
            if log_callback: log_callback(f"'appStats' found for {login_successful_url}. Assuming newer XUI, not fetching separate inbound list unless needed by logic.")
            running_state.links = [] # Default to no links from separate endpoint for new XUI version here.


        return running_state
    except Exception as e:
        # Catch any unexpected errors during the check process
        if log_callback: log_callback(f"An error occurred while checking {original_url if 'original_url' in locals() else url}: {e}")
        if log_callback: log_callback(traceback.format_exc())
        return None


def extract_domain(url: str, include_protocol: bool = True) -> str:
    if not url or not isinstance(url, str):
        return ""

    # Ensure URL has a scheme for parse.urlparse to work correctly
    if not url.startswith("http://") and not url.startswith("https://"):
        url_with_scheme = f"http://{url}" # Temporarily add http for parsing if no scheme
    else:
        url_with_scheme = url

    try:
        parsed_url = parse.urlparse(url_with_scheme)
        domain_part = parsed_url.netloc # Includes hostname and optional port
        if not domain_part:
            return "" # Handle cases where netloc is empty

        if include_protocol:
            # Reconstruct the base URL with scheme and netloc
            # Use original scheme if present, or default from parsing a schemeless url
            scheme_to_use = parsed_url.scheme if parsed_url.scheme and url.startswith(parsed_url.scheme) else \
                            ('https' if url.lower().startswith("https://") else 'http')
            
            return f"{scheme_to_use}://{domain_part}"
        else:
             # Strip port if present, return only hostname
            return domain_part.split(':')[0]

    except Exception:
        # Handle potential parsing errors for malformed URLs
        return ""


def dedup(filepath: str, log_callback: typing.Callable[[str], None] = None) -> None:
    def include_subpath(url_to_check: str) -> bool:
        url_to_check = trim(url_to_check).lower()
        # Ensure it has a scheme for correct parsing
        if not url_to_check.startswith("http://") and not url_to_check.startswith("https://"):
            url_with_scheme = f"http://{url_to_check}"
        else:
            url_with_scheme = url_to_check
        
        parsed = parse.urlparse(url_with_scheme)
        return bool(parsed.path and parsed.path != '/')

    def cmp_key(url_to_sort: str) -> tuple[int, int, str]:
        # Priority: 1. Has subpath, 2. HTTPS, 3. HTTP, then alphabetically
        has_subpath = 2 if include_subpath(url_to_sort) else 0 
        is_https = 1 if url_to_sort.lower().startswith("https://") else 0
        # Lexicographical sort for tie-breaking uses the full URL
        return (has_subpath, is_https, url_to_sort.lower()) 

    if not os.path.exists(filepath) or not os.path.isfile(filepath):
        if log_callback: log_callback(f"Dedup skipped: file {filepath} not exists")
        return

    lines_read = []
    try:
        with open(filepath, "r", encoding="utf8") as f:
            lines_read = f.readlines()
    except Exception as e:
        if log_callback: log_callback(f"Error reading file {filepath} for dedup: {e}")
        return


    groups = defaultdict(list) # Changed to list to preserve all URLs for a domain before sorting
    valid_lines_count = 0
    for line_content in lines_read:
        line_content = trim(line_content)
        if not line_content or line_content.startswith("#") or line_content.startswith(";"):
            continue
        valid_lines_count += 1

        # Normalize URL for key extraction (e.g., ensure it has a scheme for parsing)
        # Store the original line for output later
        normalized_line_for_key = line_content
        if not normalized_line_for_key.lower().startswith("http://") and \
           not normalized_line_for_key.lower().startswith("https://"):
            normalized_line_for_key = f"http://{normalized_line_for_key}" # Assume http for parsing domain key
        
        domain_key = extract_domain(url=normalized_line_for_key, include_protocol=False).lower()
        if domain_key:
             groups[domain_key].append(line_content) # Store original line


    deduped_links = []
    for domain_name, urls_in_group in groups.items():
        if not urls_in_group:
            continue

        if len(urls_in_group) > 1:
            # Sort by our custom comparison key (has_subpath, is_https, full_url_string)
            # Reverse=True means highest priority comes first
            urls_in_group.sort(key=cmp_key, reverse=True)
        
        # Select the highest priority URL after sorting
        deduped_links.append(urls_in_group[0])
    
    # Sort the final list of deduped links alphabetically for consistent output
    deduped_links.sort()


    total_read, remain = valid_lines_count, len(deduped_links)
    if log_callback:
        log_callback(f"[Dedup] finished for file: {filepath}, valid lines: {total_read}, remaining after dedup: {remain}, dropped: {total_read-remain}")

    if deduped_links or (total_read > 0 and not deduped_links) : # If file had content, overwrite it
        try:
            write_file(filename=filepath, lines=deduped_links, overwrite=True, log_callback=log_callback)
            if log_callback: log_callback(f"Deduped list saved to {filepath}")
        except Exception as e:
            if log_callback: log_callback(f"Error writing deduped list to {filepath}: {e}")


def generate_markdown(items: list[RunningState], filepath: str, log_callback: typing.Callable[[str], None] = None) -> None:
    if not filepath:
        if log_callback: log_callback("Skipping markdown generation: invalid filepath.")
        return

    if not items or not isinstance(items, list):
        if log_callback: log_callback("Skipping markdown generation: no data.")
        # Clear markdown file if it exists and no data is provided
        if os.path.exists(filepath):
            write_file(filename=filepath, lines=[], overwrite=True, log_callback=log_callback)
        return

    # Filter out items that are not RunningState instances or those that might indicate a failure (e.g., state is 'Login OK, API Error')
    # Let's only include successful checks with actual links or valid server status.
    valid_items = [item for item in items if isinstance(item, RunningState) and 
                   (item.links or (item.state not in ["unknown", "Login OK, API Error", "Offline/API Error"]))]


    if not valid_items:
         if log_callback: log_callback("Skipping markdown generation: no valid items with links or confirmed status found.")
         if os.path.exists(filepath): # Clear markdown file if no valid items
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

        uptime_str = str(item.uptime) if item.uptime is not None else "unknown"

        links_count_str = "0"
        example_link_str = "N/A"
        if item.links and isinstance(item.links, list):
            links_count_str = str(len(item.links))
            if item.links: # If there are links, show the first one as an example
                example_link_str = f"`{item.links[0][0][:60]}{'...' if len(item.links[0][0]) > 60 else ''}`" # Truncate example
        else: # If item.links is None or empty
            links_count_str = "0"
            if item.state not in ["unknown", "Login OK, API Error", "Offline/API Error"]:
                # If panel is up but just has no defined/enabled inbounds
                example_link_str = "(No links defined/enabled)"
            else: # Panel itself has issues
                example_link_str = "(Panel error)"


        row_data = [
            display_url,
            item.state,
            item.version,
            uptime_str,
            item.sent,
            item.recv,
            links_count_str,
            example_link_str,
        ]
        
        escaped_row_data = [str(cell).replace('|', '\\|') for cell in row_data]
        table_lines.append("| " + " | ".join(escaped_row_data) + " |")

    write_file(filename=filepath, lines=table_lines, overwrite=True, log_callback=log_callback)
    if log_callback: log_callback(f"Markdown table generated and saved to {filepath}")


# --- Worker Class for the Scan Logic ---
class ScanWorker(QObject):
    finished = Signal()
    error = Signal(str)
    progress = Signal(int) 
    status_message = Signal(str)
    scan_completed = Signal(list) 
    links_generated = Signal(list) 

    def __init__(self, config: dict):
        super().__init__()
        self.config = config
        self._is_canceled = False

    def cancel(self):
        self._is_canceled = True
        self.status_message.emit("Cancellation flag set.")


    def run(self):
        try:
            self.status_message.emit("Scan worker started.")

            workspace = self.config.get("workspace")
            domain_file = self.config.get("domain_file")
            available_file = self.config.get("available_file")
            link_file = self.config.get("link_file")
            markdown_file = self.config.get("markdown_file")
            num_threads = self.config.get("thread_count")
            update_mmdb = self.config.get("update_mmdb")
            
            # Get username and password, default to "admin" if empty
            username = trim(self.config.get("username")) or "admin"
            password = self.config.get("password") or "admin" # Passwords usually don't get trimmed, but "admin" is safe
            
            self.status_message.emit(f"Using credentials - Username: {username}, Password: {'*' * len(password)}")


            source_path = os.path.join(workspace, domain_file)
            available_path = os.path.join(workspace, available_file)
            link_path = os.path.join(workspace, link_file)
            markdown_path = os.path.join(workspace, markdown_file)

            if not os.path.exists(source_path) or not os.path.isfile(source_path):
                raise FileNotFoundError(f"Domain list file not found: {source_path}")

            # 1. Dedup the input file
            self.status_message.emit(f"Deduplicating input file: {source_path}")
            dedup(filepath=source_path, log_callback=self.status_message.emit)

            domains = []
            try:
                with open(source_path, "r", encoding="utf8") as f: # Ensure reading with "r"
                    domains = [trim(x) for x in f.readlines() if trim(x) and not trim(x).startswith("#") and not trim(x).startswith(";")]
            except Exception as e:
                 raise IOError(f"Error reading domain list file {source_path}: {e}")


            if not domains:
                self.status_message.emit("No valid domains found in the list after deduplication. Scan will not proceed.")
                self.scan_completed.emit([]) 
                self.links_generated.emit([]) 
                self.progress.emit(100) # Show completion, even if no work
                self.finished.emit()
                return

            self.status_message.emit(f"Loaded {len(domains)} unique domains for scanning.")

            # 2. Load MMDB database
            mmdb_dir = os.path.join(workspace, "mmdb") 
            self.status_message.emit(f"Loading MMDB database (update: {update_mmdb})...")
            reader = load_mmdb(directory=mmdb_dir, update=update_mmdb, log_callback=self.status_message.emit)
            if reader is None:
                 self.status_message.emit("Warning: MMDB reader could not be loaded. GeoIP features will be disabled.")


            # 3. Prepare and run checks in parallel
            # task arguments: url, filepath_for_availables, reader, username, password, log_callback
            tasks = [[domain, available_path, reader, username, password, self.status_message.emit] for domain in domains]

            self.status_message.emit(f"Starting checks for {len(domains)} domains with {num_threads} threads.")
            results = []
            completed_tasks_count = 0
            total_tasks_count = len(tasks)


            with futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
                # Keep track of futures to handle cancellation or errors
                active_futures = {executor.submit(check, *task_args): task_args[0] for task_args in tasks}

                for future in futures.as_completed(active_futures):
                    if self._is_canceled:
                         self.status_message.emit("Scan cancellation detected. Halting further processing.")
                         # Attempt to cancel remaining futures
                         for f_act in active_futures: # Iterate over the keys of the original dict or the remaining ones
                             if not f_act.done():
                                 f_act.cancel()
                         break 

                    url_processed = active_futures[future]
                    try:
                        result_item = future.result() # Get result from completed future
                        if result_item: 
                             results.append(result_item)
                    except futures.CancelledError:
                        self.status_message.emit(f"Task for {url_processed} was cancelled.")
                    except Exception as e:
                        self.status_message.emit(f"Error processing task for {url_processed}: {e}\n{traceback.format_exc()}")

                    completed_tasks_count += 1
                    current_progress = int((completed_tasks_count / total_tasks_count) * 100)
                    self.progress.emit(current_progress)

            if self._is_canceled:
                 self.status_message.emit("Scan was canceled by user.")
                 self.progress.emit(0) 
                 self.scan_completed.emit(results) # Emit any partial results if needed
                 self.links_generated.emit([]) # Or process partial links
                 self.finished.emit()
                 return


            self.status_message.emit("All checks finished processing.")
            self.progress.emit(100)

            # 4. Process results
            effectives = [] # Panels that are up and might have links
            all_links_collected = []
            for item in results: # Results already contains only non-None items from `check`
                if isinstance(item, RunningState): # Ensure it's a RunningState object
                    # Define 'effective' more broadly: panel is responsive and status known
                    if item.state not in ["unknown", "Login OK, API Error", "Offline/API Error"]:
                        effectives.append(item)
                    if item.links: # links is a list of tuples
                        all_links_collected.extend([link_tuple[0] for link_tuple in item.links])


            # 5. Save links
            if all_links_collected:
                self.status_message.emit(f"Found {len(all_links_collected)} valid subscription links.")
                # Base64 encode the joined links for the output file
                try:
                    link_content = base64.b64encode("\n".join(all_links_collected).encode(encoding="utf8")).decode(encoding="utf8")
                    write_file(filename=link_path, lines=link_content, overwrite=True, log_callback=self.status_message.emit)
                    self.links_generated.emit(all_links_collected)
                except Exception as e:
                    self.status_message.emit(f"Error encoding or writing links file: {e}")
                    self.links_generated.emit([]) # Send empty on error
            else:
                self.status_message.emit("No valid subscription links found across all panels.")
                self.links_generated.emit([]) 
                if os.path.exists(link_path):
                     write_file(filename=link_path, lines="", overwrite=True, log_callback=self.status_message.emit)


            # 6. Generate markdown table based on `effectives` list
            if effectives:
                 self.status_message.emit(f"Generating markdown table for {len(effectives)} responsive panels.")
                 generate_markdown(items=effectives, filepath=markdown_path, log_callback=self.status_message.emit)
                 self.scan_completed.emit(effectives) 
            else:
                 self.status_message.emit("No responsive panels found to generate markdown table.")
                 self.scan_completed.emit([]) 
                 if os.path.exists(markdown_path):
                      write_file(filename=markdown_path, lines="", overwrite=True, log_callback=self.status_message.emit)


            self.status_message.emit("Scan process completed successfully.")
            self.finished.emit()

        except FileNotFoundError as e:
             self.error.emit(f"File Error: {e}")
             self.status_message.emit(f"Scan failed due to file error: {e}")
             self.progress.emit(0) 
             self.finished.emit()
        except IOError as e:
            self.error.emit(f"I/O Error: {e}")
            self.status_message.emit(f"Scan failed due to I/O error: {e}")
            self.progress.emit(0)
            self.finished.emit()
        except Exception as e:
            self.error.emit(f"An unexpected error occurred in worker: {e}\n{traceback.format_exc()}")
            self.status_message.emit(f"Scan failed due to an unexpected error: {e}")
            self.progress.emit(0)
            self.finished.emit()


# --- GUI Main Window ---
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("XUI Panel Scanner")
        self.setGeometry(100, 100, 850, 700) # Adjusted size for new fields

        self.worker = None
        self.worker_thread = None

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

        # Input Group
        input_group = QGroupBox("Input Files and Workspace")
        input_layout = QFormLayout(input_group)

        self.domain_file_edit = QLineEdit("domains.txt")
        self.browse_domain_button = QPushButton("Browse")
        domain_file_layout = QHBoxLayout()
        domain_file_layout.addWidget(self.domain_file_edit)
        domain_file_layout.addWidget(self.browse_domain_button)
        input_layout.addRow("Domain List File:", domain_file_layout)

        self.workspace_edit = QLineEdit(DEFAULT_WORKSPACE)
        self.browse_workspace_button = QPushButton("Browse")
        workspace_layout = QHBoxLayout()
        workspace_layout.addWidget(self.workspace_edit)
        workspace_layout.addWidget(self.browse_workspace_button)
        input_layout.addRow("Workspace Directory:", workspace_layout)
        main_layout.addWidget(input_group)

        # Output Group
        output_group = QGroupBox("Output Files")
        output_layout = QFormLayout(output_group)
        self.available_file_edit = QLineEdit("availables.txt")
        output_layout.addRow("Available Panels File:", self.available_file_edit)
        self.link_file_edit = QLineEdit("links.txt")
        output_layout.addRow("Subscription Links File:", self.link_file_edit)
        self.markdown_file_edit = QLineEdit("table.md")
        output_layout.addRow("Markdown Results File:", self.markdown_file_edit)
        main_layout.addWidget(output_group)

        # Settings Group
        settings_group = QGroupBox("Settings")
        settings_layout = QFormLayout(settings_group)

        # Username and Password fields
        self.username_edit = QLineEdit("admin")
        settings_layout.addRow("Username:", self.username_edit)
        self.password_edit = QLineEdit("admin")
        self.password_edit.setEchoMode(QLineEdit.Password)
        settings_layout.addRow("Password:", self.password_edit)

        self.thread_spinbox = QSpinBox()
        self.thread_spinbox.setMinimum(1)
        default_threads = (os.cpu_count() or 1) * 2
        self.thread_spinbox.setValue(min(default_threads, 128)) # Cap default, user can increase
        self.thread_spinbox.setMaximum(512) # Practical max for threads for most systems/tasks
        settings_layout.addRow("Concurrent Threads:", self.thread_spinbox)

        self.update_mmdb_checkbox = QCheckBox("Update IP Database (GeoLite2)")
        self.update_mmdb_checkbox.setChecked(False)
        settings_layout.addRow("IP Database:", self.update_mmdb_checkbox)
        main_layout.addWidget(settings_group)

        # Control Buttons
        control_layout = QHBoxLayout()
        self.start_button = QPushButton("Start Scan")
        self.cancel_button = QPushButton("Cancel Scan")
        self.cancel_button.setEnabled(False) 
        control_layout.addWidget(self.start_button)
        control_layout.addWidget(self.cancel_button)
        main_layout.addLayout(control_layout)

        # Progress Bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        main_layout.addWidget(self.progress_bar)

        # Log Output
        log_group = QGroupBox("Log Output")
        log_layout = QVBoxLayout(log_group)
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        log_layout.addWidget(self.log_output)
        main_layout.addWidget(log_group, 1) 

        self.statusBar()

    def connect_signals(self):
        self.browse_domain_button.clicked.connect(self.browse_domain_file)
        self.browse_workspace_button.clicked.connect(self.browse_workspace)
        self.start_button.clicked.connect(self.start_scan)
        self.cancel_button.clicked.connect(self.cancel_scan)

    @Slot()
    def browse_domain_file(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Select Domain List File", self.workspace_edit.text(), "Text Files (*.txt);;All Files (*)")
        if filename:
            # Store relative path if it's inside workspace, else absolute
            workspace_path = self.workspace_edit.text()
            if filename.startswith(workspace_path):
                self.domain_file_edit.setText(os.path.relpath(filename, workspace_path))
            else:
                self.domain_file_edit.setText(filename)
                # Optionally update workspace to directory of selected file if it's different
                # self.workspace_edit.setText(os.path.dirname(filename))


    @Slot()
    def browse_workspace(self):
        directory = QFileDialog.getExistingDirectory(self, "Select Workspace Directory", self.workspace_edit.text() or QStandardPaths.writableLocation(QStandardPaths.HomeLocation))
        if directory:
            self.workspace_edit.setText(directory)

    @Slot()
    def start_scan(self):
        self.start_button.setEnabled(False)
        self.cancel_button.setEnabled(True)
        self.log_output.clear()
        self.progress_bar.setValue(0)
        self.statusBar().clearMessage()

        config = {
            "workspace": trim(self.workspace_edit.text()),
            "domain_file": trim(self.domain_file_edit.text()), # This can be absolute or relative to workspace
            "available_file": trim(self.available_file_edit.text()),
            "link_file": trim(self.link_file_edit.text()),
            "markdown_file": trim(self.markdown_file_edit.text()),
            "thread_count": self.thread_spinbox.value(),
            "update_mmdb": self.update_mmdb_checkbox.isChecked(),
            "username": self.username_edit.text(), # No trim, allow spaces if user intends
            "password": self.password_edit.text(), # No trim
        }
        
        domain_filepath = config["domain_file"]
        if not os.path.isabs(domain_filepath): # If domain file is relative, join with workspace
            domain_filepath = os.path.join(config["workspace"], domain_filepath)

        if not config["workspace"] or not os.path.isdir(config["workspace"]):
             QMessageBox.warning(self, "Input Error", "Please specify a valid workspace directory.")
             self.reset_ui_after_scan()
             return
        if not config["domain_file"]: # Check original entry, not the potentially joined one
            QMessageBox.warning(self, "Input Error", "Please specify a domain list filename.")
            self.reset_ui_after_scan()
            return
        # Check if the resolved domain_filepath exists
        if not os.path.exists(domain_filepath) or not os.path.isfile(domain_filepath):
            QMessageBox.warning(self, "Input Error", f"Domain list file not found: {domain_filepath}")
            self.reset_ui_after_scan()
            return

        if not config["available_file"] or not config["link_file"] or not config["markdown_file"]:
             QMessageBox.warning(self, "Input Error", "Please specify all output filenames.")
             self.reset_ui_after_scan()
             return

        self.worker_thread = QThread()
        self.worker = ScanWorker(config)
        self.worker.moveToThread(self.worker_thread)

        self.worker_thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.scan_finished_actions) # Combined slot
        
        self.worker.error.connect(self.handle_error)
        self.worker.progress.connect(self.progress_bar.setValue)
        self.worker.status_message.connect(self.append_log)
        self.worker.scan_completed.connect(self.show_scan_summary)
        self.worker.links_generated.connect(self.show_links_summary)

        self.worker_thread.start()
        self.statusBar().showMessage("Scan started...")
        self.append_log("Scan process initiated...")

    @Slot()
    def cancel_scan(self):
        if self.worker and self.worker_thread and self.worker_thread.isRunning():
            self.append_log("Requesting scan cancellation...")
            self.statusBar().showMessage("Canceling scan...")
            self.cancel_button.setEnabled(False) # Prevent multiple cancel clicks
            self.worker.cancel() 
            # Worker's finished signal will handle UI reset

    @Slot()
    def scan_finished_actions(self):
        self.append_log("Scan thread has signaled completion.")
        if self.statusBar().currentMessage() != "Scan canceled by user.": # Avoid overwriting cancel message
            if self.progress_bar.value() == 100 and not self.cancel_button.isEnabled(): # Assuming cancel disabled means finished/errored
                 self.statusBar().showMessage("Scan process finished.")
            elif self.worker and self.worker._is_canceled: # If it was cancelled
                 self.statusBar().showMessage("Scan canceled by user.")
            else: # Error case, error message might be in dialog
                 self.statusBar().showMessage("Scan ended with errors or was interrupted.")
        
        # Clean up thread and worker
        if self.worker_thread:
            self.worker_thread.quit()
            self.worker_thread.wait(2000) # Wait for graceful quit
            if self.worker:
                self.worker.deleteLater()
            self.worker_thread.deleteLater()
            self.worker_thread = None
            self.worker = None
        
        self.reset_ui_after_scan()


    def reset_ui_after_scan(self):
        self.start_button.setEnabled(True)
        self.cancel_button.setEnabled(False)
        # self.worker = None # Moved to scan_finished_actions for better timing
        # self.worker_thread = None

    @Slot(str)
    def handle_error(self, error_message):
        QMessageBox.critical(self, "Scan Error", error_message)
        self.append_log(f"ERROR: {error_message}")
        # UI reset is handled by finished signal


    @Slot(str)
    def append_log(self, text):
        if self.log_output:
             clean_text = text.strip() # Remove leading/trailing whitespace
             if clean_text: # Only append if there's actual content
                self.log_output.append(clean_text) # append adds newline automatically
                # self.log_output.verticalScrollBar().setValue(self.log_output.verticalScrollBar().maximum()) # Auto-scroll done by append

    @Slot(list)
    def show_scan_summary(self, effective_items: list):
        count = len(effective_items) if effective_items else 0
        self.append_log(f"Scan Summary: Found {count} responsive panels.")

    @Slot(list)
    def show_links_summary(self, links: list):
         count = len(links) if links else 0
         self.append_log(f"Links Summary: Generated {count} total subscription links.")

    def closeEvent(self, event):
        if self.worker_thread and self.worker_thread.isRunning():
            reply = QMessageBox.question(self, "Scan in Progress",
                                         "A scan is currently running. Do you want to cancel it and exit?",
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.Yes:
                self.cancel_scan() # Request cancellation
                # Allow some time for thread to acknowledge cancellation and finish
                if self.worker_thread: # Check if it's still there
                    if not self.worker_thread.wait(3000): # Wait up to 3 seconds
                        self.append_log("Scan thread did not finish gracefully after cancel request. Forcing termination.")
                        self.worker_thread.terminate() 
                        self.worker_thread.wait(500) 
                sys.stdout = sys.__stdout__
                sys.stderr = sys.__stderr__
                event.accept()
            else:
                event.ignore()
        else:
            sys.stdout = sys.__stdout__
            sys.stderr = sys.__stderr__
            event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    main_window = MainWindow()
    main_window.show()
    sys.exit(app.exec())