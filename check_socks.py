import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import requests
import concurrent.futures
import threading
import time
import re
from queue import Queue, Empty # MODIFICATION: Added Empty import

# --- 配置 ---
DEFAULT_TEST_URL = "http://httpbin.org/ip"
DEFAULT_TIMEOUT = 10
DEFAULT_THREADS = 10
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

# --- 辅助函数 ---
def parse_proxy_string_for_requests(proxy_str, proxy_type_hint):
    """
    解析代理字符串并根据类型提示格式化为 requests 库可用的URL。
    proxy_type_hint: 'SOCKS5', 'SOCKS4', 'HTTP', 'HTTPS'
    Returns: (formatted_proxy_url, original_str, actual_type) or None
    """
    proxy_str = proxy_str.strip()
    if not proxy_str:
        return None, proxy_str, None

    # 检查是否已包含 scheme
    if "://" in proxy_str:
        scheme_match = re.match(r"^(?P<scheme>\w+)://", proxy_str)
        if scheme_match:
            scheme = scheme_match.group("scheme").lower()
            if scheme in ["socks5", "socks5h"]:
                actual_type = "SOCKS5"
            elif scheme in ["socks4", "socks4a", "socks4h"]:
                actual_type = "SOCKS4"
            elif scheme == "http":
                actual_type = "HTTP"
            elif scheme == "https":
                actual_type = "HTTPS" # HTTPS proxy
            else:
                return None, proxy_str, None # 未知scheme
            return proxy_str, proxy_str, actual_type # 直接使用用户提供的完整URL
        else: # 格式错误，比如 user:pass@host:port (没有scheme 但包含了 "://") 或 "://host:port"
             pass # 继续向下尝试用 proxy_type_hint or let regexes handle/fail
    
    # 尝试解析 user:pass@host:port 或 host:port
    auth_match = re.match(r"^(?P<user>[^:@]+):(?P<password>[^:@]+)@(?P<host>[^:]+):(?P<port>\d+)$", proxy_str)
    no_auth_match = re.match(r"^(?P<host>[^:]+):(?P<port>\d+)$", proxy_str)

    parsed_parts = None
    if auth_match:
        parsed_parts = auth_match.groupdict()
    elif no_auth_match:
        parsed_parts = no_auth_match.groupdict()

    if not parsed_parts:
        return None, proxy_str, None # 格式不匹配

    host_port = f"{parsed_parts['host']}:{parsed_parts['port']}"
    user_pass = ""
    if 'user' in parsed_parts and 'password' in parsed_parts:
        user_pass = f"{parsed_parts['user']}:{parsed_parts['password']}@"

    formatted_url = None
    actual_type = proxy_type_hint
    if proxy_type_hint == 'SOCKS5':
        formatted_url = f"socks5h://{user_pass}{host_port}"
    elif proxy_type_hint == 'SOCKS4':
        if 'password' in parsed_parts: 
            return None, proxy_str, proxy_type_hint 
        formatted_url = f"socks4h://{user_pass}{host_port}" 
    elif proxy_type_hint == 'HTTP':
        formatted_url = f"http://{user_pass}{host_port}"
    elif proxy_type_hint == 'HTTPS': 
        formatted_url = f"https://{user_pass}{host_port}"
    else:
        return None, proxy_str, None

    return formatted_url, proxy_str, actual_type


class ProxyTesterApp:
    def __init__(self, root):
        self.root = root
        self.root.title("批量代理连通性测试器")
        self.root.geometry("950x700")

        self.proxies_to_test = []
        self.results_queue = Queue()
        self.stop_event = threading.Event()
        self.test_thread = None
        self.working_proxies_data = [] # Store (original_proxy_str, type, details)

        self._create_widgets()
        self.root.after(100, self._process_queue) 

    def _create_widgets(self):
        # --- 上部：配置区 ---
        config_frame = ttk.LabelFrame(self.root, text="配置", padding=10)
        config_frame.pack(padx=10, pady=10, fill="x")

        ttk.Label(config_frame, text="测试URL:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.url_var = tk.StringVar(value=DEFAULT_TEST_URL)
        ttk.Entry(config_frame, textvariable=self.url_var, width=40).grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        ttk.Label(config_frame, text="超时(秒):").grid(row=0, column=2, padx=5, pady=5, sticky="w")
        self.timeout_var = tk.IntVar(value=DEFAULT_TIMEOUT)
        ttk.Spinbox(config_frame, from_=1, to_=60, textvariable=self.timeout_var, width=5).grid(row=0, column=3, padx=5, pady=5)

        ttk.Label(config_frame, text="线程数:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.threads_var = tk.IntVar(value=DEFAULT_THREADS)
        ttk.Spinbox(config_frame, from_=1, to_=100, textvariable=self.threads_var, width=5).grid(row=1, column=1, padx=5, pady=5, sticky="w")

        ttk.Label(config_frame, text="代理类型:").grid(row=1, column=2, padx=5, pady=5, sticky="w")
        self.proxy_type_var = tk.StringVar(value="SOCKS5")
        proxy_type_options = ["SOCKS5", "SOCKS4", "HTTP", "HTTPS (代理服务器)"]
        ttk.Combobox(config_frame, textvariable=self.proxy_type_var, values=proxy_type_options, state="readonly", width=18).grid(row=1, column=3, padx=5, pady=5, sticky="w")
        
        config_frame.columnconfigure(1, weight=1)

        # --- 中部：代理输入区 ---
        input_frame = ttk.LabelFrame(self.root, text="代理列表 (每行一个,格式: host:port 或 user:pass@host:port 或 scheme://host:port)", padding=10)
        input_frame.pack(padx=10, pady=5, fill="both", expand=True)

        self.proxy_text_area = scrolledtext.ScrolledText(input_frame, wrap=tk.WORD, height=10, width=70)
        self.proxy_text_area.pack(pady=5, fill="both", expand=True)

        button_input_frame = ttk.Frame(input_frame)
        button_input_frame.pack(fill="x", pady=5)
        ttk.Button(button_input_frame, text="从文件加载", command=self._load_proxies_from_file).pack(side="left", padx=5)
        ttk.Button(button_input_frame, text="清空列表", command=self._clear_proxy_list).pack(side="left", padx=5)


        # --- 底部：控制和结果区 ---
        control_result_frame = ttk.Frame(self.root, padding=10)
        control_result_frame.pack(padx=10, pady=10, fill="both", expand=True)
        
        control_buttons_frame = ttk.Frame(control_result_frame)
        control_buttons_frame.pack(fill="x", pady=(0,10))

        self.start_button = ttk.Button(control_buttons_frame, text="开始测试", command=self._start_tests)
        self.start_button.pack(side="left", padx=5)
        self.stop_button = ttk.Button(control_buttons_frame, text="停止测试", command=self._stop_tests, state="disabled")
        self.stop_button.pack(side="left", padx=5)
        self.save_button = ttk.Button(control_buttons_frame, text="保存可用代理", command=self._save_working_proxies, state="disabled")
        self.save_button.pack(side="left", padx=5)
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(control_result_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill="x", pady=5)

        self.status_label_var = tk.StringVar(value="状态：待机")
        ttk.Label(control_result_frame, textvariable=self.status_label_var).pack(fill="x", pady=5)

        results_frame = ttk.LabelFrame(control_result_frame, text="测试结果")
        results_frame.pack(fill="both", expand=True, pady=5)

        self.results_tree = ttk.Treeview(results_frame, columns=("proxy", "type", "status", "delay", "ip", "details"), show="headings")
        self.results_tree.heading("proxy", text="代理")
        self.results_tree.heading("type", text="类型")
        self.results_tree.heading("status", text="状态")
        self.results_tree.heading("delay", text="延迟(s)")
        self.results_tree.heading("ip", text="出口IP")
        self.results_tree.heading("details", text="详情")

        self.results_tree.column("proxy", width=200, stretch=tk.NO)
        self.results_tree.column("type", width=60, anchor="center")
        self.results_tree.column("status", width=80, anchor="center")
        self.results_tree.column("delay", width=70, anchor="center")
        self.results_tree.column("ip", width=130, anchor="center")
        self.results_tree.column("details", width=300)

        vsb = ttk.Scrollbar(results_frame, orient="vertical", command=self.results_tree.yview)
        hsb = ttk.Scrollbar(results_frame, orient="horizontal", command=self.results_tree.xview)
        self.results_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")
        self.results_tree.pack(fill="both", expand=True)


    def _load_proxies_from_file(self):
        filepath = filedialog.askopenfilename(
            title="选择代理文件",
            filetypes=(("文本文件", "*.txt"), ("所有文件", "*.*"))
        )
        if not filepath:
            return
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                proxies_content = f.read()
            self.proxy_text_area.delete("1.0", tk.END)
            self.proxy_text_area.insert("1.0", proxies_content)
            self.status_label_var.set(f"状态：从 {filepath} 加载了代理")
        except Exception as e:
            messagebox.showerror("文件读取错误", f"无法读取文件: {e}")
            self.status_label_var.set(f"状态：文件读取错误")

    def _clear_proxy_list(self):
        self.proxy_text_area.delete("1.0", tk.END)
        self.status_label_var.set("状态：代理列表已清空")

    def _start_tests(self):
        self.proxies_to_test = [p.strip() for p in self.proxy_text_area.get("1.0", tk.END).splitlines() if p.strip()]
        if not self.proxies_to_test:
            messagebox.showwarning("无代理", "请输入或加载代理列表。")
            return

        self.results_tree.delete(*self.results_tree.get_children()) 
        self.working_proxies_data = []
        self.stop_event.clear()
        self.progress_var.set(0)
        if self.proxies_to_test: # Ensure maximum is not 0 if list is empty after all (though checked above)
            self.progress_bar["maximum"] = len(self.proxies_to_test)
        else:
            self.progress_bar["maximum"] = 1 # Avoid division by zero or weird state for progress bar logic

        
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.save_button.config(state="disabled")
        self.status_label_var.set(f"状态：正在测试 {len(self.proxies_to_test)} 个代理...")

        self.test_thread = threading.Thread(target=self._run_batch_tests, daemon=True)
        self.test_thread.start()

    def _run_batch_tests(self):
        test_url = self.url_var.get()
        timeout = self.timeout_var.get()
        max_workers = self.threads_var.get()
        selected_proxy_type_display = self.proxy_type_var.get()
        if selected_proxy_type_display == "HTTPS (代理服务器)":
            proxy_type_hint = "HTTPS"
        else:
            proxy_type_hint = selected_proxy_type_display 

        parsed_and_typed_proxies = []
        num_invalid_format = 0
        for p_str in self.proxies_to_test:
            if self.stop_event.is_set(): break
            fmt_url, orig_str, actual_type = parse_proxy_string_for_requests(p_str, proxy_type_hint)
            if fmt_url:
                parsed_and_typed_proxies.append((fmt_url, orig_str, actual_type))
            else:
                num_invalid_format += 1
                self.results_queue.put({
                    "original_proxy": p_str, "proxy_type": proxy_type_hint,
                    "status": "格式错误", "delay": "-", "ip": "-", "details": "无法解析代理字符串", "is_working": False
                })
        
        if not parsed_and_typed_proxies and num_invalid_format == len(self.proxies_to_test):
             self.results_queue.put({"type": "finished"}) # All were format errors
             return

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_proxy = {}
            if not self.stop_event.is_set(): # Check before submitting any tasks
                future_to_proxy = {
                    executor.submit(self._test_single_proxy, fmt_url, orig_str, actual_type, test_url, timeout): (orig_str, actual_type)
                    for fmt_url, orig_str, actual_type in parsed_and_typed_proxies
                }

            for future in concurrent.futures.as_completed(future_to_proxy):
                if self.stop_event.is_set():
                    for f_cancel in future_to_proxy: # executor.shutdown(wait=False, cancel_futures=True) in newer Python for more aggressive cancel
                        if not f_cancel.done():
                            f_cancel.cancel() 
                    break 
                
                original_proxy, p_type = future_to_proxy[future]
                try:
                    result = future.result() 
                    self.results_queue.put({
                        "original_proxy": original_proxy,
                        "proxy_type": p_type,
                        "status": "可用" if result[0] else "不可用",
                        "delay": f"{result[3]:.2f}" if result[3] is not None else "-",
                        "ip": result[2] if result[2] else "-",
                        "details": result[1],
                        "is_working": result[0]
                    })
                except concurrent.futures.CancelledError:
                    self.results_queue.put({
                        "original_proxy": original_proxy, "proxy_type": p_type,
                        "status": "已取消", "delay": "-", "ip": "-", "details": "测试被用户中止", "is_working": False
                    })
                except Exception as e:
                    self.results_queue.put({
                        "original_proxy": original_proxy, "proxy_type": p_type,
                        "status": "错误", "delay": "-", "ip": "-", "details": f"测试中意外错误: {str(e)[:100]}", "is_working": False
                    })
        
        self.results_queue.put({"type": "finished"})


    def _test_single_proxy(self, formatted_proxy_url, original_proxy_str, proxy_type, test_url, timeout):
        if self.stop_event.is_set():
            return False, "测试已中止", None, None

        proxies_dict = {
            "http": formatted_proxy_url,
            "https": formatted_proxy_url, 
        }
        headers = {"User-Agent": USER_AGENT}
        
        start_time = time.time()
        ip_address = None
        duration = None
        try:
            response = requests.get(test_url, proxies=proxies_dict, timeout=timeout, headers=headers, verify=True)
            duration = time.time() - start_time
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    if "origin" in data:
                        ip_address = data["origin"]
                    elif "ip" in data:
                        ip_address = data["ip"]
                    else: 
                        ip_address = "未知JSON结构"
                    return True, f"成功 (状态码: {response.status_code})", ip_address, duration
                except requests.exceptions.JSONDecodeError:
                    return True, f"成功 (状态码: {response.status_code}, 非JSON)", "响应非JSON", duration
                except Exception as e_json:
                     return True, f"成功 (状态码: {response.status_code}, 解析IP出错)", f"解析IP出错: {e_json}", duration
            else:
                return False, f"失败 (状态码: {response.status_code})", None, duration
        except requests.exceptions.ProxyError as e:
            return False, f"代理错误: {str(e.__cause__)[:100] if e.__cause__ else str(e)[:100]}", None, time.time() - start_time if duration is None else duration
        except requests.exceptions.ConnectTimeout:
            return False, f"连接代理超时 ({timeout}s)", None, time.time() - start_time if duration is None else duration
        except requests.exceptions.ReadTimeout:
            return False, f"读取目标URL超时 ({timeout}s)", None, time.time() - start_time if duration is None else duration
        except requests.exceptions.RequestException as e:
            return False, f"请求错误: {str(e)[:100]}", None, time.time() - start_time if duration is None else duration
        except Exception as e: 
            return False, f"未知错误: {str(e)[:100]}", None, time.time() - start_time if duration is None else duration

    def _process_queue(self):
        current_result_item = None # For error reporting
        try:
            while True: 
                current_result_item = self.results_queue.get_nowait()
                if isinstance(current_result_item, dict) and current_result_item.get("type") == "finished":
                    self._on_tests_finished()
                    break # Exit while loop for this tick, wait for next root.after
                
                self.progress_var.set(self.progress_var.get() + 1)
                
                tag_color = "bad" 
                if current_result_item.get("is_working"):
                    tag_color = "good"
                    self.working_proxies_data.append((current_result_item["original_proxy"], current_result_item["proxy_type"], current_result_item["details"]))
                
                self.results_tree.tag_configure("good", foreground="green")
                self.results_tree.tag_configure("bad", foreground="red")
                self.results_tree.tag_configure("error_format", foreground="orange")

                if current_result_item["status"] == "格式错误":
                    tag_color = "error_format"


                self.results_tree.insert("", "end", values=(
                    current_result_item["original_proxy"],
                    current_result_item["proxy_type"],
                    current_result_item["status"],
                    current_result_item["delay"],
                    current_result_item["ip"],
                    current_result_item["details"]
                ), tags=(tag_color,))

                if self.results_tree.get_children():
                    last_item_id = self.results_tree.get_children()[-1]
                    self.results_tree.see(last_item_id) # Auto-scroll to make last item visible


        except Empty: # MODIFICATION: Correctly catch queue.Empty
            pass # 队列为空时什么也不做
        except Exception as e: # MODIFICATION: Catch other errors during result processing from queue
            error_details = f"Error processing queue item. Item: {current_result_item}. Error: {e}"
            print(error_details) # Log to console for debugging
            # Optionally, update a status label in the GUI to inform the user
            # self.status_label_var.set(f"错误: {error_details[:100]}") 
        
        self.root.after(100, self._process_queue) 

    def _on_tests_finished(self):
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        if self.working_proxies_data:
             self.save_button.config(state="normal")

        total_processed = int(self.progress_var.get())
        # total_proxies = len(self.proxies_to_test) # Can be 0
        
        # Ensure progress bar is full if all tests completed naturally
        if not self.stop_event.is_set() and self.proxies_to_test:
            self.progress_var.set(len(self.proxies_to_test))
            # Update total_processed to reflect this state for the status message
            total_processed = len(self.proxies_to_test)


        status_msg = ""
        if self.stop_event.is_set():
            status_msg = f"状态：测试已中止。已处理 {total_processed}/{len(self.proxies_to_test) if self.proxies_to_test else 0}。可用: {len(self.working_proxies_data)}"
        else:
            status_msg = f"状态：测试完成。总计 {len(self.proxies_to_test) if self.proxies_to_test else 0}。可用: {len(self.working_proxies_data)}"
        self.status_label_var.set(status_msg)


    def _stop_tests(self):
        self.stop_event.set()
        self.status_label_var.set("状态：正在中止测试...")
        self.stop_button.config(state="disabled") 

    def _save_working_proxies(self):
        if not self.working_proxies_data:
            messagebox.showinfo("无可用代理", "没有可用的代理来保存。")
            return

        filepath = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=(("文本文件", "*.txt"), ("所有文件", "*.*")),
            title="保存可用的代理"
        )
        if not filepath:
            return

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                for proxy_str, proxy_type, details in self.working_proxies_data:
                    f.write(f"{proxy_str}\n") 
            messagebox.showinfo("保存成功", f"可用的代理已保存到 {filepath}")
            self.status_label_var.set(f"状态：可用代理已保存到 {filepath}")
        except Exception as e:
            messagebox.showerror("保存失败", f"无法保存文件: {e}")
            self.status_label_var.set(f"状态：保存可用代理失败")


if __name__ == "__main__":
    try:
        import socks 
    except ImportError:
        root_check = tk.Tk()
        root_check.withdraw() 
        messagebox.showerror("依赖缺失", "请先安装 'requests[socks]' 模块。\n在命令行运行: pip install \"requests[socks]\"")
        root_check.destroy()
        exit()

    root = tk.Tk()
    app = ProxyTesterApp(root)
    root.mainloop()