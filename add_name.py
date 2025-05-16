import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import urllib.parse
import socket
import base64
import json
import threading
import os

try:
    import geoip2.database
    import geoip2.errors
except ImportError:
    messagebox.showerror("依赖错误", "未找到 geoip2 库。请安装: pip install geoip2")
    exit()

try:
    import country_converter as coco
except ImportError:
    messagebox.showerror("依赖错误", "未找到 country_converter 库。请安装: pip install country_converter")
    exit()

# --- 全局变量 ---
geoip_reader = None
cc = coco.CountryConverter()

# --- 核心逻辑 ---

def get_geo_info(ip_address):
    """查询IP地址的地理信息。"""
    if not geoip_reader:
        return None, "数据库未加载", "数据库未加载"

    try:
        # geoip_reader 在加载时已指定 locales=['zh-CN', 'en']
        response = geoip_reader.city(ip_address)

        country_code = None
        country_name = "未知国家"
        city_name = "未知城市"
        emoji_str = None

        if response.country:
            country_code = response.country.iso_code
            country_name = response.country.name if response.country.name else "未知国家"
        
        if response.city:
            city_name = response.city.name if response.city.name else "未知城市"

        if country_code:
            # print(f"DEBUG: IP={ip_address}, CountryCode={country_code}") # 调试用
            try:
                # 确保使用 'emoji_flag'
                raw_emoji_output = cc.convert(names=[country_code], to='emoji_flag', not_found=None)
                # print(f"DEBUG: IP={ip_address}, RawEmojiOutput={raw_emoji_output}") # 调试用
                if raw_emoji_output:
                    # cc.convert 对列表输入返回列表，即使只有一个元素
                    if isinstance(raw_emoji_output, list) and len(raw_emoji_output) > 0:
                        emoji_str = raw_emoji_output[0] 
                    elif isinstance(raw_emoji_output, str): # 理论上 names=[...] 不会到这里
                        emoji_str = raw_emoji_output
                    
                    # 处理 cc.convert(..., not_found=None) 可能返回 "None" 字符串的情况
                    if emoji_str == "None" or emoji_str is None:
                        emoji_str = None # 确保是 Python None
                    # else:
                        # print(f"DEBUG: IP={ip_address}, EmojiStr={emoji_str}, Type={type(emoji_str)}") # 调试用

            except ValueError as ve:
                print(f"国家代码转换 (emoji) ValueError for {country_code} (IP: {ip_address}): {ve}")
                emoji_str = None
            except Exception as coco_ex:
                print(f"国家代码转换 (emoji) error for {country_code} (IP: {ip_address}): {coco_ex}")
                emoji_str = None
        
        return emoji_str, country_name, city_name

    except geoip2.errors.AddressNotFoundError:
        return None, "IP未在库中找到", "IP未在库中找到"
    except AttributeError as ae:
        # 例如，response.country 存在但 response.country.name 是 None，然后尝试 .name
        print(f"GeoIP 属性错误 for {ip_address}: {ae} (Response: country={response.country}, city={response.city})")
        return None, "数据不完整", "数据不完整"
    except Exception as e:
        print(f"GeoIP 查询时发生意外错误 for {ip_address}: {e}")
        return None, "查询错误", "查询错误"


def resolve_address_to_ip(address):
    """将主机名解析为IP地址。如果已经是IP，则直接返回。"""
    try:
        socket.inet_aton(address)
        return address
    except socket.error:
        try:
            return socket.gethostbyname(address)
        except socket.gaierror:
            return None

def parse_and_enhance_proxy(proxy_uri):
    """
    解析各种代理URI格式，提取服务器信息，获取地理位置，
    并将地理信息前置到备注中重建URI。
    """
    original_uri = proxy_uri
    geo_prefix_parts = [] # 用于构建地理前缀 [emoji, country, city]
    server_address_for_geoip = None

    try:
        parsed_url = urllib.parse.urlparse(proxy_uri)
        protocol = parsed_url.scheme.lower()
        
        server_host = parsed_url.hostname
        # server_port = parsed_url.port # Not always needed for geoip

        if protocol in ["http", "https", "socks", "socks5", "socks4"]:
            server_address_for_geoip = server_host
        
        elif protocol == "ss":
            if '@' in parsed_url.netloc:
                server_address_for_geoip = server_host
            else:
                try:
                    # 移除可能的 fragment 部分再解码
                    path_part = parsed_url.path.split('#')[0]
                    # 确保有足够的 '=' 用于 base64 解码
                    padding = '=' * (-len(path_part) % 4)
                    decoded_part = base64.urlsafe_b64decode(path_part + padding).decode('utf-8')
                    
                    if '@' in decoded_part:
                        server_address_for_geoip = decoded_part.split('@')[1].split(':')[0]
                    else: # 可能是 method:pass@host:port 或 host:port
                        parts = decoded_part.split(':')
                        # 尝试一个启发式方法来找到主机名 (通常包含点，且不是纯数字)
                        potential_host = parts[-2] if len(parts) >=2 else (parts[0] if len(parts)==1 else None)
                        if potential_host and ('.' in potential_host and not potential_host.replace('.', '').isdigit()):
                             server_address_for_geoip = potential_host
                        # 更复杂的SS URI可能需要更健壮的解析
                except Exception as e:
                    print(f"SS base64 解码错误: {e} for {proxy_uri}")
                    server_address_for_geoip = None

        elif protocol in ["vmess", "vless"]:
            if protocol == "vmess":
                try:
                    b64_config = parsed_url.netloc + parsed_url.path
                    padding = '=' * (-len(b64_config) % 4)
                    config_str = base64.urlsafe_b64decode(b64_config + padding).decode('utf-8')
                    config = json.loads(config_str)
                    server_address_for_geoip = config.get('add')
                except Exception as e:
                    print(f"VMess 解析错误: {e} for {proxy_uri}")
                    return f"[解析错误] {original_uri}"
            elif protocol == "vless":
                server_address_for_geoip = server_host
        
        elif protocol in ["trojan", "hy2", "hysteria2"]:
            server_address_for_geoip = server_host
        else:
            return f"[不支持协议] {original_uri}"

        # --- 解析并获取地理信息 ---
        final_geo_prefix_str = ""
        if server_address_for_geoip:
            ip_address = resolve_address_to_ip(server_address_for_geoip)
            if ip_address:
                emoji, country, city = get_geo_info(ip_address)
                # print(f"DEBUG URI: {proxy_uri}, IP: {ip_address}, Emoji: {emoji}, Country: {country}, City: {city}") # 调试用
                
                current_geo_parts = []
                if emoji: # 只有当 emoji 存在时才添加
                    current_geo_parts.append(emoji)
                
                # 添加国家和城市，如果它们不是默认的 "未知" 或 "N/A"
                valid_country = country and country not in ["未知国家", "IP未在库中找到", "数据不完整", "查询错误", "数据库未加载", "N/A"]
                valid_city = city and city not in ["未知城市", "IP未在库中找到", "数据不完整", "查询错误", "数据库未加载", "N/A"]

                if valid_country and valid_city:
                    current_geo_parts.append(f"{country} - {city}")
                elif valid_country:
                    current_geo_parts.append(country)
                elif valid_city: # 不太可能只有城市没有国家
                    current_geo_parts.append(city)

                if current_geo_parts:
                     final_geo_prefix_str = " ".join(current_geo_parts).strip()

            else: # 无法解析IP
                final_geo_prefix_str = "[无法解析IP]"
        else: # 没有服务器地址可供查询
            final_geo_prefix_str = "[无服务器地址]"
        
        if not final_geo_prefix_str or final_geo_prefix_str in ["[无法解析IP]", "[无服务器地址]"]: # 如果地理信息获取失败或不完整，可以选择不修改或标记
             # return original_uri # 选择1: 不修改
             pass # 选择2: 继续，让错误标记被添加

        # --- 重建URI ---
        if protocol == "vmess" and server_address_for_geoip: # 确保 config 已被解析
            try:
                # 重新解析以获取原始备注 (因为之前的 config 是局部变量)
                b64_config = parsed_url.netloc + parsed_url.path
                padding = '=' * (-len(b64_config) % 4)
                config_str = base64.urlsafe_b64decode(b64_config + padding).decode('utf-8')
                config = json.loads(config_str)
                
                original_remark = config.get('ps', '')
                new_remark = f"{final_geo_prefix_str} {original_remark}".strip()
                config['ps'] = new_remark
                
                new_config_str = json.dumps(config, separators=(',', ':'), ensure_ascii=False) # ensure_ascii=False for Chinese
                new_b64_config = base64.urlsafe_b64encode(new_config_str.encode('utf-8')).decode('utf-8').rstrip('=')
                return f"vmess://{new_b64_config}"
            except Exception as e:
                print(f"VMess 重建错误: {e} for {proxy_uri}")
                return f"[VMESS重建错误] {original_uri}"

        # 其他协议处理 fragment (#remark)
        original_fragment = parsed_url.fragment
        new_fragment = f"{final_geo_prefix_str} {original_fragment}".strip()
        
        new_uri_parts = list(parsed_url)
        new_uri_parts[5] = new_fragment # 索引 5 是 fragment
        return urllib.parse.urlunparse(new_uri_parts)

    except Exception as e:
        print(f"处理 {proxy_uri} 时发生通用错误: {e}")
        import traceback
        traceback.print_exc() # 打印更详细的错误堆栈
        return f"[通用错误] {original_uri}"


# --- GUI 函数 ---
class App:
    def __init__(self, root_window):
        self.root = root_window
        self.root.title("代理地理信息增强器")
        self.root.geometry("800x600")

        self.db_path_frame = ttk.LabelFrame(root_window, text="GeoIP2 数据库")
        self.db_path_frame.pack(padx=10, pady=5, fill="x")

        self.db_path_var = tk.StringVar()
        self.db_path_label = ttk.Label(self.db_path_frame, text="GeoLite2-City.mmdb 路径:")
        self.db_path_label.pack(side=tk.LEFT, padx=5, pady=5)
        
        self.db_path_entry = ttk.Entry(self.db_path_frame, textvariable=self.db_path_var, width=50)
        self.db_path_entry.pack(side=tk.LEFT, expand=True, fill="x", padx=5, pady=5)
        
        self.browse_button = ttk.Button(self.db_path_frame, text="浏览...", command=self.browse_db)
        self.browse_button.pack(side=tk.LEFT, padx=5, pady=5)
        
        self.load_db_button = ttk.Button(self.db_path_frame, text="加载数据库", command=self.load_geoip_db)
        self.load_db_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.input_frame = ttk.LabelFrame(root_window, text="输入代理 (每行一个)")
        self.input_frame.pack(padx=10, pady=5, fill="both", expand=True)
        self.input_text = scrolledtext.ScrolledText(self.input_frame, wrap=tk.WORD, height=10)
        self.input_text.pack(padx=5, pady=5, fill="both", expand=True)

        self.process_button = ttk.Button(root_window, text="处理代理", command=self.start_processing_thread)
        self.process_button.pack(pady=10)
        
        self.output_frame = ttk.LabelFrame(root_window, text="增强后的代理")
        self.output_frame.pack(padx=10, pady=5, fill="both", expand=True)
        self.output_text = scrolledtext.ScrolledText(self.output_frame, wrap=tk.WORD, height=10, state=tk.DISABLED)
        # 尝试指定一个可能支持Emoji的字体 (这非常依赖系统)
        # self.output_text.configure(font=("Segoe UI Emoji", 10)) # Windows
        # self.output_text.configure(font=("Apple Color Emoji", 10)) # macOS
        # self.output_text.configure(font=("Noto Color Emoji", 10)) # Linux with Noto fonts
        self.output_text.pack(padx=5, pady=5, fill="both", expand=True)


        self.status_var = tk.StringVar()
        self.status_var.set("准备就绪。请加载 GeoIP 数据库。")
        self.status_bar = ttk.Label(root_window, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill="x")

        self.find_common_db_path()

    def find_common_db_path(self):
        common_paths = [
            os.path.join(os.path.expanduser("~"), "GeoLite2-City.mmdb"),
            "GeoLite2-City.mmdb",
            "/usr/local/share/GeoIP/GeoLite2-City.mmdb",
            "/usr/share/GeoIP/GeoLite2-City.mmdb"
        ]
        for path in common_paths:
            if os.path.exists(path):
                self.db_path_var.set(path)
                self.load_geoip_db()
                break

    def browse_db(self):
        filepath = filedialog.askopenfilename(
            title="选择 GeoLite2-City.mmdb",
            filetypes=(("MaxMind DB 文件", "*.mmdb"), ("所有文件", "*.*"))
        )
        if filepath:
            self.db_path_var.set(filepath)
            self.load_geoip_db()

    def load_geoip_db(self):
        global geoip_reader
        db_path = self.db_path_var.get()
        if not db_path:
            self.status_var.set("错误: GeoIP 数据库路径为空。")
            messagebox.showerror("错误", "GeoIP 数据库路径为空。")
            return

        try:
            # 指定优先语言为中文，英文作为后备
            geoip_reader = geoip2.database.Reader(db_path, locales=['zh-CN', 'en'])
            self.status_var.set(f"GeoIP 数据库加载成功: {db_path}")
            messagebox.showinfo("成功", "GeoIP 数据库加载成功。")
        except Exception as e:
            geoip_reader = None
            self.status_var.set(f"加载 GeoIP 数据库错误: {e}")
            messagebox.showerror("数据库加载错误", f"加载 GeoIP 数据库失败: {e}\n请确保您有 GeoLite2-City.mmdb 文件。")

    def start_processing_thread(self):
        if not geoip_reader:
            messagebox.showerror("错误", "GeoIP 数据库未加载。请先加载。")
            self.status_var.set("错误: GeoIP 数据库未加载。")
            return

        proxies_input = self.input_text.get("1.0", tk.END).strip()
        if not proxies_input:
            messagebox.showwarning("警告", "输入代理列表为空。")
            return

        self.process_button.config(state=tk.DISABLED)
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete("1.0", tk.END)
        self.output_text.config(state=tk.DISABLED)
        self.status_var.set("正在处理...")

        thread = threading.Thread(target=self.process_proxies_async, args=(proxies_input,))
        thread.daemon = True
        thread.start()

    def process_proxies_async(self, proxies_input):
        proxy_list = proxies_input.splitlines()
        processed_count = 0
        
        results = []
        for i, proxy_uri in enumerate(proxy_list):
            proxy_uri = proxy_uri.strip()
            if not proxy_uri:
                continue
            
            # 使用 after 调度 GUI 更新到主线程
            self.root.after(0, self.update_status_progress, i + 1, len(proxy_list))
            enhanced_uri = parse_and_enhance_proxy(proxy_uri)
            results.append(enhanced_uri)
            processed_count += 1
        
        self.root.after(0, self.finalize_processing, results, processed_count)

    def update_status_progress(self, current, total):
        self.status_var.set(f"正在处理... ({current}/{total})")

    def finalize_processing(self, results, processed_count):
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete("1.0", tk.END)
        if results:
            self.output_text.insert(tk.END, "\n".join(results))
        self.output_text.config(state=tk.DISABLED)
        
        self.status_var.set(f"处理完成。共处理 {processed_count} 个代理。")
        self.process_button.config(state=tk.NORMAL)
        messagebox.showinfo("完成", f"已处理 {processed_count} 个代理。")


if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()