import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import urllib.parse
import socket
import base64
import json
import threading
import os
import traceback

# --- 依赖项检查 ---
# region Dependencies
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

try:
    import ipinfo
except ImportError:
    messagebox.showwarning("可选依赖", "未找到 ipinfo 库。如果需要使用 IPinfo.io 服务，请安装: pip install ipinfo")

try:
    import IP2Location
except ImportError:
    messagebox.showwarning("可选依赖", "未找到 IP2Location 库。如果需要使用 IP2Location 服务，请安装: pip install IP2Location")
# endregion

# --- 全局变量 ---
city_reader = None
asn_reader = None
cc = coco.CountryConverter()

# --- 核心逻辑 ---

# region IP Details Fetching
def determine_ip_type(org_or_isp_name):
    """根据组织或ISP名称启发式地判断IP类型。"""
    if not org_or_isp_name:
        return "未知类型"
    
    name_lower = org_or_isp_name.lower()
    
    hosting_keywords = [
        'cloud', 'hosting', 'server', 'datacenter', 'data center',
        'vps', 'dedicated', 'cdn', 'akamai', 'aws', 'amazon',
        'google', 'microsoft', 'azure', 'oracle', 'alibaba',
        'tencent', 'ovh', 'hetzner', 'digitalocean', 'linode',
        'vultr', 'leaseweb', 'choopa', 'quadranet'
    ]
    if any(keyword in name_lower for keyword in hosting_keywords):
        return "商企IP"
            
    isp_keywords = [
        'isp', 'telecom', 'communication', 'mobile', 'broadband',
        'comcast', 'verizon', 'at&t', 'sprint', 't-mobile',
        'china telecom', 'china unicom', 'china mobile', 'residential'
    ]
    if any(keyword in name_lower for keyword in isp_keywords):
        return "住宅IP"

    return "住宅IP" # 默认倾向于住宅IP

def get_ip_details_from_maxmind(ip_address):
    """使用本地MaxMind数据库获取IP详情。"""
    if not city_reader or not asn_reader:
        return None, "数据库未加载", "数据库未加载", "数据库未加载", "数据库未加载"

    emoji_str, country, city, ip_type, org = (None, "未知国家", "未知城市", "未知类型", "未知组织")
    try:
        # 地理位置
        city_resp = city_reader.city(ip_address)
        country = city_resp.country.name or "未知国家"
        city = city_resp.city.name or "未知城市"
        if city_resp.country.iso_code:
            try:
                raw_emoji = cc.convert(names=[city_resp.country.iso_code], to='emoji', not_found=None)
                if isinstance(raw_emoji, list) and raw_emoji: 
                    emoji_str = raw_emoji[0]
            except Exception as coco_error:
                print(f"Warning: Could not convert country code {city_resp.country.iso_code} to emoji. Error: {coco_error}")
                # The emoji will remain None, and the program will continue
                pass
        # ASN信息
        asn_resp = asn_reader.asn(ip_address)
        org = asn_resp.autonomous_system_organization or "未知组织"
        ip_type = determine_ip_type(org)
    except geoip2.errors.AddressNotFoundError:
        return None, "IP未在库中找到", "IP未在库中找到", "IP未在库中找到", "IP未在库中找到"
    except Exception as e:
        print(f"MaxMind查询错误 for {ip_address}: {e}")
        return None, "查询错误", "查询错误", "查询错误", "查询错误"
    return emoji_str, country, city, ip_type, org

def get_ip_details_from_ipinfo(ip_address, api_key):
    """使用 IPinfo.io API 获取IP详情。"""
    try:
        handler = ipinfo.getHandler(api_key)
        details = handler.getDetails(ip_address)
        
        country = details.country_name
        city = details.city
        org = details.org
        ip_type = determine_ip_type(org)
        
        emoji_str = None
        if details.country:
            raw_emoji = cc.convert(names=[details.country], to='emoji', not_found=None)
            if isinstance(raw_emoji, list) and raw_emoji: emoji_str = raw_emoji[0]
            
        return emoji_str, country, city, ip_type, org
    except Exception as e:
        print(f"IPinfo.io查询错误 for {ip_address}: {e}")
        return None, "API查询错误", str(e), "查询错误", "查询错误"

def get_ip_details_from_ip2location(ip_address, api_key):
    """使用 IP2Location API 获取IP详情。"""
    try:
        ws = IP2Location.IP2LocationWebService(api_key)
        rec = ws.lookup(ip_address)
        
        if 'error' in rec and rec['error']:
            raise Exception(rec['error']['error_message'])
            
        country = rec.get('country_name', '未知国家')
        city = rec.get('city_name', '未知城市')
        isp = rec.get('isp', '未知组织')
        ip_type = determine_ip_type(isp)
        
        emoji_str = None
        country_code = rec.get('country_code')
        if country_code:
            raw_emoji = cc.convert(names=[country_code], to='emoji', not_found=None)
            if isinstance(raw_emoji, list) and raw_emoji: emoji_str = raw_emoji[0]
        
        return emoji_str, country, city, ip_type, isp
    except Exception as e:
        print(f"IP2Location查询错误 for {ip_address}: {e}")
        return None, "API查询错误", str(e), "查询错误", "查询错误"
# endregion

def resolve_address_to_ip(address):
    """将主机名解析为IP地址。如果已经是IP，则直接返回。"""
    try:
        socket.inet_aton(address)
        return address
    except (socket.error, TypeError):
        try:
            return socket.gethostbyname(address)
        except socket.gaierror:
            return None

def parse_and_enhance_proxy(proxy_uri, provider_func):
    """
    解析代理URI，调用指定的provider_func获取详情，并重建URI。
    """
    original_uri = proxy_uri
    server_address_for_geoip = None

    try:
        # 解析协议和服务器地址 (此部分逻辑与之前版本相同)
        # region URI Parsing
        parsed_url = urllib.parse.urlparse(proxy_uri)
        protocol = parsed_url.scheme.lower()
        server_host = parsed_url.hostname

        if protocol in ["http", "https", "socks", "socks5", "socks4", "trojan", "hy2", "hysteria2"]:
            server_address_for_geoip = server_host
        elif protocol == "ss":
            if '@' in parsed_url.netloc:
                server_address_for_geoip = server_host
            else:
                try:
                    path_part = parsed_url.path.split('#')[0]
                    padding = '=' * (-len(path_part) % 4)
                    decoded_part = base64.urlsafe_b64decode(path_part + padding).decode('utf-8')
                    if '@' in decoded_part:
                        server_address_for_geoip = decoded_part.split('@')[1].split(':')[0]
                except Exception: pass
        elif protocol == "vmess":
            try:
                b64_config = parsed_url.netloc + parsed_url.path
                padding = '=' * (-len(b64_config) % 4)
                config = json.loads(base64.urlsafe_b64decode(b64_config + padding).decode('utf-8'))
                server_address_for_geoip = config.get('add')
            except Exception: return f"[VMess解析错误] {original_uri}"
        elif protocol == "vless":
            server_address_for_geoip = server_host
        else:
            return f"[不支持协议] {original_uri}"
        # endregion

        # --- 获取地理和类型信息 ---
        final_geo_prefix_str = ""
        if server_address_for_geoip:
            ip_address = resolve_address_to_ip(server_address_for_geoip)
            if ip_address:
                # 调用传入的查询函数
                details = provider_func(ip_address)
                emoji, country, city, ip_type, _ = details

                parts = []
                is_valid = lambda s: s and "未知" not in str(s) and "错误" not in str(s) and "未在库中找到" not in str(s) and "数据库未加载" not in str(s)
                
                if emoji: parts.append(emoji)
                if is_valid(country): parts.append(country)
                if is_valid(city): parts.append(city)
                if is_valid(ip_type): parts.append(ip_type)

                if parts:
                    final_geo_prefix_str = " ".join(parts)
                else: # 如果部分信息无效，也可能得到一个部分有效的前缀
                    final_geo_prefix_str = " ".join(p for p in [emoji, country, city, ip_type] if p and is_valid(p))

            else: final_geo_prefix_str = "[无法解析IP]"
        else: final_geo_prefix_str = "[无服务器地址]"

        # --- 重建URI ---
        # region URI Rebuilding
        if protocol == "vmess" and server_address_for_geoip:
            b64_config = parsed_url.netloc + parsed_url.path
            padding = '=' * (-len(b64_config) % 4)
            config = json.loads(base64.urlsafe_b64decode(b64_config + padding).decode('utf-8'))
            original_remark = config.get('ps', '')
            config['ps'] = f"{final_geo_prefix_str} {original_remark}".strip()
            new_b64_config = base64.urlsafe_b64encode(json.dumps(config, separators=(',', ':'), ensure_ascii=False).encode('utf-8')).decode('utf-8').rstrip('=')
            return f"vmess://{new_b64_config}"

        original_fragment = urllib.parse.unquote(parsed_url.fragment)
        new_fragment = f"{final_geo_prefix_str} {original_fragment}".strip()
        new_uri_parts = list(parsed_url)
        new_uri_parts[5] = urllib.parse.quote(new_fragment, safe='/:=&?~#+!$,;@()*[]')
        return urllib.parse.urlunparse(new_uri_parts)
        # endregion

    except Exception as e:
        print(f"处理 {proxy_uri} 时发生通用错误: {e}")
        traceback.print_exc()
        return f"[通用错误] {original_uri}"

# --- GUI 类 ---
class App:
    def __init__(self, root_window):
        self.root = root_window
        self.root.title("代理地理信息及类型增强器")
        self.root.geometry("800x750")

        # --- 服务商选择 ---
        provider_frame = ttk.LabelFrame(root_window, text="查询服务商设置")
        provider_frame.pack(padx=10, pady=10, fill="x")

        ttk.Label(provider_frame, text="服务商:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.provider_var = tk.StringVar(value="MaxMind (本地数据库)")
        self.provider_combo = ttk.Combobox(
            provider_frame,
            textvariable=self.provider_var,
            values=["MaxMind (本地数据库)", "IPinfo.io (API)", "IP2Location (API)"],
            state="readonly"
        )
        self.provider_combo.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        self.provider_combo.bind("<<ComboboxSelected>>", self.on_provider_change)

        ttk.Label(provider_frame, text="API密钥:").grid(row=0, column=2, padx=5, pady=5, sticky="w")
        self.api_key_var = tk.StringVar()
        self.api_key_entry = ttk.Entry(provider_frame, textvariable=self.api_key_var, width=30)
        self.api_key_entry.grid(row=0, column=3, padx=5, pady=5, sticky="ew")
        
        provider_frame.columnconfigure(3, weight=1)

        # --- MaxMind 数据库加载区域 (默认显示) ---
        self.db_frame = ttk.LabelFrame(root_window, text="MaxMind 数据库路径")
        self.db_frame.pack(padx=10, pady=5, fill="x")
        
        ttk.Label(self.db_frame, text="City DB:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.city_db_path_var = tk.StringVar()
        ttk.Entry(self.db_frame, textvariable=self.city_db_path_var).grid(row=0, column=1, sticky="ew", padx=5, pady=2)
        ttk.Button(self.db_frame, text="浏览...", command=lambda: self.browse_db('city')).grid(row=0, column=2, padx=5, pady=2)
        
        ttk.Label(self.db_frame, text="ASN DB:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.asn_db_path_var = tk.StringVar()
        ttk.Entry(self.db_frame, textvariable=self.asn_db_path_var).grid(row=1, column=1, sticky="ew", padx=5, pady=2)
        ttk.Button(self.db_frame, text="浏览...", command=lambda: self.browse_db('asn')).grid(row=1, column=2, padx=5, pady=2)
        
        self.db_frame.columnconfigure(1, weight=1)

        # --- 输入/输出/状态栏 (与之前版本相同) ---
        ttk.LabelFrame(root_window, text="输入代理 (每行一个)").pack(padx=10, pady=5, fill="both", expand=True)
        self.input_text = scrolledtext.ScrolledText(root_window, wrap=tk.WORD, height=10)
        self.input_text.pack(padx=10, pady=5, fill="both", expand=True)

        self.process_button = ttk.Button(root_window, text="开始处理", command=self.start_processing_thread)
        self.process_button.pack(pady=10)
        
        ttk.LabelFrame(root_window, text="增强后的代理").pack(padx=10, pady=5, fill="both", expand=True)
        self.output_text = scrolledtext.ScrolledText(root_window, wrap=tk.WORD, height=10, state=tk.DISABLED)
        self.output_text.pack(padx=10, pady=5, fill="both", expand=True)

        self.status_var = tk.StringVar(value="准备就绪。请选择服务商并配置。")
        ttk.Label(root_window, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W).pack(side=tk.BOTTOM, fill="x")

        # --- 初始化 ---
        self.find_common_db_paths()
        self.on_provider_change(None) # 根据默认选择更新UI

    def on_provider_change(self, event):
        """根据选择的服务商更新UI。"""
        provider = self.provider_var.get()
        if "MaxMind" in provider:
            self.api_key_entry.config(state=tk.DISABLED)
            for child in self.db_frame.winfo_children():
                child.config(state=tk.NORMAL)
            self.status_var.set("模式: MaxMind。请确保数据库路径正确。")
        else: # API provider
            self.api_key_entry.config(state=tk.NORMAL)
            for child in self.db_frame.winfo_children():
                child.config(state=tk.DISABLED)
            self.status_var.set(f"模式: {provider}。请输入您的API密钥。")

    def browse_db(self, db_type):
        var, name = (self.city_db_path_var, "City") if db_type == 'city' else (self.asn_db_path_var, "ASN")
        filepath = filedialog.askopenfilename(title=f"选择 GeoLite2-{name}.mmdb", filetypes=(("MaxMind DB", "*.mmdb"),))
        if filepath: var.set(filepath)

    def find_common_db_paths(self):
        # 自动查找并设置路径
        for db_type, var in [('City', self.city_db_path_var), ('ASN', self.asn_db_path_var)]:
            for path in [os.path.join(os.path.expanduser("~")), ".", "/usr/local/share/GeoIP", "/usr/share/GeoIP"]:
                db_file = os.path.join(path, f"GeoLite2-{db_type}.mmdb")
                if os.path.exists(db_file):
                    var.set(db_file)
                    break
    
    def pre_process_check(self):
        """在处理前进行检查，返回True或False。"""
        provider = self.provider_var.get()
        if "MaxMind" in provider:
            global city_reader, asn_reader
            try:
                if not self.city_db_path_var.get() or not self.asn_db_path_var.get():
                    raise ValueError("数据库路径不能为空。")
                # 仅在需要时加载/重新加载
                city_reader = geoip2.database.Reader(self.city_db_path_var.get(), locales=['zh-CN', 'en'])
                asn_reader = geoip2.database.Reader(self.asn_db_path_var.get())
                self.status_var.set("MaxMind数据库已加载。")
                return True
            except Exception as e:
                messagebox.showerror("数据库加载错误", f"加载MaxMind数据库失败: {e}")
                self.status_var.set("错误: MaxMind数据库加载失败。")
                return False
        else: # API
            if not self.api_key_var.get().strip():
                messagebox.showerror("API密钥错误", "API密钥不能为空。")
                self.status_var.set("错误: API密钥未填写。")
                return False
            # 检查对应库是否已安装
            lib_name = "ipinfo" if "IPinfo" in provider else "IP2Location"
            try:
                __import__(lib_name)
            except ImportError:
                messagebox.showerror("依赖缺失", f"需要使用 '{lib_name}' 库，但未找到。请安装: pip install {lib_name}")
                return False
            return True

    def start_processing_thread(self):
        if not self.pre_process_check():
            return
        proxies_input = self.input_text.get("1.0", tk.END).strip()
        if not proxies_input:
            messagebox.showwarning("警告", "输入代理列表为空。")
            return

        self.process_button.config(state=tk.DISABLED)
        self.output_text.config(state=tk.NORMAL); self.output_text.delete("1.0", tk.END); self.output_text.config(state=tk.DISABLED)
        self.status_var.set("正在处理...")

        # 根据选择设置查询函数
        provider_name = self.provider_var.get()
        if "IPinfo" in provider_name:
            api_key = self.api_key_var.get()
            provider_func = lambda ip: get_ip_details_from_ipinfo(ip, api_key)
        elif "IP2Location" in provider_name:
            api_key = self.api_key_var.get()
            provider_func = lambda ip: get_ip_details_from_ip2location(ip, api_key)
        else: # MaxMind
            provider_func = get_ip_details_from_maxmind
        
        thread = threading.Thread(target=self.process_proxies_async, args=(proxies_input, provider_func))
        thread.daemon = True
        thread.start()

    def process_proxies_async(self, proxies_input, provider_func):
        proxy_list = [p for p in proxies_input.splitlines() if p.strip()]
        total = len(proxy_list)
        results = []
        for i, proxy_uri in enumerate(proxy_list):
            self.root.after(0, self.update_status_progress, i + 1, total)
            enhanced_uri = parse_and_enhance_proxy(proxy_uri, provider_func)
            results.append(enhanced_uri)
        self.root.after(0, self.finalize_processing, results, total)

    def update_status_progress(self, current, total):
        self.status_var.set(f"正在处理... ({current}/{total})")

    def finalize_processing(self, results, processed_count):
        self.output_text.config(state=tk.NORMAL)
        self.output_text.insert(tk.END, "\n".join(results))
        self.output_text.config(state=tk.DISABLED)
        self.status_var.set(f"处理完成。共处理 {processed_count} 个代理。")
        self.process_button.config(state=tk.NORMAL)
        messagebox.showinfo("完成", f"已成功处理 {processed_count} 个代理。")

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()