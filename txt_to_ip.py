import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
import re
import ipaddress

# --- 正则表达式 ---
# 匹配 IPv4 地址的正则表达式 (例如: 192.168.1.1)
IPV4_REGEX_PATTERN = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'

# 匹配 IPv6 地址的正则表达式
IPV6_REGEX_PATTERN = r"""
    \b(
        (?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|                                    # 1:2:3:4:5:6:7:8
        (?:[0-9a-fA-F]{1,4}:){1,7}:|                                                   # 1::                                 1:2:3:4:5:6:7::
        (?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|                                   # 1:2::4                              1:2:3:4:5:6::8
        (?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|                         # 1:2:3::4:5                          1:2:3:4:5::8:8
        (?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|                         # 1:2:3:4::5:6:7                      1:2:3:4::8:8:8
        (?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|                         # 1:2:3::4:5:6:7                      1:2:3::8:8:8:8
        (?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|                         # 1:2::3:4:5:6:7                      1:2::8:8:8:8:8
        [0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|                              # 1::2:3:4:5:6:7                      1::8:8:8:8:8:8
        :(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|                                               # ::2:3:4:5:6:7:8                     ::8
        fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|                                # fe80::7:8%eth0                      fe80::7:8%1
        ::(?:ffff(?::0{1,4}){0,1}:){0,1}
        (?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}
        (?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|                                   # ::255.255.255.255  ::ffff:255...
        (?:[0-9a-fA-F]{1,4}:){1,4}:
        (?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}
        (?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])                                    # 2001:db8:3:4::192.0.2.33
    )\b
"""

# 匹配 IP 地址后面跟着冒号和端口号 (例如: 192.168.1.1:8080 或 [::1]:443)
# 考虑到 IPv6 地址可能包含多个冒号，需要特殊处理，通常 IPv6 地址带端口会用方括号括起来
# 对于 IPv4，可以是 IP:Port
# 对于 IPv6，通常是 [IPv6]:Port
IP_WITH_PORT_REGEX_PATTERN = r"""
    \b(                                                                             # 开始捕获整个 IP:Port 字符串
        (?:(?:[0-9]{1,3}\.){3}[0-9]{1,3})                                           # IPv4 地址
        |                                                                           # 或
        (?:\[                                                                       # IPv6 地址通常用方括号括起来
            (?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|
            (?:[0-9a-fA-F]{1,4}:){1,7}:|
            (?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|
            (?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|
            (?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|
            (?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|
            (?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|
            [0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|
            :(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|
            fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|
            ::(?:ffff(?::0{1,4}){0,1}:){0,1}
            (?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}
            (?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|
            (?:[0-9a-fA-F]{1,4}:){1,4}:
            (?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}
            (?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])
        )\]                                                                         # 结束方括号
    )
    :([0-9]{1,5})\b                                                                 # 匹配冒号和端口号 (1-5位数字)
"""

# 编译正则表达式以提高效率
IPV4_REGEX = re.compile(IPV4_REGEX_PATTERN)
IPV6_REGEX = re.compile(IPV6_REGEX_PATTERN, re.IGNORECASE | re.VERBOSE)
IP_WITH_PORT_REGEX = re.compile(IP_WITH_PORT_REGEX_PATTERN, re.IGNORECASE | re.VERBOSE)


# --- IP 提取函数 ---
def extract_ips_from_file(filepath):
    """
    从指定的 .txt 文件中提取所有有效的 IPv4 和 IPv6 地址，如果存在端口号也一并提取。

    参数:
        filepath (str): .txt 文件的路径。

    返回:
        list: 包含所有找到的有效 IP 地址（可能带端口号）的排序列表。
              如果文件未找到或发生其他错误，则抛出异常。
    """
    found_ips = set()
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
            text = file.read()

            # 查找所有潜在的 IPv4 地址字符串
            potential_ipv4s = IPV4_REGEX.findall(text)

            # 查找所有潜在的 IPv6 地址字符串
            potential_ipv6s = [match[0] for match in IPV6_REGEX.findall(text)]

            # 查找所有潜在的 IP:Port 字符串
            # IP_WITH_PORT_REGEX.findall 会返回匹配到的整个字符串和捕获组 (IP 和 Port)
            potential_ip_with_ports = IP_WITH_PORT_REGEX.findall(text)

            # 将所有纯 IP 候选者加入
            for ip_str in potential_ipv4s + potential_ipv6s:
                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                    found_ips.add(str(ip_obj))  # 添加规范化后的纯 IP 字符串
                except ValueError:
                    pass
            
            # 处理 IP:Port 候选者
            for match_tuple in potential_ip_with_ports:
                # match_tuple 的结构取决于 IP_WITH_PORT_REGEX_PATTERN 中捕获组的数量和位置
                # 需要根据实际匹配结果来确定IP部分和端口部分
                # 由于 IP_WITH_PORT_REGEX_PATTERN 设计中，第一个捕获组是整个IP部分（包含方括号的IPv6），第二个是端口
                full_match_str = match_tuple[0] # 这是整个匹配到的IP:Port字符串
                # 提取 IP 地址部分和端口部分
                # 这里需要更精细的解析，因为 match_tuple 可能会有多个捕获组，具体取决于 IP_WITH_PORT_REGEX_PATTERN 中的非捕获组和捕获组的结构
                
                # 重新审视 IP_WITH_PORT_REGEX_PATTERN 的捕获组
                # IP_WITH_PORT_REGEX_PATTERN 的设计使得完整的IP部分（可能是IPv4或[IPv6]）是第一个大的捕获组，端口是第二个捕获组。
                # 但是，内部的 IPv4 和 IPv6 模式本身也有捕获组。
                # 简化处理：我们直接使用 findall 得到的原始匹配字符串，然后尝试拆分 IP 和 Port。

                # 更直接的方式是让正则表达式只捕获IP和端口，或者迭代 finditer 来获取整个匹配。
                # 鉴于现有 findall 行为，它会返回一个元组，其中包含所有捕获组。
                # 对于 IP_WITH_PORT_REGEX_PATTERN:
                # 第一个捕获组是整个 IP 部分 (IPv4 或 [IPv6])
                # 第二个捕获组是端口
                
                # 由于 IPv6 的复杂性，re.findall 返回的元组结构可能会包含许多 None。
                # 一个更稳健的方法是使用 re.finditer 并检查整个匹配。

                for m in IP_WITH_PORT_REGEX.finditer(text):
                    full_ip_port_str = m.group(0) # 获取整个匹配到的字符串，例如 "192.168.1.1:80" 或 "[::1]:443"
                    
                    # 尝试分割 IP 和端口
                    if ']:' in full_ip_port_str and full_ip_port_str.startswith('['): # 可能是 IPv6 with port
                        try:
                            # 找到最后一个 ']:'
                            last_bracket_colon_idx = full_ip_port_str.rfind(']:')
                            if last_bracket_colon_idx != -1:
                                ip_part = full_ip_port_str[1:last_bracket_colon_idx] # 移除方括号
                                port_part = full_ip_port_str[last_bracket_colon_idx + 2:]
                                
                                # 验证 IP 和端口
                                ip_obj = ipaddress.ip_address(ip_part) # 验证 IP
                                if 0 <= int(port_part) <= 65535: # 验证端口范围
                                    found_ips.add(f"{str(ip_obj)}:{port_part}")
                        except (ValueError, IndexError):
                            pass # 忽略无效的 IP 或端口
                    elif ':' in full_ip_port_str and not full_ip_port_str.startswith('['): # 可能是 IPv4 with port
                        parts = full_ip_port_str.rsplit(':', 1) # 只分割最后一个冒号
                        if len(parts) == 2:
                            ip_part, port_part = parts
                            try:
                                ip_obj = ipaddress.ip_address(ip_part) # 验证 IP
                                if 0 <= int(port_part) <= 65535: # 验证端口范围
                                    found_ips.add(f"{str(ip_obj)}:{port_part}")
                            except (ValueError):
                                pass # 忽略无效的 IP 或端口
            
        # 对 IP 地址进行排序 (优先纯 IP，然后带端口的 IP，按 IP 数值排序)
        # 为了正确排序，我们创建一个自定义排序键
        def custom_sort_key(ip_entry):
            if ':' in ip_entry and not ip_entry.startswith('['): # 可能是 IPv4:Port
                ip_part = ip_entry.rsplit(':', 1)[0]
                port_part = ip_entry.rsplit(':', 1)[1]
                return (ipaddress.ip_address(ip_part), int(port_part))
            elif ip_entry.startswith('[') and ']:' in ip_entry: # 可能是 [IPv6]:Port
                ip_part = ip_entry[1:ip_entry.rfind(']:')]
                port_part = ip_entry[ip_entry.rfind(']:') + 2:]
                return (ipaddress.ip_address(ip_part), int(port_part))
            else: # 纯 IP
                return (ipaddress.ip_address(ip_entry), 0) # 纯 IP 端口视为 0，确保排在带端口前面

        return sorted(list(found_ips), key=custom_sort_key)

    except FileNotFoundError:
        raise
    except Exception as e:
        raise RuntimeError(f"提取 IP 时发生错误: {e}")


# --- GUI 应用 ---
class IPExtractorApp:
    def __init__(self, master):
        self.master = master
        master.title("IP 地址提取器 (IPv4 & IPv6 & Port)")
        master.geometry("600x450")

        self.filepath_label = tk.Label(master, text="未选择文件", wraplength=580)
        self.filepath_label.pack(pady=5)

        self.browse_button = tk.Button(master, text="选择 .txt 文件", command=self.browse_file)
        self.browse_button.pack(pady=5)

        self.results_text = scrolledtext.ScrolledText(master, wrap=tk.WORD, width=70, height=15)
        self.results_text.pack(pady=10, padx=10, expand=True, fill=tk.BOTH)
        self.results_text.configure(state='disabled')

        self.status_label = tk.Label(master, text="请选择一个文件开始。")
        self.status_label.pack(pady=5, side=tk.BOTTOM, fill=tk.X)

    def browse_file(self):
        filepath = filedialog.askopenfilename(
            title="选择一个文本文件",
            filetypes=(("Text files", "*.txt"), ("All files", "*.*"))
        )
        if filepath:
            self.filepath_label.config(text=f"文件: {filepath}")
            self.results_text.configure(state='normal')
            self.results_text.delete(1.0, tk.END)
            self.status_label.config(text="正在提取 IP 地址和端口...")
            self.master.update_idletasks()

            try:
                ips_with_ports = extract_ips_from_file(filepath)
                if ips_with_ports:
                    self.results_text.insert(tk.END, f"从 '{filepath}' 中提取到 {len(ips_with_ports)} 个 IP 地址 (可能带端口):\n\n")
                    for ip_entry in ips_with_ports:
                        self.results_text.insert(tk.END, ip_entry + "\n")
                    self.status_label.config(text=f"成功提取 {len(ips_with_ports)} 个 IP 地址。")
                else:
                    self.results_text.insert(tk.END, f"在 '{filepath}' 中没有找到有效的 IP 地址。")
                    self.status_label.config(text="未找到 IP 地址。")
            except FileNotFoundError:
                messagebox.showerror("错误", f"文件 '{filepath}' 未找到。")
                self.status_label.config(text="错误：文件未找到。")
                self.filepath_label.config(text="未选择文件")
            except RuntimeError as e:
                messagebox.showerror("提取错误", str(e))
                self.status_label.config(text="提取过程中发生错误。")
            except Exception as e:
                messagebox.showerror("意外错误", f"发生了一个意外错误: {e}")
                self.status_label.config(text="发生意外错误。")
            finally:
                self.results_text.configure(state='disabled')

# --- 主程序入口 ---
if __name__ == "__main__":
    root = tk.Tk()
    app = IPExtractorApp(root)
    root.mainloop()