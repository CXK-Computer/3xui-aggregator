import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
import re
import ipaddress

# --- 正则表达式 ---
# 匹配 IPv4 地址的正则表达式 (例如: 192.168.1.1)
# \b 表示单词边界，确保匹配的是完整的 IP
IPV4_REGEX_PATTERN = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'

# 匹配 IPv6 地址的正则表达式
# 这是一个相对全面的表达式，能匹配多种 IPv6 格式，包括：
# - 标准格式 (e.g., 2001:0db8:85a3:0000:0000:8a2e:0370:7334)
# - 压缩格式 (e.g., 2001:db8::1)
# - IPv4 映射的 IPv6 地址 (e.g., ::ffff:192.168.1.1)
# 由于 IPv6 的复杂性，这个正则表达式也比较长。
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

# 编译正则表达式以提高效率
# re.IGNORECASE 使 IPv6 匹配不区分大小写 (例如 a-f 和 A-F)
# re.VERBOSE 允许在正则表达式字符串中使用空格和注释（如此处的IPV6_REGEX_PATTERN）
IPV4_REGEX = re.compile(IPV4_REGEX_PATTERN)
IPV6_REGEX = re.compile(IPV6_REGEX_PATTERN, re.IGNORECASE | re.VERBOSE)

# --- IP 提取函数 ---
def extract_ips_from_file(filepath):
    """
    从指定的 .txt 文件中提取所有有效的 IPv4 和 IPv6 地址。

    参数:
        filepath (str): .txt 文件的路径。

    返回:
        list: 包含所有找到的有效 IP 地址的排序列表。
              如果文件未找到或发生其他错误，则抛出异常。
    """
    found_ips = set()
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
            text = file.read()

            # 查找所有潜在的 IPv4 地址字符串
            potential_ipv4s = IPV4_REGEX.findall(text)

            # 查找所有潜在的 IPv6 地址字符串
            # IPV6_REGEX.findall 返回的是元组列表，因为主模式被括号包围
            potential_ipv6s = [match[0] for match in IPV6_REGEX.findall(text)]

            all_potential_candidates = potential_ipv4s + potential_ipv6s

            for ip_str in all_potential_candidates:
                try:
                    # 使用 ipaddress 模块验证并规范化 IP 地址
                    ip_obj = ipaddress.ip_address(ip_str)
                    found_ips.add(str(ip_obj))  # 添加规范化后的 IP 字符串
                except ValueError:
                    # 如果 ip_str 不是有效的 IP 地址，ipaddress.ip_address 会抛出 ValueError
                    pass
        
        # 对 IP 地址进行排序 (可选，但更美观)
        # ipaddress.ip_address 作为 key 可以确保 IP 地址按数值正确排序
        return sorted(list(found_ips), key=ipaddress.ip_address)

    except FileNotFoundError:
        raise  # 由调用者处理 FileNotFoundError
    except Exception as e:
        # logger.error(f"提取 IP 时发生未知错误: {e}") # 可以考虑日志记录
        raise RuntimeError(f"提取 IP 时发生错误: {e}")


# --- GUI 应用 ---
class IPExtractorApp:
    def __init__(self, master):
        self.master = master
        master.title("IP 地址提取器 (IPv4 & IPv6)")
        master.geometry("600x450") # 设置窗口大小

        # 文件路径标签
        self.filepath_label = tk.Label(master, text="未选择文件", wraplength=580) # wraplength 防止长路径撑大窗口
        self.filepath_label.pack(pady=5)

        # 浏览按钮
        self.browse_button = tk.Button(master, text="选择 .txt 文件", command=self.browse_file)
        self.browse_button.pack(pady=5)

        # 结果显示区域 (带滚动条的文本框)
        self.results_text = scrolledtext.ScrolledText(master, wrap=tk.WORD, width=70, height=15)
        self.results_text.pack(pady=10, padx=10, expand=True, fill=tk.BOTH)
        self.results_text.configure(state='disabled') # 初始设为不可编辑

        # 状态栏标签
        self.status_label = tk.Label(master, text="请选择一个文件开始。")
        self.status_label.pack(pady=5, side=tk.BOTTOM, fill=tk.X)

    def browse_file(self):
        filepath = filedialog.askopenfilename(
            title="选择一个文本文件",
            filetypes=(("Text files", "*.txt"), ("All files", "*.*"))
        )
        if filepath:
            self.filepath_label.config(text=f"文件: {filepath}")
            self.results_text.configure(state='normal') # 启用编辑以插入文本
            self.results_text.delete(1.0, tk.END) # 清空旧结果
            self.status_label.config(text="正在提取 IP 地址...")
            self.master.update_idletasks() # 更新UI，显示“正在提取”

            try:
                ips = extract_ips_from_file(filepath)
                if ips:
                    self.results_text.insert(tk.END, f"从 '{filepath}' 中提取到 {len(ips)} 个 IP 地址:\n\n")
                    for ip in ips:
                        self.results_text.insert(tk.END, ip + "\n")
                    self.status_label.config(text=f"成功提取 {len(ips)} 个 IP 地址。")
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
                self.results_text.configure(state='disabled') # 完成后设为不可编辑

# --- 主程序入口 ---
if __name__ == "__main__":
    root = tk.Tk()
    app = IPExtractorApp(root)
    root.mainloop()