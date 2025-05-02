# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import subprocess
import threading
import queue
import os
import sys
import shlex

# 检查原始 xui.py 脚本是否存在
XUI_SCRIPT = "xui.py"
if not os.path.exists(XUI_SCRIPT):
    messagebox.showerror("错误", f"找不到脚本文件: {XUI_SCRIPT}\n请确保 {XUI_SCRIPT} 与本 GUI 脚本在同一目录。")
    sys.exit(1)

class XUIGuiApp:
    def __init__(self, master):
        self.master = master
        master.title("XUI Scanner GUI")

        # Frame for Input File
        frame_input = tk.Frame(master)
        frame_input.pack(padx=10, pady=5, fill=tk.X)

        tk.Label(frame_input, text="输入文件 (domains.txt):").pack(side=tk.LEFT)
        self.input_file_entry = tk.Entry(frame_input)
        self.input_file_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        tk.Button(frame_input, text="浏览...", command=self.browse_input_file).pack(side=tk.LEFT)

        # Frame for Output Directory
        frame_output = tk.Frame(master)
        frame_output.pack(padx=10, pady=5, fill=tk.X)

        tk.Label(frame_output, text="输出目录:").pack(side=tk.LEFT)
        self.output_dir_entry = tk.Entry(frame_output)
        self.output_dir_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        tk.Button(frame_output, text="浏览...", command=self.browse_output_dir).pack(side=tk.LEFT)

        # Set default output directory to current directory
        self.output_dir_entry.insert(0, os.path.abspath("."))


        # Frame for Options
        frame_options = tk.Frame(master)
        frame_options.pack(padx=10, pady=5, fill=tk.X)

        self.update_db_var = tk.BooleanVar()
        tk.Checkbutton(frame_options, text="更新 IP 数据库 (-u)", variable=self.update_db_var).pack(side=tk.LEFT, padx=5)

        self.invisible_var = tk.BooleanVar()
        # By default, we want to see the output in the GUI, so invisible should be False
        self.invisible_var.set(False)
        # Let's not expose the invisible option directly as we want to show output.
        # If we wanted to add it:
        # tk.Checkbutton(frame_options, text="隐藏进度条 (-i)", variable=self.invisible_var).pack(side=tk.LEFT, padx=5)

        # Run Button
        self.run_button = tk.Button(master, text="开始扫描", command=self.run_scan)
        self.run_button.pack(pady=10)

        # Status Text Area
        tk.Label(master, text="状态输出:").pack(padx=10, pady=2, anchor=tk.W)
        self.status_text = scrolledtext.ScrolledText(master, wrap=tk.WORD, width=80, height=20)
        self.status_text.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)
        self.status_text.config(state=tk.DISABLED) # Make it read-only

        self.queue = queue.Queue()
        self.update_status_periodically()

    def browse_input_file(self):
        filename = filedialog.askopenfilename(
            initialdir=".",
            title="选择输入文件",
            filetypes=(("Text files", "*.txt"), ("All files", "*.*"))
        )
        if filename:
            self.input_file_entry.delete(0, tk.END)
            self.input_file_entry.insert(0, filename)

    def browse_output_dir(self):
        dirname = filedialog.askdirectory(initialdir=".", title="选择输出目录")
        if dirname:
            self.output_dir_entry.delete(0, tk.END)
            self.output_dir_entry.insert(0, dirname)

    def update_status(self, message):
        """Append message to the status text area"""
        self.status_text.config(state=tk.NORMAL)
        self.status_text.insert(tk.END, message)
        self.status_text.see(tk.END) # Auto-scroll to the end
        self.status_text.config(state=tk.DISABLED)

    def update_status_periodically(self):
        """Check the queue for new messages and update the status text area"""
        while True:
            try:
                line = self.queue.get_nowait()
                if line is None: # Sentinel value to indicate process finished
                    self.run_button.config(state=tk.NORMAL)
                    self.update_status("\n扫描完成。\n")
                    break
                self.update_status(line)
            except queue.Empty:
                break
        self.master.after(100, self.update_status_periodically) # Check again after 100ms

    def run_scan(self):
        input_file = self.input_file_entry.get()
        output_dir = self.output_dir_entry.get()

        if not input_file:
            messagebox.showwarning("警告", "请选择输入文件。")
            return

        if not os.path.exists(input_file):
             messagebox.showwarning("警告", f"输入文件不存在: {input_file}")
             return

        if not output_dir:
             messagebox.showwarning("警告", "请选择输出目录。")
             return

        # Create output directory if it doesn't exist
        if not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir)
            except Exception as e:
                messagebox.showerror("错误", f"无法创建输出目录: {e}")
                return

        self.run_button.config(state=tk.DISABLED) # Disable button while running
        self.status_text.config(state=tk.NORMAL)
        self.status_text.delete(1.0, tk.END) # Clear previous output
        self.status_text.config(state=tk.DISABLED)
        self.update_status("开始扫描...\n")

        # Build the command
        # Use sys.executable to ensure the correct Python interpreter is used
        command = [sys.executable, XUI_SCRIPT]
        command.extend(['-f', input_file])
        command.extend(['-w', output_dir])

        if self.update_db_var.get():
            command.append('-u')

        # We want output in the GUI, so we don't add -i
        # command.append('-i') # To hide console progress bar (output still goes to stdout/stderr)


        # Run the command in a separate thread
        self.scan_thread = threading.Thread(target=self.execute_command, args=(command,))
        self.scan_thread.daemon = True # Allow thread to exit with main program
        self.scan_thread.start()

    def execute_command(self, command):
        """Execute the command and put output lines into the queue"""
        try:
            # Use text=True to get decoded output
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, # Capture both stdout and stderr
                text=True,
                encoding='utf8', # Ensure output is decoded as UTF-8
                bufsize=1 # Line-buffered output
            )

            for line in iter(process.stdout.readline, ''):
                self.queue.put(line)

            process.wait() # Wait for the process to finish
            self.queue.put(None) # Put sentinel value to signal completion

        except FileNotFoundError:
            self.queue.put(f"错误: 找不到Python解释器或脚本文件 '{XUI_SCRIPT}'\n")
            self.queue.put(None)
        except Exception as e:
            self.queue.put(f"执行命令时发生错误: {e}\n")
            self.queue.put(None)


# Main part to run the GUI
if __name__ == "__main__":
    root = tk.Tk()
    app = XUIGuiApp(root)
    root.mainloop()