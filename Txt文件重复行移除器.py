import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os

# --- 删除重复行的核心函数 (与之前基本相同，可以保持独立或放在GUI类中) ---
# 为了方便，我们将它保持独立，GUI调用它

def remove_duplicate_lines_logic(input_filepath, output_filepath=None):
    """
    从文本文件中删除重复的行，保留第一次出现的行的顺序。
    这个函数包含了主要的逻辑。
    Args:
        input_filepath (str): 输入文件的路径。
        output_filepath (str, optional): 输出文件的路径。
            如果为 None，则会创建一个临时文件，然后用它替换原始文件。
            默认为 None。
    Raises:
        FileNotFoundError: 如果找不到输入文件。
        Exception: 其他处理文件时发生的错误。
    """
    seen_lines = set()
    # 如果 output_filepath 为 None，创建一个临时文件路径
    if output_filepath is None:
        if not os.path.exists(input_filepath):
             raise FileNotFoundError(f"输入文件 '{input_filepath}' 不存在。")
        input_dir = os.path.dirname(input_filepath)
        input_filename = os.path.basename(input_filepath)
        # 构建一个临时文件路径
        temp_output_filepath = os.path.join(input_dir, f"{input_filename}.temp")
        # Ensure temporary file doesn't clash, although unlikely with .temp
        # Consider using tempfile module for robustness in real apps
    else:
        temp_output_filepath = output_filepath # If output specified, write there directly

    # Note: Using a basic print for terminal feedback; in GUI, this is captured/replaced by GUI status updates
    # print(f"正在处理文件: {input_filepath}") # Don't print directly in GUI backend

    try:
        # Ensure input file exists before opening for safety
        if not os.path.exists(input_filepath):
             raise FileNotFoundError(f"输入文件 '{input_filepath}' 不存在。")

        with open(input_filepath, 'r', encoding='utf-8', errors='ignore') as infile, \
             open(temp_output_filepath, 'w', encoding='utf-8', errors='ignore') as outfile:

            # errors='ignore' added for robustness with tricky encoding issues

            for line in infile:
                # 使用整行作为key判断是否重复
                if line not in seen_lines:
                    seen_lines.add(line)
                    outfile.write(line)

        # print(f"处理完成。唯一行已写入临时文件: {temp_output_filepath if output_filepath is None else output_filepath}") # Backend print

        # 如果 output_filepath 是 None (即原地替换)
        if output_filepath is None:
            # print(f"正在替换原始文件: {input_filepath}") # Backend print
            # 删除原始文件
            os.remove(input_filepath)
            # 将临时文件重命名为原始文件名
            os.rename(temp_output_filepath, input_filepath)
            # print("原始文件已成功替换为去重后的文件。") # Backend print

    except Exception as e:
        # Clean up temp file if error occurs during rename/write after creation
        if output_filepath is None and 'temp_output_filepath' in locals() and os.path.exists(temp_output_filepath):
             os.remove(temp_output_filepath)
        raise e # Re-raise the exception for the GUI to catch and report

# --- Tkinter GUI 实现 ---

class DuplicateRemoverGUI:
    def __init__(self, root):
        self.root = root
        root.title("Txt文件重复行移除器")

        # 使用 ttk 提升控件外观 (需要 Python 3+)
        style = ttk.Style()
        style.theme_use('clam') # 或者 'alt', 'default', 'classic'

        # --- 变量 ---
        self.input_filepath = tk.StringVar()
        self.output_filepath = tk.StringVar()
        # 0: Overwrite, 1: Save to new
        self.output_mode = tk.IntVar(value=0) # Default to overwrite
        self.status_text = tk.StringVar(value="请选择输入文件...")

        # --- GUI 控件 ---

        # 主框架，用于包含所有控件并设置内边距
        main_frame = ttk.Frame(root, padding="15")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # 配置 grid 权重，使 main_frame 可扩展
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1) # 让输入/输出路径输入框可扩展

        # 输入文件选择
        ttk.Label(main_frame, text="输入文件:").grid(row=0, column=0, sticky=tk.W, pady=5, padx=5)
        ttk.Entry(main_frame, textvariable=self.input_filepath, width=50).grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)
        ttk.Button(main_frame, text="浏览...", command=self.browse_input_file).grid(row=0, column=2, sticky=tk.W, pady=5, padx=5)

        # 输出模式选择
        ttk.Label(main_frame, text="处理方式:").grid(row=1, column=0, sticky=tk.W, pady=5, padx=5)

        overwrite_radio = ttk.Radiobutton(main_frame, text="覆盖原文件", variable=self.output_mode, value=0, command=self.update_output_fields_state)
        overwrite_radio.grid(row=1, column=1, sticky=tk.W, pady=5, padx=5)

        save_new_radio = ttk.Radiobutton(main_frame, text="保存到新文件", variable=self.output_mode, value=1, command=self.update_output_fields_state)
        save_new_radio.grid(row=2, column=1, sticky=tk.W, pady=5, padx=5)


        # 输出文件选择 (只有在选择“保存到新文件”时启用)
        self.output_label = ttk.Label(main_frame, text="输出文件:")
        self.output_label.grid(row=3, column=0, sticky=tk.W, pady=5, padx=5)

        self.output_entry = ttk.Entry(main_frame, textvariable=self.output_filepath, width=50)
        self.output_entry.grid(row=3, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)

        self.output_button = ttk.Button(main_frame, text="浏览...", command=self.browse_output_file)
        self.output_button.grid(row=3, column=2, sticky=tk.W, pady=5, padx=5)

        # 初始设置输出文件控件的状态
        self.update_output_fields_state()

        # 启动处理按钮
        ttk.Button(main_frame, text="开始处理", command=self.start_process).grid(row=4, column=0, columnspan=3, pady=15)

        # 状态栏
        ttk.Label(main_frame, textvariable=self.status_text, anchor=tk.W).grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5, padx=5)


    # --- 事件处理方法 ---

    def browse_input_file(self):
        filepath = filedialog.askopenfilename(
            title="选择输入文件",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if filepath:
            self.input_filepath.set(filepath)
            # 如果选择新文件模式，且输出路径未设置，尝试根据输入路径设置默认输出路径
            if self.output_mode.get() == 1 and not self.output_filepath.get():
                 input_dir = os.path.dirname(filepath)
                 input_filename_base, input_filename_ext = os.path.splitext(os.path.basename(filepath))
                 default_output_filename = f"{input_filename_base}_unique{input_filename_ext}"
                 self.output_filepath.set(os.path.join(input_dir, default_output_filename))
            self.status_text.set(f"已选择文件: {filepath}")


    def browse_output_file(self):
         # 当处于“保存到新文件”模式下才执行浏览
         if self.output_mode.get() == 1:
            filepath = filedialog.asksaveasfilename(
                title="保存去重后的文件",
                defaultextension=".txt", # 如果文件名没有后缀，默认添加.txt
                filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
            )
            if filepath:
                self.output_filepath.set(filepath)
                self.status_text.set(f"将保存到: {filepath}")
         else:
             # Should not happen due to state management, but good practice
             messagebox.showwarning("提示", "当前模式为覆盖原文件，无需指定输出路径。")


    def update_output_fields_state(self):
        """根据选择的输出模式，启用/禁用输出文件相关的控件。"""
        if self.output_mode.get() == 0: # Overwrite
            self.output_label.state(['disabled'])
            self.output_entry.state(['disabled'])
            self.output_button.state(['disabled'])
            self.status_text.set("模式：覆盖原文件。请选择输入文件...")
            self.output_filepath.set("") # Clear output path when switching to overwrite
        else: # Save to new
            self.output_label.state(['!disabled']) # Enable
            self.output_entry.state(['!disabled'])
            self.output_button.state(['!disabled'])
            self.status_text.set("模式：保存到新文件。请选择输入/输出文件...")
             # 如果已经选了输入文件，且输出路径为空，自动设置一个默认输出路径
            if self.input_filepath.get() and not self.output_filepath.get():
                filepath = self.input_filepath.get()
                input_dir = os.path.dirname(filepath)
                input_filename_base, input_filename_ext = os.path.splitext(os.path.basename(filepath))
                default_output_filename = f"{input_filename_base}_unique{input_filename_ext}"
                self.output_filepath.set(os.path.join(input_dir, default_output_filename))


    def start_process(self):
        input_file = self.input_filepath.get()
        output_file = None # Default to None for overwrite mode

        # 验证输入文件是否已选择
        if not input_file:
            messagebox.showwarning("输入错误", "请选择一个输入文件。")
            self.status_text.set("错误：请选择输入文件。")
            return

        # 如果是保存到新文件模式，获取输出文件路径
        if self.output_mode.get() == 1:
            output_file = self.output_filepath.get()
            if not output_file:
                 messagebox.showwarning("输入错误", "请指定去重后文件保存路径。")
                 self.status_text.set("错误：请指定输出文件。")
                 return
            # Simple check to prevent overwriting input if input == output AND save to new is chosen
            # Note: Overwriting input is intended behavior when Overwrite mode is selected (output_file=None)
            if input_file == output_file:
                 messagebox.showwarning("警告", "输出文件路径不能与输入文件路径相同，因为当前选择的是'保存到新文件'模式。请选择不同的输出路径。")
                 self.status_text.set("错误：输入输出文件相同，且为保存模式。")
                 return


        self.status_text.set("正在处理，请稍候...")

        try:
            # 调用核心处理函数
            remove_duplicate_lines_logic(input_file, output_file)
            self.status_text.set("处理完成！")
            if self.output_mode.get() == 0:
                 messagebox.showinfo("完成", f"文件 '{input_file}' 的重复行已移除。")
            else:
                 messagebox.showinfo("完成", f"重复行已移除，文件已保存到 '{output_file}'。")

        except FileNotFoundError:
             self.status_text.set("处理失败: 文件未找到")
             messagebox.showerror("错误", f"处理失败：找不到指定的输入文件 '{input_file}'。")
        except Exception as e:
            self.status_text.set(f"处理失败: {e}")
            messagebox.showerror("处理错误", f"处理过程中发生错误：\n{e}")


# --- 运行 GUI ---
if __name__ == "__main__":
    root = tk.Tk()
    app = DuplicateRemoverGUI(root)
    root.mainloop()