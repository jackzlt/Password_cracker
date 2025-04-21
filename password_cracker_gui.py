"""
密码破解工具GUI应用
功能：
1. 支持MD5/SHA1/SHA256/SHA512哈希算法破解
2. 支持ZIP/RAR压缩文件破解
3. 提供字典攻击和暴力破解两种模式
4. 多线程实现，避免界面卡顿
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import hashlib  # 哈希算法库
import zipfile  # ZIP文件处理
import rarfile  # RAR文件处理
import threading  # 多线程支持
import queue  # 添加队列支持
import os  # 操作系统功能
from itertools import product  # 用于暴力破解的排列组合
import string  # 字符串处理
import logging
from datetime import datetime

# 配置日志系统
def setup_logging():
    log_dir = os.path.join(os.getcwd(), "logs")
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    log_file = os.path.join(log_dir, f"cracker_{datetime.now().strftime('%Y%m%d')}.log")
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

logger = setup_logging()

class PasswordCrackerApp:
    """主应用程序类，负责GUI界面和破解逻辑"""
    
    def __init__(self, root):
        """初始化主窗口"""
        self.root = root
        self.root.title("密码破解工具")
        self.root.geometry("800x600")  # 设置窗口大小
        
        # 创建标签页
        self.notebook = ttk.Notebook(root)
        self.hash_tab = ttk.Frame(self.notebook)  # 哈希破解标签页
        self.archive_tab = ttk.Frame(self.notebook)  # 压缩文件破解标签页
        self.notebook.add(self.hash_tab, text="哈希破解")
        self.notebook.add(self.archive_tab, text="压缩文件破解")
        self.notebook.pack(expand=True, fill="both")  # 填充整个窗口
        
        # 初始化各个标签页
        self.setup_hash_tab()
        self.setup_archive_tab()
    
    def setup_hash_tab(self):
        """设置哈希破解标签页的UI组件"""
        
        # 哈希算法选择下拉菜单
        self.hash_algo = tk.StringVar(value="md5")  # 默认选择MD5
        algorithms = ["md5", "sha1", "sha256", "sha512"]  # 支持的算法
        tk.Label(self.hash_tab, text="哈希算法:").grid(row=0, column=0, padx=5, pady=5)
        tk.OptionMenu(self.hash_tab, self.hash_algo, *algorithms).grid(row=0, column=1, padx=5, pady=5)
        
        # 哈希值输入
        tk.Label(self.hash_tab, text="目标哈希:").grid(row=1, column=0, padx=5, pady=5)
        self.hash_entry = tk.Entry(self.hash_tab, width=50)
        self.hash_entry.grid(row=1, column=1, padx=5, pady=5)
        
        # 破解模式选择
        self.hash_mode = tk.StringVar(value="dictionary")
        tk.Label(self.hash_tab, text="破解模式:").grid(row=2, column=0, padx=5, pady=5)
        tk.Radiobutton(self.hash_tab, text="字典攻击", variable=self.hash_mode, value="dictionary").grid(row=2, column=1, sticky="w")
        tk.Radiobutton(self.hash_tab, text="暴力破解", variable=self.hash_mode, value="bruteforce").grid(row=2, column=2, sticky="w")
        
        # 字典文件选择
        self.dict_file = tk.StringVar()
        tk.Label(self.hash_tab, text="字典文件:").grid(row=3, column=0, padx=5, pady=5)
        tk.Entry(self.hash_tab, textvariable=self.dict_file, width=40).grid(row=3, column=1, padx=5, pady=5)
        tk.Button(self.hash_tab, text="浏览...", command=self.select_dict_file).grid(row=3, column=2, padx=5, pady=5)
        
        # 暴力破解设置
        tk.Label(self.hash_tab, text="最小长度:").grid(row=4, column=0, padx=5, pady=5)
        self.min_len = tk.Spinbox(self.hash_tab, from_=1, to=10, width=5)
        self.min_len.grid(row=4, column=1, sticky="w", padx=5, pady=5)
        
        tk.Label(self.hash_tab, text="最大长度:").grid(row=5, column=0, padx=5, pady=5)
        self.max_len = tk.Spinbox(self.hash_tab, from_=1, to=10, width=5)
        self.max_len.grid(row=5, column=1, sticky="w", padx=5, pady=5)
        
        # 开始破解按钮
        tk.Button(self.hash_tab, text="开始破解", command=self.start_hash_crack).grid(row=6, column=1, pady=10)
        
        # 结果显示
        self.hash_result = tk.Text(self.hash_tab, height=10, width=70)
        self.hash_result.grid(row=7, column=0, columnspan=3, padx=5, pady=5)
    
    def setup_archive_tab(self):
        """设置压缩文件破解标签页的UI组件"""
        
        # 文件类型选择下拉菜单
        self.archive_type = tk.StringVar(value="zip")  # 默认选择ZIP
        tk.Label(self.archive_tab, text="文件类型:").grid(row=0, column=0, padx=5, pady=5)
        tk.OptionMenu(self.archive_tab, self.archive_type, "zip", "rar").grid(row=0, column=1, padx=5, pady=5)
        
        # 文件选择
        self.archive_file = tk.StringVar()
        tk.Label(self.archive_tab, text="压缩文件:").grid(row=1, column=0, padx=5, pady=5)
        tk.Entry(self.archive_tab, textvariable=self.archive_file, width=40).grid(row=1, column=1, padx=5, pady=5)
        tk.Button(self.archive_tab, text="浏览...", command=self.select_archive_file).grid(row=1, column=2, padx=5, pady=5)
        
        # 破解模式选择
        self.archive_mode = tk.StringVar(value="dictionary")
        tk.Label(self.archive_tab, text="破解模式:").grid(row=2, column=0, padx=5, pady=5)
        tk.Radiobutton(self.archive_tab, text="字典攻击", variable=self.archive_mode, value="dictionary").grid(row=2, column=1, sticky="w")
        tk.Radiobutton(self.archive_tab, text="暴力破解", variable=self.archive_mode, value="bruteforce").grid(row=2, column=2, sticky="w")
        
        # 字典文件选择
        self.archive_dict_file = tk.StringVar()
        tk.Label(self.archive_tab, text="字典文件:").grid(row=3, column=0, padx=5, pady=5)
        tk.Entry(self.archive_tab, textvariable=self.archive_dict_file, width=40).grid(row=3, column=1, padx=5, pady=5)
        tk.Button(self.archive_tab, text="浏览...", command=self.select_archive_dict_file).grid(row=3, column=2, padx=5, pady=5)
        
        # 暴力破解设置
        tk.Label(self.archive_tab, text="最小长度:").grid(row=4, column=0, padx=5, pady=5)
        self.archive_min_len = tk.Spinbox(self.archive_tab, from_=1, to=10, width=5)
        self.archive_min_len.grid(row=4, column=1, sticky="w", padx=5, pady=5)
        
        tk.Label(self.archive_tab, text="最大长度:").grid(row=5, column=0, padx=5, pady=5)
        self.archive_max_len = tk.Spinbox(self.archive_tab, from_=1, to=10, width=5)
        self.archive_max_len.grid(row=5, column=1, sticky="w", padx=5, pady=5)
        
        # 输出路径选择
        self.output_path = tk.StringVar(value=os.getcwd())
        tk.Label(self.archive_tab, text="输出路径:").grid(row=6, column=0, padx=5, pady=5)
        tk.Entry(self.archive_tab, textvariable=self.output_path, width=40).grid(row=6, column=1, padx=5, pady=5)
        tk.Button(self.archive_tab, text="浏览...", command=self.select_output_path).grid(row=6, column=2, padx=5, pady=5)
        
        # 开始破解按钮
        tk.Button(self.archive_tab, text="开始破解", command=self.start_archive_crack).grid(row=7, column=1, pady=10)
        
        # 结果显示
        self.archive_result = tk.Text(self.archive_tab, height=10, width=70)
        self.archive_result.grid(row=8, column=0, columnspan=3, padx=5, pady=5)
    
    def select_dict_file(self):
        filepath = filedialog.askopenfilename(title="选择字典文件", filetypes=[("文本文件", "*.txt")])
        if filepath:
            self.dict_file.set(filepath)
    
    def select_archive_file(self):
        filepath = filedialog.askopenfilename(title="选择压缩文件", filetypes=[("ZIP文件", "*.zip"), ("RAR文件", "*.rar")])
        if filepath:
            self.archive_file.set(filepath)
    
    def select_archive_dict_file(self):
        filepath = filedialog.askopenfilename(title="选择字典文件", filetypes=[("文本文件", "*.txt")])
        if filepath:
            self.archive_dict_file.set(filepath)
    
    def select_output_path(self):
        dirpath = filedialog.askdirectory(title="选择输出目录")
        if dirpath:
            self.output_path.set(dirpath)
    
    def start_hash_crack(self):
        target_hash = self.hash_entry.get().strip()
        if not target_hash:
            messagebox.showerror("错误", "请输入目标哈希值")
            return
        
        if self.hash_mode.get() == "dictionary" and not self.dict_file.get():
            messagebox.showerror("错误", "请选择字典文件")
            return
        
        # 创建破解线程
        thread = threading.Thread(target=self.crack_hash_thread, daemon=True)
        thread.start()
    
    def crack_hash_thread(self):
        """
        哈希破解线程函数
        根据选择的模式(字典/暴力)尝试破解哈希值
        """
        target_hash = self.hash_entry.get().strip().lower()  # 获取目标哈希值
        algo = self.hash_algo.get()  # 获取选择的算法
        
        if self.hash_mode.get() == "dictionary":
            # 字典攻击模式
            try:
                with open(self.dict_file.get(), 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        password = line.strip()  # 从字典中读取密码
                        # 计算当前密码的哈希值
                        hashed = hashlib.new(algo, password.encode()).hexdigest()
                        if hashed == target_hash:  # 匹配成功
                            self.hash_result.insert(tk.END, f"破解成功! 密码是: {password}\n")
                            return
            except Exception as e:
                self.hash_result.insert(tk.END, f"错误: {str(e)}\n")
        else:
            # 暴力破解模式
            min_len = int(self.min_len.get())  # 最小密码长度
            max_len = int(self.max_len.get())  # 最大密码长度
            # 所有可能的字符组合(字母+数字+标点)
            chars = string.ascii_letters + string.digits + string.punctuation
            
            # 尝试所有可能的组合
            for length in range(min_len, max_len + 1):
                for candidate in product(chars, repeat=length):
                    password = ''.join(candidate)
                    hashed = hashlib.new(algo, password.encode()).hexdigest()
                    if hashed == target_hash:  # 匹配成功
                        self.hash_result.insert(tk.END, f"破解成功! 密码是: {password}\n")
                        return
        
        self.hash_result.insert(tk.END, "破解失败，未找到匹配密码\n")
    
    def start_archive_crack(self):
        archive_path = self.archive_file.get()
        if not archive_path:
            messagebox.showerror("错误", "请选择压缩文件")
            return
        
        if self.archive_mode.get() == "dictionary" and not self.archive_dict_file.get():
            messagebox.showerror("错误", "请选择字典文件")
            return
        
        # 创建破解线程
        thread = threading.Thread(target=self.crack_archive_thread, daemon=True)
        thread.start()
    
    def crack_archive_thread(self):
        """优化后的压缩文件破解线程函数"""
        archive_path = self.archive_file.get()
        output_path = self.output_path.get()
        archive_type = self.archive_type.get()
        
        # 先尝试无密码解压
        try:
            if archive_type == "zip":
                with zipfile.ZipFile(archive_path) as zf:
                    encrypted = any(f.flag_bits & 0x1 for f in zf.infolist())
                    if not encrypted:
                        zf.extractall(output_path)
                        self.archive_result.insert(tk.END, "文件无密码，已成功解压\n")
                        return True
            elif archive_type == "rar":
                with rarfile.RarFile(archive_path) as rf:
                    try:
                        rf.extractall(output_path)
                        self.archive_result.insert(tk.END, "文件无密码，已成功解压\n")
                        return True
                    except rarfile.PasswordRequired:
                        pass
        except (zipfile.BadZipFile, rarfile.BadRarFile, rarfile.NeedFirstVolume) as e:
            self.archive_result.insert(tk.END, f"文件错误: {str(e)}\n")
            return False

        # 多线程破解实现
        password_queue = queue.Queue()
        found_event = threading.Event()
        result = [None]  # 使用列表实现线程间共享
        
        def worker():
            while not found_event.is_set() and not password_queue.empty():
                password = password_queue.get()
                try:
                    if archive_type == "zip":
                        with zipfile.ZipFile(archive_path) as zf:
                            zf.extractall(output_path, pwd=password.encode())
                    elif archive_type == "rar":
                        with rarfile.RarFile(archive_path) as rf:
                            rf.extractall(output_path, pwd=password)
                    
                    with threading.Lock():
                        result[0] = password
                        found_event.set()
                        self.archive_result.insert(tk.END, f"破解成功! 密码是: {password}\n")
                except Exception:
                    pass
                finally:
                    password_queue.task_done()

        # 填充密码队列
        if self.archive_mode.get() == "dictionary":
            with open(self.archive_dict_file.get(), 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    password_queue.put(line.strip())
        else:
            min_len = int(self.archive_min_len.get())
            max_len = int(self.archive_max_len.get())
            chars = string.ascii_letters + string.digits + string.punctuation
            
            for length in range(min_len, max_len + 1):
                for candidate in product(chars, repeat=length):
                    if found_event.is_set():
                        break
                    password_queue.put(''.join(candidate))

        # 启动工作线程
        threads = []
        for _ in range(4):  # 使用4个工作线程
            t = threading.Thread(target=worker)
            t.daemon = True
            t.start()
            threads.append(t)

        # 等待队列处理完成
        password_queue.join()
        found_event.set()
        
        if not result[0]:
            self.archive_result.insert(tk.END, "破解失败，未找到匹配密码\n")

if __name__ == "__main__":
    """程序入口"""
    root = tk.Tk()  # 创建主窗口
    app = PasswordCrackerApp(root)  # 创建应用程序实例
    root.mainloop()  # 启动主事件循环