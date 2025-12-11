#!/usr/bin/env python3
"""
pentool_gui.py

A simple, modular Penetration Testing Toolkit with GUI (tkinter).
Modules included:
 - Port Scanner (TCP connect scan, port range)
 - Banner Grabber (connect & read small banner)
 - Ping (calls system ping; cross-platform handling)
 - Password Auditor (local only: checks password complexity or checks user-provided hashes against a wordlist -- no remote brute forcing)

Safety:
 - Requires explicit "I have authorization" checkbox before network actions.
 - Rate-limited and threaded to avoid UI freeze.

Run:
    python3 pentool_gui.py
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import socket
import threading
import time
import subprocess
import platform
import hashlib
import os
from queue import Queue

# ---------- Helper functions ----------

def timestamp():
    return time.strftime("%Y-%m-%d %H:%M:%S")

def safe_log(widget, txt):
    widget.configure(state='normal')
    widget.insert(tk.END, f"[{timestamp()}] {txt}\n")
    widget.see(tk.END)
    widget.configure(state='disabled')

def has_authorization(checkbox_var):
    return checkbox_var.get() == 1

# ---------- Networking modules (non-destructive, for authorized testing) ----------

def tcp_connect_scan(host, port, timeout=1.0):
    """Attempt to connect to a TCP port. Returns True if open, False otherwise."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            res = s.connect_ex((host, port))
            return res == 0
    except Exception:
        return False

def banner_grab(host, port, timeout=2.0, max_read=1024):
    """Connect and read a small banner from a service (if any)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            try:
                data = s.recv(max_read)
                return data.decode(errors='replace').strip()
            except Exception:
                return "<no-banner-or-read-failed>"
    except Exception as e:
        return f"<connect-failed: {e}>"

def run_ping(host, count=4, timeout=4):
    """Run system ping. Return stdout/stderr combined."""
    system = platform.system().lower()
    if system == 'windows':
        cmd = ['ping', '-n', str(count), '-w', str(timeout * 1000), host]
    else:
        # -c count, -W timeout (seconds)
        cmd = ['ping', '-c', str(count), '-W', str(timeout), host]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout*count + 5)
        return proc.stdout + proc.stderr
    except subprocess.TimeoutExpired:
        return "<ping-timeout>"

# ---------- Password auditor helpers (local-only) ----------

def sha256_of_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()

def check_password_strength(pw):
    score = 0
    length = len(pw)
    if length >= 8:
        score += 1
    if any(c.islower() for c in pw) and any(c.isupper() for c in pw):
        score += 1
    if any(c.isdigit() for c in pw):
        score += 1
    if any(not c.isalnum() for c in pw):
        score += 1
    return score  # 0-4

# ---------- GUI Implementation ----------

class PentoolGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CODTECH - Penetration Testing Toolkit (GUI)")
        self.geometry("900x650")
        self.create_widgets()

    def create_widgets(self):
        # Top frame: Authorization
        top = ttk.Frame(self, padding=8)
        top.pack(side=tk.TOP, fill=tk.X)

        self.auth_var = tk.IntVar(value=0)
        auth_chk = ttk.Checkbutton(top, text="I confirm I have written authorization to test the target systems (required)", variable=self.auth_var)
        auth_chk.pack(side=tk.LEFT, padx=(0,10))

        help_btn = ttk.Button(top, text="Usage / Safety", command=self.show_safety)
        help_btn.pack(side=tk.LEFT)

        # Notebook for modules
        nb = ttk.Notebook(self)
        nb.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        # Port Scanner tab
        self.port_tab = ttk.Frame(nb)
        nb.add(self.port_tab, text="Port Scanner")

        # Banner Grabber tab
        self.banner_tab = ttk.Frame(nb)
        nb.add(self.banner_tab, text="Banner Grabber")

        # Ping tab
        self.ping_tab = ttk.Frame(nb)
        nb.add(self.ping_tab, text="Ping")

        # Password Auditor tab
        self.pw_tab = ttk.Frame(nb)
        nb.add(self.pw_tab, text="Password Auditor")

        # Shared logging pane on bottom
        log_frame = ttk.LabelFrame(self, text="Activity Log")
        log_frame.pack(side=tk.BOTTOM, fill=tk.BOTH, padx=8, pady=8, expand=False)
        self.log = scrolledtext.ScrolledText(log_frame, height=10, state='disabled')
        self.log.pack(fill=tk.BOTH, expand=True)

        # Build each tab
        self.build_port_tab()
        self.build_banner_tab()
        self.build_ping_tab()
        self.build_pw_tab()

    def show_safety(self):
        msg = (
            "SAFETY & ETHICS\n\n"
            "This toolkit is intended for educational and authorized penetration testing only.\n"
            "Do NOT use it against systems or networks without explicit written permission.\n\n"
            "Modules are intentionally non-destructive and include checks to reduce abuse.\n\n"
            "By checking the authorization box you confirm you have permission to test targets."
        )
        messagebox.showinfo("Usage / Safety", msg)

    # ---------- Port tab ----------
    def build_port_tab(self):
        frm = self.port_tab
        left = ttk.Frame(frm, padding=8)
        left.pack(side=tk.LEFT, fill=tk.Y)

        ttk.Label(left, text="Target Hostname / IP:").pack(anchor='w')
        self.port_host = ttk.Entry(left, width=28)
        self.port_host.pack(anchor='w', pady=(0,8))
        ttk.Label(left, text="Port Range (e.g. 1-1024):").pack(anchor='w')
        self.port_range = ttk.Entry(left, width=28)
        self.port_range.insert(0, "1-1024")
        self.port_range.pack(anchor='w', pady=(0,8))
        ttk.Label(left, text="Timeout (seconds):").pack(anchor='w')
        self.port_timeout = ttk.Entry(left, width=10)
        self.port_timeout.insert(0, "0.7")
        self.port_timeout.pack(anchor='w', pady=(0,8))

        scan_btn = ttk.Button(left, text="Start Scan", command=self.start_port_scan)
        scan_btn.pack(anchor='w', pady=(6,0))

        stop_btn = ttk.Button(left, text="Stop Scan", command=self.stop_port_scan)
        stop_btn.pack(anchor='w', pady=(4,0))

        # Right: results
        right = ttk.Frame(frm, padding=8)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        ttk.Label(right, text="Scan Results:").pack(anchor='w')
        self.port_results = scrolledtext.ScrolledText(right, state='disabled')
        self.port_results.pack(fill=tk.BOTH, expand=True)

        # scanning control
        self._scan_thread = None
        self._scan_stop = threading.Event()

    def start_port_scan(self):
        if not has_authorization(self.auth_var):
            messagebox.showwarning("Authorization required", "You must confirm you have authorization to run scans.")
            return

        host = self.port_host.get().strip()
        port_range_str = self.port_range.get().strip()
        try:
            timeout = float(self.port_timeout.get().strip())
        except ValueError:
            timeout = 0.7

        if not host:
            messagebox.showerror("Input error", "Please enter a target hostname or IP.")
            return

        try:
            rparts = port_range_str.split('-')
            start = int(rparts[0])
            end = int(rparts[1]) if len(rparts) > 1 else start
            if start < 0 or end > 65535 or start > end:
                raise ValueError
        except Exception:
            messagebox.showerror("Input error", "Invalid port range. Use format start-end (e.g. 1-1024).")
            return

        # start thread
        self._scan_stop.clear()
        self.port_results.configure(state='normal')
        self.port_results.delete(1.0, tk.END)
        self.port_results.configure(state='disabled')
        safe_log(self.log, f"Starting port scan on {host} ports {start}-{end} (timeout {timeout}s)")
        self._scan_thread = threading.Thread(target=self._port_scan_worker, args=(host, start, end, timeout), daemon=True)
        self._scan_thread.start()

    def stop_port_scan(self):
        if self._scan_thread and self._scan_thread.is_alive():
            self._scan_stop.set()
            safe_log(self.log, "Stop requested for port scan.")
        else:
            safe_log(self.log, "No active port scan to stop.")

    def _port_scan_worker(self, host, start, end, timeout):
        q = Queue()
        # simple thread pool for concurrency
        def worker():
            while not self._scan_stop.is_set():
                try:
                    port = q.get_nowait()
                except:
                    return
                openp = tcp_connect_scan(host, port, timeout=timeout)
                if openp:
                    self.port_results.configure(state='normal')
                    self.port_results.insert(tk.END, f"Port {port}: OPEN\n")
                    self.port_results.configure(state='disabled')
                    safe_log(self.log, f"Found OPEN port {port} on {host}")
                q.task_done()

        # enqueue ports
        for p in range(start, end+1):
            q.put(p)
        # spawn a small pool
        threads = []
        pool_size = min(80, (end-start+1))
        for _ in range(pool_size):
            t = threading.Thread(target=worker, daemon=True)
            threads.append(t)
            t.start()

        q.join()
        safe_log(self.log, f"Port scan finished for {host}.")

    # ---------- Banner tab ----------
    def build_banner_tab(self):
        frm = self.banner_tab
        left = ttk.Frame(frm, padding=8)
        left.pack(side=tk.LEFT, fill=tk.Y)
        ttk.Label(left, text="Target Hostname / IP:").pack(anchor='w')
        self.banner_host = ttk.Entry(left, width=28)
        self.banner_host.pack(anchor='w', pady=(0,8))
        ttk.Label(left, text="Port:").pack(anchor='w')
        self.banner_port = ttk.Entry(left, width=10)
        self.banner_port.insert(0, "80")
        self.banner_port.pack(anchor='w', pady=(0,8))
        grab_btn = ttk.Button(left, text="Grab Banner", command=self.do_banner_grab)
        grab_btn.pack(anchor='w', pady=(6,0))

        right = ttk.Frame(frm, padding=8)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        ttk.Label(right, text="Banner Output:").pack(anchor='w')
        self.banner_out = scrolledtext.ScrolledText(right, state='disabled')
        self.banner_out.pack(fill=tk.BOTH, expand=True)

    def do_banner_grab(self):
        if not has_authorization(self.auth_var):
            messagebox.showwarning("Authorization required", "You must confirm you have authorization to run banner grabs.")
            return
        host = self.banner_host.get().strip()
        try:
            port = int(self.banner_port.get().strip())
        except ValueError:
            messagebox.showerror("Input error", "Enter a valid port number.")
            return
        self.banner_out.configure(state='normal')
        self.banner_out.delete(1.0, tk.END)
        self.banner_out.configure(state='disabled')
        safe_log(self.log, f"Grabbing banner from {host}:{port}")
        def bg():
            b = banner_grab(host, port)
            self.banner_out.configure(state='normal')
            self.banner_out.insert(tk.END, f"Banner for {host}:{port} ->\n{b}\n")
            self.banner_out.configure(state='disabled')
            safe_log(self.log, f"Banner grabbed from {host}:{port}")
        threading.Thread(target=bg, daemon=True).start()

    # ---------- Ping tab ----------
    def build_ping_tab(self):
        frm = self.ping_tab
        top = ttk.Frame(frm, padding=8)
        top.pack(side=tk.TOP, fill=tk.X)
        ttk.Label(top, text="Host to ping:").pack(anchor='w')
        self.ping_host = ttk.Entry(top, width=28)
        self.ping_host.pack(anchor='w', pady=(0,8))
        ttk.Label(top, text="Count:").pack(anchor='w')
        self.ping_count = ttk.Entry(top, width=8)
        self.ping_count.insert(0, "4")
        self.ping_count.pack(anchor='w', pady=(0,8))
        ping_btn = ttk.Button(top, text="Run Ping", command=self.run_ping_action)
        ping_btn.pack(anchor='w', pady=(4,0))

        self.ping_out = scrolledtext.ScrolledText(frm, state='disabled')
        self.ping_out.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

    def run_ping_action(self):
        host = self.ping_host.get().strip()
        try:
            count = int(self.ping_count.get().strip())
        except ValueError:
            count = 4
        if not host:
            messagebox.showerror("Input error", "Provide a host to ping.")
            return
        self.ping_out.configure(state='normal')
        self.ping_out.delete(1.0, tk.END)
        self.ping_out.configure(state='disabled')
        safe_log(self.log, f"Pinging {host} ({count} packets)")
        def bg():
            res = run_ping(host, count=count)
            self.ping_out.configure(state='normal')
            self.ping_out.insert(tk.END, res)
            self.ping_out.configure(state='disabled')
            safe_log(self.log, f"Ping finished for {host}")
        threading.Thread(target=bg, daemon=True).start()

    # ---------- Password Auditor tab ----------
    def build_pw_tab(self):
        frm = self.pw_tab
        left = ttk.Frame(frm, padding=8)
        left.pack(side=tk.LEFT, fill=tk.Y)

        ttk.Label(left, text="Mode:").pack(anchor='w')
        self.pw_mode = tk.StringVar(value='strength')
        ttk.Radiobutton(left, text="Strength check (local password)", variable=self.pw_mode, value='strength').pack(anchor='w')
        ttk.Radiobutton(left, text="Wordlist hash-check (local only)", variable=self.pw_mode, value='hashcheck').pack(anchor='w')

        ttk.Label(left, text="Password (for strength):").pack(anchor='w', pady=(6,0))
        self.pw_entry = ttk.Entry(left, width=30, show='*')
        self.pw_entry.pack(anchor='w', pady=(0,8))

        ttk.Label(left, text="Or select hash file and wordlist (for hashcheck):").pack(anchor='w')
        self.hashfile_btn = ttk.Button(left, text="Select file with hashes", command=self.select_hash_file)
        self.hashfile_btn.pack(anchor='w', pady=(4,2))
        self.hashfile_lbl = ttk.Label(left, text="No file selected")
        self.hashfile_lbl.pack(anchor='w')

        self.wordlist_btn = ttk.Button(left, text="Select wordlist", command=self.select_wordlist)
        self.wordlist_btn.pack(anchor='w', pady=(4,2))
        self.wordlist_lbl = ttk.Label(left, text="No wordlist selected")
        self.wordlist_lbl.pack(anchor='w')

        run_btn = ttk.Button(left, text="Run Auditor", command=self.run_pw_audit)
        run_btn.pack(anchor='w', pady=(8,0))

        right = ttk.Frame(frm, padding=8)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        ttk.Label(right, text="Password Auditor Output:").pack(anchor='w')
        self.pw_out = scrolledtext.ScrolledText(right, state='disabled')
        self.pw_out.pack(fill=tk.BOTH, expand=True)

        self.hash_file = None
        self.wordlist_file = None

    def select_hash_file(self):
        p = filedialog.askopenfilename(title="Select file containing hashes (one per line)")
        if p:
            self.hash_file = p
            self.hashfile_lbl.config(text=os.path.basename(p))

    def select_wordlist(self):
        p = filedialog.askopenfilename(title="Select wordlist file (one password per line)")
        if p:
            self.wordlist_file = p
            self.wordlist_lbl.config(text=os.path.basename(p))

    def run_pw_audit(self):
        mode = self.pw_mode.get()
        if mode == 'strength':
            pw = self.pw_entry.get()
            if not pw:
                messagebox.showerror("Input error", "Enter a password for strength check.")
                return
            score = check_password_strength(pw)
            msg = f"Password strength score (0-4): {score}\n"
            if score < 3:
                msg += "Recommendation: use >=12 chars, mix upper/lower, digits, symbols.\n"
            else:
                msg += "Password appears reasonably strong for basic use.\n"
            self.pw_out.configure(state='normal')
            self.pw_out.insert(tk.END, msg + "\n")
            self.pw_out.configure(state='disabled')
            safe_log(self.log, "Password strength check performed locally.")
        else:
            if not self.hash_file or not self.wordlist_file:
                messagebox.showerror("Input error", "Select both a hash file and a wordlist file for hash-check mode.")
                return
            # Hash-check: supports SHA256 lines in hash_file; compares wordlist hashed to find matches.
            self.pw_out.configure(state='normal')
            self.pw_out.delete(1.0, tk.END)
            self.pw_out.configure(state='disabled')
            safe_log(self.log, f"Starting local hash-check: hashes={self.hash_file}, wordlist={self.wordlist_file}")
            def bg():
                try:
                    with open(self.hash_file, 'r') as hf:
                        target_hashes = {line.strip().lower() for line in hf if line.strip()}
                    found = []
                    total = 0
                    with open(self.wordlist_file, 'r', errors='ignore') as wf:
                        for line in wf:
                            pw = line.rstrip('\n')
                            total += 1
                            h = hashlib.sha256(pw.encode()).hexdigest()
                            if h in target_hashes:
                                found.append((pw, h))
                    self.pw_out.configure(state='normal')
                    self.pw_out.insert(tk.END, f"Checked {total} candidates. Matches found: {len(found)}\n")
                    for pw, h in found:
                        self.pw_out.insert(tk.END, f"MATCH: '{pw}' -> {h}\n")
                    self.pw_out.configure(state='disabled')
                    safe_log(self.log, f"Local hash-check finished. {len(found)} matches.")
                except Exception as e:
                    self.pw_out.configure(state='normal')
                    self.pw_out.insert(tk.END, f"Error during hash-check: {e}\n")
                    self.pw_out.configure(state='disabled')
                    safe_log(self.log, f"Hash-check error: {e}")
            threading.Thread(target=bg, daemon=True).start()

# ---------- Main ----------
def main():
    app = PentoolGUI()
    app.mainloop()

if __name__ == "__main__":
    main()
