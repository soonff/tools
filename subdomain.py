#!/usr/bin/env python3
"""
subdomain_gui.py

A fast GUI multi-tool subdomain enumerator for Kali/Ubuntu:
 - Runs available local tools: amass, subfinder, assetfinder, sublist3r (if on PATH)
 - Adds crt.sh passive lookups
 - Concurrent DNS resolution (optional)
 - Marks "interesting" subdomains automatically
 - Saves results to <domain>.txt

Usage:
  pip3 install requests
  python3 subdomain_gui.py
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import concurrent.futures
import subprocess
import shutil
import re
import socket
import queue
import time
import requests
from urllib.parse import quote_plus

# ---------- Config / heuristics ----------
FAST_DEFAULT_TIMEOUT = 60         # seconds per external tool in fast mode
SLOW_DEFAULT_TIMEOUT = 180
DEFAULT_THREADS = 30

INTERESTING_KEYWORDS = [
    "admin", "login", "panel", "wp-admin", "cpanel", "mail", "imap", "smtp",
    "vpn", "remote", "db", "database", "api", "auth", "git", "gitlab", "gitweb",
    "staging", "dev", "test", "backup", "smtp", "secure", "portal", "backend"
]

# ---------- Helpers ----------
def which(name: str):
    return shutil.which(name)

def run_cmd(cmd, timeout):
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        out = proc.stdout or ""
        err = proc.stderr or ""
        return out + ("\n" + err if err else "")
    except subprocess.TimeoutExpired:
        return ""
    except FileNotFoundError:
        return ""
    except Exception:
        return ""

def extract_names(text: str, domain: str):
    """Extract hostname-like tokens that end with domain from arbitrary text."""
    if not text:
        return set()
    pattern = re.compile(r"([a-z0-9\-\._]*\." + re.escape(domain) + r")", re.IGNORECASE)
    found = set()
    for m in pattern.finditer(text):
        name = m.group(1).strip().lower().lstrip("*.") 
        if name.endswith(domain):
            # basic sanitation
            if re.match(r"^[a-z0-9\-\._]+\." + re.escape(domain) + r"$", name):
                found.add(name)
    return found

def crtsh_lookup(domain: str):
    results = set()
    try:
        q = quote_plus(f"%.{domain}")
        url = f"https://crt.sh/?q={q}&output=json"
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            try:
                data = r.json()
                for item in data:
                    nv = item.get("name_value") or item.get("common_name") or ""
                    for n in str(nv).splitlines():
                        n = n.strip().lower().lstrip("*.")
                        if n.endswith(domain):
                            results.add(n)
            except ValueError:
                pass
    except Exception:
        pass
    return results

def resolve_host(host: str, timeout=3.0):
    try:
        socket.getaddrinfo(host, None)
        return True
    except Exception:
        return False

def mark_interesting(name: str):
    for kw in INTERESTING_KEYWORDS:
        if kw in name:
            return True
    return False

# ---------- Worker thread logic ----------
class Enumerator:
    def __init__(self, domain, use_tools, timeout, threads, resolve, q_log, q_result):
        self.domain = domain
        self.use_tools = use_tools  # dict of toolname->bool
        self.timeout = timeout
        self.threads = threads
        self.resolve = resolve
        self.q_log = q_log
        self.q_result = q_result
        self.found = set()
        self.lock = threading.Lock()

    def log(self, msg):
        self.q_log.put(msg)

    def add_results(self, names):
        with self.lock:
            new = names - self.found
            if new:
                for n in sorted(new):
                    self.q_result.put(("found", n))
                self.found.update(new)
                self.log(f"[+] Added {len(new)} new names (total {len(self.found)})")

    def run_tool(self, name, func):
        self.log(f"[~] Running {name}...")
        try:
            names = func(self.domain, self.timeout)
            self.add_results(names)
            self.log(f"[~] {name} finished: {len(names)} found")
        except Exception as e:
            self.log(f"[!] {name} error: {e}")

    def run_amass(self, domain, timeout):
        if not which("amass"):
            return set()
        cmd = ["amass", "enum", "-passive", "-d", domain]
        out = run_cmd(cmd, timeout)
        return extract_names(out, domain)

    def run_subfinder(self, domain, timeout):
        if not which("subfinder"):
            return set()
        cmd = ["subfinder", "-silent", "-d", domain]
        out = run_cmd(cmd, timeout)
        return extract_names(out, domain)

    def run_assetfinder(self, domain, timeout):
        if not which("assetfinder"):
            return set()
        cmd = ["assetfinder", "--subs-only", domain]
        out = run_cmd(cmd, timeout)
        return extract_names(out, domain)

    def run_sublist3r(self, domain, timeout):
        if not which("sublist3r"):
            return set()
        cmd = ["sublist3r", "-d", domain, "-o", "-"]
        out = run_cmd(cmd, timeout)
        return extract_names(out, domain)

    def run_crtsh(self):
        self.log("[~] Querying crt.sh (fast passive)...")
        names = crtsh_lookup(self.domain)
        self.add_results(names)

    def run_all(self):
        # start crt.sh immediately (fast)
        t_crt = threading.Thread(target=self.run_crtsh, daemon=True)
        t_crt.start()

        # prepare tool functions mapping
        tool_funcs = []
        if self.use_tools.get("amass"):
            tool_funcs.append(("amass", self.run_amass))
        if self.use_tools.get("subfinder"):
            tool_funcs.append(("subfinder", self.run_subfinder))
        if self.use_tools.get("assetfinder"):
            tool_funcs.append(("assetfinder", self.run_assetfinder))
        if self.use_tools.get("sublist3r"):
            tool_funcs.append(("sublist3r", self.run_sublist3r))

        # run external tools concurrently with ThreadPoolExecutor
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(tool_funcs))) as exe:
            futures = []
            for name, func in tool_funcs:
                futures.append(exe.submit(self.run_tool, name, func))
            # wait for tools to finish (they'll push results to queue as they find them)
            for fut in concurrent.futures.as_completed(futures):
                pass

        # optionally resolve found hosts concurrently to filter live ones
        if self.resolve:
            self.log("[~] Resolving hostnames (concurrent)...")
            resolved = set()
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as exe:
                future_map = {exe.submit(resolve_host, n): n for n in list(self.found)}
                for fut in concurrent.futures.as_completed(future_map):
                    name = future_map[fut]
                    try:
                        ok = fut.result()
                        if ok:
                            resolved.add(name)
                            self.q_result.put(("resolved", name))
                    except Exception:
                        pass
            # replace found with resolved
            with self.lock:
                self.found = resolved
            self.log(f"[+] Resolution finished. Resolvable: {len(resolved)}")

        # final push of summary
        self.q_result.put(("done", len(self.found)))
        self.log("[+] Enumeration complete.")

# ---------- GUI ----------
class SubGUI:
    def __init__(self, root):
        self.root = root
        root.title("SubLister GUI — fast multi-tool subdomain enumerator")
        root.geometry("920x620")
        self.q_log = queue.Queue()
        self.q_result = queue.Queue()
        self.enumerator_thread = None
        self.enumerator = None
        self.stop_event = threading.Event()

        # Top frame: inputs
        top = ttk.Frame(root, padding=10)
        top.pack(fill=tk.X)

        ttk.Label(top, text="Domain:").pack(side=tk.LEFT)
        self.entry_domain = ttk.Entry(top, width=32)
        self.entry_domain.pack(side=tk.LEFT, padx=(5, 10))
        self.entry_domain.insert(0, "")

        self.var_resolve = tk.BooleanVar(value=True)
        ttk.Checkbutton(top, text="Resolve (filter live)", variable=self.var_resolve).pack(side=tk.LEFT, padx=5)

        ttk.Label(top, text="Timeout/tool(s):").pack(side=tk.LEFT, padx=(10,5))
        self.timeout_var = tk.IntVar(value=FAST_DEFAULT_TIMEOUT)
        self.timeout_spin = ttk.Spinbox(top, from_=10, to=600, increment=10, width=6, textvariable=self.timeout_var)
        self.timeout_spin.pack(side=tk.LEFT)

        ttk.Label(top, text="Threads:").pack(side=tk.LEFT, padx=(10,2))
        self.threads_var = tk.IntVar(value=DEFAULT_THREADS)
        self.threads_spin = ttk.Spinbox(top, from_=2, to=200, increment=2, width=6, textvariable=self.threads_var)
        self.threads_spin.pack(side=tk.LEFT)

        # Tools checkboxes
        tools_frame = ttk.Frame(root, padding=(10,0))
        tools_frame.pack(fill=tk.X)
        ttk.Label(tools_frame, text="Use tools (only if installed):").pack(side=tk.LEFT)
        self.tool_vars = {
            "amass": tk.BooleanVar(value=bool(which("amass"))),
            "subfinder": tk.BooleanVar(value=bool(which("subfinder"))),
            "assetfinder": tk.BooleanVar(value=bool(which("assetfinder"))),
            "sublist3r": tk.BooleanVar(value=bool(which("sublist3r"))),
        }
        for k,v in self.tool_vars.items():
            ttk.Checkbutton(tools_frame, text=k, variable=v).pack(side=tk.LEFT, padx=6)

        # Buttons
        btn_frame = ttk.Frame(root, padding=10)
        btn_frame.pack(fill=tk.X)
        self.btn_start = ttk.Button(btn_frame, text="Start", command=self.start)
        self.btn_start.pack(side=tk.LEFT)
        self.btn_stop = ttk.Button(btn_frame, text="Stop", command=self.stop, state=tk.DISABLED)
        self.btn_stop.pack(side=tk.LEFT, padx=6)
        self.btn_save = ttk.Button(btn_frame, text="Save results", command=self.save_results, state=tk.DISABLED)
        self.btn_save.pack(side=tk.LEFT, padx=6)
        self.btn_clear = ttk.Button(btn_frame, text="Clear", command=self.clear_all)
        self.btn_clear.pack(side=tk.LEFT, padx=6)

        # Main panes: log (left) and results (right)
        main_panes = ttk.Panedwindow(root, orient=tk.HORIZONTAL)
        main_panes.pack(fill=tk.BOTH, expand=True, padx=10, pady=6)

        # left: log
        log_frame = ttk.Labelframe(main_panes, text="Progress & Log", width=420)
        self.text_log = tk.Text(log_frame, height=30, wrap=tk.NONE)
        self.text_log.pack(fill=tk.BOTH, expand=True)
        main_panes.add(log_frame, weight=1)

        # right: results + interesting
        right_frame = ttk.Frame(main_panes, width=420)
        # results list
        res_frame = ttk.Labelframe(right_frame, text="Found subdomains")
        res_frame.pack(fill=tk.BOTH, expand=True)
        self.list_results = tk.Listbox(res_frame)
        self.list_results.pack(fill=tk.BOTH, expand=True)
        # interesting
        int_frame = ttk.Labelframe(right_frame, text="Interesting (auto-detected)")
        int_frame.pack(fill=tk.BOTH)
        self.list_interesting = tk.Listbox(int_frame, height=8)
        self.list_interesting.pack(fill=tk.BOTH, expand=True)
        main_panes.add(right_frame, weight=1)

        # status bar
        self.status_var = tk.StringVar(value="Idle")
        status = ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status.pack(fill=tk.X, side=tk.BOTTOM)

        # schedule periodic GUI update from queues
        self.root.after(200, self.process_queues)

    def log(self, msg):
        timestamp = time.strftime("%H:%M:%S")
        self.text_log.insert(tk.END, f"[{timestamp}] {msg}\n")
        self.text_log.see(tk.END)

    def add_result(self, name, resolved=False):
        # avoid duplicates visually
        items = set(self.list_results.get(0, tk.END))
        if name not in items:
            self.list_results.insert(tk.END, name)
        # interesting?
        if mark_interesting(name):
            if name not in set(self.list_interesting.get(0, tk.END)):
                self.list_interesting.insert(tk.END, name)
        # update status
        self.status_var.set(f"Found: {self.list_results.size()}  Interesting: {self.list_interesting.size()}")

    def process_queues(self):
        # process log queue
        while not self.q_log.empty():
            try:
                msg = self.q_log.get_nowait()
                self.log(msg)
            except queue.Empty:
                break
        # process result queue
        while not self.q_result.empty():
            try:
                typ, payload = self.q_result.get_nowait()
                if typ == "found":
                    self.add_result(payload)
                elif typ == "resolved":
                    # mark visually (prefix)
                    # keep original entry if present, but we can add star
                    self.add_result(payload, resolved=True)
                elif typ == "done":
                    total = payload
                    self.btn_stop.config(state=tk.DISABLED)
                    self.btn_start.config(state=tk.NORMAL)
                    self.btn_save.config(state=tk.NORMAL)
                    self.status_var.set(f"Done. Total: {total}")
                else:
                    self.log(f"Queue: {typ} -> {payload}")
            except queue.Empty:
                break
        # re-schedule
        self.root.after(200, self.process_queues)

    def start(self):
        domain = self.entry_domain.get().strip().lower()
        if not domain:
            messagebox.showwarning("No domain", "Please enter a domain (e.g. example.com).")
            return
        # disable UI bits
        self.btn_start.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.btn_save.config(state=tk.DISABLED)
        self.status_var.set("Running...")
        # prepare enumerator
        use_tools = {k: v.get() for k, v in self.tool_vars.items()}
        timeout = int(self.timeout_var.get())
        threads = int(self.threads_var.get())
        resolve = bool(self.var_resolve.get())
        self.enumerator = Enumerator(domain, use_tools, timeout, threads, resolve, self.q_log, self.q_result)
        # clear previous lists
        self.list_results.delete(0, tk.END)
        self.list_interesting.delete(0, tk.END)
        # start in background
        self.enumerator_thread = threading.Thread(target=self.enumerator.run_all, daemon=True)
        self.enumerator_thread.start()
        self.log(f"[+] Started enumeration for {domain}")

    def stop(self):
        # not a perfect stop (we didn't implement cancellable subprocess); best-effort
        if messagebox.askyesno("Stop", "Stop the enumeration? Running tools may still finish or timeout."):
            self.btn_stop.config(state=tk.DISABLED)
            self.btn_start.config(state=tk.NORMAL)
            self.status_var.set("Stopping... (tools will timeout soon)")
            self.log("[!] Stop requested; tools will be allowed to timeout or finish.")
            # We intentionally don't kill external tools here to avoid orphan processes on the system.
            # You can manually kill known tool PIDs if needed.
            self.btn_save.config(state=tk.NORMAL)

    def save_results(self):
        domain = self.entry_domain.get().strip().lower()
        if not domain:
            return
        # default filename domain.txt (user may choose folder)
        default_name = f"{domain}.txt"
        file = filedialog.asksaveasfilename(defaultextension=".txt", initialfile=default_name,
                                            filetypes=[("Text files","*.txt"),("All files","*.*")])
        if not file:
            return
        items = list(self.list_results.get(0, tk.END))
        try:
            with open(file, "w", encoding="utf-8") as f:
                for it in items:
                    f.write(it + "\n")
            messagebox.showinfo("Saved", f"Saved {len(items)} entries to:\n{file}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save: {e}")

    def clear_all(self):
        self.list_results.delete(0, tk.END)
        self.list_interesting.delete(0, tk.END)
        self.text_log.delete(1.0, tk.END)
        self.status_var.set("Idle")

# ---------- main ----------
def main():
    root = tk.Tk()
    app = SubGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()

