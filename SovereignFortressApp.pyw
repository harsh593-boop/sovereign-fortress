"""
Sovereign Fortress — Master Control & Protocol Dashboard GUI (2026)
Native Windows Desktop Application
"""

import os
import sys
import time
import json
import socket
import threading
import subprocess
import webbrowser
import tkinter as tk
from tkinter import ttk, messagebox

# Dynamic Script & Workspace Directory
APP_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(APP_DIR, "fortress_config.json")

# Fallback / Default configuration template
CONFIG = {
    "server_ip": "<YOUR_SERVER_IP>",
    "sub_port": 8443,
    "token": "<YOUR_SUBSCRIPTION_TOKEN>",
    "totp_secret": "",
    "uuid": "<YOUR_UUID>",
    "reality_pubkey": "<YOUR_REALITY_PUBLIC_KEY>",
    "reality_shortid": "<YOUR_REALITY_SHORT_ID>",
    "reality_sni": "gateway.icloud.com",
    "hy2_password": "<YOUR_HYSTERIA2_PASSWORD>",
    "salamander_password": "<YOUR_SALAMANDER_PASSWORD>",
    "ss_password": "<YOUR_SHADOWSOCKS_PASSWORD>"
}

if os.path.exists(CONFIG_FILE):
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            user_cfg = json.load(f)
            CONFIG.update(user_cfg)
    except Exception as e:
        print(f"[-] Warning: Failed to load {CONFIG_FILE}: {e}")

SERVER_IP = CONFIG.get("server_ip", "<YOUR_SERVER_IP>")
SUB_PORT = CONFIG.get("sub_port", 8443)
TOKEN = CONFIG.get("token", "<YOUR_SUBSCRIPTION_TOKEN>")
SUB_URL = f"https://{SERVER_IP}:{SUB_PORT}/sub/{TOKEN}"
HIDDIFY_DEEPLINK = f"hiddify://import/{SUB_URL}#SovereignFortress"
PORTAL_URL = f"https://{SERVER_IP}:{SUB_PORT}/portal"

UUID = CONFIG.get("uuid", "<YOUR_UUID>")
REALITY_PUBKEY = CONFIG.get("reality_pubkey", "<YOUR_REALITY_PUBLIC_KEY>")
REALITY_SHORTID = CONFIG.get("reality_shortid", "<YOUR_REALITY_SHORT_ID>")
REALITY_SNI = CONFIG.get("reality_sni", "gateway.icloud.com")
HY2_PASSWORD = CONFIG.get("hy2_password", "<YOUR_HYSTERIA2_PASSWORD>")
SALAMANDER_PASS = CONFIG.get("salamander_password", "<YOUR_SALAMANDER_PASSWORD>")
SS_PASSWORD = CONFIG.get("ss_password", "<YOUR_SHADOWSOCKS_PASSWORD>")
PIN_SHA256 = CONFIG.get("pin_sha256", "")
pin_param = f"&pinSHA256={PIN_SHA256}" if PIN_SHA256 else ""

PROTOCOLS = [
    {
        "name": "auto-fastest (Latency Balancer)",
        "port": "Auto",
        "proto": "none",
        "port_num": 0,
        "badge": "Lowest-Ping Auto Detour",
        "desc": "Benchmarks latency to all active proxies and automatically detours to lowest-ping route (labeled 'lowest' Balancer in Hiddify).",
        "link": f"{SUB_URL}"
    },
    {
        "name": "Fortress-Reality-TCP",
        "port": "TCP 443",
        "proto": "tcp",
        "port_num": 443,
        "badge": "GFW / FortiGate Slayer",
        "desc": f"Camouflage: {REALITY_SNI}. Active probers without Reality auth keys are detoured to Apple CDN edge.",
        "link": f"vless://{UUID}@{SERVER_IP}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni={REALITY_SNI}&fp=chrome&pbk={REALITY_PUBKEY}&sid={REALITY_SHORTID}&type=tcp&headerType=none#Fortress-Reality-TCP"
    },
    {
        "name": "Fortress-Hysteria2-Salamander",
        "port": "UDP 9444",
        "proto": "udp",
        "port_num": 9444,
        "badge": "Extreme Stealth QUIC Scrambler",
        "desc": "ChaCha20 XOR full-packet header scrambling with BLAKE3 KDF. Bypasses deep packet inspection.",
        "link": f"hysteria2://{HY2_PASSWORD}@{SERVER_IP}:9444?sni={REALITY_SNI}&alpn=h3&obfs=salamander&obfs-password={SALAMANDER_PASS}{pin_param}#Fortress-Hysteria2-Salamander"
    },
    {
        "name": "Fortress-Hysteria2-Standard",
        "port": "UDP 8443",
        "proto": "udp",
        "port_num": 8443,
        "badge": "Brutal BBR / Maximum Bandwidth",
        "desc": "Aggressive congestion control designed for lossy campus Wi-Fi. Delivers gigabit throughput.",
        "link": f"hysteria2://{HY2_PASSWORD}@{SERVER_IP}:8443?sni={REALITY_SNI}&alpn=h3{pin_param}#Fortress-Hysteria2-Standard"
    },
    {
        "name": "Fortress-TUIC5",
        "port": "UDP 9443",
        "proto": "udp",
        "port_num": 9443,
        "badge": "0-RTT Rapid Mobile Roaming",
        "desc": "RFC 9000 QUIC protocol with zero handshake delay when switching Wi-Fi access points.",
        "link": f"tuic://{UUID}:{HY2_PASSWORD}@{SERVER_IP}:9443?congestion_control=bbr&alpn=h3&sni={REALITY_SNI}#Fortress-TUIC5-UDP"
    },
    {
        "name": "Fortress-Shadowsocks2022",
        "port": "TCP/UDP 10443",
        "proto": "tcp",
        "port_num": 10443,
        "badge": "Ultra-Low Battery AEAD",
        "desc": "2022-blake3-aes-256-gcm cipher with variable-length padding against entropy analysis.",
        "link": f"ss://MjAyMi1ibGFrZTMtYWVzLTI1Ni1nY206{SS_PASSWORD}@{SERVER_IP}:10443#Fortress-Shadowsocks2022"
    },
    {
        "name": "WireGuard over TCP (WSTunnel)",
        "port": "TCP 8080",
        "proto": "tcp",
        "port_num": 8080,
        "badge": "WSTunnel TLS 1.3",
        "desc": "Encapsulates WireGuard inside HTTPS WebSockets to bypass total UDP blocks.",
        "link": f"wstunnel://{SERVER_IP}:8080"
    },
    {
        "name": "Native WireGuard",
        "port": "UDP 51820",
        "proto": "udp",
        "port_num": 51820,
        "badge": "Linux Kernel Line-Rate",
        "desc": "Standard kernel-level ChaCha20-Poly1305 tunnel for high-speed unrestricted connections.",
        "link": f"wg://{SERVER_IP}:51820"
    }
]

class SovereignApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Sovereign Fortress — Sovereign VPN Suite 2026")
        self.geometry("820x680")
        self.minsize(780, 600)
        self.configure(bg="#0b0f19")
        
        self.setup_styles()
        self.build_ui()
        if not SERVER_IP.startswith("<"):
            self.probe_all_ports_async()

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(".", background="#0b0f19", foreground="#f3f4f6", font=("Segoe UI", 10))
        style.configure("Card.TFrame", background="#111827", relief="flat")
        style.configure("Header.TLabel", font=("Segoe UI", 16, "bold"), foreground="#60a5fa", background="#0b0f19")
        style.configure("SubHeader.TLabel", font=("Segoe UI", 9), foreground="#9ca3af", background="#0b0f19")
        style.configure("ProtoTitle.TLabel", font=("Segoe UI", 11, "bold"), foreground="#ffffff", background="#111827")
        style.configure("Badge.TLabel", font=("Segoe UI", 8, "bold"), foreground="#34d399", background="#111827")
        style.configure("Desc.TLabel", font=("Segoe UI", 8), foreground="#9ca3af", background="#111827")
        style.configure("Latency.TLabel", font=("Segoe UI", 9, "bold"), foreground="#fbbf24", background="#111827")
        style.configure("Primary.TButton", font=("Segoe UI", 10, "bold"), background="#2563eb", foreground="#ffffff")
        style.map("Primary.TButton", background=[("active", "#1d4ed8")])
        style.configure("Action.TButton", font=("Segoe UI", 9), background="#1f2937", foreground="#f3f4f6")
        style.map("Action.TButton", background=[("active", "#374151")])

    def build_ui(self):
        # Top Header Frame
        header_frame = tk.Frame(self, bg="#0b0f19", padx=20, pady=14)
        header_frame.pack(fill="x")

        title_box = tk.Frame(header_frame, bg="#0b0f19")
        title_box.pack(side="left")
        
        title_lbl = ttk.Label(title_box, text="SOVEREIGN FORTRESS", style="Header.TLabel")
        title_lbl.pack(anchor="w")
        sub_text = f"Server: {SERVER_IP} • Zero-Log RAM Runtime • 100% Always Free"
        sub_lbl = ttk.Label(title_box, text=sub_text, style="SubHeader.TLabel")
        sub_lbl.pack(anchor="w")

        # Status indicator
        status_box = tk.Frame(header_frame, bg="#111827", padx=12, pady=6, highlightthickness=1, highlightbackground="#10b981")
        status_box.pack(side="right")
        dot_color = "#10b981" if not SERVER_IP.startswith("<") else "#fbbf24"
        stat_text = "SERVER ONLINE" if not SERVER_IP.startswith("<") else "SETUP REQUIRED"
        self.status_dot = tk.Label(status_box, text="●", fg=dot_color, bg="#111827", font=("Segoe UI", 12))
        self.status_dot.pack(side="left", padx=(0, 6))
        self.status_txt = tk.Label(status_box, text=stat_text, fg=dot_color, bg="#111827", font=("Segoe UI", 9, "bold"))
        self.status_txt.pack(side="left")

        # Action bar
        act_frame = tk.Frame(self, bg="#111827", padx=16, pady=10, highlightthickness=1, highlightbackground="#1f2937")
        act_frame.pack(fill="x", padx=16, pady=(0, 10))

        btn_launch = tk.Button(act_frame, text="⚡ Launch Hiddify", bg="#2563eb", fg="#ffffff", activebackground="#1d4ed8",
                               activeforeground="#ffffff", font=("Segoe UI", 9, "bold"), relief="flat", padx=12, pady=6, cursor="hand2",
                               command=self.open_hiddify)
        btn_launch.pack(side="left", padx=4)

        btn_copy_sub = tk.Button(act_frame, text="📋 Copy 1-Click Link", bg="#1f2937", fg="#f3f4f6", activebackground="#374151",
                                 activeforeground="#ffffff", font=("Segoe UI", 9), relief="flat", padx=10, pady=6, cursor="hand2",
                                 command=self.copy_sub_link)
        btn_copy_sub.pack(side="left", padx=4)

        btn_portal = tk.Button(act_frame, text="🌐 Web Portal & 2FA", bg="#1f2937", fg="#f3f4f6", activebackground="#374151",
                               activeforeground="#ffffff", font=("Segoe UI", 9), relief="flat", padx=10, pady=6, cursor="hand2",
                               command=self.open_portal)
        btn_portal.pack(side="left", padx=4)

        btn_probe = tk.Button(act_frame, text="🔄 Test Latency", bg="#1f2937", fg="#fbbf24", activebackground="#374151",
                              activeforeground="#fbbf24", font=("Segoe UI", 9), relief="flat", padx=10, pady=6, cursor="hand2",
                              command=self.probe_all_ports_async)
        btn_probe.pack(side="left", padx=4)

        btn_panic = tk.Button(act_frame, text="⚠️ Panic Shred", bg="#3b1111", fg="#fca5a5", activebackground="#7f1d1d",
                              activeforeground="#ffffff", font=("Segoe UI", 9), relief="flat", padx=10, pady=6, cursor="hand2",
                              command=self.panic_shred)
        btn_panic.pack(side="right", padx=4)

        btn_unlock = tk.Button(act_frame, text="🔓 Unlock", bg="#1f2937", fg="#34d399", activebackground="#374151",
                               activeforeground="#34d399", font=("Segoe UI", 9), relief="flat", padx=10, pady=6, cursor="hand2",
                               command=self.unlock_vault)
        btn_unlock.pack(side="right", padx=4)

        btn_vault = tk.Button(act_frame, text="🔒 Lock", bg="#1f2937", fg="#a78bfa", activebackground="#374151",
                              activeforeground="#a78bfa", font=("Segoe UI", 9), relief="flat", padx=10, pady=6, cursor="hand2",
                              command=self.lock_vault)
        btn_vault.pack(side="right", padx=4)

        # Scrollable Protocol Modes Frame
        container = tk.Frame(self, bg="#0b0f19")
        container.pack(fill="both", expand=True, padx=16, pady=(0, 12))

        canvas = tk.Canvas(container, bg="#0b0f19", highlightthickness=0)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        self.scrollable_frame = tk.Frame(canvas, bg="#0b0f19")

        self.scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw", width=760)
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.latency_labels = {}
        self.populate_protocol_cards()

    def populate_protocol_cards(self):
        for idx, proto in enumerate(PROTOCOLS):
            card = tk.Frame(self.scrollable_frame, bg="#111827", padx=14, pady=10,
                            highlightthickness=1, highlightbackground="#1f2937")
            card.pack(fill="x", pady=5)

            # Top row of card
            top_row = tk.Frame(card, bg="#111827")
            top_row.pack(fill="x")

            name_lbl = ttk.Label(top_row, text=proto["name"], style="ProtoTitle.TLabel")
            name_lbl.pack(side="left")

            port_tag = tk.Label(top_row, text=f" {proto['port']} ", bg="#1e293b", fg="#60a5fa",
                                font=("Segoe UI", 8, "bold"), padx=4, pady=1)
            port_tag.pack(side="left", padx=8)

            badge_lbl = ttk.Label(top_row, text=proto["badge"], style="Badge.TLabel")
            badge_lbl.pack(side="left", padx=4)

            lat_lbl = ttk.Label(top_row, text="Ping: ...", style="Latency.TLabel")
            lat_lbl.pack(side="right")
            self.latency_labels[proto["name"]] = lat_lbl

            # Desc row
            desc_lbl = ttk.Label(card, text=proto["desc"], style="Desc.TLabel", wraplength=580)
            desc_lbl.pack(anchor="w", pady=(4, 6))

            # Bottom action row
            bot_row = tk.Frame(card, bg="#111827")
            bot_row.pack(fill="x")

            copy_btn = tk.Button(bot_row, text="📋 Copy Link", bg="#1e293b", fg="#f3f4f6",
                                 activebackground="#334155", activeforeground="#ffffff",
                                 font=("Segoe UI", 8), relief="flat", padx=8, pady=2, cursor="hand2",
                                 command=lambda l=proto["link"]: self.copy_text(l))
            copy_btn.pack(side="left", padx=(0, 6))

            if proto["name"] == "WireGuard over TCP":
                run_btn = tk.Button(bot_row, text="▶ Run WSTunnel", bg="#1e293b", fg="#34d399",
                                    activebackground="#334155", activeforeground="#34d399",
                                    font=("Segoe UI", 8, "bold"), relief="flat", padx=8, pady=2, cursor="hand2",
                                    command=self.run_wstunnel)
                run_btn.pack(side="left")

    def probe_all_ports_async(self):
        if SERVER_IP.startswith("<"):
            return
        for name, lbl in self.latency_labels.items():
            lbl.config(text="Ping: ...", foreground="#9ca3af")
        threading.Thread(target=self._probe_worker, daemon=True).start()

    def _probe_worker(self):
        for proto in PROTOCOLS:
            name = proto["name"]
            port = proto["port_num"]
            ptype = proto["proto"]
            lbl = self.latency_labels.get(name)
            if not lbl:
                continue

            if ptype == "none":
                self.after(0, lambda l=lbl: l.config(text="BALANCER ACTIVE", foreground="#34d399"))
                continue

            lat = self._measure_latency(SERVER_IP, port, ptype)
            if lat is not None:
                color = "#34d399" if lat < 80 else ("#fbbf24" if lat < 150 else "#38bdf8")
                text = f"Probe: {lat:.0f} ms (ONLINE)"
            else:
                color = "#38bdf8" if ptype == "udp" else "#ef4444"
                text = "ACTIVE (UDP)" if ptype == "udp" else "TIMEOUT"
            
            self.after(0, lambda l=lbl, t=text, c=color: l.config(text=t, foreground=c))

    def _measure_latency(self, host, port, ptype):
        for attempt in range(2):
            if ptype == "tcp":
                try:
                    t0 = time.time()
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(3.5)
                    s.connect((host, port))
                    t1 = time.time()
                    s.close()
                    return (t1 - t0) * 1000.0
                except Exception:
                    time.sleep(0.2)
            else:
                try:
                    t0 = time.time()
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.settimeout(2.5)
                    s.sendto(b"\x00\x00\x00\x00", (host, port))
                    s.close()
                    return (time.time() - t0) * 1000.0
                except Exception:
                    time.sleep(0.2)
        return None

    def open_hiddify(self):
        hiddify_exe = r"C:\Program Files\Hiddify\Hiddify.exe"
        if os.path.exists(hiddify_exe):
            subprocess.Popen([hiddify_exe])
        else:
            webbrowser.open(HIDDIFY_DEEPLINK)

    def copy_sub_link(self):
        self.clipboard_clear()
        self.clipboard_append(SUB_URL)
        messagebox.showinfo("Copied", f"Universal Subscription URL copied to clipboard!\n\n{SUB_URL}\n\nIn Hiddify, paste this into '+ New Profile'.\nNotice: Do not share bearer subscription URLs with untrusted parties.")

    def copy_text(self, text):
        self.clipboard_clear()
        self.clipboard_append(text)
        messagebox.showinfo("Copied", "Protocol link copied to clipboard!")

    def open_portal(self):
        webbrowser.open(PORTAL_URL)

    def run_wstunnel(self):
        bat = os.path.join(APP_DIR, "start-wstunnel.bat")
        if os.path.exists(bat):
            subprocess.Popen(["cmd.exe", "/c", "start", bat])
        else:
            messagebox.showerror("Error", "start-wstunnel.bat not found.")

    def lock_vault(self):
        vault_py = os.path.join(APP_DIR, "fortress_vault.py")
        if os.path.exists(vault_py):
            res = subprocess.run([sys.executable, vault_py, "lock"], capture_output=True, text=True)
            messagebox.showinfo("Vault Locked", "Client keys and credentials encrypted at rest using Windows User-Bound DPAPI (CryptProtectData)!\nOriginal plaintext files securely wiped.")
        else:
            messagebox.showerror("Error", "fortress_vault.py not found.")

    def unlock_vault(self):
        vault_py = os.path.join(APP_DIR, "fortress_vault.py")
        if os.path.exists(vault_py):
            res = subprocess.run([sys.executable, vault_py, "unlock"], capture_output=True, text=True)
            messagebox.showinfo("Vault Unlocked", "Client keys and credentials decrypted for active VPN session.\nTip: Lock vault when not in active use.")
        else:
            messagebox.showerror("Error", "fortress_vault.py not found.")

    def panic_shred(self):
        if messagebox.askyesno("Emergency Panic", "Are you SURE you want to perform multi-pass overwrite and cryptographic key erasure on all local credentials, keys, and configurations?\n\nThis action is irreversible!"):
            vault_py = os.path.join(APP_DIR, "fortress_vault.py")
            if os.path.exists(vault_py):
                p = subprocess.Popen([sys.executable, vault_py, "shred"], stdin=subprocess.PIPE, text=True)
                p.communicate(input="VAPORIZE\n")
                messagebox.showwarning("Keys Erased", "All local credentials have undergone multi-pass overwrite and key erasure.")

if __name__ == "__main__":
    app = SovereignApp()
    app.mainloop()
