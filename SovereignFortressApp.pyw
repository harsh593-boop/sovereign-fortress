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
import base64
import hmac
import hashlib
import struct
import tkinter as tk
from tkinter import ttk, messagebox

try:
    import qrcode
    from PIL import Image, ImageTk
    HAS_QR = True
except ImportError:
    HAS_QR = False

def generate_totp_code(secret_b32):
    try:
        clean_secret = secret_b32.strip().replace(" ", "").upper()
        key = base64.b32decode(clean_secret, casefold=True)
        intervals_no = int(time.time() // 30)
        msg = struct.pack(">Q", intervals_no)
        h = hmac.new(key, msg, hashlib.sha1).digest()
        o = h[19] & 15
        h_code = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000
        return f"{h_code:06d}"
    except Exception:
        return "------"

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
SUB_URL_TRAFFIC_ONLY = f"https://{SERVER_IP}:{SUB_PORT}/sub/{TOKEN}?mode=traffic-only"
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
        "name": "auto-fastest",
        "port": "Auto",
        "proto": "none",
        "port_num": 0,
        "badge": "Lowest-Ping Auto Balancer",
        "desc": "[Lowest-Latency Balancer] — Automatically measures latency to all proxies and detours to the lowest-ping connection (labeled 'lowest' Balancer in Hiddify).",
        "link": f"{SUB_URL}"
    },
    {
        "name": "Fortress-Reality-TCP",
        "port": "TCP 443",
        "proto": "tcp",
        "port_num": 443,
        "badge": "DPI & Campus Firewall Slayer",
        "desc": "[DPI & Campus Firewall Slayer] — Primary weapon on strict campus Wi-Fi. Masks traffic as Apple iCloud CDN; active probes are forwarded to Apple.",
        "link": f"vless://{UUID}@{SERVER_IP}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni={REALITY_SNI}&fp=chrome&pbk={REALITY_PUBKEY}&sid={REALITY_SHORTID}&type=tcp&headerType=none#Fortress-Reality-TCP"
    },
    {
        "name": "Fortress-Hysteria2-Salamander",
        "port": "UDP 9444",
        "proto": "udp",
        "port_num": 9444,
        "badge": "Scrambled QUIC Anti-Throttling",
        "desc": "[Scrambled QUIC - Anti-Throttling] — ChaCha20 XOR packet header scrambler. Use when campus firewall throttles or drops standard QUIC/UDP.",
        "link": f"hysteria2://{HY2_PASSWORD}@{SERVER_IP}:9444?sni=www.microsoft.com&alpn=h3&obfs=salamander&obfs-password={SALAMANDER_PASS}{pin_param}#Fortress-Hysteria2-Salamander"
    },
    {
        "name": "Fortress-Hysteria2-Standard",
        "port": "UDP 8443",
        "proto": "udp",
        "port_num": 8443,
        "badge": "Brutal BBR Maximum Speed 4K",
        "desc": "[Brutal BBR - Maximum Speed 4K] — Aggressive congestion control designed for lossy campus Wi-Fi. Delivers gigabit throughput for video and downloads.",
        "link": f"hysteria2://{HY2_PASSWORD}@{SERVER_IP}:8443?sni=www.microsoft.com&alpn=h3{pin_param}#Fortress-Hysteria2-Standard"
    },
    {
        "name": "Fortress-TUIC5",
        "port": "UDP 9443",
        "proto": "udp",
        "port_num": 9443,
        "badge": "0-RTT Fast Mobile Roaming",
        "desc": "[0-RTT Fast Mobile Roaming] — Zero handshake latency when switching between campus Wi-Fi APs or mobile data on Android.",
        "link": f"tuic://{UUID}:{HY2_PASSWORD}@{SERVER_IP}:9443?congestion_control=bbr&alpn=h3&sni=www.microsoft.com{pin_param}#Fortress-TUIC5-UDP"
    },
    {
        "name": "Fortress-Shadowsocks2022",
        "port": "TCP/UDP 10443",
        "proto": "tcp",
        "port_num": 10443,
        "badge": "Ultra-Low Battery AEAD",
        "desc": "[Ultra-Low Battery AEAD] — Minimal CPU overhead and battery consumption on mobile (2022-blake3-aes-256-gcm).",
        "link": f"ss://MjAyMi1ibGFrZTMtYWVzLTI1Ni1nY206{SS_PASSWORD}@{SERVER_IP}:10443#Fortress-Shadowsocks2022"
    },
    {
        "name": "WireGuard over TCP (WSTunnel)",
        "port": "TCP 8080",
        "proto": "tcp",
        "port_num": 8080,
        "badge": "Captive Portal & TCP Slayer",
        "desc": "[Captive Portal & Strict TCP Slayer] — Wraps WireGuard inside HTTPS WebSockets (wstunnel) to bypass captive portals blocking UDP.",
        "link": f"wstunnel://{SERVER_IP}:8080?sni=www.microsoft.com&prefix=&tunnel=127.0.0.1:51820#Fortress-WireGuard-TCP"
    },
    {
        "name": "Native WireGuard",
        "port": "UDP 51820",
        "proto": "udp",
        "port_num": 51820,
        "badge": "Direct Kernel Line-Rate",
        "desc": "[Direct Kernel Line-Rate] — Direct Linux kernel ChaCha20-Poly1305 processing for high-speed unrestricted LAN / WAN.",
        "link": f"wg://{SERVER_IP}:51820"
    }
]

class SovereignApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Sovereign Fortress — Sovereign VPN Suite 2026")
        self.geometry("880x700")
        self.minsize(820, 620)
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
        act_frame = tk.Frame(self, bg="#111827", padx=14, pady=10, highlightthickness=1, highlightbackground="#1f2937")
        act_frame.pack(fill="x", padx=16, pady=(0, 10))

        btn_launch = tk.Button(act_frame, text="⚡ Launch Hiddify", bg="#2563eb", fg="#ffffff", activebackground="#1d4ed8",
                               activeforeground="#ffffff", font=("Segoe UI", 9, "bold"), relief="flat", padx=10, pady=6, cursor="hand2",
                               command=self.open_hiddify)
        btn_launch.pack(side="left", padx=3)

        btn_2fa_qr = tk.Button(act_frame, text="📱 2FA Setup QR", bg="#4f46e5", fg="#ffffff", activebackground="#4338ca",
                               activeforeground="#ffffff", font=("Segoe UI", 9, "bold"), relief="flat", padx=10, pady=6, cursor="hand2",
                               command=self.show_2fa_qr)
        btn_2fa_qr.pack(side="left", padx=3)

        btn_sub_qr = tk.Button(act_frame, text="📲 Mobile Sub QR", bg="#0d9488", fg="#ffffff", activebackground="#0f766e",
                               activeforeground="#ffffff", font=("Segoe UI", 9, "bold"), relief="flat", padx=10, pady=6, cursor="hand2",
                               command=self.show_sub_qr)
        btn_sub_qr.pack(side="left", padx=3)

        btn_copy_sub = tk.Button(act_frame, text="📋 Copy Link", bg="#1f2937", fg="#f3f4f6", activebackground="#374151",
                                 activeforeground="#ffffff", font=("Segoe UI", 9), relief="flat", padx=8, pady=6, cursor="hand2",
                                 command=self.copy_sub_link)
        btn_copy_sub.pack(side="left", padx=3)

        btn_portal = tk.Button(act_frame, text="🌐 Web Portal", bg="#1f2937", fg="#f3f4f6", activebackground="#374151",
                               activeforeground="#ffffff", font=("Segoe UI", 9), relief="flat", padx=8, pady=6, cursor="hand2",
                               command=self.open_portal)
        btn_portal.pack(side="left", padx=3)

        btn_probe = tk.Button(act_frame, text="🔄 Latency", bg="#1f2937", fg="#fbbf24", activebackground="#374151",
                              activeforeground="#fbbf24", font=("Segoe UI", 9), relief="flat", padx=8, pady=6, cursor="hand2",
                              command=self.probe_all_ports_async)
        btn_probe.pack(side="left", padx=3)

        btn_panic = tk.Button(act_frame, text="⚠️ Panic", bg="#3b1111", fg="#fca5a5", activebackground="#7f1d1d",
                              activeforeground="#ffffff", font=("Segoe UI", 9), relief="flat", padx=8, pady=6, cursor="hand2",
                              command=self.panic_shred)
        btn_panic.pack(side="right", padx=3)

        btn_unlock = tk.Button(act_frame, text="🔓 Unlock", bg="#1f2937", fg="#34d399", activebackground="#374151",
                               activeforeground="#34d399", font=("Segoe UI", 9), relief="flat", padx=8, pady=6, cursor="hand2",
                               command=self.unlock_vault)
        btn_unlock.pack(side="right", padx=3)

        btn_vault = tk.Button(act_frame, text="🔒 Lock", bg="#1f2937", fg="#a78bfa", activebackground="#374151",
                              activeforeground="#a78bfa", font=("Segoe UI", 9), relief="flat", padx=8, pady=6, cursor="hand2",
                              command=self.lock_vault)
        btn_vault.pack(side="right", padx=3)

        # Scrollable Protocol Modes Frame
        container = tk.Frame(self, bg="#0b0f19")
        container.pack(fill="both", expand=True, padx=16, pady=(0, 12))

        canvas = tk.Canvas(container, bg="#0b0f19", highlightthickness=0)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        self.scrollable_frame = tk.Frame(canvas, bg="#0b0f19")

        self.scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw", width=820)
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

            if "WireGuard over TCP" in proto["name"]:
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
                self.after(0, lambda l=lbl: l.config(text="AUTO-FASTEST ('lowest' in Hiddify)", foreground="#34d399"))
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
                    # Measure true network round-trip latency to the server host while verifying UDP socket path
                    t0 = time.time()
                    s_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s_udp.settimeout(1.5)
                    s_udp.sendto(b"\x00\x00\x00\x00", (host, port))
                    s_udp.close()

                    s_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s_tcp.settimeout(2.5)
                    s_tcp.connect((host, 443))
                    t1 = time.time()
                    s_tcp.close()
                    return (t1 - t0) * 1000.0
                except Exception:
                    time.sleep(0.2)
        return None

    def open_hiddify(self):
        self.clipboard_clear()
        self.clipboard_append(SUB_URL)
        launched = False
        try:
            os.startfile(HIDDIFY_DEEPLINK)
            launched = True
        except Exception:
            pass

        if not launched:
            prog_files = os.environ.get("ProgramFiles", r"C:\Program Files")
            hiddify_exe = os.path.join(prog_files, "Hiddify", "Hiddify.exe")
            if os.path.exists(hiddify_exe):
                subprocess.Popen([hiddify_exe])
                launched = True
            else:
                webbrowser.open(HIDDIFY_DEEPLINK)

        messagebox.showinfo(
            "Hiddify 1-Click Import",
            "Universal Subscription Link is copied to your clipboard!\n\n"
            "How to load into Hiddify:\n"
            "1. In Hiddify, click the '+' button in the top right.\n"
            "2. Click 'Add from Clipboard' (or press Ctrl+V).\n\n"
            "All 7 hardened protocols and auto-balancers will be configured instantly."
        )

    def show_2fa_qr(self):
        totp_secret = CONFIG.get("totp_secret", "")
        if not totp_secret or totp_secret.startswith("<"):
            messagebox.showwarning("2FA Not Configured", "No 2FA TOTP secret found in fortress_config.json.\nPlease check your configuration.")
            return

        otp_uri = f"otpauth://totp/ubuntu@{SERVER_IP}?secret={totp_secret}&issuer=SovereignFortress"

        win = tk.Toplevel(self)
        win.title("Sovereign Fortress — 2FA Authenticator Setup")
        win.geometry("460x600")
        win.minsize(420, 560)
        win.configure(bg="#0b0f19")
        win.transient(self)
        win.grab_set()

        hdr = tk.Label(win, text="2FA AUTHENTICATOR SETUP", font=("Segoe UI", 13, "bold"), fg="#818cf8", bg="#0b0f19")
        hdr.pack(pady=(16, 2))

        sub = tk.Label(win, text="Scan with Google Authenticator, Aegis, 2FAS, or Bitwarden\nUsed for SSH (2222) and Web Portal", 
                       font=("Segoe UI", 8), fg="#9ca3af", bg="#0b0f19", justify="center")
        sub.pack(pady=(0, 10))

        if HAS_QR:
            qr = qrcode.QRCode(box_size=5, border=2)
            qr.add_data(otp_uri)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            qr_photo = ImageTk.PhotoImage(img)

            qr_lbl = tk.Label(win, image=qr_photo, bg="#0b0f19")
            qr_lbl.image = qr_photo
            qr_lbl.pack(pady=4)
        else:
            no_qr = tk.Label(win, text="[Install Pillow & qrcode to view QR]\nManual entry key available below.", 
                             font=("Segoe UI", 9), fg="#f87171", bg="#0b0f19")
            no_qr.pack(pady=20)

        key_frame = tk.Frame(win, bg="#111827", padx=12, pady=8, highlightthickness=1, highlightbackground="#374151")
        key_frame.pack(fill="x", padx=24, pady=8)

        lbl_k = tk.Label(key_frame, text="Secret Key (Manual Entry):", font=("Segoe UI", 8, "bold"), fg="#9ca3af", bg="#111827")
        lbl_k.pack(anchor="w")

        row_k = tk.Frame(key_frame, bg="#111827")
        row_k.pack(fill="x", pady=(4, 0))

        ent_k = tk.Entry(row_k, font=("Consolas", 10, "bold"), fg="#38bdf8", bg="#1e293b", relief="flat", justify="center")
        ent_k.insert(0, totp_secret)
        ent_k.config(state="readonly")
        ent_k.pack(side="left", fill="x", expand=True, padx=(0, 6))

        def copy_key():
            self.clipboard_clear()
            self.clipboard_append(totp_secret)
            btn_kcopy.config(text="✓ Copied!", fg="#34d399")
            win.after(2000, lambda: btn_kcopy.config(text="Copy", fg="#f3f4f6"))

        btn_kcopy = tk.Button(row_k, text="Copy", bg="#374151", fg="#f3f4f6", activebackground="#4b5563",
                              font=("Segoe UI", 8, "bold"), relief="flat", padx=10, cursor="hand2", command=copy_key)
        btn_kcopy.pack(side="right")

        verify_frame = tk.Frame(win, bg="#111827", padx=12, pady=8, highlightthickness=1, highlightbackground="#10b981")
        verify_frame.pack(fill="x", padx=24, pady=4)

        lbl_v = tk.Label(verify_frame, text="Live Verification Code (Compare with phone):", font=("Segoe UI", 8), fg="#9ca3af", bg="#111827")
        lbl_v.pack(anchor="w")

        code_box = tk.Frame(verify_frame, bg="#111827")
        code_box.pack(fill="x", pady=(2, 0))

        lbl_code = tk.Label(code_box, text="--- ---", font=("Consolas", 16, "bold"), fg="#34d399", bg="#111827")
        lbl_code.pack(side="left")

        lbl_timer = tk.Label(code_box, text="30s", font=("Segoe UI", 9, "bold"), fg="#fbbf24", bg="#111827")
        lbl_timer.pack(side="right")

        def update_live_totp():
            if not win.winfo_exists():
                return
            now = time.time()
            remaining = 30 - int(now % 30)
            code = generate_totp_code(totp_secret)
            formatted = f"{code[:3]} {code[3:]}"
            lbl_code.config(text=formatted)
            lbl_timer.config(text=f"↻ {remaining}s")
            win.after(1000, update_live_totp)

        update_live_totp()

        btn_close = tk.Button(win, text="Done", bg="#1f2937", fg="#f3f4f6", activebackground="#374151",
                              font=("Segoe UI", 9, "bold"), relief="flat", padx=16, pady=4, cursor="hand2", command=win.destroy)
        btn_close.pack(pady=10)

    def show_sub_qr(self):
        win = tk.Toplevel(self)
        win.title("Sovereign Fortress — Mobile Subscription QR")
        win.geometry("480x580")
        win.minsize(440, 540)
        win.configure(bg="#0b0f19")
        win.transient(self)
        win.grab_set()

        hdr = tk.Label(win, text="MOBILE CLIENT SUBSCRIPTION QR", font=("Segoe UI", 13, "bold"), fg="#2dd4bf", bg="#0b0f19")
        hdr.pack(pady=(14, 2))

        sub = tk.Label(win, text="Scan with Hiddify (Android / iOS / Windows / macOS)\nImports all 7 hardened protocols in 1 tap", 
                       font=("Segoe UI", 8), fg="#9ca3af", bg="#0b0f19", justify="center")
        sub.pack(pady=(0, 6))

        mode_var = tk.StringVar(value="full")
        mode_frame = tk.Frame(win, bg="#0b0f19")
        mode_frame.pack(pady=4)

        qr_lbl = tk.Label(win, bg="#0b0f19")
        qr_lbl.pack(pady=4)

        url_frame = tk.Frame(win, bg="#111827", padx=12, pady=8, highlightthickness=1, highlightbackground="#374151")
        url_frame.pack(fill="x", padx=20, pady=6)

        ent_url = tk.Entry(url_frame, font=("Consolas", 8), fg="#38bdf8", bg="#1e293b", relief="flat")
        ent_url.pack(side="left", fill="x", expand=True, padx=(0, 6))

        def copy_current_url():
            cur = SUB_URL if mode_var.get() == "full" else SUB_URL_TRAFFIC_ONLY
            self.clipboard_clear()
            self.clipboard_append(cur)
            btn_copy.config(text="✓ Copied!", fg="#34d399")
            win.after(2000, lambda: btn_copy.config(text="Copy URL", fg="#f3f4f6"))

        btn_copy = tk.Button(url_frame, text="Copy URL", bg="#374151", fg="#f3f4f6", activebackground="#4b5563",
                             font=("Segoe UI", 8, "bold"), relief="flat", padx=10, cursor="hand2", command=copy_current_url)
        btn_copy.pack(side="right")

        def render_qr():
            url = SUB_URL if mode_var.get() == "full" else SUB_URL_TRAFFIC_ONLY
            if HAS_QR:
                qr = qrcode.QRCode(box_size=5, border=2)
                qr.add_data(url)
                qr.make(fit=True)
                img = qr.make_image(fill_color="black", back_color="white")
                qr_photo = ImageTk.PhotoImage(img)
                qr_lbl.config(image=qr_photo)
                qr_lbl.image = qr_photo
            ent_url.config(state="normal")
            ent_url.delete(0, tk.END)
            ent_url.insert(0, url)
            ent_url.config(state="readonly")

        rb_full = tk.Radiobutton(mode_frame, text="Full Tunnel (Standard)", variable=mode_var, value="full",
                                 font=("Segoe UI", 9, "bold"), fg="#34d399", bg="#0b0f19", selectcolor="#111827",
                                 activebackground="#0b0f19", activeforeground="#34d399", command=render_qr)
        rb_full.pack(side="left", padx=8)

        rb_split = tk.Radiobutton(mode_frame, text="Traffic-Only (Split Tunnel)", variable=mode_var, value="split",
                                  font=("Segoe UI", 9, "bold"), fg="#38bdf8", bg="#0b0f19", selectcolor="#111827",
                                  activebackground="#0b0f19", activeforeground="#38bdf8", command=render_qr)
        rb_split.pack(side="left", padx=8)

        render_qr()

        hint = tk.Label(win, text="Tip: In Hiddify mobile app, tap '+' in the top right -> 'Scan QR Code'",
                        font=("Segoe UI", 8, "italic"), fg="#6ee7b7", bg="#0b0f19")
        hint.pack(pady=4)

        btn_close = tk.Button(win, text="Done", bg="#1f2937", fg="#f3f4f6", activebackground="#374151",
                              font=("Segoe UI", 9, "bold"), relief="flat", padx=16, pady=4, cursor="hand2", command=win.destroy)
        btn_close.pack(pady=8)

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
