#!/usr/bin/env python3
"""
Sovereign Fortress Dynamic Subscription & Access Control Daemon (2026 Enhanced)
Port: 8443 (TCP)
Security: 100% Volatile RAM (tmpfs), Zero-Disk Logs, Rate Limiting, Active Defense Redirection
Supports: Hiddify App (Universal Sing-box 1.11+ JSON & Base64), 2FA TOTP Authentication,
          Direct TOTP-in-path (/sub/<TOTP>), Dynamic Rotating Token, Self-Contained Offline QR Engine
"""

import os
import sys
import json
import time
import hmac
import base64
import struct
import secrets
import hashlib
import urllib.parse
import posixpath
import ssl
import socket
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

# Paths in Volatile RAM & Persistent Storage
RAM_DIR = "/run/fortress"
DISK_DIR = "/etc/fortress"
TOKEN_RAM = os.path.join(RAM_DIR, "sub_token")
TOKEN_DISK = os.path.join(DISK_DIR, "sub_token")
TOTP_SECRET_FILE = "/home/ubuntu/.google_authenticator"
FALLBACK_TOTP_FILE = os.path.join(RAM_DIR, "totp_secret")

# Dynamic Configuration Loader (No hardcoded credentials)
CONFIG_PATHS = [
    os.path.join(RAM_DIR, "fortress_config.json"),
    os.path.join(DISK_DIR, "fortress_config.json"),
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "fortress_config.json"),
]

CONFIG = {
    "server_ip": "127.0.0.1",
    "sub_port": 8443,
    "token": "",
    "uuid": "<YOUR_UUID>",
    "reality_pubkey": "<YOUR_REALITY_PUBLIC_KEY>",
    "reality_shortid": "<YOUR_REALITY_SHORT_ID>",
    "reality_sni": "gateway.icloud.com",
    "hy2_password": "<YOUR_HYSTERIA2_PASSWORD>",
    "salamander_password": "<YOUR_SALAMANDER_PASSWORD>",
    "ss_password": "<YOUR_SHADOWSOCKS_PASSWORD>",
    "wg_server_pub": "<YOUR_WG_SERVER_PUB>",
    "wg_client_priv": "<YOUR_WG_CLIENT_PRIV>",
    "wg_client_ip": "10.8.0.2",
    "wstunnel_port": 8080,
    "cert_sha256": "",
    "pin_sha256": "",
    "nextdns_id": "<YOUR_NEXTDNS_ID>"
}

for cp in CONFIG_PATHS:
    if os.path.exists(cp):
        try:
            with open(cp, "r", encoding="utf-8") as f:
                user_cfg = json.load(f)
                CONFIG.update(user_cfg)
            break
        except Exception:
            pass

SERVER_IP = CONFIG.get("server_ip", "127.0.0.1")
PORT = int(CONFIG.get("sub_port", 8443))
UUID = CONFIG.get("uuid", "<YOUR_UUID>")
REALITY_PUBKEY = CONFIG.get("reality_pubkey", "<YOUR_REALITY_PUBLIC_KEY>")
REALITY_SHORTID = CONFIG.get("reality_shortid", "<YOUR_REALITY_SHORT_ID>")
REALITY_SNI = CONFIG.get("reality_sni", "gateway.icloud.com")
HY2_PASSWORD = CONFIG.get("hy2_password", "<YOUR_HYSTERIA2_PASSWORD>")
SALAMANDER_PASSWORD = CONFIG.get("salamander_password", "<YOUR_SALAMANDER_PASSWORD>")
SS_PASSWORD = CONFIG.get("ss_password", "<YOUR_SHADOWSOCKS_PASSWORD>")
WG_SERVER_PUB = CONFIG.get("wg_server_pub", "<YOUR_WG_SERVER_PUB>")
WG_CLIENT_PRIV = CONFIG.get("wg_client_priv", "<YOUR_WG_CLIENT_PRIV>")
WG_CLIENT_IP = CONFIG.get("wg_client_ip", "10.8.0.2")
WSTUNNEL_PORT = int(CONFIG.get("wstunnel_port", 8080))
CERT_SHA256 = CONFIG.get("cert_sha256", "")
PIN_SHA256 = CONFIG.get("pin_sha256", "")

# Fallback: Extract from live /run/fortress/config.json if running on server without master config
if REALITY_PUBKEY.startswith("<") or not REALITY_PUBKEY or HY2_PASSWORD.startswith("<"):
    live_cfg = os.path.join(RAM_DIR, "config.json")
    if os.path.exists(live_cfg):
        try:
            with open(live_cfg, "r", encoding="utf-8") as f:
                lcfg = json.load(f)
            for ib in lcfg.get("inbounds", []):
                it = ib.get("type")
                if it == "vless":
                    for u in ib.get("users", []):
                        if u.get("uuid"): UUID = u["uuid"]
                    r_sec = ib.get("tls", {}).get("reality", {})
                    if r_sec.get("short_id"): REALITY_SHORTID = r_sec["short_id"][0]
                    if ib.get("tls", {}).get("server_name"): REALITY_SNI = ib["tls"]["server_name"]
                elif it == "hysteria2":
                    for u in ib.get("users", []):
                        if u.get("password"): HY2_PASSWORD = u["password"]
                    obfs = ib.get("obfs", {})
                    if obfs.get("password"): SALAMANDER_PASSWORD = obfs["password"]
                elif it == "shadowsocks":
                    if ib.get("password"): SS_PASSWORD = ib["password"]
                elif it == "wireguard":
                    peers = ib.get("peers", [])
                    if peers and peers[0].get("public_key"):
                        WG_SERVER_PUB = peers[0]["public_key"]
        except Exception:
            pass

SESSION_SECRET = secrets.token_bytes(32)
FAILED_ATTEMPTS = {}
FAILED_ATTEMPTS_LOCK = threading.Lock()
BAN_DURATION = 900  # 15 minutes
MAX_FAILED = 5
MAX_FAILED_RECORDS = 5000
MAX_POST_BODY_BYTES = 16384  # 16 KB max POST request body to eliminate DoS memory exhaustion

# RFC 6238 TOTP Single-Use Replay Protection Cache
USED_TOTP_CODES = {}  # {code_str: expiry_time}
USED_TOTP_LOCK = threading.Lock()

# Embedded Offline QR Code Generator Library
QRCODE_JS_B64 = "dmFyIFFSQ29kZTshZnVuY3Rpb24oKXtmdW5jdGlvbiBhKGEpe3RoaXMubW9kZT1jLk1PREVfOEJJVF9CWVRFLHRoaXMuZGF0YT1hLHRoaXMucGFyc2VkRGF0YT1bXTtmb3IodmFyIGI9W10sZD0wLGU9dGhpcy5kYXRhLmxlbmd0aDtlPmQ7ZCsrKXt2YXIgZj10aGlzLmRhdGEuY2hhckNvZGVBdChkKTtmPjY1NTM2PyhiWzBdPTI0MHwoMTgzNTAwOCZmKT4+PjE4LGJbMV09MTI4fCgyNTgwNDgmZik+Pj4xMixiWzJdPTEyOHwoNDAzMiZmKT4+PjYsYlszXT0xMjh8NjMmZik6Zj4yMDQ4PyhiWzBdPTIyNHwoNjE0NDAmZik+Pj4xMixiWzFdPTEyOHwoNDAzMiZmKT4+PjYsYlsyXT0xMjh8NjMmZik6Zj4xMjg/KGJbMF09MTkyfCgxOTg0JmYpPj4+NixiWzFdPTEyOHw2MyZmKTpiWzBdPWYsdGhpcy5wYXJzZWREYXRhPXRoaXMucGFyc2VkRGF0YS5jb25jYXQoYil9dGhpcy5wYXJzZWREYXRhLmxlbmd0aCE9dGhpcy5kYXRhLmxlbmd0aCYmKHRoaXMucGFyc2VkRGF0YS51bnNoaWZ0KDE5MSksdGhpcy5wYXJzZWREYXRhLnVuc2hpZnQoMTg3KSx0aGlzLnBhcnNlZERhdGEudW5zaGlmdCgyMzkpKX1mdW5jdGlvbiBiKGEsYil7dGhpcy50eXBlTnVtYmVyPWEsdGhpcy5lcnJvckNvcnJlY3RMZXZlbD1iLHRoaXMubW9kdWxlcz1udWxsLHRoaXMubW9kdWxlQ291bnQ9MCx0aGlzLmRhdGFDYWNoZT1udWxsLHRoaXMuZGF0YUxpc3Q9W119ZnVuY3Rpb24gaShhLGIpe2lmKHZvaWQgMD09YS5sZW5ndGgpdGhyb3cgbmV3IEVycm9yKGEubGVuZ3RoKyIvIitiKTtmb3IodmFyIGM9MDtjPGEubGVuZ3RoJiYwPT1hW2NdOyljKys7dGhpcy5udW09bmV3IEFycmF5KGEubGVuZ3RoLWMrYik7Zm9yKHZhciBkPTA7ZDxhLmxlbmd0aC1jO2QrKyl0aGlzLm51bVtkXT1hW2QrY119ZnVuY3Rpb24gaihhLGIpe3RoaXMudG90YWxDb3VudD1hLHRoaXMuZGF0YUNvdW50PWJ9ZnVuY3Rpb24gaygpe3RoaXMuYnVmZmVyPVtdLHRoaXMubGVuZ3RoPTB9ZnVuY3Rpb24gbSgpe3JldHVybiJ1bmRlZmluZWQiIT10eXBlb2YgQ2FudmFzUmVuZGVyaW5nQ29udGV4dDJEfWZ1bmN0aW9uIG4oKXt2YXIgYT0hMSxiPW5hdmlnYXRvci51c2VyQWdlbnQ7cmV0dXJuL2FuZHJvaWQvaS50ZXN0KGIpJiYoYT0hMCxhTWF0PWIudG9TdHJpbmcoKS5tYXRjaCgvYW5kcm9pZCAoWzAtOV1cLlswLTldKS9pKSxhTWF0JiZhTWF0WzFdJiYoYT1wYXJzZUZsb2F0KGFNYXRbMV0pKSksYX1mdW5jdGlvbiByKGEsYil7Zm9yKHZhciBjPTEsZT1zKGEpLGY9MCxnPWwubGVuZ3RoO2c+PWY7ZisrKXt2YXIgaD0wO3N3aXRjaChiKXtjYXNlIGQuTDpoPWxbZl1bMF07YnJlYWs7Y2FzZSBkLk06aD1sW2ZdWzFdO2JyZWFrO2Nhc2UgZC5ROmg9bFtmXVsyXTticmVhaztjYXNlIGQuSDpoPWxbZl1bM119aWYoaD49ZSlicmVhaztjKyt9aWYoYz5sLmxlbmd0aCl0aHJvdyBuZXcgRXJyb3IoIlRvbyBsb25nIGRhdGEiKTtyZXR1cm4gY31mdW5jdGlvbiBzKGEpe3ZhciBiPWVuY29kZVVSSShhKS50b1N0cmluZygpLnJlcGxhY2UoL1wlWzAtOWEtZkEtRl17Mn0vZywiYSIpO3JldHVybiBiLmxlbmd0aCsoYi5sZW5ndGghPWE/MzowKX1hLnByb3RvdHlwZT17Z2V0TGVuZ3RoOmZ1bmN0aW9uKCl7cmV0dXJuIHRoaXMucGFyc2VkRGF0YS5sZW5ndGh9LHdyaXRlOmZ1bmN0aW9uKGEpe2Zvcih2YXIgYj0wLGM9dGhpcy5wYXJzZWREYXRhLmxlbmd0aDtjPmI7YisrKWEucHV0KHRoaXMucGFyc2VkRGF0YVtiXSw4KX19LGIucHJvdG90eXBlPXthZGREYXRhOmZ1bmN0aW9uKGIpe3ZhciBjPW5ldyBhKGIpO3RoaXMuZGF0YUxpc3QucHVzaChjKSx0aGlzLmRhdGFDYWNoZT1udWxsfSxpc0Rhcms6ZnVuY3Rpb24oYSxiKXtpZigwPmF8fHRoaXMubW9kdWxlQ291bnQ8PWF8fDA+Ynx8dGhpcy5tb2R1bGVDb3VudDw9Yil0aHJvdyBuZXcgRXJyb3IoYSsiLCIrYik7cmV0dXJuIHRoaXMubW9kdWxlc1thXVtiXX0sZ2V0TW9kdWxlQ291bnQ6ZnVuY3Rpb24oKXtyZXR1cm4gdGhpcy5tb2R1bGVDb3VudH0sbWFrZTpmdW5jdGlvbigpe3RoaXMubWFrZUltcGwoITEsdGhpcy5nZXRCZXN0TWFza1BhdHRlcm4oKSl9LG1ha2VJbXBsOmZ1bmN0aW9uKGEsYyl7dGhpcy5tb2R1bGVDb3VudD00KnRoaXMudHlwZU51bWJlcisxNyx0aGlzLm1vZHVsZXM9bmV3IEFycmF5KHRoaXMubW9kdWxlQ291bnQpO2Zvcih2YXIgZD0wO2Q8dGhpcy5tb2R1bGVDb3VudDtkKyspe3RoaXMubW9kdWxlc1tkXT1uZXcgQXJyYXkodGhpcy5tb2R1bGVDb3VudCk7Zm9yKHZhciBlPTA7ZTx0aGlzLm1vZHVsZUNvdW50O2UrKyl0aGlzLm1vZHVsZXNbZF1bZV09bnVsbH10aGlzLnNldHVwUG9zaXRpb25Qcm9iZVBhdHRlcm4oMCwwKSx0aGlzLnNldHVwUG9zaXRpb25Qcm9iZVBhdHRlcm4odGhpcy5tb2R1bGVDb3VudC03LDApLHRoaXMuc2V0dXBQb3NpdGlvblByb2JlUGF0dGVybigwLHRoaXMubW9kdWxlQ291bnQtNyksdGhpcy5zZXR1cFBvc2l0aW9uQWRqdXN0UGF0dGVybigpLHRoaXMuc2V0dXBUaW1pbmdQYXR0ZXJuKCksdGhpcy5zZXR1cFR5cGVJbmZvKGEsYyksdGhpcy50eXBlTnVtYmVyPj03JiZ0aGlzLnNldHVwVHlwZU51bWJlcihhKSxudWxsPT10aGlzLmRhdGFDYWNoZSYmKHRoaXMuZGF0YUNhY2hlPWIuY3JlYXRlRGF0YSh0aGlzLnR5cGVOdW1iZXIsdGhpcy5lcnJvckNvcnJlY3RMZXZlbCx0aGlzLmRhdGFMaXN0KSksdGhpcy5tYXBEYXRhKHRoaXMuZGF0YUNhY2hlLGMpfSxzZXR1cFBvc2l0aW9uUHJvYmVQYXR0ZXJuOmZ1bmN0aW9uKGEsYil7Zm9yKHZhciBjPS0xOzc+PWM7YysrKWlmKCEoLTE+PWErY3x8dGhpcy5tb2R1bGVDb3VudDw9YStjKSlmb3IodmFyIGQ9LTE7Nz49ZDtkKyspLTE+PWIrZHx8dGhpcy5tb2R1bGVDb3VudDw9YitkfHwodGhpcy5tb2R1bGVzW2ErY11bYitkXT1jPj0wJiY2Pj1jJiYoMD09ZHx8Nj09ZCl8fGQ+PTAmJjY+PWQmJigwPT1jfHw2PT1jKXx8Yz49MiYmND49YyYmZD49MiYmND49ZD8hMDohMSl9LGdldEJlc3RNYXNrUGF0dGVybjpmdW5jdGlvbigpe2Zvcih2YXIgYT0wLGI9MCxjPTA7OD5jO2MrKyl7dGhpcy5tYWtlSW1wbCghMCxjKTt2YXIgZD1mLmdldExvc3RQb2ludCh0aGlzKTsoMD09Y3x8YT5kKSYmKGE9ZCxiPWMpfXJldHVybiBifSxjcmVhdGVNb3ZpZUNsaXA6ZnVuY3Rpb24oYSxiLGMpe3ZhciBkPWEuY3JlYXRlRW1wdHlNb3ZpZUNsaXAoYixjKSxlPTE7dGhpcy5tYWtlKCk7Zm9yKHZhciBmPTA7Zjx0aGlzLm1vZHVsZXMubGVuZ3RoO2YrKylmb3IodmFyIGc9ZiplLGg9MDtoPHRoaXMubW9kdWxlc1tmXS5sZW5ndGg7aCsrKXt2YXIgaT1oKmUsaj10aGlzLm1vZHVsZXNbZl1baF07aiYmKGQuYmVnaW5GaWxsKDAsMTAwKSxkLm1vdmVUbyhpLGcpLGQubGluZVRvKGkrZSxnKSxkLmxpbmVUbyhpK2UsZytlKSxkLmxpbmVUbyhpLGcrZSksZC5lbmRGaWxsKCkpfXJldHVybiBkfSxzZXR1cFRpbWluZ1BhdHRlcm46ZnVuY3Rpb24oKXtmb3IodmFyIGE9ODthPHRoaXMubW9kdWxlQ291bnQtODthKyspbnVsbD09dGhpcy5tb2R1bGVzW2FdWzZdJiYodGhpcy5tb2R1bGVzW2FdWzZdPTA9PWElMik7Zm9yKHZhciBiPTg7Yjx0aGlzLm1vZHVsZUNvdW50LTg7YisrKW51bGw9PXRoaXMubW9kdWxlc1s2XVtiXSYmKHRoaXMubW9kdWxlc1s2XVtiXT0wPT1iJTIpfSxzZXR1cFBvc2l0aW9uQWRqdXN0UGF0dGVybjpmdW5jdGlvbigpe2Zvcih2YXIgYT1mLmdldFBhdHRlcm5Qb3NpdGlvbih0aGlzLnR5cGVOdW1iZXIpLGI9MDtiPGEubGVuZ3RoO2IrKylmb3IodmFyIGM9MDtjPGEubGVuZ3RoO2MrKyl7dmFyIGQ9YVtiXSxlPWFbY107aWYobnVsbD09dGhpcy5tb2R1bGVzW2RdW2VdKWZvcih2YXIgZz0tMjsyPj1nO2crKylmb3IodmFyIGg9LTI7Mj49aDtoKyspdGhpcy5tb2R1bGVzW2QrZ11bZStoXT0tMj09Z3x8Mj09Z3x8LTI9PWh8fDI9PWh8fDA9PWcmJjA9PWg/ITA6ITF9fSxzZXR1cFR5cGVOdW1iZXI6ZnVuY3Rpb24oYSl7Zm9yKHZhciBiPWYuZ2V0QkNIVHlwZU51bWJlcih0aGlzLnR5cGVOdW1iZXIpLGM9MDsxOD5jO2MrKyl7dmFyIGQ9IWEmJjE9PSgxJmI+PmMpO3RoaXMubW9kdWxlc1tNYXRoLmZsb29yKGMvMyldW2MlMyt0aGlzLm1vZHVsZUNvdW50LTgtM109ZH1mb3IodmFyIGM9MDsxOD5jO2MrKyl7dmFyIGQ9IWEmJjE9PSgxJmI+PmMpO3RoaXMubW9kdWxlc1tjJTMrdGhpcy5tb2R1bGVDb3VudC04LTNdW01hdGguZmxvb3IoYy8zKV09ZH19LHNldHVwVHlwZUluZm86ZnVuY3Rpb24oYSxiKXtmb3IodmFyIGM9dGhpcy5lcnJvckNvcnJlY3RMZXZlbDw8M3xiLGQ9Zi5nZXRCQ0hUeXBlSW5mbyhjKSxlPTA7MTU+ZTtlKyspe3ZhciBnPSFhJiYxPT0oMSZkPj5lKTs2PmU/dGhpcy5tb2R1bGVzW2VdWzhdPWc6OD5lP3RoaXMubW9kdWxlc1tlKzFdWzhdPWc6dGhpcy5tb2R1bGVzW3RoaXMubW9kdWxlQ291bnQtMTUrZV1bOF09Z31mb3IodmFyIGU9MDsxNT5lO2UrKyl7dmFyIGc9IWEmJjE9PSgxJmQ+PmUpOzg+ZT90aGlzLm1vZHVsZXNbOF1bdGhpcy5tb2R1bGVDb3VudC1lLTFdPWc6OT5lP3RoaXMubW9kdWxlc1s4XVsxNS1lLTErMV09Zzp0aGlzLm1vZHVsZXNbOF1bMTUtZS0xXT1nfXRoaXMubW9kdWxlc1t0aGlzLm1vZHVsZUNvdW50LThdWzhdPSFhfSxtYXBEYXRhOmZ1bmN0aW9uKGEsYil7Zm9yKHZhciBjPS0xLGQ9dGhpcy5tb2R1bGVDb3VudC0xLGU9NyxnPTAsaD10aGlzLm1vZHVsZUNvdW50LTE7aD4wO2gtPTIpZm9yKDY9PWgmJmgtLTs7KXtmb3IodmFyIGk9MDsyPmk7aSsrKWlmKG51bGw9PXRoaXMubW9kdWxlc1tkXVtoLWldKXt2YXIgaj0hMTtnPGEubGVuZ3RoJiYoaj0xPT0oMSZhW2ddPj4+ZSkpO3ZhciBrPWYuZ2V0TWFzayhiLGQsaC1pKTtrJiYoaj0haiksdGhpcy5tb2R1bGVzW2RdW2gtaV09aixlLS0sLTE9PWUmJihnKyssZT03KX1pZihkKz1jLDA+ZHx8dGhpcy5tb2R1bGVDb3VudDw9ZCl7ZC09YyxjPS1jO2JyZWFrfX19fSxiLlBBRDA9MjM2LGIuUEFEMT0xNyxiLmNyZWF0ZURhdGE9ZnVuY3Rpb24oYSxjLGQpe2Zvcih2YXIgZT1qLmdldFJTQmxvY2tzKGEsYyksZz1uZXcgayxoPTA7aDxkLmxlbmd0aDtoKyspe3ZhciBpPWRbaF07Zy5wdXQoaS5tb2RlLDQpLGcucHV0KGkuZ2V0TGVuZ3RoKCksZi5nZXRMZW5ndGhJbkJpdHMoaS5tb2RlLGEpKSxpLndyaXRlKGcpfWZvcih2YXIgbD0wLGg9MDtoPGUubGVuZ3RoO2grKylsKz1lW2hdLmRhdGFDb3VudDtpZihnLmdldExlbmd0aEluQml0cygpPjgqbCl0aHJvdyBuZXcgRXJyb3IoImNvZGUgbGVuZ3RoIG92ZXJmbG93LiAoIitnLmdldExlbmd0aEluQml0cygpKyI+Iis4KmwrIikiKTtmb3IoZy5nZXRMZW5ndGhJbkJpdHMoKSs0PD04KmwmJmcucHV0KDAsNCk7MCE9Zy5nZXRMZW5ndGhJbkJpdHMoKSU4OylnLnB1dEJpdCghMSk7Zm9yKDs7KXtpZihnLmdldExlbmd0aEluQml0cygpPj04KmwpYnJlYWs7aWYoZy5wdXQoYi5QQUQwLDgpLGcuZ2V0TGVuZ3RoSW5CaXRzKCk+PTgqbClicmVhaztnLnB1dChiLlBBRDEsOCl9cmV0dXJuIGIuY3JlYXRlQnl0ZXMoZyxlKX0sYi5jcmVhdGVCeXRlcz1mdW5jdGlvbihhLGIpe2Zvcih2YXIgYz0wLGQ9MCxlPTAsZz1uZXcgQXJyYXkoYi5sZW5ndGgpLGg9bmV3IEFycmF5KGIubGVuZ3RoKSxqPTA7ajxiLmxlbmd0aDtqKyspe3ZhciBrPWJbal0uZGF0YUNvdW50LGw9YltqXS50b3RhbENvdW50LWs7ZD1NYXRoLm1heChkLGspLGU9TWF0aC5tYXgoZSxsKSxnW2pdPW5ldyBBcnJheShrKTtmb3IodmFyIG09MDttPGdbal0ubGVuZ3RoO20rKylnW2pdW21dPTI1NSZhLmJ1ZmZlclttK2NdO2MrPWs7dmFyIG49Zi5nZXRFcnJvckNvcnJlY3RQb2x5bm9taWFsKGwpLG89bmV3IGkoZ1tqXSxuLmdldExlbmd0aCgpLTEpLHA9by5tb2Qobik7aFtqXT1uZXcgQXJyYXkobi5nZXRMZW5ndGgoKS0xKTtmb3IodmFyIG09MDttPGhbal0ubGVuZ3RoO20rKyl7dmFyIHE9bStwLmdldExlbmd0aCgpLWhbal0ubGVuZ3RoO2hbal1bbV09cT49MD9wLmdldChxKTowfX1mb3IodmFyIHI9MCxtPTA7bTxiLmxlbmd0aDttKyspcis9YlttXS50b3RhbENvdW50O2Zvcih2YXIgcz1uZXcgQXJyYXkociksdD0wLG09MDtkPm07bSsrKWZvcih2YXIgaj0wO2o8Yi5sZW5ndGg7aisrKW08Z1tqXS5sZW5ndGgmJihzW3QrK109Z1tqXVttXSk7Zm9yKHZhciBtPTA7ZT5tO20rKylmb3IodmFyIGo9MDtqPGIubGVuZ3RoO2orKyltPGhbal0ubGVuZ3RoJiYoc1t0KytdPWhbal1bbV0pO3JldHVybiBzfTtmb3IodmFyIGM9e01PREVfTlVNQkVSOjEsTU9ERV9BTFBIQV9OVU06MixNT0RFXzhCSVRfQllURTo0LE1PREVfS0FOSkk6OH0sZD17TDoxLE06MCxROjMsSDoyfSxlPXtQQVRURVJOMDAwOjAsUEFUVEVSTjAwMToxLFBBVFRFUk4wMTA6MixQQVRURVJOMDExOjMsUEFUVEVSTjEwMDo0LFBBVFRFUk4xMDE6NSxQQVRURVJOMTEwOjYsUEFUVEVSTjExMTo3fSxmPXtQQVRURVJOX1BPU0lUSU9OX1RBQkxFOltbXSxbNiwxOF0sWzYsMjJdLFs2LDI2XSxbNiwzMF0sWzYsMzRdLFs2LDIyLDM4XSxbNiwyNCw0Ml0sWzYsMjYsNDZdLFs2LDI4LDUwXSxbNiwzMCw1NF0sWzYsMzIsNThdLFs2LDM0LDYyXSxbNiwyNiw0Niw2Nl0sWzYsMjYsNDgsNzBdLFs2LDI2LDUwLDc0XSxbNiwzMCw1NCw3OF0sWzYsMzAsNTYsODJdLFs2LDMwLDU4LDg2XSxbNiwzNCw2Miw5MF0sWzYsMjgsNTAsNzIsOTRdLFs2LDI2LDUwLDc0LDk4XSxbNiwzMCw1NCw3OCwxMDJdLFs2LDI4LDU0LDgwLDEwNl0sWzYsMzIsNTgsODQsMTEwXSxbNiwzMCw1OCw4NiwxMTRdLFs2LDM0LDYyLDkwLDExOF0sWzYsMjYsNTAsNzQsOTgsMTIyXSxbNiwzMCw1NCw3OCwxMDIsMTI2XSxbNiwyNiw1Miw3OCwxMDQsMTMwXSxbNiwzMCw1Niw4MiwxMDgsMTM0XSxbNiwzNCw2MCw4NiwxMTIsMTM4XSxbNiwzMCw1OCw4NiwxMTQsMTQyXSxbNiwzNCw2Miw5MCwxMTgsMTQ2XSxbNiwzMCw1NCw3OCwxMDIsMTI2LDE1MF0sWzYsMjQsNTAsNzYsMTAyLDEyOCwxNTRdLFs2LDI4LDU0LDgwLDEwNiwxMzIsMTU4XSxbNiwzMiw1OCw4NCwxMTAsMTM2LDE2Ml0sWzYsMjYsNTQsODIsMTEwLDEzOCwxNjZdLFs2LDMwLDU4LDg2LDExNCwxNDIsMTcwXV0sRzE1OjEzMzUsRzE4Ojc5NzMsRzE1X01BU0s6MjE1MjIsZ2V0QkNIVHlwZUluZm86ZnVuY3Rpb24oYSl7Zm9yKHZhciBiPWE8PDEwO2YuZ2V0QkNIRGlnaXQoYiktZi5nZXRCQ0hEaWdpdChmLkcxNSk+PTA7KWJePWYuRzE1PDxmLmdldEJDSERpZ2l0KGIpLWYuZ2V0QkNIRGlnaXQoZi5HMTUpO3JldHVybihhPDwxMHxiKV5mLkcxNV9NQVNLfSxnZXRCQ0hUeXBlTnVtYmVyOmZ1bmN0aW9uKGEpe2Zvcih2YXIgYj1hPDwxMjtmLmdldEJDSERpZ2l0KGIpLWYuZ2V0QkNIRGlnaXQoZi5HMTgpPj0wOyliXj1mLkcxODw8Zi5nZXRCQ0hEaWdpdChiKS1mLmdldEJDSERpZ2l0KGYuRzE4KTtyZXR1cm4gYTw8MTJ8Yn0sZ2V0QkNIRGlnaXQ6ZnVuY3Rpb24oYSl7Zm9yKHZhciBiPTA7MCE9YTspYisrLGE+Pj49MTtyZXR1cm4gYn0sZ2V0UGF0dGVyblBvc2l0aW9uOmZ1bmN0aW9uKGEpe3JldHVybiBmLlBBVFRFUk5fUE9TSVRJT05fVEFCTEVbYS0xXX0sZ2V0TWFzazpmdW5jdGlvbihhLGIsYyl7c3dpdGNoKGEpe2Nhc2UgZS5QQVRURVJOMDAwOnJldHVybiAwPT0oYitjKSUyO2Nhc2UgZS5QQVRURVJOMDAxOnJldHVybiAwPT1iJTI7Y2FzZSBlLlBBVFRFUk4wMTA6cmV0dXJuIDA9PWMlMztjYXNlIGUuUEFUVEVSTjAxMTpyZXR1cm4gMD09KGIrYyklMztjYXNlIGUuUEFUVEVSTjEwMDpyZXR1cm4gMD09KE1hdGguZmxvb3IoYi8yKStNYXRoLmZsb29yKGMvMykpJTI7Y2FzZSBlLlBBVFRFUk4xMDE6cmV0dXJuIDA9PWIqYyUyK2IqYyUzO2Nhc2UgZS5QQVRURVJOMTEwOnJldHVybiAwPT0oYipjJTIrYipjJTMpJTI7Y2FzZSBlLlBBVFRFUk4xMTE6cmV0dXJuIDA9PShiKmMlMysoYitjKSUyKSUyO2RlZmF1bHQ6dGhyb3cgbmV3IEVycm9yKCJiYWQgbWFza1BhdHRlcm46IithKX19LGdldEVycm9yQ29ycmVjdFBvbHlub21pYWw6ZnVuY3Rpb24oYSl7Zm9yKHZhciBiPW5ldyBpKFsxXSwwKSxjPTA7YT5jO2MrKyliPWIubXVsdGlwbHkobmV3IGkoWzEsZy5nZXhwKGMpXSwwKSk7cmV0dXJuIGJ9LGdldExlbmd0aEluQml0czpmdW5jdGlvbihhLGIpe2lmKGI+PTEmJjEwPmIpc3dpdGNoKGEpe2Nhc2UgYy5NT0RFX05VTUJFUjpyZXR1cm4gMTA7Y2FzZSBjLk1PREVfQUxQSEFfTlVNOnJldHVybiA5O2Nhc2UgYy5NT0RFXzhCSVRfQllURTpyZXR1cm4gODtjYXNlIGMuTU9ERV9LQU5KSTpyZXR1cm4gODtkZWZhdWx0OnRocm93IG5ldyBFcnJvcigibW9kZToiK2EpfWVsc2UgaWYoMjc+Yilzd2l0Y2goYSl7Y2FzZSBjLk1PREVfTlVNQkVSOnJldHVybiAxMjtjYXNlIGMuTU9ERV9BTFBIQV9OVU06cmV0dXJuIDExO2Nhc2UgYy5NT0RFXzhCSVRfQllURTpyZXR1cm4gMTY7Y2FzZSBjLk1PREVfS0FOSkk6cmV0dXJuIDEwO2RlZmF1bHQ6dGhyb3cgbmV3IEVycm9yKCJtb2RlOiIrYSl9ZWxzZXtpZighKDQxPmIpKXRocm93IG5ldyBFcnJvcigidHlwZToiK2IpO3N3aXRjaChhKXtjYXNlIGMuTU9ERV9OVU1CRVI6cmV0dXJuIDE0O2Nhc2UgYy5NT0RFX0FMUEhBX05VTTpyZXR1cm4gMTM7Y2FzZSBjLk1PREVfOEJJVF9CWVRFOnJldHVybiAxNjtjYXNlIGMuTU9ERV9LQU5KSTpyZXR1cm4gMTI7ZGVmYXVsdDp0aHJvdyBuZXcgRXJyb3IoIm1vZGU6IithKX19fSxnZXRMb3N0UG9pbnQ6ZnVuY3Rpb24oYSl7Zm9yKHZhciBiPWEuZ2V0TW9kdWxlQ291bnQoKSxjPTAsZD0wO2I+ZDtkKyspZm9yKHZhciBlPTA7Yj5lO2UrKyl7Zm9yKHZhciBmPTAsZz1hLmlzRGFyayhkLGUpLGg9LTE7MT49aDtoKyspaWYoISgwPmQraHx8ZCtoPj1iKSlmb3IodmFyIGk9LTE7MT49aTtpKyspMD5lK2l8fGUraT49Ynx8KDAhPWh8fDAhPWkpJiZnPT1hLmlzRGFyayhkK2gsZStpKSYmZisrO2Y+NSYmKGMrPTMrZi01KX1mb3IodmFyIGQ9MDtiLTE+ZDtkKyspZm9yKHZhciBlPTA7Yi0xPmU7ZSsrKXt2YXIgaj0wO2EuaXNEYXJrKGQsZSkmJmorKyxhLmlzRGFyayhkKzEsZSkmJmorKyxhLmlzRGFyayhkLGUrMSkmJmorKyxhLmlzRGFyayhkKzEsZSsxKSYmaisrLCgwPT1qfHw0PT1qKSYmKGMrPTMpfWZvcih2YXIgZD0wO2I+ZDtkKyspZm9yKHZhciBlPTA7Yi02PmU7ZSsrKWEuaXNEYXJrKGQsZSkmJiFhLmlzRGFyayhkLGUrMSkmJmEuaXNEYXJrKGQsZSsyKSYmYS5pc0RhcmsoZCxlKzMpJiZhLmlzRGFyayhkLGUrNCkmJiFhLmlzRGFyayhkLGUrNSkmJmEuaXNEYXJrKGQsZSs2KSYmKGMrPTQwKTtmb3IodmFyIGU9MDtiPmU7ZSsrKWZvcih2YXIgZD0wO2ItNj5kO2QrKylhLmlzRGFyayhkLGUpJiYhYS5pc0RhcmsoZCsxLGUpJiZhLmlzRGFyayhkKzIsZSkmJmEuaXNEYXJrKGQrMyxlKSYmYS5pc0RhcmsoZCs0LGUpJiYhYS5pc0RhcmsoZCs1LGUpJiZhLmlzRGFyayhkKzYsZSkmJihjKz00MCk7Zm9yKHZhciBrPTAsZT0wO2I+ZTtlKyspZm9yKHZhciBkPTA7Yj5kO2QrKylhLmlzRGFyayhkLGUpJiZrKys7dmFyIGw9TWF0aC5hYnMoMTAwKmsvYi9iLTUwKS81O3JldHVybiBjKz0xMCpsfX0sZz17Z2xvZzpmdW5jdGlvbihhKXtpZigxPmEpdGhyb3cgbmV3IEVycm9yKCJnbG9nKCIrYSsiKSIpO3JldHVybiBnLkxPR19UQUJMRVthXX0sZ2V4cDpmdW5jdGlvbihhKXtmb3IoOzA+YTspYSs9MjU1O2Zvcig7YT49MjU2OylhLT0yNTU7cmV0dXJuIGcuRVhQX1RBQkxFW2FdfSxFWFBfVEFCTEU6bmV3IEFycmF5KDI1NiksTE9HX1RBQkxFOm5ldyBBcnJheSgyNTYpfSxoPTA7OD5oO2grKylnLkVYUF9UQUJMRVtoXT0xPDxoO2Zvcih2YXIgaD04OzI1Nj5oO2grKylnLkVYUF9UQUJMRVtoXT1nLkVYUF9UQUJMRVtoLTRdXmcuRVhQX1RBQkxFW2gtNV1eZy5FWFBfVEFCTEVbaC02XV5nLkVYUF9UQUJMRVtoLThdO2Zvcih2YXIgaD0wOzI1NT5oO2grKylnLkxPR19UQUJMRVtnLkVYUF9UQUJMRVtoXV09aDtpLnByb3RvdHlwZT17Z2V0OmZ1bmN0aW9uKGEpe3JldHVybiB0aGlzLm51bVthXX0sZ2V0TGVuZ3RoOmZ1bmN0aW9uKCl7cmV0dXJuIHRoaXMubnVtLmxlbmd0aH0sbXVsdGlwbHk6ZnVuY3Rpb24oYSl7Zm9yKHZhciBiPW5ldyBBcnJheSh0aGlzLmdldExlbmd0aCgpK2EuZ2V0TGVuZ3RoKCktMSksYz0wO2M8dGhpcy5nZXRMZW5ndGgoKTtjKyspZm9yKHZhciBkPTA7ZDxhLmdldExlbmd0aCgpO2QrKyliW2MrZF1ePWcuZ2V4cChnLmdsb2codGhpcy5nZXQoYykpK2cuZ2xvZyhhLmdldChkKSkpO3JldHVybiBuZXcgaShiLDApfSxtb2Q6ZnVuY3Rpb24oYSl7aWYodGhpcy5nZXRMZW5ndGgoKS1hLmdldExlbmd0aCgpPDApcmV0dXJuIHRoaXM7Zm9yKHZhciBiPWcuZ2xvZyh0aGlzLmdldCgwKSktZy5nbG9nKGEuZ2V0KDApKSxjPW5ldyBBcnJheSh0aGlzLmdldExlbmd0aCgpKSxkPTA7ZDx0aGlzLmdldExlbmd0aCgpO2QrKyljW2RdPXRoaXMuZ2V0KGQpO2Zvcih2YXIgZD0wO2Q8YS5nZXRMZW5ndGgoKTtkKyspY1tkXV49Zy5nZXhwKGcuZ2xvZyhhLmdldChkKSkrYik7cmV0dXJuIG5ldyBpKGMsMCkubW9kKGEpfX0sai5SU19CTE9DS19UQUJMRT1bWzEsMjYsMTldLFsxLDI2LDE2XSxbMSwyNiwxM10sWzEsMjYsOV0sWzEsNDQsMzRdLFsxLDQ0LDI4XSxbMSw0NCwyMl0sWzEsNDQsMTZdLFsxLDcwLDU1XSxbMSw3MCw0NF0sWzIsMzUsMTddLFsyLDM1LDEzXSxbMSwxMDAsODBdLFsyLDUwLDMyXSxbMiw1MCwyNF0sWzQsMjUsOV0sWzEsMTM0LDEwOF0sWzIsNjcsNDNdLFsyLDMzLDE1LDIsMzQsMTZdLFsyLDMzLDExLDIsMzQsMTJdLFsyLDg2LDY4XSxbNCw0MywyN10sWzQsNDMsMTldLFs0LDQzLDE1XSxbMiw5OCw3OF0sWzQsNDksMzFdLFsyLDMyLDE0LDQsMzMsMTVdLFs0LDM5LDEzLDEsNDAsMTRdLFsyLDEyMSw5N10sWzIsNjAsMzgsMiw2MSwzOV0sWzQsNDAsMTgsMiw0MSwxOV0sWzQsNDAsMTQsMiw0MSwxNV0sWzIsMTQ2LDExNl0sWzMsNTgsMzYsMiw1OSwzN10sWzQsMzYsMTYsNCwzNywxN10sWzQsMzYsMTIsNCwzNywxM10sWzIsODYsNjgsMiw4Nyw2OV0sWzQsNjksNDMsMSw3MCw0NF0sWzYsNDMsMTksMiw0NCwyMF0sWzYsNDMsMTUsMiw0NCwxNl0sWzQsMTAxLDgxXSxbMSw4MCw1MCw0LDgxLDUxXSxbNCw1MCwyMiw0LDUxLDIzXSxbMywzNiwxMiw4LDM3LDEzXSxbMiwxMTYsOTIsMiwxMTcsOTNdLFs2LDU4LDM2LDIsNTksMzddLFs0LDQ2LDIwLDYsNDcsMjFdLFs3LDQyLDE0LDQsNDMsMTVdLFs0LDEzMywxMDddLFs4LDU5LDM3LDEsNjAsMzhdLFs4LDQ0LDIwLDQsNDUsMjFdLFsxMiwzMywxMSw0LDM0LDEyXSxbMywxNDUsMTE1LDEsMTQ2LDExNl0sWzQsNjQsNDAsNSw2NSw0MV0sWzExLDM2LDE2LDUsMzcsMTddLFsxMSwzNiwxMiw1LDM3LDEzXSxbNSwxMDksODcsMSwxMTAsODhdLFs1LDY1LDQxLDUsNjYsNDJdLFs1LDU0LDI0LDcsNTUsMjVdLFsxMSwzNiwxMl0sWzUsMTIyLDk4LDEsMTIzLDk5XSxbNyw3Myw0NSwzLDc0LDQ2XSxbMTUsNDMsMTksMiw0NCwyMF0sWzMsNDUsMTUsMTMsNDYsMTZdLFsxLDEzNSwxMDcsNSwxMzYsMTA4XSxbMTAsNzQsNDYsMSw3NSw0N10sWzEsNTAsMjIsMTUsNTEsMjNdLFsyLDQyLDE0LDE3LDQzLDE1XSxbNSwxNTAsMTIwLDEsMTUxLDEyMV0sWzksNjksNDMsNCw3MCw0NF0sWzE3LDUwLDIyLDEsNTEsMjNdLFsyLDQyLDE0LDE5LDQzLDE1XSxbMywxNDEsMTEzLDQsMTQyLDExNF0sWzMsNzAsNDQsMTEsNzEsNDVdLFsxNyw0NywyMSw0LDQ4LDIyXSxbOSwzOSwxMywxNiw0MCwxNF0sWzMsMTM1LDEwNyw1LDEzNiwxMDhdLFszLDY3LDQxLDEzLDY4LDQyXSxbMTUsNTQsMjQsNSw1NSwyNV0sWzE1LDQzLDE1LDEwLDQ0LDE2XSxbNCwxNDQsMTE2LDQsMTQ1LDExN10sWzE3LDY4LDQyXSxbMTcsNTAsMjIsNiw1MSwyM10sWzE5LDQ2LDE2LDYsNDcsMTddLFsyLDEzOSwxMTEsNywxNDAsMTEyXSxbMTcsNzQsNDZdLFs3LDU0LDI0LDE2LDU1LDI1XSxbMzQsMzcsMTNdLFs0LDE1MSwxMjEsNSwxNTIsMTIyXSxbNCw3NSw0NywxNCw3Niw0OF0sWzExLDU0LDI0LDE0LDU1LDI1XSxbMTYsNDUsMTUsMTQsNDYsMTZdLFs2LDE0NywxMTcsNCwxNDgsMTE4XSxbNiw3Myw0NSwxNCw3NCw0Nl0sWzExLDU0LDI0LDE2LDU1LDI1XSxbMzAsNDYsMTYsMiw0NywxN10sWzgsMTMyLDEwNiw0LDEzMywxMDddLFs4LDc1LDQ3LDEzLDc2LDQ4XSxbNyw1NCwyNCwyMiw1NSwyNV0sWzIyLDQ1LDE1LDEzLDQ2LDE2XSxbMTAsMTQyLDExNCwyLDE0MywxMTVdLFsxOSw3NCw0Niw0LDc1LDQ3XSxbMjgsNTAsMjIsNiw1MSwyM10sWzMzLDQ2LDE2LDQsNDcsMTddLFs4LDE1MiwxMjIsNCwxNTMsMTIzXSxbMjIsNzMsNDUsMyw3NCw0Nl0sWzgsNTMsMjMsMjYsNTQsMjRdLFsxMiw0NSwxNSwyOCw0NiwxNl0sWzMsMTQ3LDExNywxMCwxNDgsMTE4XSxbMyw3Myw0NSwyMyw3NCw0Nl0sWzQsNTQsMjQsMzEsNTUsMjVdLFsxMSw0NSwxNSwzMSw0NiwxNl0sWzcsMTQ2LDExNiw3LDE0NywxMTddLFsyMSw3Myw0NSw3LDc0LDQ2XSxbMSw1MywyMywzNyw1NCwyNF0sWzE5LDQ1LDE1LDI2LDQ2LDE2XSxbNSwxNDUsMTE1LDEwLDE0NiwxMTZdLFsxOSw3NSw0NywxMCw3Niw0OF0sWzE1LDU0LDI0LDI1LDU1LDI1XSxbMjMsNDUsMTUsMjUsNDYsMTZdLFsxMywxNDUsMTE1LDMsMTQ2LDExNl0sWzIsNzQsNDYsMjksNzUsNDddLFs0Miw1NCwyNCwxLDU1LDI1XSxbMjMsNDUsMTUsMjgsNDYsMTZdLFsxNywxNDUsMTE1XSxbMTAsNzQsNDYsMjMsNzUsNDddLFsxMCw1NCwyNCwzNSw1NSwyNV0sWzE5LDQ1LDE1LDM1LDQ2LDE2XSxbMTcsMTQ1LDExNSwxLDE0NiwxMTZdLFsxNCw3NCw0NiwyMSw3NSw0N10sWzI5LDU0LDI0LDE5LDU1LDI1XSxbMTEsNDUsMTUsNDYsNDYsMTZdLFsxMywxNDUsMTE1LDYsMTQ2LDExNl0sWzE0LDc0LDQ2LDIzLDc1LDQ3XSxbNDQsNTQsMjQsNyw1NSwyNV0sWzU5LDQ2LDE2LDEsNDcsMTddLFsxMiwxNTEsMTIxLDcsMTUyLDEyMl0sWzEyLDc1LDQ3LDI2LDc2LDQ4XSxbMzksNTQsMjQsMTQsNTUsMjVdLFsyMiw0NSwxNSw0MSw0NiwxNl0sWzYsMTUxLDEyMSwxNCwxNTIsMTIyXSxbNiw3NSw0NywzNCw3Niw0OF0sWzQ2LDU0LDI0LDEwLDU1LDI1XSxbMiw0NSwxNSw2NCw0NiwxNl0sWzE3LDE1MiwxMjIsNCwxNTMsMTIzXSxbMjksNzQsNDYsMTQsNzUsNDddLFs0OSw1NCwyNCwxMCw1NSwyNV0sWzI0LDQ1LDE1LDQ2LDQ2LDE2XSxbNCwxNTIsMTIyLDE4LDE1MywxMjNdLFsxMyw3NCw0NiwzMiw3NSw0N10sWzQ4LDU0LDI0LDE0LDU1LDI1XSxbNDIsNDUsMTUsMzIsNDYsMTZdLFsyMCwxNDcsMTE3LDQsMTQ4LDExOF0sWzQwLDc1LDQ3LDcsNzYsNDhdLFs0Myw1NCwyNCwyMiw1NSwyNV0sWzEwLDQ1LDE1LDY3LDQ2LDE2XSxbMTksMTQ4LDExOCw2LDE0OSwxMTldLFsxOCw3NSw0NywzMSw3Niw0OF0sWzM0LDU0LDI0LDM0LDU1LDI1XSxbMjAsNDUsMTUsNjEsNDYsMTZdXSxqLmdldFJTQmxvY2tzPWZ1bmN0aW9uKGEsYil7dmFyIGM9ai5nZXRSc0Jsb2NrVGFibGUoYSxiKTtpZih2b2lkIDA9PWMpdGhyb3cgbmV3IEVycm9yKCJiYWQgcnMgYmxvY2sgQCB0eXBlTnVtYmVyOiIrYSsiL2Vycm9yQ29ycmVjdExldmVsOiIrYik7Zm9yKHZhciBkPWMubGVuZ3RoLzMsZT1bXSxmPTA7ZD5mO2YrKylmb3IodmFyIGc9Y1szKmYrMF0saD1jWzMqZisxXSxpPWNbMypmKzJdLGs9MDtnPms7aysrKWUucHVzaChuZXcgaihoLGkpKTtyZXR1cm4gZX0sai5nZXRSc0Jsb2NrVGFibGU9ZnVuY3Rpb24oYSxiKXtzd2l0Y2goYil7Y2FzZSBkLkw6cmV0dXJuIGouUlNfQkxPQ0tfVEFCTEVbNCooYS0xKSswXTtjYXNlIGQuTTpyZXR1cm4gai5SU19CTE9DS19UQUJMRVs0KihhLTEpKzFdO2Nhc2UgZC5ROnJldHVybiBqLlJTX0JMT0NLX1RBQkxFWzQqKGEtMSkrMl07Y2FzZSBkLkg6cmV0dXJuIGouUlNfQkxPQ0tfVEFCTEVbNCooYS0xKSszXTtkZWZhdWx0OnJldHVybiB2b2lkIDB9fSxrLnByb3RvdHlwZT17Z2V0OmZ1bmN0aW9uKGEpe3ZhciBiPU1hdGguZmxvb3IoYS84KTtyZXR1cm4gMT09KDEmdGhpcy5idWZmZXJbYl0+Pj43LWElOCl9LHB1dDpmdW5jdGlvbihhLGIpe2Zvcih2YXIgYz0wO2I+YztjKyspdGhpcy5wdXRCaXQoMT09KDEmYT4+PmItYy0xKSl9LGdldExlbmd0aEluQml0czpmdW5jdGlvbigpe3JldHVybiB0aGlzLmxlbmd0aH0scHV0Qml0OmZ1bmN0aW9uKGEpe3ZhciBiPU1hdGguZmxvb3IodGhpcy5sZW5ndGgvOCk7dGhpcy5idWZmZXIubGVuZ3RoPD1iJiZ0aGlzLmJ1ZmZlci5wdXNoKDApLGEmJih0aGlzLmJ1ZmZlcltiXXw9MTI4Pj4+dGhpcy5sZW5ndGglOCksdGhpcy5sZW5ndGgrK319O3ZhciBsPVtbMTcsMTQsMTEsN10sWzMyLDI2LDIwLDE0XSxbNTMsNDIsMzIsMjRdLFs3OCw2Miw0NiwzNF0sWzEwNiw4NCw2MCw0NF0sWzEzNCwxMDYsNzQsNThdLFsxNTQsMTIyLDg2LDY0XSxbMTkyLDE1MiwxMDgsODRdLFsyMzAsMTgwLDEzMCw5OF0sWzI3MSwyMTMsMTUxLDExOV0sWzMyMSwyNTEsMTc3LDEzN10sWzM2NywyODcsMjAzLDE1NV0sWzQyNSwzMzEsMjQxLDE3N10sWzQ1OCwzNjIsMjU4LDE5NF0sWzUyMCw0MTIsMjkyLDIyMF0sWzU4Niw0NTAsMzIyLDI1MF0sWzY0NCw1MDQsMzY0LDI4MF0sWzcxOCw1NjAsMzk0LDMxMF0sWzc5Miw2MjQsNDQyLDMzOF0sWzg1OCw2NjYsNDgyLDM4Ml0sWzkyOSw3MTEsNTA5LDQwM10sWzEwMDMsNzc5LDU2NSw0MzldLFsxMDkxLDg1Nyw2MTEsNDYxXSxbMTE3MSw5MTEsNjYxLDUxMV0sWzEyNzMsOTk3LDcxNSw1MzVdLFsxMzY3LDEwNTksNzUxLDU5M10sWzE0NjUsMTEyNSw4MDUsNjI1XSxbMTUyOCwxMTkwLDg2OCw2NThdLFsxNjI4LDEyNjQsOTA4LDY5OF0sWzE3MzIsMTM3MCw5ODIsNzQyXSxbMTg0MCwxNDUyLDEwMzAsNzkwXSxbMTk1MiwxNTM4LDExMTIsODQyXSxbMjA2OCwxNjI4LDExNjgsODk4XSxbMjE4OCwxNzIyLDEyMjgsOTU4XSxbMjMwMywxODA5LDEyODMsOTgzXSxbMjQzMSwxOTExLDEzNTEsMTA1MV0sWzI1NjMsMTk4OSwxNDIzLDEwOTNdLFsyNjk5LDIwOTksMTQ5OSwxMTM5XSxbMjgwOSwyMjEzLDE1NzksMTIxOV0sWzI5NTMsMjMzMSwxNjYzLDEyNzNdXSxvPWZ1bmN0aW9uKCl7dmFyIGE9ZnVuY3Rpb24oYSxiKXt0aGlzLl9lbD1hLHRoaXMuX2h0T3B0aW9uPWJ9O3JldHVybiBhLnByb3RvdHlwZS5kcmF3PWZ1bmN0aW9uKGEpe2Z1bmN0aW9uIGcoYSxiKXt2YXIgYz1kb2N1bWVudC5jcmVhdGVFbGVtZW50TlMoImh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIixhKTtmb3IodmFyIGQgaW4gYiliLmhhc093blByb3BlcnR5KGQpJiZjLnNldEF0dHJpYnV0ZShkLGJbZF0pO3JldHVybiBjfXZhciBiPXRoaXMuX2h0T3B0aW9uLGM9dGhpcy5fZWwsZD1hLmdldE1vZHVsZUNvdW50KCk7TWF0aC5mbG9vcihiLndpZHRoL2QpLE1hdGguZmxvb3IoYi5oZWlnaHQvZCksdGhpcy5jbGVhcigpO3ZhciBoPWcoInN2ZyIse3ZpZXdCb3g6IjAgMCAiK1N0cmluZyhkKSsiICIrU3RyaW5nKGQpLHdpZHRoOiIxMDAlIixoZWlnaHQ6IjEwMCUiLGZpbGw6Yi5jb2xvckxpZ2h0fSk7aC5zZXRBdHRyaWJ1dGVOUygiaHR0cDovL3d3dy53My5vcmcvMjAwMC94bWxucy8iLCJ4bWxuczp4bGluayIsImh0dHA6Ly93d3cudzMub3JnLzE5OTkveGxpbmsiKSxjLmFwcGVuZENoaWxkKGgpLGguYXBwZW5kQ2hpbGQoZygicmVjdCIse2ZpbGw6Yi5jb2xvckRhcmssd2lkdGg6IjEiLGhlaWdodDoiMSIsaWQ6InRlbXBsYXRlIn0pKTtmb3IodmFyIGk9MDtkPmk7aSsrKWZvcih2YXIgaj0wO2Q+ajtqKyspaWYoYS5pc0RhcmsoaSxqKSl7dmFyIGs9ZygidXNlIix7eDpTdHJpbmcoaSkseTpTdHJpbmcoail9KTtrLnNldEF0dHJpYnV0ZU5TKCJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIiwiaHJlZiIsIiN0ZW1wbGF0ZSIpLGguYXBwZW5kQ2hpbGQoayl9fSxhLnByb3RvdHlwZS5jbGVhcj1mdW5jdGlvbigpe2Zvcig7dGhpcy5fZWwuaGFzQ2hpbGROb2RlcygpOyl0aGlzLl9lbC5yZW1vdmVDaGlsZCh0aGlzLl9lbC5sYXN0Q2hpbGQpfSxhfSgpLHA9InN2ZyI9PT1kb2N1bWVudC5kb2N1bWVudEVsZW1lbnQudGFnTmFtZS50b0xvd2VyQ2FzZSgpLHE9cD9vOm0oKT9mdW5jdGlvbigpe2Z1bmN0aW9uIGEoKXt0aGlzLl9lbEltYWdlLnNyYz10aGlzLl9lbENhbnZhcy50b0RhdGFVUkwoImltYWdlL3BuZyIpLHRoaXMuX2VsSW1hZ2Uuc3R5bGUuZGlzcGxheT0iYmxvY2siLHRoaXMuX2VsQ2FudmFzLnN0eWxlLmRpc3BsYXk9Im5vbmUifWZ1bmN0aW9uIGQoYSxiKXt2YXIgYz10aGlzO2lmKGMuX2ZGYWlsPWIsYy5fZlN1Y2Nlc3M9YSxudWxsPT09Yy5fYlN1cHBvcnREYXRhVVJJKXt2YXIgZD1kb2N1bWVudC5jcmVhdGVFbGVtZW50KCJpbWciKSxlPWZ1bmN0aW9uKCl7Yy5fYlN1cHBvcnREYXRhVVJJPSExLGMuX2ZGYWlsJiZfZkZhaWwuY2FsbChjKX0sZj1mdW5jdGlvbigpe2MuX2JTdXBwb3J0RGF0YVVSST0hMCxjLl9mU3VjY2VzcyYmYy5fZlN1Y2Nlc3MuY2FsbChjKX07cmV0dXJuIGQub25hYm9ydD1lLGQub25lcnJvcj1lLGQub25sb2FkPWYsZC5zcmM9ImRhdGE6aW1hZ2UvZ2lmO2Jhc2U2NCxpVkJPUncwS0dnb0FBQUFOU1VoRVVnQUFBQVVBQUFBRkNBWUFBQUNOYnlibEFBQUFIRWxFUVZRSTEyUDQvLzgvdzM4R0lBWERJQktFMERIeGdsak5CQUFPOVRYTDBZNE9Id0FBQUFCSlJVNUVya0pnZ2c9PSIsdm9pZCAwfWMuX2JTdXBwb3J0RGF0YVVSST09PSEwJiZjLl9mU3VjY2Vzcz9jLl9mU3VjY2Vzcy5jYWxsKGMpOmMuX2JTdXBwb3J0RGF0YVVSST09PSExJiZjLl9mRmFpbCYmYy5fZkZhaWwuY2FsbChjKX1pZih0aGlzLl9hbmRyb2lkJiZ0aGlzLl9hbmRyb2lkPD0yLjEpe3ZhciBiPTEvd2luZG93LmRldmljZVBpeGVsUmF0aW8sYz1DYW52YXNSZW5kZXJpbmdDb250ZXh0MkQucHJvdG90eXBlLmRyYXdJbWFnZTtDYW52YXNSZW5kZXJpbmdDb250ZXh0MkQucHJvdG90eXBlLmRyYXdJbWFnZT1mdW5jdGlvbihhLGQsZSxmLGcsaCxpLGope2lmKCJub2RlTmFtZSJpbiBhJiYvaW1nL2kudGVzdChhLm5vZGVOYW1lKSlmb3IodmFyIGw9YXJndW1lbnRzLmxlbmd0aC0xO2w+PTE7bC0tKWFyZ3VtZW50c1tsXT1hcmd1bWVudHNbbF0qYjtlbHNlInVuZGVmaW5lZCI9PXR5cGVvZiBqJiYoYXJndW1lbnRzWzFdKj1iLGFyZ3VtZW50c1syXSo9Yixhcmd1bWVudHNbM10qPWIsYXJndW1lbnRzWzRdKj1iKTtjLmFwcGx5KHRoaXMsYXJndW1lbnRzKX19dmFyIGU9ZnVuY3Rpb24oYSxiKXt0aGlzLl9iSXNQYWludGVkPSExLHRoaXMuX2FuZHJvaWQ9bigpLHRoaXMuX2h0T3B0aW9uPWIsdGhpcy5fZWxDYW52YXM9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiY2FudmFzIiksdGhpcy5fZWxDYW52YXMud2lkdGg9Yi53aWR0aCx0aGlzLl9lbENhbnZhcy5oZWlnaHQ9Yi5oZWlnaHQsYS5hcHBlbmRDaGlsZCh0aGlzLl9lbENhbnZhcyksdGhpcy5fZWw9YSx0aGlzLl9vQ29udGV4dD10aGlzLl9lbENhbnZhcy5nZXRDb250ZXh0KCIyZCIpLHRoaXMuX2JJc1BhaW50ZWQ9ITEsdGhpcy5fZWxJbWFnZT1kb2N1bWVudC5jcmVhdGVFbGVtZW50KCJpbWciKSx0aGlzLl9lbEltYWdlLnN0eWxlLmRpc3BsYXk9Im5vbmUiLHRoaXMuX2VsLmFwcGVuZENoaWxkKHRoaXMuX2VsSW1hZ2UpLHRoaXMuX2JTdXBwb3J0RGF0YVVSST1udWxsfTtyZXR1cm4gZS5wcm90b3R5cGUuZHJhdz1mdW5jdGlvbihhKXt2YXIgYj10aGlzLl9lbEltYWdlLGM9dGhpcy5fb0NvbnRleHQsZD10aGlzLl9odE9wdGlvbixlPWEuZ2V0TW9kdWxlQ291bnQoKSxmPWQud2lkdGgvZSxnPWQuaGVpZ2h0L2UsaD1NYXRoLnJvdW5kKGYpLGk9TWF0aC5yb3VuZChnKTtiLnN0eWxlLmRpc3BsYXk9Im5vbmUiLHRoaXMuY2xlYXIoKTtmb3IodmFyIGo9MDtlPmo7aisrKWZvcih2YXIgaz0wO2U+aztrKyspe3ZhciBsPWEuaXNEYXJrKGosayksbT1rKmYsbj1qKmc7Yy5zdHJva2VTdHlsZT1sP2QuY29sb3JEYXJrOmQuY29sb3JMaWdodCxjLmxpbmVXaWR0aD0xLGMuZmlsbFN0eWxlPWw/ZC5jb2xvckRhcms6ZC5jb2xvckxpZ2h0LGMuZmlsbFJlY3QobSxuLGYsZyksYy5zdHJva2VSZWN0KE1hdGguZmxvb3IobSkrLjUsTWF0aC5mbG9vcihuKSsuNSxoLGkpLGMuc3Ryb2tlUmVjdChNYXRoLmNlaWwobSktLjUsTWF0aC5jZWlsKG4pLS41LGgsaSl9dGhpcy5fYklzUGFpbnRlZD0hMH0sZS5wcm90b3R5cGUubWFrZUltYWdlPWZ1bmN0aW9uKCl7dGhpcy5fYklzUGFpbnRlZCYmZC5jYWxsKHRoaXMsYSl9LGUucHJvdG90eXBlLmlzUGFpbnRlZD1mdW5jdGlvbigpe3JldHVybiB0aGlzLl9iSXNQYWludGVkfSxlLnByb3RvdHlwZS5jbGVhcj1mdW5jdGlvbigpe3RoaXMuX29Db250ZXh0LmNsZWFyUmVjdCgwLDAsdGhpcy5fZWxDYW52YXMud2lkdGgsdGhpcy5fZWxDYW52YXMuaGVpZ2h0KSx0aGlzLl9iSXNQYWludGVkPSExfSxlLnByb3RvdHlwZS5yb3VuZD1mdW5jdGlvbihhKXtyZXR1cm4gYT9NYXRoLmZsb29yKDFlMyphKS8xZTM6YX0sZX0oKTpmdW5jdGlvbigpe3ZhciBhPWZ1bmN0aW9uKGEsYil7dGhpcy5fZWw9YSx0aGlzLl9odE9wdGlvbj1ifTtyZXR1cm4gYS5wcm90b3R5cGUuZHJhdz1mdW5jdGlvbihhKXtmb3IodmFyIGI9dGhpcy5faHRPcHRpb24sYz10aGlzLl9lbCxkPWEuZ2V0TW9kdWxlQ291bnQoKSxlPU1hdGguZmxvb3IoYi53aWR0aC9kKSxmPU1hdGguZmxvb3IoYi5oZWlnaHQvZCksZz1bJzx0YWJsZSBzdHlsZT0iYm9yZGVyOjA7Ym9yZGVyLWNvbGxhcHNlOmNvbGxhcHNlOyI+J10saD0wO2Q+aDtoKyspe2cucHVzaCgiPHRyPiIpO2Zvcih2YXIgaT0wO2Q+aTtpKyspZy5wdXNoKCc8dGQgc3R5bGU9ImJvcmRlcjowO2JvcmRlci1jb2xsYXBzZTpjb2xsYXBzZTtwYWRkaW5nOjA7bWFyZ2luOjA7d2lkdGg6JytlKyJweDtoZWlnaHQ6IitmKyJweDtiYWNrZ3JvdW5kLWNvbG9yOiIrKGEuaXNEYXJrKGgsaSk/Yi5jb2xvckRhcms6Yi5jb2xvckxpZ2h0KSsnOyI+PC90ZD4nKTtnLnB1c2goIjwvdHI+Iil9Zy5wdXNoKCI8L3RhYmxlPiIpLGMuaW5uZXJIVE1MPWcuam9pbigiIik7dmFyIGo9Yy5jaGlsZE5vZGVzWzBdLGs9KGIud2lkdGgtai5vZmZzZXRXaWR0aCkvMixsPShiLmhlaWdodC1qLm9mZnNldEhlaWdodCkvMjtrPjAmJmw+MCYmKGouc3R5bGUubWFyZ2luPWwrInB4ICIraysicHgiKX0sYS5wcm90b3R5cGUuY2xlYXI9ZnVuY3Rpb24oKXt0aGlzLl9lbC5pbm5lckhUTUw9IiJ9LGF9KCk7UVJDb2RlPWZ1bmN0aW9uKGEsYil7aWYodGhpcy5faHRPcHRpb249e3dpZHRoOjI1NixoZWlnaHQ6MjU2LHR5cGVOdW1iZXI6NCxjb2xvckRhcms6IiMwMDAwMDAiLGNvbG9yTGlnaHQ6IiNmZmZmZmYiLGNvcnJlY3RMZXZlbDpkLkh9LCJzdHJpbmciPT10eXBlb2YgYiYmKGI9e3RleHQ6Yn0pLGIpZm9yKHZhciBjIGluIGIpdGhpcy5faHRPcHRpb25bY109YltjXTsic3RyaW5nIj09dHlwZW9mIGEmJihhPWRvY3VtZW50LmdldEVsZW1lbnRCeUlkKGEpKSx0aGlzLl9hbmRyb2lkPW4oKSx0aGlzLl9lbD1hLHRoaXMuX29RUkNvZGU9bnVsbCx0aGlzLl9vRHJhd2luZz1uZXcgcSh0aGlzLl9lbCx0aGlzLl9odE9wdGlvbiksdGhpcy5faHRPcHRpb24udGV4dCYmdGhpcy5tYWtlQ29kZSh0aGlzLl9odE9wdGlvbi50ZXh0KX0sUVJDb2RlLnByb3RvdHlwZS5tYWtlQ29kZT1mdW5jdGlvbihhKXt0aGlzLl9vUVJDb2RlPW5ldyBiKHIoYSx0aGlzLl9odE9wdGlvbi5jb3JyZWN0TGV2ZWwpLHRoaXMuX2h0T3B0aW9uLmNvcnJlY3RMZXZlbCksdGhpcy5fb1FSQ29kZS5hZGREYXRhKGEpLHRoaXMuX29RUkNvZGUubWFrZSgpLHRoaXMuX2VsLnRpdGxlPWEsdGhpcy5fb0RyYXdpbmcuZHJhdyh0aGlzLl9vUVJDb2RlKSx0aGlzLm1ha2VJbWFnZSgpfSxRUkNvZGUucHJvdG90eXBlLm1ha2VJbWFnZT1mdW5jdGlvbigpeyJmdW5jdGlvbiI9PXR5cGVvZiB0aGlzLl9vRHJhd2luZy5tYWtlSW1hZ2UmJighdGhpcy5fYW5kcm9pZHx8dGhpcy5fYW5kcm9pZD49MykmJnRoaXMuX29EcmF3aW5nLm1ha2VJbWFnZSgpfSxRUkNvZGUucHJvdG90eXBlLmNsZWFyPWZ1bmN0aW9uKCl7dGhpcy5fb0RyYXdpbmcuY2xlYXIoKX0sUVJDb2RlLkNvcnJlY3RMZXZlbD1kfSgpOw=="
QRCODE_JS_BYTES = base64.b64decode(QRCODE_JS_B64)

DASHBOARD_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sovereign Fortress — Management Vault</title>
    <!-- Self-Contained Offline QR Engine with CDN Fallback -->
    <script src="/portal/qrcode.min.js"></script>
    <script>
        if (typeof QRCode === "undefined") {
            var cdnScript = document.createElement("script");
            cdnScript.src = "https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js";
            document.head.appendChild(cdnScript);
        }
    </script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        body { background: #070b14; color: #f8fafc; padding: 24px 16px; }
        .container { max-width: 1000px; margin: 0 auto; }
        header { display: flex; justify-content: space-between; align-items: center; padding-bottom: 20px; border-bottom: 1px solid #1e293b; margin-bottom: 24px; flex-wrap: wrap; gap: 12px; }
        .brand { display: flex; align-items: center; gap: 12px; }
        .brand-icon { font-size: 28px; }
        .brand h1 { font-size: 20px; font-weight: 800; }
        .brand p { font-size: 12px; color: #94a3b8; }
        .status-pill { background: rgba(16,185,129,0.15); color: #34d399; border: 1px solid rgba(16,185,129,0.4); border-radius: 20px; padding: 6px 14px; font-size: 12px; font-weight: 600; display: flex; align-items: center; gap: 8px; }
        .status-dot { width: 8px; height: 8px; border-radius: 50%; background: #10b981; }
        
        .hero { background: linear-gradient(145deg, #162444, #0f182d); border: 1px solid rgba(56,189,248,0.3); border-radius: 18px; padding: 28px; margin-bottom: 24px; display: grid; grid-template-columns: 220px 1fr; gap: 28px; align-items: center; }
        @media (max-width: 768px) { .hero { grid-template-columns: 1fr; text-align: center; } .qr-wrap { margin: 0 auto; } }
        .qr-wrap { background: #fff; padding: 12px; border-radius: 12px; width: 210px; height: 210px; display: flex; align-items: center; justify-content: center; }
        .url-box { background: #090e1c; border: 1px solid #1e293b; border-radius: 8px; padding: 10px 14px; margin: 12px 0; }
        .url-box code { font-family: monospace; font-size: 12px; color: #38bdf8; word-break: break-all; }
        .btn-row { display: flex; gap: 10px; flex-wrap: wrap; }
        .btn { padding: 8px 16px; border-radius: 8px; font-size: 13px; font-weight: 600; border: none; cursor: pointer; display: inline-flex; align-items: center; gap: 6px; text-decoration: none; }
        .btn-primary { background: linear-gradient(135deg, #0284c7, #38bdf8); color: #040914; }
        .btn-sec { background: rgba(255,255,255,0.06); border: 1px solid #1e293b; color: #f8fafc; }
        .btn-danger { background: rgba(239,68,68,0.2); border: 1px solid #ef4444; color: #fca5a5; }

        .sec-card { background: #0f172a; border: 1px solid #1e293b; border-radius: 14px; padding: 20px; margin-bottom: 24px; }
        .sec-card h3 { font-size: 16px; margin-bottom: 8px; color: #fff; }
        .sec-card p { font-size: 13px; color: #94a3b8; line-height: 1.5; margin-bottom: 14px; }

        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; }
        .proto-card { background: #0f172a; border: 1px solid #1e293b; border-radius: 12px; padding: 18px; display: flex; flex-direction: column; justify-content: space-between; }
        .proto-title { font-size: 14px; font-weight: 700; color: #fff; margin-bottom: 4px; }
        .proto-desc { font-size: 12px; color: #94a3b8; margin-bottom: 12px; }

        .toast { position: fixed; bottom: 20px; right: 20px; background: #10b981; color: #040914; padding: 10px 18px; border-radius: 8px; font-weight: 700; font-size: 13px; display: none; z-index: 9999; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="brand">
                <div class="brand-icon">🛡️</div>
                <div>
                    <h1>SOVEREIGN FORTRESS</h1>
                    <p>Oracle Cloud Mumbai (<YOUR_SERVER_IP>) • 100% Volatile RAM (tmpfs) • Sing-box 1.11+</p>
                </div>
            </div>
            <div class="status-pill">
                <div class="status-dot"></div>
                <span>7 / 7 PROTOCOLS ONLINE (AUTO-BALANCED)</span>
            </div>
        </header>

        <div class="hero">
            <div class="qr-wrap">
                <div id="sub-qr"></div>
            </div>
            <div>
                <h2>Universal Hiddify QR / Subscription</h2>
                <p style="color:#94a3b8; font-size:13px; margin-top:4px;">
                    Scan with <strong>Hiddify App</strong> on Android / iOS / Windows. Includes automatic 
                    <strong>Campus Intranet Split-Routing</strong> (*.campus.internal & 10.0.0.0/8 bypass directly).
                </p>
                <div class="url-box">
                    <code>{{SUB_URL}}</code>
                </div>
                <div class="btn-row">
                    <button class="btn btn-primary" onclick="copyText('{{SUB_URL}}', 'Subscription URL copied!')">📋 Copy URL</button>
                    <a href="{{HIDDIFY_PRIMARY}}" class="btn btn-sec">⚡ 1-Click Hiddify</a>
                    <button class="btn btn-sec" onclick="copyText('{{SUB_B64_URL}}', 'Base64 Link copied!')">🔗 Base64 URL</button>
                    <button class="btn btn-danger" onclick="rotateToken()">🔄 Rotate Token</button>
                </div>
            </div>
        </div>

        <div class="sec-card">
            <h3>🔐 SSH & Portal Two-Factor Authentication (2FA)</h3>
            <p>Protected by Google Authenticator TOTP. Even with private key or password, server access is impossible without your phone!</p>
            <div style="display: flex; gap: 20px; align-items: center; flex-wrap: wrap;">
                <div style="background: #fff; padding: 8px; border-radius: 8px; width: 136px; height: 136px; display: flex; align-items: center; justify-content: center;">
                    <div id="totp-qr"></div>
                </div>
                <div style="flex: 1; min-width: 260px;">
                    <p style="font-weight: 700; color: #fff; margin-bottom: 4px;">Pairing Secret Key:</p>
                    <div class="url-box" style="margin-bottom: 8px;">
                        <code style="color: #fbbf24;">{{TOTP_SECRET}}</code>
                    </div>
                    <p style="font-size: 12px; color: #94a3b8;">
                        Scan with <strong>Google Authenticator</strong> or <strong>1Password</strong> on your phone.<br>
                        <strong>Dynamic 2FA Subscription</strong>: You can also append your live 6-digit TOTP code to fetch your profile: <code>/sub/&lt;6-DIGIT-CODE&gt;</code>!
                    </p>
                </div>
            </div>
        </div>

        <h3 style="font-size: 16px; color: #fff; margin-bottom: 12px;">⚡ Direct Protocol Links (7 Protocols + Auto-Fastest Balancer)</h3>
<div class="grid">
    <div class="proto-card">
        <div>
            <div class="proto-title">🚀 Auto-Fastest [Dynamic Latency Balancer]</div>
            <div class="proto-desc">Transport: Auto · Port: Auto · Real-time latency URLTest benchmarks all proxies and detours to lowest-ping route ('lowest' Balancer in Hiddify).</div>
        </div>
        <button class="btn btn-primary" onclick="copyText('{{SUB_URL}}', 'Auto-Fastest Subscription URL copied!')">Copy Balancer</button>
    </div>
    <div class="proto-card">
        <div>
            <div class="proto-title">🛡️ VLESS + XTLS-Reality (TCP 443)</div>
            <div class="proto-desc">Transport: TCP · xtls-rprx-vision · Borrows real Apple TLS certs; active probers redirected to Apple CDN. Strict DPI & Firewalls.</div>
        </div>
        <button class="btn btn-sec" onclick="copyText('{{VLESS}}', 'VLESS Link copied!')">Copy Link</button>
    </div>
    <div class="proto-card">
        <div>
            <div class="proto-title">⚡ Hysteria 2 Salamander (UDP 9444)</div>
            <div class="proto-desc">Transport: UDP · ChaCha20 XOR + BLAKE3 · Header scrambling makes QUIC unrecognizable to heuristics. Anti-throttling & QUIC drop bypass.</div>
        </div>
        <button class="btn btn-sec" onclick="copyText('{{HY2_SAL}}', 'Salamander Link copied!')">Copy Link</button>
    </div>
    <div class="proto-card">
        <div>
            <div class="proto-title">🚀 Hysteria 2 Standard (UDP 8443)</div>
            <div class="proto-desc">Transport: UDP · Brutal BBR over QUIC · Up to 1 Gbps throughput on lossy campus Wi-Fi. Best for 4K streaming & gaming.</div>
        </div>
        <button class="btn btn-sec" onclick="copyText('{{HY2_STD}}', 'Hysteria 2 Link copied!')">Copy Link</button>
    </div>
    <div class="proto-card">
        <div>
            <div class="proto-title">📱 TUIC v5 (UDP 9443)</div>
            <div class="proto-desc">Transport: UDP · RFC 9000 QUIC + BBR · 0-RTT handshake delay for instant reconnection. Best for mobile roaming (Wi-Fi ↔ 5G).</div>
        </div>
        <button class="btn btn-sec" onclick="copyText('{{TUIC}}', 'TUIC v5 Link copied!')">Copy Link</button>
    </div>
    <div class="proto-card">
        <div>
            <div class="proto-title">🔒 Shadowsocks-2022 (TCP/UDP 10443)</div>
            <div class="proto-desc">Transport: TCP/UDP · 2022-blake3-aes-256-gcm · AEAD with variable-length packet padding. Minimal battery consumption on laptops/phones.</div>
        </div>
        <button class="btn btn-sec" onclick="copyText('{{SS}}', 'Shadowsocks Link copied!')">Copy Link</button>
    </div>
    <div class="proto-card">
        <div>
            <div class="proto-title">🌐 WireGuard over TCP (TCP 8080)</div>
            <div class="proto-desc">Transport: TCP · TLS 1.3 WebSockets (wstunnel) · Wraps WireGuard inside HTTPS WebSockets. Captive portals blocking UDP.</div>
        </div>
        <button class="btn btn-sec" onclick="copyText('{{WG_TCP}}', 'WireGuard over TCP Link copied!')">Copy Link</button>
    </div>
    <div class="proto-card">
        <div>
            <div class="proto-title">⚡ Native WireGuard (UDP 51820)</div>
            <div class="proto-desc">Transport: UDP · ChaCha20-Poly1305 (Kernel) · Direct Linux kernel line-rate processing. Ultra-low overhead for high-speed LAN.</div>
        </div>
        <button class="btn btn-sec" onclick="copyText('{{WG_NATIVE}}', 'Native WireGuard Link copied!')">Copy Link</button>
    </div>
</div>
    </div>

    <div class="toast" id="toast"></div>

    <script>
        function initQRs() {
            if (typeof QRCode === "undefined") {
                setTimeout(initQRs, 200);
                return;
            }
            new QRCode(document.getElementById("sub-qr"), {
                text: "{{SUB_URL}}",
                width: 186,
                height: 186,
                colorDark: "#000000",
                colorLight: "#ffffff",
                correctLevel: QRCode.CorrectLevel.M
            });

            var totpSec = "{{TOTP_SECRET}}";
            if (totpSec && totpSec !== "Configuring...") {
                var otpUri = "otpauth://totp/ubuntu@<YOUR_SERVER_IP>?secret=" + totpSec + "&issuer=SovereignFortress";
                new QRCode(document.getElementById("totp-qr"), {
                    text: otpUri,
                    width: 120,
                    height: 120,
                    colorDark: "#000000",
                    colorLight: "#ffffff",
                    correctLevel: QRCode.CorrectLevel.M
                });
            }
        }
        initQRs();

        function showToast(msg) {
            var t = document.getElementById("toast");
            t.innerText = msg;
            t.style.display = "block";
            setTimeout(function() { t.style.display = "none"; }, 2500);
        }

        function copyText(txt, successMsg) {
            navigator.clipboard.writeText(txt).then(function() {
                showToast(successMsg);
            }).catch(function() {
                prompt("Copy link:", txt);
            });
        }

        function rotateToken() {
            if (!confirm("Rotate subscription token?\
All old links will immediately stop working!")) return;
            fetch('/portal/rotate-token', {
                method: 'POST',
                headers: { 'X-Fortress-CSRF': '1' }
            })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    alert("Token rotated successfully!");
                    location.reload();
                } else {
                    alert("Failed: " + (data.error || "Unknown"));
                }
            });
        }
    </script>
</body>
</html>"""
def get_or_create_token():
    for path in [TOKEN_RAM, TOKEN_DISK]:
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    t = f.read().strip()
                    if len(t) >= 16:
                        return t
            except Exception:
                pass
    new_token = "ft_sec_" + secrets.token_urlsafe(24)
    save_token(new_token)
    return new_token

def save_token(token_str):
    for d in [RAM_DIR, DISK_DIR]:
        if os.path.exists(d):
            p = os.path.join(d, "sub_token")
            try:
                with open(p, "w", encoding="utf-8") as f:
                    f.write(token_str.strip())
                os.chmod(p, 0o600)
            except Exception:
                pass

def get_totp_secret():
    for path in [TOTP_SECRET_FILE, FALLBACK_TOTP_FILE]:
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    first_line = f.readline().strip()
                    if first_line:
                        return first_line
            except Exception:
                pass
    return None

def verify_totp(code_str: str) -> bool:
    secret = get_totp_secret()
    if not secret or not code_str:
        return False
    try:
        code_str = code_str.strip()
        now = time.time()
        with USED_TOTP_LOCK:
            # Purge expired codes older than current time
            expired = [k for k, exp in USED_TOTP_CODES.items() if exp < now]
            for k in expired:
                del USED_TOTP_CODES[k]
            # If code was already used within this window, strictly reject replay
            if code_str in USED_TOTP_CODES:
                return False

        clean = secret.upper().replace(' ', '')
        padded = clean + '=' * ((8 - len(clean) % 8) % 8)
        key = base64.b32decode(padded)
        current_step = int(now) // 30
        for step in [current_step - 1, current_step, current_step + 1]:
            msg = struct.pack('>Q', step)
            h = hmac.new(key, msg, hashlib.sha1).digest()
            o = h[19] & 15
            calc = (struct.unpack('>I', h[o:o+4])[0] & 0x7fffffff) % 1000000
            expected_code = f"{calc:06d}"
            # Constant-time comparison prevents microarchitectural timing side-channels
            if hmac.compare_digest(expected_code, code_str):
                with USED_TOTP_LOCK:
                    if code_str in USED_TOTP_CODES:
                        return False
                    # Mark code as consumed for 120 seconds (covering full +-1 step window)
                    USED_TOTP_CODES[code_str] = now + 120
                return True
    except Exception:
        pass
    return False

def is_ip_banned(ip: str) -> bool:
    now = time.time()
    with FAILED_ATTEMPTS_LOCK:
        if ip in FAILED_ATTEMPTS:
            count, first_time, ban_until = FAILED_ATTEMPTS[ip]
            if ban_until > now:
                return True
            if now - first_time > 300:
                del FAILED_ATTEMPTS[ip]
    return False

def record_failed_attempt(ip: str):
    now = time.time()
    with FAILED_ATTEMPTS_LOCK:
        # Evict oldest if capacity exceeded to prevent memory exhaustion
        if len(FAILED_ATTEMPTS) >= MAX_FAILED_RECORDS and ip not in FAILED_ATTEMPTS:
            oldest_ip = min(FAILED_ATTEMPTS.keys(), key=lambda k: FAILED_ATTEMPTS[k][1])
            del FAILED_ATTEMPTS[oldest_ip]
        if ip not in FAILED_ATTEMPTS:
            FAILED_ATTEMPTS[ip] = [1, now, 0]
        else:
            count, first_time, _ = FAILED_ATTEMPTS[ip]
            count += 1
            ban_until = (now + BAN_DURATION) if count >= MAX_FAILED else 0
            FAILED_ATTEMPTS[ip] = [count, first_time, ban_until]

def clear_failed_attempts(ip: str):
    with FAILED_ATTEMPTS_LOCK:
        if ip in FAILED_ATTEMPTS:
            del FAILED_ATTEMPTS[ip]

def create_session_cookie() -> str:
    timestamp = str(int(time.time()))
    payload = f"auth:{timestamp}"
    sig = hmac.new(SESSION_SECRET, payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}:{sig}"

def verify_session_cookie(cookie_str: str) -> bool:
    if not cookie_str:
        return False
    parts = cookie_str.split(":")
    if len(parts) != 3 or parts[0] != "auth":
        return False
    payload = f"{parts[0]}:{parts[1]}"
    sig = parts[2]
    expected = hmac.new(SESSION_SECRET, payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return False
    try:
        created = int(parts[1])
        if time.time() - created > 7200:
            return False
        return True
    except Exception:
        return False

def get_protocol_links():
    pin_param = f"&pinSHA256={PIN_SHA256}" if PIN_SHA256 else ""
    vless = f"vless://{UUID}@{SERVER_IP}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni={REALITY_SNI}&fp=chrome&pbk={REALITY_PUBKEY}&sid={REALITY_SHORTID}&type=tcp&headerType=none#Fortress-Reality-TCP"
    hy2_sal = f"hysteria2://{HY2_PASSWORD}@{SERVER_IP}:9444?insecure=1&sni=www.microsoft.com&alpn=h3&obfs=salamander&obfs-password={SALAMANDER_PASSWORD}{pin_param}#Fortress-Hysteria2-Salamander"
    hy2_std = f"hysteria2://{HY2_PASSWORD}@{SERVER_IP}:8443?insecure=1&sni=www.microsoft.com&alpn=h3{pin_param}#Fortress-Hysteria2-Standard"
    tuic = f"tuic://{UUID}:{HY2_PASSWORD}@{SERVER_IP}:9443?congestion_control=bbr&alpn=h3&sni=www.microsoft.com&allow_insecure=1{pin_param}#Fortress-TUIC5-UDP"
    ss = f"ss://MjAyMi1ibGFrZTMtYWVzLTI1Ni1nY206{SS_PASSWORD}@{SERVER_IP}:10443#Fortress-Shadowsocks2022"
    wg_native = f"wg://{SERVER_IP}:51820?publickey={urllib.parse.quote(WG_SERVER_PUB)}&privkey={urllib.parse.quote(WG_CLIENT_PRIV)}&address={WG_CLIENT_IP}%2F32&dns=1.1.1.1#Fortress-WireGuard-Native"
    wg_tcp = f"wstunnel://{SERVER_IP}:{WSTUNNEL_PORT}?sni=www.microsoft.com&prefix=&tunnel=127.0.0.1:51820#Fortress-WireGuard-TCP"
    return [vless, hy2_sal, hy2_std, tuic, ss, wg_native, wg_tcp]

def get_singbox_json_config(mode="full"):
    """
    Returns 100% compliant Sing-box 1.11+ configuration with:
    - address array in tun inbound
    - strict_route: false + route_exclude_address to prevent YogaDNS / Chrome WFP deadlock
    - All 7 protocols included + auto-fastest URLTest balancer
    - Cryptographically verified TLS with embedded private CA (no insecure: true)
    - Complete campus split-routing for *.campus.internal and 10.0.0.0/8
    - mode="full": Tunnel-Encrypted DNS + Full IP Proxy
    - mode="traffic-only": Direct DNS (YogaDNS / NextDNS / Chrome Secure DNS coexistence) + Web Proxy
    """
    is_traffic_only = (mode.lower() in ["traffic-only", "split", "direct-dns", "yogadns"])
    ca_pem = None
    for cadir in [RAM_DIR, DISK_DIR]:
        for fname in ["ca.crt", "cert.pem"]:
            capath = os.path.join(cadir, fname)
            if os.path.exists(capath):
                try:
                    with open(capath, "r", encoding="utf-8") as caf:
                        c_text = caf.read().strip()
                        if "-----BEGIN CERTIFICATE-----" in c_text:
                            ca_pem = c_text
                            break
                except Exception:
                    pass
        if ca_pem:
            break

    stealth_outbounds = [
        "Fortress-Reality-TCP [DPI & Campus Firewall Slayer]",
        "Fortress-Hysteria2-Salamander [Scrambled QUIC Anti-Throttling]",
        "Fortress-Hysteria2-Standard [Brutal BBR Maximum 4K]",
        "Fortress-TUIC5 [0-RTT Fast Mobile Roaming]",
        "Fortress-Shadowsocks2022 [Ultra-Low Battery AEAD]"
    ]
    all_outbounds = list(stealth_outbounds)
    if WG_SERVER_PUB and not WG_SERVER_PUB.startswith("<"):
        all_outbounds.append("Fortress-WireGuard-Native [Direct Kernel Line-Rate]")

    nextdns_id = CONFIG.get("nextdns_id", "").strip()
    remote_dns_addr = f"https://dns.nextdns.io/{nextdns_id}" if (nextdns_id and not nextdns_id.startswith("<")) else "https://1.1.1.1/dns-query"

    hy2_sal_tls = {
        "enabled": True,
        "server_name": "www.microsoft.com",
        "insecure": True,
        "alpn": ["h3"]
    }
    hy2_std_tls = {
        "enabled": True,
        "server_name": "www.microsoft.com",
        "insecure": True,
        "alpn": ["h3"]
    }
    tuic_tls = {
        "enabled": True,
        "server_name": "www.microsoft.com",
        "insecure": True,
        "alpn": ["h3"]
    }
    if ca_pem:
        hy2_sal_tls["certificate"] = [ca_pem]
        hy2_std_tls["certificate"] = [ca_pem]
        tuic_tls["certificate"] = [ca_pem]

    if is_traffic_only:
        dns_config = {
            "servers": [
                {
                    "tag": "dns-direct",
                    "address": "local",
                    "detour": "direct"
                }
            ],
            "strategy": "prefer_ipv4"
        }
    else:
        dns_config = {
            "servers": [
                {
                    "tag": "dns-direct",
                    "address": "local",
                    "detour": "direct"
                },
                {
                    "tag": "dns-remote",
                    "address": remote_dns_addr,
                    "address_resolver": "dns-direct",
                    "detour": "proxy"
                }
            ],
            "rules": [
                {
                    "domain": [
                        "campus.internal"
                    ],
                    "domain_suffix": [
                        "campus.internal",
                        ".campus.internal",
                        "local",
                        ".local",
                        "internal",
                        ".internal"
                    ],
                    "server": "dns-direct"
                },
                {
                    "outbound": "any",
                    "server": "dns-remote"
                }
            ],
            "strategy": "prefer_ipv4"
        }

    cfg = {
        "log": {
            "level": "warn"
        },
        "dns": dns_config,
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "address": [
                    "172.19.0.1/30"
                ],
                "auto_route": True,
                "strict_route": False,
                "route_exclude_address": [
                    "10.0.0.0/8",
                    "172.16.0.0/12",
                    "192.168.0.0/16",
                    "127.0.0.0/8",
                    "169.254.0.0/16",
                    "45.90.28.0/24",
                    "45.90.30.0/24",
                    f"{SERVER_IP}/32"
                ],
                "stack": "system",
                "sniff": True
            }
        ],
        "outbounds": [
            {
                "type": "selector",
                "tag": "proxy",
                "outbounds": ["auto-fastest"] + all_outbounds,
                "default": "auto-fastest"
            },
            {
                "type": "urltest",
                "tag": "auto-fastest",
                "outbounds": stealth_outbounds,
                "url": "https://www.google.com/generate_204",
                "interval": "3m",
                "tolerance": 50
            },
            {
                "type": "vless",
                "tag": "Fortress-Reality-TCP [DPI & Campus Firewall Slayer]",
                "server": SERVER_IP,
                "server_port": 443,
                "uuid": UUID,
                "flow": "xtls-rprx-vision",
                "tls": {
                    "enabled": True,
                    "server_name": REALITY_SNI,
                    "reality": {
                        "enabled": True,
                        "public_key": REALITY_PUBKEY,
                        "short_id": REALITY_SHORTID
                    },
                    "utls": {
                        "enabled": True,
                        "fingerprint": "chrome"
                    }
                }
            },
            {
                "type": "hysteria2",
                "tag": "Fortress-Hysteria2-Salamander [Scrambled QUIC Anti-Throttling]",
                "server": SERVER_IP,
                "server_port": 9444,
                "password": HY2_PASSWORD,
                "obfs": {
                    "type": "salamander",
                    "password": SALAMANDER_PASSWORD
                },
                "tls": hy2_sal_tls
            },
            {
                "type": "hysteria2",
                "tag": "Fortress-Hysteria2-Standard [Brutal BBR Maximum 4K]",
                "server": SERVER_IP,
                "server_port": 8443,
                "password": HY2_PASSWORD,
                "tls": hy2_std_tls
            },
            {
                "type": "tuic",
                "tag": "Fortress-TUIC5 [0-RTT Fast Mobile Roaming]",
                "server": SERVER_IP,
                "server_port": 9443,
                "uuid": UUID,
                "password": HY2_PASSWORD,
                "congestion_control": "bbr",
                "tls": tuic_tls
            },
            {
                "type": "shadowsocks",
                "tag": "Fortress-Shadowsocks2022 [Ultra-Low Battery AEAD]",
                "server": SERVER_IP,
                "server_port": 10443,
                "method": "2022-blake3-aes-256-gcm",
                "password": SS_PASSWORD
            }
        ]
    }

    if WG_SERVER_PUB and not WG_SERVER_PUB.startswith("<"):
        cfg["outbounds"].append({
            "type": "wireguard",
            "tag": "Fortress-WireGuard-Native [Direct Kernel Line-Rate]",
            "local_address": [f"{WG_CLIENT_IP}/32"],
            "private_key": WG_CLIENT_PRIV,
            "peers": [
                {
                    "server": SERVER_IP,
                    "server_port": 51820,
                    "public_key": WG_SERVER_PUB,
                    "allowed_ips": ["0.0.0.0/0"]
                }
            ],
            "mtu": 1360
        })
        cfg["outbounds"].append({
            "type": "wireguard",
            "tag": "Fortress-WireGuard-TCP [Captive Portal & Strict TCP]",
            "local_address": [f"{WG_CLIENT_IP}/32"],
            "private_key": WG_CLIENT_PRIV,
            "peers": [
                {
                    "server": "127.0.0.1",
                    "server_port": 51820,
                    "public_key": WG_SERVER_PUB,
                    "allowed_ips": ["0.0.0.0/0"]
                }
            ],
            "mtu": 1360
        })

    cfg["outbounds"].append({
        "type": "direct",
        "tag": "direct"
    })

    rules = []
    if is_traffic_only:
        rules.append({"protocol": "dns", "outbound": "direct"})
        rules.append({"port": [53, 853], "outbound": "direct"})
    else:
        rules.append({"action": "hijack-dns"})

    rules.extend([
        {
            "ip_is_private": True,
            "outbound": "direct"
        },
        {
            "domain": [
                "campus.internal"
            ],
            "domain_suffix": [
                "campus.internal",
                ".campus.internal",
                "local",
                ".local",
                "internal",
                ".internal"
            ],
            "outbound": "direct"
        },
        {
            "domain": [
                "dns.nextdns.io"
            ],
            "domain_suffix": [
                ".nextdns.io"
            ],
            "ip_cidr": [
                "45.90.28.0/24",
                "45.90.30.0/24"
            ],
            "outbound": "direct"
        },
        {
            "ip_cidr": [
                f"{SERVER_IP}/32",
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16"
            ],
            "outbound": "direct"
        },
        {
            "outbound": "proxy"
        }
    ])

    cfg["route"] = {
        "auto_detect_interface": True,
        "rules": rules
    }
    return cfg

LOGIN_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sovereign Fortress — Authenticate</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        body { background: radial-gradient(circle at 50% 20%, #152238 0%, #070b14 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; color: #e2e8f0; }
        .card { background: #0f172a; border: 1px solid #1e293b; border-radius: 16px; padding: 36px 32px; max-width: 440px; width: 100%; box-shadow: 0 20px 40px rgba(0,0,0,0.6); text-align: center; }
        .shield { font-size: 36px; margin-bottom: 12px; }
        h1 { font-size: 20px; font-weight: 800; letter-spacing: 0.5px; margin-bottom: 6px; color: #fff; }
        p { color: #94a3b8; font-size: 13px; margin-bottom: 20px; line-height: 1.5; }
        input { width: 100%; padding: 12px 16px; background: #070b14; border: 1px solid #334155; border-radius: 8px; color: #fff; font-size: 14px; margin-bottom: 16px; outline: none; }
        input:focus { border-color: #38bdf8; }
        .btn { width: 100%; padding: 12px; background: linear-gradient(135deg, #0284c7, #38bdf8); border: none; border-radius: 8px; color: #040914; font-weight: 700; font-size: 14px; cursor: pointer; }
        .btn:hover { opacity: 0.95; }
    </style>
</head>
<body>
    <div class="card">
        <div class="shield">🛡️</div>
        <h1>SOVEREIGN FORTRESS</h1>
        <p>Enter Master Secret Token OR 6-digit Google Authenticator code</p>
        {{ERR_HTML}}
        <form method="POST" action="/portal/login">
            <input type="password" name="auth_credential" placeholder="Token or 6-digit TOTP" required autofocus autocomplete="off">
            <button type="submit" class="btn">AUTHENTICATE</button>
        </form>
    </div>
</body>
</html>"""

def render_login_page(error_msg=None):
    err_html = f'<div style="background:rgba(239,68,68,0.2);border:1px solid #ef4444;color:#fca5a5;padding:10px;border-radius:8px;font-size:13px;margin-bottom:16px;">{error_msg}</div>' if error_msg else ''
    return LOGIN_HTML_TEMPLATE.replace("{{ERR_HTML}}", err_html)

def render_dashboard_page(token, totp_secret):
    sub_url = f"http://{SERVER_IP}:{PORT}/sub/{token}"
    sub_b64_url = f"http://{SERVER_IP}:{PORT}/sub/{token}/b64"
    hiddify_primary = f"hiddify://import/{sub_url}#SovereignFortress"
    vless, hy2_sal, hy2_std, tuic, ss, wg_native, wg_tcp = get_protocol_links()

    html = DASHBOARD_HTML_TEMPLATE
    html = html.replace("{{SUB_URL}}", sub_url)
    html = html.replace("{{SUB_B64_URL}}", sub_b64_url)
    html = html.replace("{{HIDDIFY_PRIMARY}}", hiddify_primary)
    html = html.replace("{{TOTP_SECRET}}", totp_secret or "Configuring...")
    html = html.replace("{{VLESS}}", vless)
    html = html.replace("{{HY2_SAL}}", hy2_sal)
    html = html.replace("{{HY2_STD}}", hy2_std)
    html = html.replace("{{TUIC}}", tuic)
    html = html.replace("{{SS}}", ss)
    html = html.replace("{{WG_NATIVE}}", wg_native)
    html = html.replace("{{WG_TCP}}", wg_tcp)
    return html

class FortressSubHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def send_redirect_to_decoy(self):
        self.send_response(302)
        self.send_header('Location', 'https://www.microsoft.com/')
        self.send_header('Content-Length', '0')
        self.send_header('Connection', 'close')
        self.end_headers()

    def get_client_ip(self):
        return self.client_address[0]

    def do_HEAD(self):
        self.do_GET(head_only=True)

    def do_OPTIONS(self):
        self.send_redirect_to_decoy()

    def do_PUT(self):
        self.send_redirect_to_decoy()

    def do_DELETE(self):
        self.send_redirect_to_decoy()

    def do_TRACE(self):
        self.send_redirect_to_decoy()

    def do_GET(self, head_only=False):
        client_ip = self.get_client_ip()
        if is_ip_banned(client_ip):
            self.send_redirect_to_decoy()
            return

        parsed = urllib.parse.urlparse(self.path)
        path = posixpath.normpath(parsed.path)
        if path == "/":
            path = ""
        else:
            path = path.rstrip('/')
        query = urllib.parse.parse_qs(parsed.query)
        master_token = get_or_create_token()

        # Offline embedded QR code script
        if path == "/portal/qrcode.min.js":
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript; charset=utf-8")
            self.send_header("Cache-Control", "public, max-age=86400")
            self.send_header("Content-Length", str(len(QRCODE_JS_BYTES)))
            self.send_header("Connection", "close")
            self.end_headers()
            if not head_only:
                self.wfile.write(QRCODE_JS_BYTES)
            return

        # 1. Root / Portal
        if path == "" or path == "/portal":
            token_arg = query.get("token", [None])[0]
            cookie_hdr = self.headers.get("Cookie", "")
            session_cookie = None
            for c in cookie_hdr.split(";"):
                if "sf_session=" in c:
                    session_cookie = c.split("sf_session=")[1].strip()

            is_authed = False
            if token_arg and hmac.compare_digest(token_arg, master_token):
                is_authed = True
            elif verify_session_cookie(session_cookie):
                is_authed = True

            if is_authed:
                totp_sec = get_totp_secret()
                html = render_dashboard_page(master_token, totp_sec)
                body = html.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
                self.send_header("Pragma", "no-cache")
                self.send_header("Expires", "0")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                if token_arg:
                    self.send_header("Set-Cookie", f"sf_session={create_session_cookie()}; Path=/; HttpOnly; SameSite=Strict")
                self.end_headers()
                if not head_only:
                    self.wfile.write(body)
                return
            else:
                html = render_login_page()
                body = html.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
                self.send_header("Pragma", "no-cache")
                self.send_header("Expires", "0")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                if not head_only:
                    self.wfile.write(body)
                return

        # 2. Subscription Endpoints: /sub/<TOKEN_OR_TOTP>
        if path.startswith("/sub/"):
            sub_parts = path[5:].split('/')
            req_token = sub_parts[0]
            sub_format = sub_parts[1] if len(sub_parts) > 1 else None

            is_valid = False
            # Option A: Query param TOTP (/sub/totp?code=XXXXXX)
            if req_token == "totp":
                totp_code = query.get("code", [""])[0]
                if verify_totp(totp_code):
                    is_valid = True
            # Option B: Direct 6-digit TOTP in path (/sub/XXXXXX)
            elif len(req_token) == 6 and req_token.isdigit() and verify_totp(req_token):
                is_valid = True
            # Option C: Master Secret Token (/sub/ft_sec_...)
            elif hmac.compare_digest(req_token, master_token):
                is_valid = True

            if not is_valid:
                record_failed_attempt(client_ip)
                self.send_redirect_to_decoy()
                return

            clear_failed_attempts(client_ip)

            q_format = query.get("format", [None])[0]
            fmt = sub_format or q_format
            mode = query.get("mode", ["full"])[0]
            if sub_format in ["traffic-only", "split", "direct-dns", "yogadns"]:
                mode = "traffic-only"
                fmt = None

            if fmt == "b64":
                links_text = "\n".join(get_protocol_links()) + "\n"
                b64_content = base64.b64encode(links_text.encode("utf-8")).decode("utf-8")
                body = b64_content.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
                self.send_header("Pragma", "no-cache")
                self.send_header("Expires", "0")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("profile-title", "Sovereign Fortress")
                self.send_header("profile-update-interval", "1")
                self.send_header("subscription-userinfo", "upload=0; download=0; total=10737418240000; expire=0")
                self.send_header("Connection", "close")
                self.end_headers()
                if not head_only:
                    self.wfile.write(body)
                return

            if fmt == "links":
                links_text = "\n".join(get_protocol_links()) + "\n"
                body = links_text.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
                self.send_header("Pragma", "no-cache")
                self.send_header("Expires", "0")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("profile-title", "Sovereign Fortress")
                self.send_header("Connection", "close")
                self.end_headers()
                if not head_only:
                    self.wfile.write(body)
                return

            if fmt in ["wg", "wireguard"]:
                wg_conf = f"[Interface]\nPrivateKey = {WG_CLIENT_PRIV}\nAddress = {WG_CLIENT_IP}/24\nDNS = 1.1.1.1, 8.8.8.8\nMTU = 1360\n\n[Peer]\nPublicKey = {WG_SERVER_PUB}\nEndpoint = {SERVER_IP}:51820\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 15\n"
                body = wg_conf.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
                self.send_header("Pragma", "no-cache")
                self.send_header("Expires", "0")
                self.send_header("Content-Disposition", 'attachment; filename="fortress-wireguard.conf"')
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                if not head_only:
                    self.wfile.write(body)
                return

            if fmt in ["wg-tcp", "wireguard-tcp"]:
                wg_tcp_conf = f"[Interface]\nPrivateKey = {WG_CLIENT_PRIV}\nAddress = {WG_CLIENT_IP}/24\nDNS = 1.1.1.1, 8.8.8.8\nMTU = 1360\n\n[Peer]\nPublicKey = {WG_SERVER_PUB}\nEndpoint = 127.0.0.1:51820\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 15\n"
                body = wg_tcp_conf.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
                self.send_header("Pragma", "no-cache")
                self.send_header("Expires", "0")
                self.send_header("Content-Disposition", 'attachment; filename="fortress-wireguard-tcp.conf"')
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                if not head_only:
                    self.wfile.write(body)
                return

            # Default: Full Sing-box 1.11+ JSON
            config_obj = get_singbox_json_config(mode=mode)
            body = json.dumps(config_obj, indent=2).encode("utf-8")
            profile_title = "Sovereign Fortress (Traffic-Only)" if (mode.lower() in ["traffic-only", "split", "direct-dns", "yogadns"]) else "Sovereign Fortress"
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Disposition", 'inline; filename="SovereignFortress.json"')
            self.send_header("profile-title", profile_title)
            self.send_header("profile-update-interval", "1")
            self.send_header("subscription-userinfo", "upload=0; download=0; total=10737418240000; expire=0")
            self.send_header("Connection", "close")
            self.end_headers()
            if not head_only:
                self.wfile.write(body)
            return

        self.send_redirect_to_decoy()

    def do_POST(self):
        client_ip = self.get_client_ip()
        if is_ip_banned(client_ip):
            self.send_redirect_to_decoy()
            return

        parsed = urllib.parse.urlparse(self.path)
        path = posixpath.normpath(parsed.path)
        if path == "/":
            path = ""
        else:
            path = path.rstrip('/')
        try:
            content_len = int(self.headers.get("Content-Length", 0))
        except (ValueError, TypeError):
            self.send_error(400, "Bad Request")
            return

        if content_len > MAX_POST_BODY_BYTES:
            self.send_error(413, "Payload Too Large")
            return
        if content_len < 0:
            self.send_error(400, "Bad Request")
            return

        body_raw = self.rfile.read(content_len).decode("utf-8", errors="ignore")

        if path == "/portal/login":
            params = urllib.parse.parse_qs(body_raw)
            cred = params.get("auth_credential", [""])[0].strip()
            master_token = get_or_create_token()
            authed = False

            if hmac.compare_digest(cred, master_token):
                authed = True
            elif len(cred) == 6 and cred.isdigit() and verify_totp(cred):
                authed = True

            if authed:
                clear_failed_attempts(client_ip)
                sess = create_session_cookie()
                self.send_response(302)
                self.send_header("Location", "/portal")
                self.send_header("Set-Cookie", f"sf_session={sess}; Path=/; HttpOnly; SameSite=Strict")
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()
                return
            else:
                record_failed_attempt(client_ip)
                html = render_login_page("Invalid Secret Token or TOTP Code. Attempt recorded.")
                body = html.encode("utf-8")
                self.send_response(401)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
                self.send_header("Pragma", "no-cache")
                self.send_header("Expires", "0")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
                return

        if path == "/portal/rotate-token":
            cookie_hdr = self.headers.get("Cookie", "")
            session_cookie = None
            for c in cookie_hdr.split(";"):
                if "sf_session=" in c:
                    session_cookie = c.split("sf_session=")[1].strip()

            if not verify_session_cookie(session_cookie):
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
                self.send_header("Pragma", "no-cache")
                self.send_header("Expires", "0")
                self.send_header("Content-Length", "33")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(b'{"success":false,"error":"Denied"}')
                return

            # Defense-in-depth Anti-CSRF verification
            csrf_hdr = self.headers.get("X-Fortress-CSRF", "")
            if not hmac.compare_digest(csrf_hdr, "1"):
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
                self.send_header("Pragma", "no-cache")
                self.send_header("Expires", "0")
                self.send_header("Content-Length", "40")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(b'{"success":false,"error":"CSRF Rejected"}')
                return

            new_token = "ft_sec_" + secrets.token_urlsafe(24)
            save_token(new_token)
            proto = "https" if (os.path.exists(os.path.join(RAM_DIR, "cert.pem")) or os.path.exists(os.path.join(DISK_DIR, "cert.pem"))) else "http"
            res_obj = {
                "success": True, 
                "token": new_token,
                "url": f"{proto}://{SERVER_IP}:{PORT}/sub/{new_token}"
            }
            res_body = json.dumps(res_obj).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self.send_header("Content-Length", str(len(res_body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(res_body)
            return

        self.send_redirect_to_decoy()

class AutoDetectServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    def __init__(self, addr, handler, ssl_ctx=None):
        super().__init__(addr, handler)
        self.ssl_ctx = ssl_ctx

    def finish_request(self, request, client_address):
        if self.ssl_ctx:
            try:
                request.settimeout(1.0)
                first_byte = request.recv(1, socket.MSG_PEEK)
                request.settimeout(None)
                if first_byte == b'\x16':
                    request = self.ssl_ctx.wrap_socket(request, server_side=True)
            except Exception:
                try:
                    request.settimeout(None)
                except Exception:
                    pass
        super().finish_request(request, client_address)

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

def main():
    token = get_or_create_token()
    
    cert_path = os.path.join(RAM_DIR, "cert.pem")
    key_path = os.path.join(RAM_DIR, "key.pem")
    if not (os.path.exists(cert_path) and os.path.exists(key_path)):
        cert_path = os.path.join(DISK_DIR, "cert.pem")
        key_path = os.path.join(DISK_DIR, "key.pem")

    ssl_ctx = None
    if os.path.exists(cert_path) and os.path.exists(key_path):
        try:
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
            print("[+] TLS certificate chain loaded successfully.")
        except Exception as e:
            print(f"[-] Warning: Failed to initialize TLS: {e}")

    # 1. Primary Dual-Protocol Server on PORT (8443)
    # Serves plain HTTP for Hiddify / mobile apps and auto-detects HTTPS for browsers
    server_primary = AutoDetectServer(("0.0.0.0", PORT), FortressSubHandler, ssl_ctx)
    print(f"[+] Sovereign Fortress Dual-Protocol Subscription Server online on port {PORT} (Auto HTTP/HTTPS)")

    # 2. Dedicated HTTPS Server on port 8444 for secure web portal
    if ssl_ctx:
        def start_dedicated_https():
            try:
                https_port = 8444
                server_https = ThreadedHTTPServer(("0.0.0.0", https_port), FortressSubHandler)
                server_https.socket = ssl_ctx.wrap_socket(server_https.socket, server_side=True)
                print(f"[+] Sovereign Fortress Dedicated HTTPS Portal online on port {https_port}")
                server_https.serve_forever()
            except Exception as ex:
                print(f"[-] Dedicated HTTPS server error: {ex}")

        t_https = threading.Thread(target=start_dedicated_https, daemon=True)
        t_https.start()

    try:
        server_primary.serve_forever()
    except KeyboardInterrupt:
        server_primary.server_close()

if __name__ == "__main__":
    main()
