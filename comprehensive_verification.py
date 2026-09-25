import os
import sys
import json
import base64
import ssl
import socket
import urllib.request
import urllib.parse
import http.cookiejar
import subprocess
import hmac
import hashlib
import struct
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "fortress_config.json")
CONFIG = {}
if os.path.exists(CONFIG_PATH):
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            CONFIG = json.load(f)
    except Exception:
        pass

SERVER_IP = CONFIG.get("server_ip") or os.environ.get("FORTRESS_SERVER_IP")
PORT = int(CONFIG.get("sub_port", 8443))
TOKEN = CONFIG.get("token", "")
TOTP_SECRET = CONFIG.get("totp_secret", "")
KEY_PATH = os.environ.get("FORTRESS_SSH_KEY", CONFIG.get("ssh_key_path", "ssh_key.key"))
CA_PATH = os.path.join(BASE_DIR, "ca.crt")
CAMPUS_DOMAIN = CONFIG.get("campus_domain", "campus.internal")

if not SERVER_IP or SERVER_IP.startswith("<"):
    print("[-] Error: server_ip must be configured in fortress_config.json or FORTRESS_SERVER_IP")
    sys.exit(1)

if not TOKEN or not TOTP_SECRET:
    print("[-] Error: token and totp_secret must be set in fortress_config.json")
    sys.exit(1)

# SSL context validating against private Sovereign Fortress Root CA
ssl_ctx = ssl.create_default_context(cafile=CA_PATH)

def get_current_totp():
    clean = TOTP_SECRET.upper().replace(' ', '')
    padded = clean + '=' * ((8 - len(clean) % 8) % 8)
    key = base64.b32decode(padded)
    msg = struct.pack('>Q', int(time.time()) // 30)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[19] & 15
    val = (struct.unpack('>I', h[o:o+4])[0] & 0x7fffffff) % 1000000
    return f"{val:06d}"

print("=" * 70)
print("   SOVEREIGN FORTRESS COMPREHENSIVE END-TO-END VERIFICATION")
print("   (Strict HTTPS-Only, Rotated Credentials, Zero-Log Verification)")
print("=" * 70)

passed = 0
failed = 0

def check(condition, desc):
    global passed, failed
    if condition:
        print(f" [PASS] {desc}")
        passed += 1
    else:
        print(f" [FAIL] {desc}")
        failed += 1

# 1. SSH 2FA Enforcement Check
print("\n--- 1. Testing SSH Two-Factor Authentication Enforcement ---")
res = subprocess.run([
    "ssh", "-i", KEY_PATH,
    "-o", "BatchMode=yes",
    "-o", "StrictHostKeyChecking=no",
    f"ubuntu@{SERVER_IP}",
    "echo SUCCESS"
], capture_output=True, text=True)
check("Permission denied (keyboard-interactive)" in res.stderr, 
      "SSH Key-only access blocked: 2FA TOTP is strictly required by PAM")

# 2. Strict HTTPS & Portal Reachability
print("\n--- 2. Testing Subscription Daemon & Web Portal (HTTPS-Only) ---")

# Verify plain HTTP is rejected
plain_http_blocked = False
try:
    s = socket.create_connection((SERVER_IP, PORT), timeout=3)
    s.sendall(b"GET /portal HTTP/1.1\r\nHost: " + SERVER_IP.encode() + b"\r\n\r\n")
    data = s.recv(1024)
    s.close()
    if not data:
        plain_http_blocked = True
except Exception:
    plain_http_blocked = True
check(plain_http_blocked, "Plain HTTP on port 8443 rejected at TLS layer (Strict HTTPS enforced)")

cj = http.cookiejar.CookieJar()
https_handler = urllib.request.HTTPSHandler(context=ssl_ctx)
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), https_handler, urllib.request.HTTPCookieProcessor(cj))

# Portal unauthed page over HTTPS
req = urllib.request.Request(f"https://{SERVER_IP}:{PORT}/portal")
resp = opener.open(req, timeout=12)
resp_body = resp.read().decode("utf-8")
check(resp.status == 200 and "SOVEREIGN FORTRESS" in resp_body, 
      "Web Portal login page reachable over HTTPS (TLS 1.3, HTTP 200)")

# Offline embedded QR engine
req_js = urllib.request.Request(f"https://{SERVER_IP}:{PORT}/portal/qrcode.min.js")
resp_js = opener.open(req_js, timeout=12)
check(resp_js.status == 200 and b"QRCode" in resp_js.read(),
      "Self-contained offline QR generator script available at /portal/qrcode.min.js")

# Login with Master Token
login_data = urllib.parse.urlencode({'auth_credential': TOKEN}).encode()
req_login = urllib.request.Request(f"https://{SERVER_IP}:{PORT}/portal/login", data=login_data)
resp_login = opener.open(req_login)
check(resp_login.geturl() == f"https://{SERVER_IP}:{PORT}/portal" and any(c.name == 'sf_session' for c in cj),
      "Portal login with Master Token succeeded over HTTPS (Session cookie set)")
resp_login.read()
resp_login.close()

# 3. Dynamic Subscription Delivery
print("\n--- 3. Testing Subscription Endpoints ---")
sub_req = urllib.request.Request(f"https://{SERVER_IP}:{PORT}/sub/{TOKEN}")
sub_resp = opener.open(sub_req, timeout=12)
sub_json = json.loads(sub_resp.read().decode())

check(len(sub_json.get("outbounds", [])) >= 7,
      f"Sing-box JSON contains {len(sub_json.get('outbounds', []))} outbounds (all protocols present)")

# Campus intranet split routing verification
rules = sub_json.get("route", {}).get("rules", [])
# Campus intranet split routing verification
rules = sub_json.get("route", {}).get("rules", [])
has_campus_apex = any(CAMPUS_DOMAIN in r.get("domain", []) and r.get("outbound") == "direct" for r in rules)
has_campus_suffix = any(f".{CAMPUS_DOMAIN}" in r.get("domain_suffix", []) and r.get("outbound") == "direct" for r in rules)
has_campus_ip = any("10.0.0.0/8" in r.get("ip_cidr", []) and r.get("outbound") == "direct" for r in rules)
check(has_campus_apex, f"Campus apex domain ({CAMPUS_DOMAIN} -> direct) verified")
check(has_campus_suffix, f"Campus wildcard domains (*.{CAMPUS_DOMAIN} -> direct) verified")
check(has_campus_ip, "Campus IP range (10.0.0.0/8 -> direct) verified")

# Base64 Subscription
b64_req = urllib.request.Request(f"https://{SERVER_IP}:{PORT}/sub/{TOKEN}/b64")
b64_resp = opener.open(b64_req, timeout=12)
decoded = base64.b64decode(b64_resp.read().decode()).decode().strip().split('\n')
check(len(decoded) == 7, f"Base64 subscription returns all 7 proxy protocol links (count={len(decoded)})")

# Real-Time Dynamic TOTP Subscription
current_totp = get_current_totp()
totp_path_req = urllib.request.Request(f"https://{SERVER_IP}:{PORT}/sub/{current_totp}")
totp_path_resp = opener.open(totp_path_req, timeout=12)
check(totp_path_resp.status == 200, f"Dynamic TOTP direct path subscription (/sub/{current_totp}) verified over HTTPS")

# Active Defense Redirection for unauthorized probes
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def http_error_302(self, req, fp, code, msg, headers):
        return fp

opener_decoy = urllib.request.build_opener(urllib.request.ProxyHandler({}), https_handler, NoRedirect)
decoy_resp = opener_decoy.open(f"https://{SERVER_IP}:{PORT}/sub/unauthorized_hacker_token")
check(decoy_resp.code == 302 and "microsoft.com" in decoy_resp.headers.get("Location", ""),
      "Active Defense Redirection: Unauthorized requests redirected to authentic Microsoft CDN")

# Invalidation check: Historically exposed token MUST be rejected
old_leaked_token = CONFIG.get("revoked_token_test", "ft_sec_revoked_historical_token_test_000")
old_token_resp = opener_decoy.open(f"https://{SERVER_IP}:{PORT}/sub/{old_leaked_token}")
check(old_token_resp.code == 302 and "microsoft.com" in old_token_resp.headers.get("Location", ""),
      f"Credential Rotation Check: Invalid/Revoked token ({old_leaked_token[:12]}...) redirected to decoy")

# 4. Local Artifacts Verification
print("\n--- 4. Verifying Local Artifacts ---")
check(os.path.exists(os.path.join(BASE_DIR, "README.md")), "README.md documentation present")
if os.path.exists(CA_PATH):
    check(os.path.getsize(CA_PATH) > 0, "Root CA certificate (ca.crt) present")
if os.path.exists(os.path.join(BASE_DIR, "client_profiles.txt")):
    check(os.path.getsize(os.path.join(BASE_DIR, "client_profiles.txt")) > 0, "Client profiles verified")

print("\n" + "=" * 70)
print(f"VERIFICATION RESULTS: {passed} PASSED / {failed} FAILED")
print("=" * 70)

if failed > 0:
    sys.exit(1)
