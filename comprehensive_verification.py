import os
import sys
import json
import base64
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

SERVER_IP = CONFIG.get("server_ip", "<YOUR_SERVER_IP>")
PORT = int(CONFIG.get("sub_port", 8443))
TOKEN = CONFIG.get("token", "ft_sec_qZUVS6g_2N6d-Oyyzx0xLT53aKYnhfOo")
TOTP_SECRET = CONFIG.get("totp_secret", "XUO7RN6RXQYYOU2BZJBMHZOZQA")
KEY_PATH = os.environ.get("FORTRESS_SSH_KEY", r"C:\Users\<USER>\Downloads\ssh-key-2026-09-18.key")

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
print("=" * 70)

# Enforce direct connections (bypass local client proxies)
default_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
urllib.request.install_opener(default_opener)

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

# 2. Portal Reachability & Login
print("\n--- 2. Testing Subscription Daemon & Web Portal ---")
cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(cj))

# Portal unauthed page
resp = urllib.request.urlopen(f"http://{SERVER_IP}:{PORT}/portal", timeout=12)
check(resp.status == 200 and "SOVEREIGN FORTRESS" in resp.read().decode(), 
      "Web Portal login page reachable on port 8443 (HTTP 200)")

# Offline embedded QR engine
resp_js = urllib.request.urlopen(f"http://{SERVER_IP}:{PORT}/portal/qrcode.min.js", timeout=12)
check(resp_js.status == 200 and b"QRCode" in resp_js.read(),
      "Self-contained offline QR generator script available at /portal/qrcode.min.js")

# Login with Token
login_data = urllib.parse.urlencode({'auth_credential': TOKEN}).encode()
req = urllib.request.Request(f"http://{SERVER_IP}:{PORT}/portal/login", data=login_data)
resp = opener.open(req)
check(resp.geturl() == f"http://{SERVER_IP}:{PORT}/portal" and any(c.name == 'sf_session' for c in cj),
      "Portal login with Master Token succeeded (Session cookie set)")
resp.read()
resp.close()

# Login with Dynamic TOTP
def wait_for_fresh_totp():
    t = int(time.time())
    wait = 30 - (t % 30) + 2
    print(f"[*] Synchronizing with fresh RFC 6238 TOTP window ({wait}s)...", flush=True)
    time.sleep(wait)
    return get_current_totp()

cj_totp = http.cookiejar.CookieJar()
opener_totp = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(cj_totp))
totp_code = wait_for_fresh_totp()
login_data_totp = urllib.parse.urlencode({'auth_credential': totp_code}).encode()
req_totp = urllib.request.Request(f"http://{SERVER_IP}:{PORT}/portal/login", data=login_data_totp)
resp_totp = opener_totp.open(req_totp)
check(resp_totp.geturl() == f"http://{SERVER_IP}:{PORT}/portal" and any(c.name == 'sf_session' for c in cj_totp),
      f"Portal login with 6-digit TOTP code ({totp_code}) succeeded")
resp_totp.read()
resp_totp.close()

# 3. Dynamic Subscription Delivery
print("\n--- 3. Testing Subscription Endpoints ---")
sub_resp = urllib.request.urlopen(f"http://{SERVER_IP}:{PORT}/sub/{TOKEN}", timeout=12)
sub_json = json.loads(sub_resp.read().decode())

check(len(sub_json.get("outbounds", [])) >= 7,
      f"Sing-box JSON contains {len(sub_json.get('outbounds', []))} outbounds (all protocols present)")

# Sing-box 1.11 schema checks
check("address" in sub_json.get("inbounds", [{}])[0],
      "Sing-box 1.11+ tun schema: 'address' present (no deprecated inet4_address)")
check(any(r.get("action") == "hijack-dns" for r in sub_json.get("route", {}).get("rules", [])),
      "Sing-box 1.11+ route schema: 'hijack-dns' action present")

# Campus intranet split routing verification
rules = sub_json.get("route", {}).get("rules", [])
has_campus_apex = any("campus.internal" in r.get("domain", []) and r.get("outbound") == "direct" for r in rules)
has_campus_suffix = any(".campus.internal" in r.get("domain_suffix", []) and r.get("outbound") == "direct" for r in rules)
has_campus_ip = any("10.0.0.0/8" in r.get("ip_cidr", []) and r.get("outbound") == "direct" for r in rules)
check(has_campus_apex, "Campus apex domain (campus.internal -> direct) verified")
check(has_campus_suffix, "Campus wildcard domains (*.campus.internal -> direct) verified")
check(has_campus_ip, "Campus IP range (10.0.0.0/8 -> direct) verified")

# Base64 Subscription
b64_resp = urllib.request.urlopen(f"http://{SERVER_IP}:{PORT}/sub/{TOKEN}/b64", timeout=12)
decoded = base64.b64decode(b64_resp.read().decode()).decode().strip().split('\n')
check(len(decoded) == 7, f"Base64 subscription returns all 7 proxy protocol links (count={len(decoded)})")

# Real-Time TOTP Subscription (Query param & Direct path)
fresh_totp = wait_for_fresh_totp()
totp_path_resp = urllib.request.urlopen(f"http://{SERVER_IP}:{PORT}/sub/{fresh_totp}", timeout=12)
check(totp_path_resp.status == 200, f"Dynamic TOTP direct path subscription (/sub/{fresh_totp}) verified")

# Active Defense Redirection for unauthorized probes
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def http_error_302(self, req, fp, code, msg, headers):
        return fp

opener_decoy = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)
decoy_resp = opener_decoy.open(f"http://{SERVER_IP}:{PORT}/sub/unauthorized_hacker_token")
check(decoy_resp.code == 302 and "microsoft.com" in decoy_resp.headers.get("Location", ""),
      "Active Defense Redirection: Unauthorized requests redirected to authentic Microsoft CDN")

# 4. Local Artifacts Verification
print("\n--- 4. Verifying Local Artifacts ---")
files_to_check = [
    os.path.join(BASE_DIR, "qr_codes", "qr_hiddify_universal.png"),
    os.path.join(BASE_DIR, "qr_codes", "qr_ssh_totp.png"),
    os.path.join(BASE_DIR, "client_profiles.txt"),
    os.path.join(BASE_DIR, "README.md"),
    os.path.join(BASE_DIR, "fortress_dashboard.html")
]

for f in files_to_check:
    check(os.path.exists(f) and os.path.getsize(f) > 0, f"Artifact verified: {os.path.basename(f)}")

print("\n" + "=" * 70)
print(f"VERIFICATION RESULTS: {passed} PASSED / {failed} FAILED")
print("=" * 70)

if failed > 0:
    sys.exit(1)
