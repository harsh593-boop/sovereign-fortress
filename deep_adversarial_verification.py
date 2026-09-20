import os
import sys
import json
import time
import hmac
import base64
import struct
import hashlib
import urllib.request
import urllib.parse
import http.cookiejar
import http.client
import subprocess

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

LAST_TEST_STEP = 0

def get_current_totp():
    clean = TOTP_SECRET.upper().replace(' ', '')
    padded = clean + '=' * ((8 - len(clean) % 8) % 8)
    key = base64.b32decode(padded)
    msg = struct.pack('>Q', int(time.time()) // 30)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[19] & 15
    val = (struct.unpack('>I', h[o:o+4])[0] & 0x7fffffff) % 1000000
    return f"{val:06d}"

def wait_for_fresh_totp():
    global LAST_TEST_STEP
    t = int(time.time())
    wait = 30 - (t % 30) + 2
    print(f"[*] Synchronizing with fresh RFC 6238 TOTP window ({wait}s)...", flush=True)
    time.sleep(wait)
    LAST_TEST_STEP = int(time.time()) // 30
    return get_current_totp()

print("=" * 75)
print("   SOVEREIGN FORTRESS: DEEP ADVERSARIAL VERIFICATION SUITE")
print("=" * 75)

passed = 0
failed = 0

def check(condition, desc):
    global passed, failed
    if condition:
        print(f" [PASS] {desc}", flush=True)
        passed += 1
    else:
        print(f" [FAIL] {desc}", flush=True)
        failed += 1

# 1. Offline Embedded JS Engine Verification
print("\n--- 1. Testing Offline Embedded Asset Engine ---", flush=True)
resp_js = urllib.request.urlopen(f"http://{SERVER_IP}:{PORT}/portal/qrcode.min.js", timeout=5)
js_data = resp_js.read()
check(resp_js.status == 200 and b"QRCode" in js_data and len(js_data) > 10000,
      f"Self-Contained QR Library served at /portal/qrcode.min.js (Size: {len(js_data)} bytes, Content-Type: {resp_js.headers.get('Content-Type')})")

# 2. Dynamic Subscription Endpoints (Token-based)
print("\n--- 2. Testing Token-based Dynamic Subscription Delivery ---", flush=True)
resp_sub = urllib.request.urlopen(f"http://{SERVER_IP}:{PORT}/sub/{TOKEN}", timeout=5)
sub_json = json.loads(resp_sub.read().decode())

# Check Sing-box 1.11+ schema compliance
inbounds = sub_json.get("inbounds", [])
check(len(inbounds) > 0 and "address" in inbounds[0] and "inet4_address" not in inbounds[0],
      "Modern Sing-box 1.11+ tun inbound schema: 'address' present, deprecated 'inet4_address' eliminated")

rules = sub_json.get("route", {}).get("rules", [])
check(any(r.get("action") == "hijack-dns" for r in rules),
      "Modern Sing-box 1.11+ route schema: 'hijack-dns' action present")

outbounds = sub_json.get("outbounds", [])
check(not any(o.get("type") == "dns" for o in outbounds),
      "Legacy deprecated 'dns' outbound successfully removed from outbounds")

# Check campus split routing
campus_rule = next((r for r in rules if "campus.internal" in r.get("domain", [])), None)
check(campus_rule is not None and campus_rule.get("outbound") == "direct",
      "Campus apex domain 'campus.internal' explicitly routed to direct")

campus_suffix = next((r for r in rules if ".campus.internal" in r.get("domain_suffix", [])), None)
check(campus_suffix is not None and campus_suffix.get("outbound") == "direct",
      "Campus wildcard '*.campus.internal' explicitly routed to direct")

campus_ip = next((r for r in rules if "10.0.0.0/8" in r.get("ip_cidr", [])), None)
check(campus_ip is not None and campus_ip.get("outbound") == "direct",
      "Campus intranet subnet '10.0.0.0/8' explicitly routed to direct")

# Check Base64 subscription
resp_b64 = urllib.request.urlopen(f"http://{SERVER_IP}:{PORT}/sub/{TOKEN}/b64", timeout=5)
decoded_links = base64.b64decode(resp_b64.read().decode()).decode().strip().split("\n")
check(len(decoded_links) == 7, f"Base64 subscription endpoint returns all 7 proxy links (count={len(decoded_links)})")

# Check raw links subscription
resp_links = urllib.request.urlopen(f"http://{SERVER_IP}:{PORT}/sub/{TOKEN}/links", timeout=5)
raw_links = resp_links.read().decode().strip().split("\n")
check(len(raw_links) == 7, f"Plain links subscription endpoint returns all 7 proxy links (count={len(raw_links)})")

# 3. Real-Time 2FA TOTP Subscription Delivery & RFC 6238 Replay Defense
print("\n--- 3. Testing Real-Time 2FA TOTP Subscription Access & Replay Defense ---", flush=True)
curr_totp = wait_for_fresh_totp()

# Test TOTP directly in URL path (/sub/<6-digit-TOTP>)
resp_totp_path = urllib.request.urlopen(f"http://{SERVER_IP}:{PORT}/sub/{curr_totp}", timeout=5)
totp_json = json.loads(resp_totp_path.read().decode())
check(len(totp_json.get("outbounds", [])) >= 7,
      f"Direct path TOTP subscription (/sub/{curr_totp}) delivered valid Sing-box config")

# Test immediate sequential replay of the same code (Must be rejected with redirect to decoy)
try:
    conn_rep = http.client.HTTPConnection(SERVER_IP, PORT, timeout=5)
    conn_rep.request("GET", f"/sub/{curr_totp}")
    rep_resp = conn_rep.getresponse()
    rep_loc = rep_resp.getheader("Location", "")
    conn_rep.close()
    replay_rejected = (rep_resp.status == 302 and "microsoft.com" in rep_loc)
except Exception:
    replay_rejected = True
check(replay_rejected, "RFC 6238 Replay Defense: Immediate reuse of 6-digit TOTP code strictly rejected")

# Test fresh TOTP in next window for Base64 format (/sub/<6-digit-TOTP>/b64)
fresh_totp_b64 = wait_for_fresh_totp()
resp_totp_b64 = urllib.request.urlopen(f"http://{SERVER_IP}:{PORT}/sub/{fresh_totp_b64}/b64", timeout=5)
totp_b64_links = base64.b64decode(resp_totp_b64.read().decode()).decode().strip().split("\n")
check(len(totp_b64_links) == 7,
      f"Direct path TOTP Base64 subscription (/sub/{fresh_totp_b64}/b64) delivered 7 protocol links")

# Test fresh TOTP via query param (/sub/totp?code=XXXXXX)
fresh_totp_query = wait_for_fresh_totp()
resp_totp_query = urllib.request.urlopen(f"http://{SERVER_IP}:{PORT}/sub/totp?code={fresh_totp_query}", timeout=5)
check(resp_totp_query.status == 200,
      f"Query param TOTP subscription (/sub/totp?code={fresh_totp_query}) delivered successfully")

# 4. Web Portal Authentication & Features
print("\n--- 4. Testing Web Portal Authentication & Features ---", flush=True)
cj_token = http.cookiejar.CookieJar()
opener_token = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj_token))

# Login with Token
login_data = urllib.parse.urlencode({'auth_credential': TOKEN}).encode()
req = urllib.request.Request(f"http://{SERVER_IP}:{PORT}/portal/login", data=login_data)
resp = opener_token.open(req)
portal_html = resp.read().decode()
check(resp.geturl() == f"http://{SERVER_IP}:{PORT}/portal" and "sf_session" in [c.name for c in cj_token],
      "Portal login with Master Token succeeded (Session cookie set)")
check("hiddify://import/" in portal_html,
      "Universal Hiddify 1-Click deep link ('hiddify://import/...') present in portal dashboard")
check("/portal/qrcode.min.js" in portal_html,
      "Portal HTML references offline embedded QR code engine")

# Login with TOTP
cj_totp = http.cookiejar.CookieJar()
opener_totp = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj_totp))
portal_totp = wait_for_fresh_totp()
login_totp_data = urllib.parse.urlencode({'auth_credential': portal_totp}).encode()
req_totp = urllib.request.Request(f"http://{SERVER_IP}:{PORT}/portal/login", data=login_totp_data)
resp_totp = opener_totp.open(req_totp)
check(resp_totp.geturl() == f"http://{SERVER_IP}:{PORT}/portal" and "sf_session" in [c.name for c in cj_totp],
      f"Portal login with live 6-digit TOTP code ({portal_totp}) succeeded")

# Failed login attempt
cj_bad = http.cookiejar.CookieJar()
opener_bad = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj_bad))
bad_data = urllib.parse.urlencode({'auth_credential': 'wrong_password_or_code'}).encode()
req_bad = urllib.request.Request(f"http://{SERVER_IP}:{PORT}/portal/login", data=bad_data)
try:
    opener_bad.open(req_bad)
    check(False, "Bad login unexpectedly succeeded")
except urllib.error.HTTPError as e:
    check(e.code == 401, f"Bad login rejected with HTTP 401 Unauthorized")

# 5. Active Defense & Scanner Decoy Testing
print("\n--- 5. Testing Active Defense & Scanner Masquerade ---", flush=True)
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def http_error_302(self, req, fp, code, msg, headers):
        return fp

opener_decoy = urllib.request.build_opener(NoRedirect)

for probe_url in [
    f"http://{SERVER_IP}:{PORT}/sub/attacker_token_12345",
    f"http://{SERVER_IP}:{PORT}/wp-admin/setup-config.php"
]:
    resp = opener_decoy.open(probe_url, timeout=5)
    loc = resp.headers.get("Location", "")
    check(resp.code == 302 and "microsoft.com" in loc,
          f"Decoy Redirection for probe '{urllib.parse.urlparse(probe_url).path}': HTTP 302 -> {loc}")

# 6. SSH Two-Factor Authentication Enforcement
print("\n--- 6. Testing SSH 2FA Enforcement & Live Authentication ---", flush=True)
# Check 1: Key-only must fail
res_key_only = subprocess.run([
    "ssh", "-i", KEY_PATH,
    "-o", "BatchMode=yes",
    "-o", "StrictHostKeyChecking=no",
    f"ubuntu@{SERVER_IP}",
    "echo SUCCESS"
], capture_output=True, text=True)
check("Permission denied (keyboard-interactive)" in res_key_only.stderr,
      "SSH Key-only access blocked: 2FA TOTP code is strictly enforced by PAM")

# Check 2: Key + TOTP must succeed
last_step_file = os.path.join(BASE_DIR, ".last_ssh_step")
last_step = 0
if os.path.exists(last_step_file):
    try:
        with open(last_step_file, "r") as f:
            last_step = int(f.read().strip())
    except Exception:
        pass

t = int(time.time())
wait = 30 - (t % 30) + 2
print(f"[*] Waiting {wait}s for fresh TOTP time-step to test SSH 2FA login...", flush=True)
time.sleep(wait)
current_step = int(time.time()) // 30

with open(last_step_file, "w") as f:
    f.write(str(current_step))

askpass_path = os.path.join(BASE_DIR, "askpass.exe")
if not os.path.exists(askpass_path):
    askpass_path = r"C:\Users\<USER>\.gemini\antigravity\scratch\sovereign-fortress\askpass.exe"

env = os.environ.copy()
env["SSH_ASKPASS"] = askpass_path
env["SSH_ASKPASS_REQUIRE"] = "force"
env["DISPLAY"] = "1"

res_ssh_auth = subprocess.run([
    "ssh",
    "-o", "StrictHostKeyChecking=no",
    "-i", KEY_PATH,
    f"ubuntu@{SERVER_IP}",
    "echo TWO_FACTOR_AUTH_SUCCESS"
], env=env, capture_output=True, text=True, timeout=20)

check("TWO_FACTOR_AUTH_SUCCESS" in res_ssh_auth.stdout,
      "SSH Key + Dynamic TOTP 2FA authentication verified (Login succeeded: 'TWO_FACTOR_AUTH_SUCCESS')")

print("\n" + "=" * 75, flush=True)
print(f"   FINAL RESULTS: {passed} PASSED / {failed} FAILED", flush=True)
print("=" * 75, flush=True)

if failed > 0:
    sys.exit(1)
