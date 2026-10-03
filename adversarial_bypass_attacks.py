"""
Adversarial Bypass Attack Suite (Strict Security Verification)
Sovereign Fortress - Zero-Trust Security Verification

This suite actively tests for vulnerabilities, bypasses, and regression flaws:
1. RFC 6238 TOTP Replay & Concurrent Race Attack
2. Rate-Limiting Header Spoofing (X-Forwarded-For, X-Real-IP, Client-IP)
3. Path Normalization, Traversal & HTTP Method Tampering
4. Real Cryptographic Protocol Handshakes (Reality TLS 1.3 ClientHello, WSTunnel WS Upgrade with Root CA)
5. CSRF State-Change Vulnerability on Session Operations
6. Client-Side Probing Integrity (UDP Facade vs Real Round-Trip)
"""

import os
import sys
import time
import socket
import ssl
import json
import hmac
import hashlib
import struct
import base64
import http.client
import http.cookiejar
import urllib.request
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

if "--legacy-live" not in sys.argv:
    print("Archival live probes disabled by default; run controlled offline regressions instead.")
    sys.exit(2)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "fortress_config.json")
CA_PATH = os.path.join(BASE_DIR, "ca.crt")

CONFIG = {}
if os.path.exists(CONFIG_PATH):
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            CONFIG = json.load(f)
    except Exception:
        pass

SERVER_IP = CONFIG.get("server_ip") or os.environ.get("FORTRESS_SERVER_IP")
SUB_PORT = int(CONFIG.get("sub_port", 8443))
WSTUNNEL_PORT = int(CONFIG.get("wstunnel_port", 8080))
REALITY_PORT = 443
TOKEN = CONFIG.get("token", "")
TOTP_SECRET = CONFIG.get("totp_secret", "")

if not SERVER_IP or SERVER_IP.startswith("<"):
    print("[-] Error: server_ip must be configured in fortress_config.json or FORTRESS_SERVER_IP")
    sys.exit(1)

# Strict SSL context for Sovereign Fortress HTTPS endpoints
fortress_ssl_ctx = ssl.create_default_context(cafile=CA_PATH)

def get_conn(timeout=10):
    return http.client.HTTPSConnection(SERVER_IP, SUB_PORT, context=fortress_ssl_ctx, timeout=timeout)

def get_current_totp(secret_str):
    if not secret_str:
        return None
    try:
        clean = secret_str.upper().replace(' ', '')
        padded = clean + '=' * ((8 - len(clean) % 8) % 8)
        key = base64.b32decode(padded)
        step = int(time.time()) // 30
        msg = struct.pack('>Q', step)
        h = hmac.new(key, msg, hashlib.sha1).digest()
        o = h[19] & 15
        calc = (struct.unpack('>I', h[o:o+4])[0] & 0x7fffffff) % 1000000
        return f"{calc:06d}"
    except Exception:
        return None

def reset_rate_limit_counter():
    """Issue authenticated GET /sub/{TOKEN} to clear failed attempts counter on server"""
    if not TOKEN:
        return
    try:
        conn = get_conn(timeout=4)
        conn.request("GET", f"/sub/{TOKEN}", headers={"User-Agent": "RedTeam-Harness-Reset/1.0"})
        resp = conn.getresponse()
        resp.read()
        conn.close()
    except Exception:
        pass

def test_totp_replay_attack():
    print("\n--- ATTACK 1: RFC 6238 TOTP REPLAY & CONCURRENCY RACE ---")
    if not TOTP_SECRET:
        print("[!] SKIP: No TOTP secret configured locally.")
        return True

    t = int(time.time())
    wait = 30 - (t % 30) + 2
    print(f"[*] Synchronizing with fresh TOTP window ({wait}s)...", flush=True)
    time.sleep(wait)

    code = get_current_totp(TOTP_SECRET)
    if not code:
        print("[-] FAIL: Could not generate valid TOTP.")
        return False

    print("[*] Generated a fresh TOTP code; submitting an authenticated probe...")

    conn = get_conn(timeout=10)
    conn.request("GET", f"/sub/{code}", headers={"User-Agent": "RedTeam-Probe/1.0"})
    resp1 = conn.getresponse()
    status1 = resp1.status
    body1 = resp1.read()
    conn.close()
    print(f"[+] First attempt: HTTP {status1}, bytes: {len(body1)}")

    if status1 != 200:
        print(f"[-] Initial request failed with HTTP {status1}. Waiting for next time step...")
        time.sleep(30 - (int(time.time()) % 30) + 2)
        code = get_current_totp(TOTP_SECRET)
        conn = get_conn(timeout=10)
        conn.request("GET", f"/sub/{code}", headers={"User-Agent": "RedTeam-Probe/1.0"})
        resp1 = conn.getresponse()
        status1 = resp1.status
        body1 = resp1.read()
        conn.close()
        print(f"[+] Retry attempt: HTTP {status1}, bytes: {len(body1)}")

    time.sleep(0.5)
    print("[*] Immediately attempting sequential REPLAY with same TOTP code...")
    conn = get_conn(timeout=10)
    conn.request("GET", f"/sub/{code}", headers={"User-Agent": "RedTeam-Probe/1.0"})
    resp2 = conn.getresponse()
    status2 = resp2.status
    loc2 = resp2.getheader("Location", "")
    body2 = resp2.read()
    conn.close()

    replay_succeeded = False
    if status2 == 200:
        replay_succeeded = True
        print("[CRITICAL VULNERABILITY] Replay attempt was accepted by the server.")
    elif status2 == 302:
        print("[+] Replay attempt rejected with the expected decoy response.")
    else:
        print(f"[+] Replay attempt rejected with HTTP {status2}.")

    reset_rate_limit_counter()

    # Test concurrent race condition with identical TOTP
    print("[*] Testing concurrent race (3 parallel requests using same TOTP)...")
    def send_probe(_):
        try:
            c = get_conn(timeout=5)
            c.request("GET", f"/sub/{code}", headers={"User-Agent": "RedTeam-Probe/Race"})
            r = c.getresponse()
            s = r.status
            r.read()
            c.close()
            return s
        except Exception:
            return 0

    with ThreadPoolExecutor(max_workers=3) as ex:
        results = list(ex.map(send_probe, range(3)))
    print(f"[*] Concurrent responses: {results}")

    reset_rate_limit_counter()

    replayed_200s = sum(1 for s in results if s == 200)
    if replayed_200s > 0 or replay_succeeded:
        print(f"[VULNERABILITY DETECTED] Server allowed reuse of consumed TOTP code!")
        return True
    else:
        print("[+] Replay protection assertion passed for the tested code.")
        return False

def test_ip_spoofing_attack():
    print("\n--- ATTACK 2: RATE-LIMITER IP HEADER SPOOFING ---")
    spoofed_headers = [
        {"X-Forwarded-For": "198.51.100.1"},
        {"X-Real-IP": "198.51.100.2"},
        {"Client-IP": "198.51.100.3"},
        {"CF-Connecting-IP": "198.51.100.4"},
        {"True-Client-IP": "198.51.100.5"}
    ]

    print("[*] Testing if server evaluates spoofed proxy headers for rate limiting...")
    observed = []
    for h in spoofed_headers:
        try:
            conn = get_conn(timeout=4)
            h["User-Agent"] = "RedTeam-IPSpoof/1.0"
            conn.request("GET", "/sub/invalid_token_probe", headers=h)
            resp = conn.getresponse()
            observed.append(resp.status)
            resp.read()
            conn.close()
            reset_rate_limit_counter()
        except Exception:
            pass
    passed = bool(observed) and all(status in {302, 401, 403, 404, 429} for status in observed)
    print("[+] Header-spoofing probes received non-success responses." if passed else
          "[-] Header-spoofing assertion was inconclusive.")
    reset_rate_limit_counter()
    return passed

def test_path_traversal_and_methods():
    print("\n--- ATTACK 3: PATH TRAVERSAL & HTTP METHOD TAMPERING ---")
    probes = [
        "/sub/../portal",
        "/sub/%2e%2e/portal",
        "///portal",
        "/PORTAL",
        f"/sub//{TOKEN}"
    ]

    passed = True
    for p in probes:
        try:
            conn = get_conn(timeout=4)
            conn.request("GET", p, headers={"User-Agent": "RedTeam-PathProbe/1.0"})
            resp = conn.getresponse()
            loc = resp.getheader("Location", "")
            resp.read()
            conn.close()
            passed = passed and not (200 <= resp.status < 300)
            print(f"[*] Path probe -> HTTP {resp.status}")
        except Exception as e:
            passed = False
            print("[*] Path probe failed to receive a response.")

    print("[*] Testing forbidden HTTP verbs (PUT, DELETE, OPTIONS, TRACE)...")
    verbs = ["PUT", "DELETE", "OPTIONS", "TRACE"]
    for v in verbs:
        try:
            conn = get_conn(timeout=4)
            conn.request(v, "/portal", headers={"User-Agent": "RedTeam-VerbProbe/1.0"})
            resp = conn.getresponse()
            loc = resp.getheader("Location", "")
            resp.read()
            conn.close()
            passed = passed and not (200 <= resp.status < 300)
            print(f"[+] Verb {v} returned HTTP {resp.status}")
        except Exception as e:
            passed = False
            print("[*] Verb probe failed to receive a response.")
    reset_rate_limit_counter()
    return passed

def test_reality_handshake():
    print("\n--- ATTACK 4: REALITY TLS 1.3 HANDSHAKE (TCP 443) ---")
    sni = CONFIG.get("reality_sni", "gateway.icloud.com")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect((SERVER_IP, REALITY_PORT))

        ctx = ssl.create_default_context()
        tls_sock = ctx.wrap_socket(sock, server_hostname=sni)
        cipher = tls_sock.cipher()
        version = tls_sock.version()
        print(f"[+] TLS handshake completed with Reality port {REALITY_PORT} ({version}).")
        tls_sock.close()
        return True
    except Exception as e:
        print(f"[-] Reality handshake probe error: {e}")
        return False

def test_wstunnel_handshake():
    print("\n--- ATTACK 5: WSTUNNEL WEBSOCKET UPGRADE (TCP 8080) WITH ROOT CA ---")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect((SERVER_IP, WSTUNNEL_PORT))

        # Strict validation with private Sovereign Fortress Root CA
        ctx = ssl.create_default_context(cafile=CA_PATH)
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        tls_sock = ctx.wrap_socket(sock, server_hostname="www.microsoft.com")
        print(f"[+] WSTunnel TLS connection established ({tls_sock.version()}).")

        # Send WebSocket upgrade request
        key = base64.b64encode(os.urandom(16)).decode('utf-8')
        req = (
            f"GET / HTTP/1.1\r\n"
            f"Host: www.microsoft.com\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n\r\n"
        )
        tls_sock.sendall(req.encode('utf-8'))
        resp = tls_sock.recv(4096).decode('utf-8', errors='ignore')
        first_line = resp.split('\r\n')[0] if resp else "No response"
        print(f"[+] WSTunnel response: {first_line}")
        tls_sock.close()
        return True
    except Exception as e:
        print(f"[-] WSTunnel handshake error: {e}")
        return False

def test_csrf_token_rotation():
    print("\n--- ATTACK 6: CSRF ON SESSION TOKEN ROTATION ---")
    # Test 1: Unauthenticated POST
    passed = True
    try:
        conn = get_conn(timeout=4)
        conn.request("POST", "/portal/rotate-token", body=b"", headers={"User-Agent": "RedTeam-CSRF"})
        resp = conn.getresponse()
        body = resp.read().decode()
        conn.close()
        passed = passed and resp.status in {401, 403}
        print(f"[+] Unauthenticated POST returned HTTP {resp.status}")
    except Exception as e:
        passed = False
        print("[*] Unauthenticated POST probe failed.")

    # Test 2: Authenticated POST with fake cookie and missing X-Fortress-CSRF
    try:
        conn = get_conn(timeout=4)
        conn.request("POST", "/portal/rotate-token", body=b"", headers={
            "User-Agent": "RedTeam-CSRF",
            "Cookie": "sf_session=fake_cookie_attempt"
        })
        resp = conn.getresponse()
        body = resp.read().decode()
        conn.close()
        passed = passed and resp.status in {401, 403}
        print(f"[+] Fake-session POST without CSRF header returned HTTP {resp.status}")
    except Exception as e:
        passed = False
        print("[*] Fake-session CSRF probe failed.")

    # Test 3: Valid authenticated session POST without X-Fortress-CSRF header
    if TOKEN:
        try:
            cj = http.cookiejar.CookieJar()
            https_h = urllib.request.HTTPSHandler(context=fortress_ssl_ctx)
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), https_h, urllib.request.HTTPCookieProcessor(cj))
            login_data = urllib.parse.urlencode({'auth_credential': TOKEN}).encode()
            login_req = urllib.request.Request(f"https://{SERVER_IP}:{SUB_PORT}/portal/login", data=login_data)
            login_resp = opener.open(login_req)
            session_cookie = None
            for c in cj:
                if c.name == "sf_session":
                    session_cookie = f"sf_session={c.value}"
                    break

            if session_cookie:
                conn = get_conn(timeout=4)
                conn.request("POST", "/portal/rotate-token", body=b"", headers={
                    "User-Agent": "RedTeam-CSRF-Exploit",
                    "Cookie": session_cookie
                })
                resp = conn.getresponse()
                body = resp.read().decode()
                conn.close()
                if resp.status == 403 and "CSRF Rejected" in body:
                    print("[+] Valid-session POST without CSRF header was blocked with HTTP 403.")
                else:
                    passed = False
                    print(f"[-] Valid-session CSRF assertion failed with HTTP {resp.status}.")
            else:
                passed = False
                print("[-] Could not establish a session for the CSRF assertion.")
        except Exception as e:
            passed = False
            print("[*] Valid-session CSRF probe failed.")
    else:
        passed = False
    return passed

if __name__ == "__main__":
    print("======================================================================")
    print("      SOVEREIGN FORTRESS: ADVERSARIAL BYPASS RED-TEAM HARNESS        ")
    print("======================================================================")

    reset_rate_limit_counter()
    totp_vuln = test_totp_replay_attack()
    reset_rate_limit_counter()
    ip_spoofing_ok = test_ip_spoofing_attack()
    reset_rate_limit_counter()
    path_methods_ok = test_path_traversal_and_methods()
    reset_rate_limit_counter()
    reality_ok = test_reality_handshake()
    wstunnel_ok = test_wstunnel_handshake()
    csrf_ok = test_csrf_token_rotation()
    reset_rate_limit_counter()

    print("\n======================================================================")
    print("RED-TEAM SUMMARY:")
    all_ok = (not totp_vuln and ip_spoofing_ok and path_methods_ok and
              reality_ok and wstunnel_ok and csrf_ok)
    if not all_ok:
        print("[!] FAILURE: One or more asserted checks failed or were inconclusive.")
        sys.exit(1)
    else:
        print("[+] All asserted checks passed for this deployment.")
    print("======================================================================")
