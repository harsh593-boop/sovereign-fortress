"""Fetch server params over SSH, download+verify sing-box for Windows, render and validate
both client configs. Everything secret goes to %LOCALAPPDATA%\\SovereignFortress (outside the repo).
Usage: python tools/gen_client.py [--refresh]"""
import hashlib, io, json, os, subprocess, sys, urllib.request, zipfile
sys.path.insert(0, os.path.dirname(__file__))
import vps

SB_VER = "1.14.3"
SB_SHA256 = "d8b86ef58936dba9230ec6a57ffa4243933f3c14ef4809828b6c553440ed1518"
SB_URL = f"https://github.com/SagerNet/sing-box/releases/download/v{SB_VER}/sing-box-{SB_VER}-windows-amd64.zip"
BASE = os.path.join(os.environ["LOCALAPPDATA"], "SovereignFortress")
BIN = os.path.join(BASE, "bin")
DNS_PORT = 5353


def ensure_binary():
    exe = os.path.join(BIN, "sing-box.exe")
    if os.path.exists(exe):
        out = subprocess.run([exe, "version"], capture_output=True, text=True).stdout
        if SB_VER in out:
            return exe
    # The campus network blocks/intercepts GitHub: fetch via the VPS, verify the pinned hash here.
    t = vps.connect()
    vps.run(t, f"curl -fsSL -o /tmp/sb-win.zip {SB_URL}")
    tmp = os.path.join(os.environ["TEMP"], "sb-win.zip")
    vps.get(t, "/tmp/sb-win.zip", tmp)
    data = open(tmp, "rb").read()
    os.remove(tmp)
    if hashlib.sha256(data).hexdigest() != SB_SHA256:
        raise SystemExit("sing-box download checksum mismatch")
    os.makedirs(BIN, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for n in z.namelist():
            if n.endswith(("sing-box.exe", "libcronet.dll")):
                open(os.path.join(BIN, os.path.basename(n)), "wb").write(z.read(n))
    return exe


def fetch_params(refresh):
    p = os.path.join(BASE, "params.json")
    if os.path.exists(p) and not refresh:
        return json.load(open(p))
    t = vps.connect()
    s = vps.paramiko.SFTPClient.from_transport(t)
    # file is root:singbox 0640; ubuntu is not in that group, so read through sudo
    _, out, _ = vps.run(t, "cat /etc/sing-box/params.json", sudo=True)
    params = json.loads(out)
    params["server"] = vps.HOST
    os.makedirs(BASE, exist_ok=True)
    json.dump(params, open(p, "w"))
    return params


def proxy_outbound(p):
    return {"type": "vless", "tag": "proxy", "server": p["server"], "server_port": p["port"],
            "uuid": p["uuid"], "flow": "xtls-rprx-vision", "packet_encoding": "xudp",
            "tls": {"enabled": True, "server_name": p["sni"],
                    "utls": {"enabled": True, "fingerprint": "chrome"},
                    "reality": {"enabled": True, "public_key": p["public_key"], "short_id": p["short_id"]}}}


def tun_inbound():
    return {"type": "tun", "tag": "tun-in", "interface_name": "fortress0",
            "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
            "mtu": 1400, "auto_route": True, "strict_route": True, "stack": "mixed"}


def base(p, level):
    return {"log": {"level": level, "timestamp": True},
            "inbounds": [tun_inbound()],
            "outbounds": [proxy_outbound(p), {"type": "direct", "tag": "direct"}]}


def full_tunnel(p):
    c = base(p, "warn")
    c["dns"] = {"servers": [{"type": "udp", "tag": "vps-dns", "server": "127.0.0.1",
                             "server_port": DNS_PORT, "detour": "proxy"}],
                "final": "vps-dns", "strategy": "ipv4_only"}
    c["route"] = {"auto_detect_interface": True, "final": "proxy", "rules": [
        {"port": [53], "action": "hijack-dns"},
        {"protocol": "dns", "action": "hijack-dns"},
        {"ip_version": 6, "action": "reject"},
        {"ip_is_private": True, "outbound": "direct"}]}
    return c


def traffic_only(p):
    c = base(p, "warn")
    # No DNS hijack: name resolution stays with the OS (YogaDNS -> NextDNS).
    c["dns"] = {"servers": [{"type": "local", "tag": "local"}], "final": "local", "strategy": "ipv4_only"}
    c["route"] = {"auto_detect_interface": True, "find_process": True, "final": "proxy", "rules": [
        {"process_name": ["YogaDNS.exe", "ServiceManager.exe"], "outbound": "direct"},
        {"ip_version": 6, "action": "reject"},
        {"ip_is_private": True, "outbound": "direct"}]}
    return c


def main():
    exe = ensure_binary()
    p = fetch_params("--refresh" in sys.argv)
    for name, cfg in (("full", full_tunnel(p)), ("traffic", traffic_only(p))):
        path = os.path.join(BASE, f"{name}.json")
        json.dump(cfg, open(path, "w"), indent=2)
        r = subprocess.run([exe, "check", "-c", path], capture_output=True, text=True)
        print(name, "check:", "OK" if r.returncode == 0 else "FAIL\n" + r.stdout + r.stderr)
        if r.returncode:
            sys.exit(1)
    print("output dir:", BASE)


if __name__ == "__main__":
    main()
