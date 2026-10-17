"""Secure SSH helper: key + TOTP (keyboard-interactive). Secrets are read at runtime
from local files outside the repo and never printed. Usage: python vps.py "<cmd>" [--sudo]"""
import base64, hashlib, hmac, os, re, struct, sys, time
import paramiko
HOST = os.environ.get("FORTRESS_HOST", "144.24.112.45")
USER = "ubuntu"
DL = os.path.expanduser(r"~\Downloads")
KEY = os.environ.get("FORTRESS_SSH_KEY", os.path.join(DL, "ssh-key-2026-09-18.key"))
def _read(p): return open(p, encoding="utf-8", errors="ignore").read()
def totp():
    m = re.search(r"[A-Z2-7]{16,}", _read(os.path.join(DL, "topt.txt")))
    k = base64.b32decode(m.group(0), True)
    h = hmac.new(k, struct.pack(">Q", int(time.time() // 30)), hashlib.sha1).digest()
    o = h[-1] & 15
    return f"{(struct.unpack('>I', h[o:o+4])[0] & 0x7fffffff) % 10**6:06d}"
def sudo_pw():
    for l in _read(os.path.join(DL, "keys.txt")).splitlines():
        if "sudo password" in l.lower():
            return re.split(r"[:\t]", l, 1)[1].strip()
def connect():
    for attempt in range(3):
        t = paramiko.Transport((HOST, 22))
        t.start_client(timeout=20)
        pkey = None
        for c in (paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey):
            try: pkey = c.from_private_key_file(KEY); break
            except Exception: pass
        try:
            t.auth_publickey(USER, pkey)
        except paramiko.BadAuthenticationType:
            pass
        except paramiko.AuthenticationException:
            pass
        if not t.is_authenticated():
            try:
                t.auth_interactive(USER, lambda title, inst, prompts: [totp() if "verif" in p[0].lower() or "code" in p[0].lower() or "otp" in p[0].lower() else (sudo_pw() if "password" in p[0].lower() else totp()) for p in prompts])
            except paramiko.AuthenticationException:
                pass
        if t.is_authenticated(): return t
        t.close(); time.sleep(31)
    raise SystemExit("auth failed")
def run(t, cmd, sudo=False, timeout=600):
    if sudo: cmd = "sudo -S -p '' bash -c " + __import__("shlex").quote(cmd)
    ch = t.open_session(); ch.settimeout(timeout); ch.exec_command(cmd)
    if sudo: ch.send(sudo_pw() + "\n")
    out = b""
    while True:
        d = ch.recv(65536)
        if not d: break
        out += d
    err = b""
    while ch.recv_stderr_ready(): err += ch.recv_stderr(65536)
    return ch.recv_exit_status(), out.decode(errors="replace"), err.decode(errors="replace")
def put(t, local, remote):
    s = paramiko.SFTPClient.from_transport(t); s.put(local, remote); s.close()
def get(t, remote, local):
    s = paramiko.SFTPClient.from_transport(t); s.get(remote, local); s.close()
if __name__ == "__main__":
    t = connect()
    if sys.argv[1] == "--put": put(t, sys.argv[2], sys.argv[3]); sys.exit(0)
    if sys.argv[1] == "--get": get(t, sys.argv[2], sys.argv[3]); sys.exit(0)
    cmd = open(sys.argv[2]).read() if sys.argv[1] == "-f" else sys.argv[1]
    c, o, e = run(t, cmd, sudo="--sudo" in sys.argv)
    sys.stdout.write(o); sys.stderr.write(e); sys.exit(c)



