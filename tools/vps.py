"""Unattended VPS runner: SSH key + TOTP (keyboard-interactive), sudo via stdin, SFTP.
Secrets are read at runtime from ~/Downloads (keys.txt, topt.txt) and never printed.
  python tools/vps.py "<cmd>" [--sudo]
  python tools/vps.py -f script.sh [--sudo]
  python tools/vps.py --put <local> <remote> [<local> <remote> ...]
  python tools/vps.py --get <remote> <local>"""
import base64, hashlib, hmac, os, re, shlex, struct, sys, time
import paramiko

HOST = os.environ.get("FORTRESS_HOST") or sys.exit("set FORTRESS_HOST to the VPS IP")
USER = "ubuntu"
DL = os.path.expanduser(r"~\Downloads")
KEY = os.environ.get("FORTRESS_SSH_KEY", os.path.join(DL, "ssh-key-2026-09-18.key"))
STAMP = os.path.join(os.path.expanduser("~"), ".fortress_totp_step")


def _read(p):
    return open(p, encoding="utf-8", errors="ignore").read()


def totp(step):
    m = re.search(r"[A-Z2-7]{32}", _read(os.path.join(DL, "topt.txt")))
    k = base64.b32decode(m.group(0), True)
    h = hmac.new(k, struct.pack(">Q", step), hashlib.sha1).digest()
    o = h[-1] & 15
    return f"{(struct.unpack('>I', h[o:o + 4])[0] & 0x7fffffff) % 10**6:06d}"


def sudo_pw():
    for line in _read(os.path.join(DL, "keys.txt")).splitlines():
        if "sudo password" in line.lower():
            return re.split(r"[:\t]", line, 1)[1].strip()
    raise SystemExit("sudo password not found in keys.txt")


def fresh_step():
    """PAM rejects TOTP replay: never reuse the 30 s window of the previous login."""
    try:
        last = int(open(STAMP).read())
    except Exception:
        last = 0
    while int(time.time() // 30) <= last:
        time.sleep(1)
    step = int(time.time() // 30)
    open(STAMP, "w").write(str(step))
    return step


def load_key():
    for c in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
        try:
            return c.from_private_key_file(KEY)
        except Exception:
            pass
    raise SystemExit("cannot load ssh key")


def connect():
    pkey = load_key()
    for _ in range(3):
        t = paramiko.Transport((HOST, 22))
        t.start_client(timeout=20)
        try:
            t.auth_publickey(USER, pkey)  # partial success -> keyboard-interactive next
        except paramiko.AuthenticationException:
            pass
        if not t.is_authenticated():
            code = totp(fresh_step())
            try:
                t.auth_interactive(USER, lambda _t, _i, prompts: [code for _ in prompts])
            except paramiko.AuthenticationException:
                pass
        if t.is_authenticated():
            t.set_keepalive(15)
            return t
        t.close()
    raise SystemExit("auth failed")


def run(t, cmd, sudo=False, timeout=900):
    if sudo:
        cmd = "sudo -S -p '' bash -c " + shlex.quote(cmd)
    ch = t.open_session()
    ch.settimeout(timeout)
    ch.exec_command(cmd)
    if sudo:
        ch.sendall(sudo_pw() + "\n")
    ch.shutdown_write()
    while True:
        if ch.recv_ready():
            sys.stdout.write(ch.recv(65536).decode(errors="replace")); sys.stdout.flush()
        elif ch.recv_stderr_ready():
            sys.stderr.write(ch.recv_stderr(65536).decode(errors="replace")); sys.stderr.flush()
        elif ch.exit_status_ready() and not ch.recv_ready() and not ch.recv_stderr_ready():
            break
        else:
            time.sleep(0.05)
    return ch.recv_exit_status()


if __name__ == "__main__":
    a = sys.argv[1:]
    t = connect()
    if a[0] == "--put":
        s = paramiko.SFTPClient.from_transport(t)
        for i in range(1, len(a), 2):
            s.put(a[i], a[i + 1])
        sys.exit(0)
    if a[0] == "--get":
        paramiko.SFTPClient.from_transport(t).get(a[1], a[2]); sys.exit(0)
    cmd = open(a[1], encoding="utf-8").read().replace("\r\n", "\n") if a[0] == "-f" else a[0]
    sys.exit(run(t, cmd, sudo="--sudo" in a))
