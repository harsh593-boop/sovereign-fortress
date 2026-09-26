import sys
import socket
import threading

def main():
    if len(sys.argv) < 3:
        sys.exit(1)
    target_host = sys.argv[1]
    target_port = int(sys.argv[2])

    proxy_host = "127.0.0.1"
    proxy_port = 12334

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((proxy_host, proxy_port))
    s.sendall(b"\x05\x01\x00")
    resp = s.recv(2)
    if resp != b"\x05\x00":
        sys.exit(1)

    try:
        ip_bytes = socket.inet_aton(target_host)
        req = b"\x05\x01\x00\x01" + ip_bytes + target_port.to_bytes(2, "big")
    except Exception:
        host_bytes = target_host.encode('utf-8')
        req = b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes + target_port.to_bytes(2, "big")

    s.sendall(req)
    resp2 = s.recv(10)
    if len(resp2) < 2 or resp2[1] != 0:
        sys.exit(1)

    def sock_to_stdout():
        try:
            while True:
                data = s.recv(4096)
                if not data:
                    break
                sys.stdout.buffer.write(data)
                sys.stdout.buffer.flush()
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass
            import os
            os._exit(0)

    t = threading.Thread(target=sock_to_stdout, daemon=True)
    t.start()

    try:
        while True:
            chunk = sys.stdin.buffer.read1(4096) if hasattr(sys.stdin.buffer, 'read1') else sys.stdin.buffer.read(4096)
            if not chunk:
                break
            s.sendall(chunk)
    except Exception:
        pass
    try:
        s.shutdown(socket.SHUT_WR)
    except Exception:
        pass
    try:
        s.close()
    except Exception:
        pass

if __name__ == "__main__":
    main()
