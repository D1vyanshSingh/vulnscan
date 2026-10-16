"""Local test rig: fake services with deliberate vulnerabilities for scanner tests.

Run:  python3 tests/fake_services.py   (serve until Ctrl+C)
Ports: 21 fake FTP (anonymous + vsftpd 2.3.4 banner), 6379 fake Redis (no auth),
       8080 plain HTTP, 8443 self-signed HTTPS, 11211 fake memcached, 2375 Docker API
"""

import http.server
import os
import socket
import socketserver
import ssl
import subprocess
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CERT_DIR = os.path.join(ROOT, "out")


def raw_server(port: int, handler) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.listen(16)

    def accept_loop() -> None:
        while True:
            try:
                conn, _addr = sock.accept()
            except OSError:
                return
            threading.Thread(target=handler, args=(conn,), daemon=True).start()

    threading.Thread(target=accept_loop, daemon=True).start()
    print(f"  fake service on {port}")


def redis_handler(conn: socket.socket) -> None:
    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            conn.sendall(b"# Server\r\nredis_version:7.2.4\r\n"
                         b"redis_mode:standalone\r\nresponse:2\r\n")
    except OSError:
        pass
    finally:
        conn.close()


def memcached_handler(conn: socket.socket) -> None:
    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            conn.sendall(b"STAT pid 4242\r\nSTAT version 1.6.9\r\nSTAT curr_items 1\r\nEND\r\n")
    except OSError:
        pass
    finally:
        conn.close()


def ftp_handler(conn: socket.socket) -> None:
    try:
        conn.sendall(b"220 (vsFTPD 2.3.4)\r\n")
        while True:
            data = conn.recv(1024)
            if not data:
                break
            replies = b""
            for line in data.decode("latin-1", "replace").split("\r\n"):
                line = line.strip().upper()
                if not line:
                    continue
                if line.startswith("USER"):
                    replies += b"331 Please specify the password.\r\n"
                elif line.startswith("PASS"):
                    replies += b"230 Login successful.\r\n"
                else:
                    replies += b"200 command ok\r\n"
            if replies:
                conn.sendall(replies)
    except OSError:
        pass
    finally:
        conn.close()


_HTTP_BODY = (b"<html><head><title>Test Application Home</title></head>"
              b"<body><h1>placeholder</h1></body></html>")


def http_payload() -> bytes:
    header = ("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
              f"Content-Length: {len(_HTTP_BODY)}\r\nServer: TestWeb/1.2\r\n"
              "Connection: close\r\n\r\n").encode("latin-1")
    return header + _HTTP_BODY


def plain_http_handler(conn: socket.socket) -> None:
    try:
        conn.recv(8192)
        conn.sendall(http_payload())
    except OSError:
        pass
    finally:
        conn.close()


def make_https_handler(cert_dir: str, port: int = 8443) -> None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.path.join(cert_dir, "selfsigned.pem"),
                        os.path.join(cert_dir, "selfsigned.key"))

    def handler(conn: socket.socket) -> None:
        try:
            with ctx.wrap_socket(conn, server_side=True) as tls_conn:
                tls_conn.recv(8192)
                tls_conn.sendall(http_payload())
        except OSError:
            pass

    raw_server(port, handler)


def start_http_subprocess(port: int) -> None:
    handler = http.server.SimpleHTTPRequestHandler
    try:
        allow_reuse = socketserver.TCPServer.allow_reuse_address
        socketserver.TCPServer.allow_reuse_address = True
        httpd = socketserver.TCPServer(("127.0.0.1", port), handler)
        socketserver.TCPServer.allow_reuse_address = allow_reuse
    except OSError as exc:
        print(f"  port {port} already in use ({exc}); skipping it")
        return
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    print(f"  http.server on {port}")


def main() -> int:
    os.makedirs(CERT_DIR, exist_ok=True)
    pem = os.path.join(CERT_DIR, "selfsigned.pem")
    key = os.path.join(CERT_DIR, "selfsigned.key")
    if not (os.path.exists(pem) and os.path.exists(key)):
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-days", "3650", "-subj", "/CN=testapp.local",
             "-keyout", key, "-out", pem],
            check=True, capture_output=True)
        print("  generated self-signed certificate")

    for port, handler_fn in ((6379, redis_handler), (11211, memcached_handler),
                             (8443, None)):
        try:
            if handler_fn is None:
                make_https_handler(CERT_DIR, port)
            else:
                raw_server(port, handler_fn)
        except OSError as exc:
            print(f"  port {port} unavailable ({exc}); skipping it")
    # Windows reserves some low ports (PermissionError) → fall back to 2121.
    for ftp_port in (21, 2121):
        try:
            raw_server(ftp_port, ftp_handler)
            break
        except PermissionError:
            print(f"  port {ftp_port} reserved by Windows, trying next")
    make_https_handler(CERT_DIR)
    start_http_subprocess(8080)
    start_http_subprocess(2375)

    print("test services running — Ctrl+C to stop")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
