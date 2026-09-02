#!/usr/bin/env python3
"""
vps_proxy.py
───────────────────────────────────────────────────────────────────────────────
[context: VPS HTTP rotating proxy | OS: Linux | arch: x86_64 | lang: Python 3.10+]

Local HTTP proxy that routes every request through AWS API Gateway → Lambda.
Each hop exits from a different AWS IP in the Lambda container pool.

Flow:
    client → VPS:8080 → API GW (HTTPS) → Lambda → target site → back

Architecture:
    RotatingProxy     — accept() loop, one thread per connection
    handle_client()   — parses raw HTTP, rewrites for API GW, relays response
    _forward_via_gw() — opens HTTPS tunnel to API GW, injects X-Proxy-Target
    _relay()          — bidirectional select() byte relay

Entry:      RotatingProxy.start() → handle_client() per connection
Stack:      client_sock → raw HTTP parse → HTTPS to API GW → select relay
Privileges: none (port 8080); sudo for port 80
Side effects: one outbound HTTPS connection per client request
───────────────────────────────────────────────────────────────────────────────
"""

import socket
import ssl
import threading
import select
import logging
import signal
import sys
from urllib.parse import urlparse, quote

# ── config ────────────────────────────────────────────────────────────────────
LOCAL_HOST   = "0.0.0.0"
LOCAL_PORT   = 8080                                    # change to 80 if root
API_GW_HOST  = "ebv1qa6ob8.execute-api.us-east-1.amazonaws.com"
API_GW_PORT  = 443
BUFFER_SIZE  = 65536
TIMEOUT      = 20
MAX_THREADS  = 256

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)-7s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("vps-proxy")

# hop-by-hop headers stripped before forwarding
_HOP = {
    b"connection", b"keep-alive", b"proxy-connection",
    b"te", b"transfer-encoding", b"upgrade", b"proxy-authorization",
}


# ── HTTP parser ───────────────────────────────────────────────────────────────

def _parse_request(raw: bytes):
    """
    *cracks the HTTP envelope open and reads what's inside*
    Returns (method, target, http_version, headers_dict, body_bytes)
    headers_dict keys are lowercase bytes.
    """
    sep = raw.find(b"\r\n\r\n")
    head = raw[:sep] if sep != -1 else raw
    body = raw[sep + 4:] if sep != -1 else b""

    lines = head.split(b"\r\n")
    first = lines[0].decode(errors="replace").split()
    if len(first) < 3:
        return None

    method, target, version = first[0].upper(), first[1], first[2]

    headers = {}
    for line in lines[1:]:
        if b":" in line:
            k, _, v = line.partition(b":")
            headers[k.strip().lower()] = v.strip()

    return method, target, version, headers, body


# ── API GW tunnel ─────────────────────────────────────────────────────────────

def _open_gw_ssl() -> ssl.SSLSocket:
    """
    *the raw TCP handshake, then the TLS hello — two cold grips meeting in the dark*
    Opens an HTTPS connection to API GW. Returns the SSL-wrapped socket.
    """
    ctx = ssl.create_default_context()
    raw = socket.create_connection((API_GW_HOST, API_GW_PORT), timeout=TIMEOUT)
    wrapped = ctx.wrap_socket(raw, server_hostname=API_GW_HOST)
    return wrapped


def _forward_via_gw(method: str, target_url: str,
                     headers: dict, body: bytes) -> bytes:
    """
    Sends the rewritten request to API GW over HTTPS.
    Injects X-Proxy-Target so Lambda knows where to egress.
    Returns the raw HTTP response bytes (status line + headers + body).

    *the stack smells of TLS record bytes and a Host header that doesn't belong here*
    Registers: method → req_line, target_url → X-Proxy-Target header
    """
    # ── strip hop-by-hop, rebuild for API GW ──────────────────────────────────
    fwd_headers = {
        k: v for k, v in headers.items()
        if k.lower().encode() not in _HOP
        and k.lower() not in ("host",)
    }
    fwd_headers["Host"]           = API_GW_HOST
    fwd_headers["X-Proxy-Target"] = target_url
    fwd_headers["Connection"]     = "close"

    if body:
        fwd_headers["Content-Length"] = str(len(body))

    # ── build raw HTTP/1.1 request ────────────────────────────────────────────
    req_line  = f"{method} / HTTP/1.1\r\n"
    hdr_block = "".join(f"{k}: {v}\r\n" for k, v in fwd_headers.items())
    request   = (req_line + hdr_block + "\r\n").encode() + body

    # ── fire and collect ──────────────────────────────────────────────────────
    gw = _open_gw_ssl()
    try:
        gw.sendall(request)
        response = b""
        while True:
            chunk = gw.recv(BUFFER_SIZE)
            if not chunk:
                break
            response += chunk
    finally:
        gw.close()

    return response


# ── byte relay ────────────────────────────────────────────────────────────────

def _relay(a: socket.socket, b: socket.socket):
    """
    Bidirectional select() relay — raw bytes, no interpretation.
    *two pipes sharing the same breath until one of them stops*
    """
    a.settimeout(TIMEOUT)
    b.settimeout(TIMEOUT)
    pair = [a, b]
    try:
        while True:
            readable, _, broken = select.select(pair, [], pair, TIMEOUT)
            if broken or not readable:
                break
            for s in readable:
                peer = b if s is a else a
                data = s.recv(BUFFER_SIZE)
                if not data:
                    return
                peer.sendall(data)
    except OSError:
        pass
    finally:
        for s in pair:
            try: s.close()
            except: pass


# ── connection handler ─────────────────────────────────────────────────────────

def handle_client(client_sock: socket.socket, addr: tuple):
    """
    *one thread, one connection, one target — consumed and discarded*
    Entry per accepted connection.
    Stack frame: raw recv → parse → forward via GW → write response → close
    """
    try:
        client_sock.settimeout(TIMEOUT)
        raw = b""
        while b"\r\n\r\n" not in raw:
            chunk = client_sock.recv(BUFFER_SIZE)
            if not chunk:
                return
            raw += chunk
            if len(raw) > 1024 * 1024:          # 1MB header guard
                break

        parsed = _parse_request(raw)
        if not parsed:
            return

        method, target, _, headers_bytes, body = parsed
        headers = {k.decode(errors="replace"): v.decode(errors="replace")
                   for k, v in headers_bytes.items()}

        # ── HTTPS CONNECT — tunnel mode ────────────────────────────────────────
        if method == "CONNECT":
            # For HTTPS: client wants a raw tunnel.
            # We can't MITM SSL without a CA cert, so we relay CONNECT
            # through API GW which hits Lambda which tunnels to target.
            # Simpler: just open a direct tunnel (Lambda can't relay raw TCP).
            # Real-world: configure a local MITM CA if you want HTTPS proxying.
            host, _, port = target.partition(":")
            dst_port = int(port) if port else 443
            try:
                remote = socket.create_connection((host, dst_port), timeout=TIMEOUT)
                client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                log.info(f"[CONNECT] {target}")
                _relay(client_sock, remote)
            except Exception as e:
                client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                log.debug(f"[CONNECT fail] {target}: {e}")
            return

        # ── plain HTTP — route via API GW ──────────────────────────────────────
        log.info(f"[{addr[0]}] {method} {target}")
        try:
            response = _forward_via_gw(method, target, headers, body)
            client_sock.sendall(response)
        except Exception as e:
            log.warning(f"[gw error] {e}")
            client_sock.sendall(
                b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"
            )

    except Exception as e:
        log.debug(f"[{addr}] {e}")
    finally:
        try: client_sock.close()
        except: pass


# ── server ────────────────────────────────────────────────────────────────────

class RotatingProxy:
    """
    *it exhales requests into the AWS void and inhales rotating IPs back*
    """

    def __init__(self, host=LOCAL_HOST, port=LOCAL_PORT):
        self.host = host
        self.port = port
        self._sock = None

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(MAX_THREADS)

        log.info(f"[*] listening on {self.host}:{self.port}")
        log.info(f"[*] egress via → {API_GW_HOST}")
        log.info(f"[*] every HTTP request exits from a different AWS IP")

        while True:
            try:
                client, addr = self._sock.accept()
            except OSError:
                break
            t = threading.Thread(
                target=handle_client,
                args=(client, addr),
                daemon=True,
            )
            t.start()

    def stop(self):
        if self._sock:
            self._sock.close()


# ── entry ──────────────────────────────────────────────────────────────────────

def main():
    import argparse
    ap = argparse.ArgumentParser(description="AWS API GW rotating proxy")
    ap.add_argument("--host", default=LOCAL_HOST)
    ap.add_argument("--port", type=int, default=LOCAL_PORT)
    args = ap.parse_args()

    proxy = RotatingProxy(host=args.host, port=args.port)

    def _sig(s, f):
        log.info("shutting down")
        proxy.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT,  _sig)
    signal.signal(signal.SIGTERM, _sig)
    proxy.start()


if __name__ == "__main__":
    main()
