#!/usr/bin/env python3
"""
vps_proxy.py
───────────────────────────────────────────────────────────────────────────────
[context: VPS HTTP rotating proxy | OS: Linux | arch: x86_64 | lang: Python 3.10+]

Global rotating proxy — 18 AWS regions, different IP every request.

Flow:
    client → VPS:80 → random AWS API GW region → target site → back

Regions: us-east-1/2, us-west-1/2, ap-south-1/2, ap-northeast-1/2/3,
         ap-southeast-1/2, ca-central-1, eu-central-1, eu-west-1/2/3,
         eu-north-1, sa-east-1

Entry:      RotatingProxy.start() → handle() per connection
Privileges: root (port 80)
Side effects: one outbound HTTPS per client request, random region selected
───────────────────────────────────────────────────────────────────────────────
"""

import socket, ssl, threading, select, logging, signal, sys, random
from urllib.parse import urlparse

LOCAL_HOST  = "0.0.0.0"
LOCAL_PORT  = 80
BUFFER_SIZE = 65536
TIMEOUT     = 25

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)-7s %(message)s")
log = logging.getLogger("rotator")

# ── 18 global API GW endpoints ────────────────────────────────────────────────
API_GATEWAYS = [
    ("us-east-1",      "ebv1qa6ob8.execute-api.us-east-1.amazonaws.com"),
    ("us-east-2",      "zqt43528j7.execute-api.us-east-2.amazonaws.com"),
    ("us-west-1",      "1l0h5o566f.execute-api.us-west-1.amazonaws.com"),
    ("us-west-2",      "4r2s4sikg0.execute-api.us-west-2.amazonaws.com"),
    ("ap-south-2",     "jnvzcob7f2.execute-api.ap-south-2.amazonaws.com"),
    ("ap-south-1",     "b28zi24x7i.execute-api.ap-south-1.amazonaws.com"),
    ("ap-northeast-3", "q6o0s9hvhg.execute-api.ap-northeast-3.amazonaws.com"),
    ("ap-northeast-2", "n1hem0ovaa.execute-api.ap-northeast-2.amazonaws.com"),
    ("ap-southeast-1", "m4qd3228qe.execute-api.ap-southeast-1.amazonaws.com"),
    ("ap-southeast-2", "4m16doe0ie.execute-api.ap-southeast-2.amazonaws.com"),
    ("ap-northeast-1", "xrnwfoxj72.execute-api.ap-northeast-1.amazonaws.com"),
    ("ca-central-1",   "pshccrdmq3.execute-api.ca-central-1.amazonaws.com"),
    ("eu-central-1",   "8qjcaacw0d.execute-api.eu-central-1.amazonaws.com"),
    ("eu-west-1",      "9hnydysfh7.execute-api.eu-west-1.amazonaws.com"),
    ("eu-west-2",      "ivu7de1awk.execute-api.eu-west-2.amazonaws.com"),
    ("eu-west-3",      "xsfwq7r12m.execute-api.eu-west-3.amazonaws.com"),
    ("eu-north-1",     "5lzbote1me.execute-api.eu-north-1.amazonaws.com"),
    ("sa-east-1",      "dtrtw0otyc.execute-api.sa-east-1.amazonaws.com"),
]

_HOP = {
    "connection","keep-alive","proxy-connection",
    "te","transfer-encoding","upgrade","proxy-authorization",
}

# ── helpers ───────────────────────────────────────────────────────────────────

def _pick_gw():
    """*spins the globe and lands on a random AWS region*"""
    return random.choice(API_GATEWAYS)

def _parse(raw: bytes):
    sep   = raw.find(b"\r\n\r\n")
    head  = raw[:sep] if sep != -1 else raw
    body  = raw[sep+4:] if sep != -1 else b""
    lines = head.split(b"\r\n")
    first = lines[0].decode(errors="replace").split()
    if len(first) < 2:
        return None
    method, target = first[0].upper(), first[1]
    headers = {}
    for line in lines[1:]:
        if b":" in line:
            k, _, v = line.partition(b":")
            headers[k.strip().lower().decode(errors="replace")] = v.strip().decode(errors="replace")
    return method, target, headers, body

def _relay(a: socket.socket, b: socket.socket):
    """
    Bidirectional select() relay.
    *two pipes breathing in sync until one of them goes quiet*
    """
    a.settimeout(TIMEOUT); b.settimeout(TIMEOUT)
    pair = [a, b]
    try:
        while True:
            readable, _, broken = select.select(pair, [], pair, TIMEOUT)
            if broken or not readable: break
            for s in readable:
                peer = b if s is a else a
                data = s.recv(BUFFER_SIZE)
                if not data: return
                peer.sendall(data)
    except OSError: pass
    finally:
        for s in pair:
            try: s.close()
            except: pass

def _open_gw(gw_host: str) -> ssl.SSLSocket:
    ctx = ssl.create_default_context()
    raw = socket.create_connection((gw_host, 443), timeout=TIMEOUT)
    return ctx.wrap_socket(raw, server_hostname=gw_host)

def _forward(method: str, target_url: str, headers: dict, body: bytes) -> bytes:
    """
    Fire request through a randomly chosen AWS API GW region.
    *picks a continent, dials in, and lets the packet disappear into AWS's veins*
    Registers: region → log, gw_host → SSL SNI, path → HTTP request line
    """
    region, gw_host = _pick_gw()
    parsed = urlparse(target_url)
    path   = parsed.path or "/"
    if parsed.query: path += "?" + parsed.query

    fwd = {k: v for k, v in headers.items() if k not in _HOP and k != "host"}
    fwd["Host"]       = gw_host
    fwd["Connection"] = "close"
    if body: fwd["Content-Length"] = str(len(body))

    req  = f"{method} {path} HTTP/1.1\r\n"
    req += "".join(f"{k}: {v}\r\n" for k, v in fwd.items())
    req += "\r\n"

    log.info(f"→ {region}")
    gw = _open_gw(gw_host)
    try:
        gw.sendall(req.encode() + body)
        resp = b""
        while True:
            chunk = gw.recv(BUFFER_SIZE)
            if not chunk: break
            resp += chunk
    finally:
        gw.close()
    return resp


# ── connection handler ────────────────────────────────────────────────────────

def handle(client: socket.socket, addr: tuple):
    try:
        client.settimeout(TIMEOUT)
        raw = b""
        while b"\r\n\r\n" not in raw:
            chunk = client.recv(BUFFER_SIZE)
            if not chunk: return
            raw += chunk
            if len(raw) > 1024 * 1024: break

        parsed = _parse(raw)
        if not parsed: return
        method, target, headers, body = parsed

        if method == "CONNECT":
            # HTTPS — direct tunnel (SSL passthrough)
            host, _, port = target.partition(":")
            try:
                remote = socket.create_connection((host, int(port or 443)), timeout=TIMEOUT)
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                log.info(f"[CONNECT] {target}")
                _relay(client, remote)
            except Exception as e:
                client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            return

        log.info(f"[{addr[0]}] {method} {target}")
        try:
            resp = _forward(method, target, headers, body)
            client.sendall(resp)
        except Exception as e:
            log.warning(f"[gw error] {e}")
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")

    except Exception as e:
        log.debug(f"[{addr}] {e}")
    finally:
        try: client.close()
        except: pass


# ── server ────────────────────────────────────────────────────────────────────

def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((LOCAL_HOST, LOCAL_PORT))
    srv.listen(512)

    log.info(f"[*] listening on {LOCAL_HOST}:{LOCAL_PORT}")
    log.info(f"[*] {len(API_GATEWAYS)} regions loaded — global IP pool active")
    for r, h in API_GATEWAYS:
        log.info(f"    {r.ljust(18)} {h}")

    while True:
        try:
            client, addr = srv.accept()
            threading.Thread(target=handle, args=(client, addr), daemon=True).start()
        except OSError: break

signal.signal(signal.SIGINT,  lambda s, f: sys.exit(0))
signal.signal(signal.SIGTERM, lambda s, f: sys.exit(0))
main()
