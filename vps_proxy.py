#!/usr/bin/env python3
"""
vps_proxy.py
───────────────────────────────────────────────────────────────────────────────
[context: VPS HTTP rotating proxy | OS: Linux | arch: x86_64 | lang: Python 3.10+]

Global rotating proxy — 18 AWS regions, round-robin per request.
Tuned for high concurrency: semaphore-capped threads, 512KB stacks,
65535 FDs via systemd, 4096 listen backlog.

Theoretical max concurrent: ~5000 (RAM-bound, not FD-bound after tuning)
Tested box: 8vCPU AMD EPYC / 32GB RAM
───────────────────────────────────────────────────────────────────────────────
"""

import socket, ssl, threading, select, logging, signal, sys
from urllib.parse import urlparse

# ── reduce thread stack to 512 KB (default 8 MB) ─────────────────────────────
# 5000 threads * 512KB = 2.5GB — fits easily in 32GB RAM
threading.stack_size(512 * 1024)

LOCAL_HOST   = "0.0.0.0"
LOCAL_PORT   = 80
BUFFER_SIZE  = 65536
TIMEOUT      = 25
LISTEN_BACKLOG   = 4096
MAX_CONCURRENT   = 5000   # semaphore cap — tune up/down based on load

# ── proxy credentials (change these) ─────────────────────────────────────────
PROXY_USER = "electra"
PROXY_PASS = "ElectraOp272"

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)-7s %(message)s",
)
log = logging.getLogger("rotator")

# ── 18 AWS API Gateway endpoints ──────────────────────────────────────────────
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
    "connection", "keep-alive", "proxy-connection",
    "te", "transfer-encoding", "upgrade", "proxy-authorization",
}

import base64

# ── auth ──────────────────────────────────────────────────────────────────────
_EXPECTED_CRED = base64.b64encode(f"{PROXY_USER}:{PROXY_PASS}".encode()).decode()

_407 = (
    b"HTTP/1.1 407 Proxy Authentication Required\r\n"
    b"Proxy-Authenticate: Basic realm=\"RotatingProxy\"\r\n"
    b"Content-Length: 0\r\n"
    b"Connection: close\r\n\r\n"
)

def _auth_ok(headers: dict) -> bool:
    """
    Validates Proxy-Authorization: Basic base64(user:pass).
    *checks the ticket at the door — wrong cred, no entry*
    Returns True if credentials match, False otherwise.
    """
    raw = headers.get("proxy-authorization", "")
    if not raw.lower().startswith("basic "):
        return False
    return raw[6:].strip() == _EXPECTED_CRED


# ── round-robin state ─────────────────────────────────────────────────────────
_gw_lock  = threading.Lock()
_gw_index = 0

# ── concurrency cap ───────────────────────────────────────────────────────────
_sem = threading.Semaphore(MAX_CONCURRENT)

# ── live connection counter ───────────────────────────────────────────────────
_active     = 0
_active_lock = threading.Lock()


def _pick_gw():
    """
    Thread-safe round-robin — steps through all 18 regions in order.
    *the counter ticks forward, never backward, never skipping a continent*
    """
    global _gw_index
    with _gw_lock:
        region, host = API_GATEWAYS[_gw_index % len(API_GATEWAYS)]
        _gw_index += 1
    return region, host


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _parse(raw: bytes):
    sep   = raw.find(b"\r\n\r\n")
    head  = raw[:sep] if sep != -1 else raw
    body  = raw[sep + 4:] if sep != -1 else b""
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
    Bidirectional select() relay — zero-copy path, minimal overhead.
    *two pipes breathing in sync until one goes silent*
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
            try:
                s.close()
            except Exception:
                pass


def _forward(method: str, target_url: str, headers: dict, body: bytes) -> bytes:
    """
    Grab the next gateway in rotation, open SSL, fire request.
    *the index ticks, a continent is chosen, the packet dissolves into AWS*
    """
    region, gw_host = _pick_gw()

    parsed = urlparse(target_url)
    path   = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    fwd = {k: v for k, v in headers.items() if k not in _HOP and k != "host"}
    fwd["Host"]       = gw_host
    fwd["Connection"] = "close"
    if body:
        fwd["Content-Length"] = str(len(body))

    req  = f"{method} {path} HTTP/1.1\r\n"
    req += "".join(f"{k}: {v}\r\n" for k, v in fwd.items())
    req += "\r\n"

    log.info(f"  -> {region}")

    ctx = ssl.create_default_context()
    raw = socket.create_connection((gw_host, 443), timeout=TIMEOUT)
    gw  = ctx.wrap_socket(raw, server_hostname=gw_host)
    try:
        gw.sendall(req.encode() + body)
        resp = b""
        while True:
            chunk = gw.recv(BUFFER_SIZE)
            if not chunk:
                break
            resp += chunk
    finally:
        gw.close()

    return resp


# ── per-connection handler ────────────────────────────────────────────────────

def handle(client: socket.socket, addr: tuple):
    """
    *one thread, one connection — lives for the duration of the relay, then dies*
    Semaphore is acquired before this is called and released on exit.
    Active counter tracks live connections for stats.
    """
    global _active
    with _active_lock:
        _active += 1

    try:
        client.settimeout(TIMEOUT)
        raw = b""
        while b"\r\n\r\n" not in raw:
            chunk = client.recv(BUFFER_SIZE)
            if not chunk:
                return
            raw += chunk
            if len(raw) > 1024 * 1024:
                break

        parsed = _parse(raw)
        if not parsed:
            return
        method, target, headers, body = parsed

        # ── auth gate ─────────────────────────────────────────────────────────
        if not _auth_ok(headers):
            client.sendall(_407)
            log.warning(f"[auth fail] {addr[0]} {method} {target}")
            return

        if method == "CONNECT":
            host, _, port = target.partition(":")
            try:
                remote = socket.create_connection((host, int(port or 443)), timeout=TIMEOUT)
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                log.info(f"[CONNECT] {target}")
                _relay(client, remote)
            except Exception:
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
        try:
            client.close()
        except Exception:
            pass
        with _active_lock:
            _active -= 1
        _sem.release()


# ── stats logger (every 60s) ──────────────────────────────────────────────────

def _stats_loop():
    import time
    while True:
        time.sleep(60)
        with _active_lock:
            a = _active
        with _gw_lock:
            idx = _gw_index
        log.info(f"[stats] active={a}  total_requests={idx}  free_slots={MAX_CONCURRENT - a}")


# ── server ────────────────────────────────────────────────────────────────────

def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # TCP_DEFER_ACCEPT: don't wake the accept loop until data arrives
    if hasattr(socket, "TCP_DEFER_ACCEPT"):
        srv.setsockopt(socket.IPPROTO_TCP, socket.TCP_DEFER_ACCEPT, 1)
    srv.bind((LOCAL_HOST, LOCAL_PORT))
    srv.listen(LISTEN_BACKLOG)

    log.info(f"[*] listening on 0.0.0.0:{LOCAL_PORT} | backlog={LISTEN_BACKLOG}")
    log.info(f"[*] {len(API_GATEWAYS)} regions | round-robin | max_concurrent={MAX_CONCURRENT}")
    log.info(f"[*] thread stack=512KB | fd_limit via systemd LimitNOFILE=65535")

    threading.Thread(target=_stats_loop, daemon=True).start()

    while True:
        try:
            client, addr = srv.accept()
        except OSError:
            break

        if not _sem.acquire(blocking=False):
            # at capacity — reject immediately
            try:
                client.sendall(b"HTTP/1.1 503 Too Many Connections\r\nContent-Length: 0\r\n\r\n")
                client.close()
            except Exception:
                pass
            log.warning("[!] connection rejected — at capacity")
            continue

        threading.Thread(
            target=handle,
            args=(client, addr),
            daemon=True,
        ).start()


signal.signal(signal.SIGINT,  lambda s, f: sys.exit(0))
signal.signal(signal.SIGTERM, lambda s, f: sys.exit(0))
main()
