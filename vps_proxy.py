#!/usr/bin/env python3
import socket, ssl, threading, select, logging, signal, sys
from urllib.parse import urlparse

LOCAL_HOST  = '0.0.0.0'
LOCAL_PORT  = 8080
API_GW_HOST = 'ebv1qa6ob8.execute-api.us-east-1.amazonaws.com'
API_GW_PORT = 443
BUFFER_SIZE = 65536
TIMEOUT     = 20

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)-7s %(message)s')
log = logging.getLogger('vps-proxy')

_HOP = {'connection','keep-alive','proxy-connection','te','transfer-encoding','upgrade','proxy-authorization','proxy-connection'}

def _parse(raw):
    sep   = raw.find(b'\r\n\r\n')
    head  = raw[:sep] if sep != -1 else raw
    body  = raw[sep+4:] if sep != -1 else b''
    lines = head.split(b'\r\n')
    first = lines[0].decode(errors='replace').split()
    if len(first) < 2: return None
    method, target = first[0].upper(), first[1]
    headers = {}
    for line in lines[1:]:
        if b':' in line:
            k, _, v = line.partition(b':')
            headers[k.strip().lower().decode(errors='replace')] = v.strip().decode(errors='replace')
    return method, target, headers, body

def _relay(a, b):
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

def _forward(method, target_url, headers, body):
    parsed   = urlparse(target_url)
    # preserve path+query so API GW proxy+ passes them to backend
    path     = parsed.path or '/'
    if parsed.query: path += '?' + parsed.query

    fwd = {k: v for k, v in headers.items() if k not in _HOP and k != 'host'}
    fwd['Host']       = API_GW_HOST
    fwd['Connection'] = 'close'
    if body: fwd['Content-Length'] = str(len(body))

    req  = f'{method} {path} HTTP/1.1\r\n'
    req += ''.join(f'{k}: {v}\r\n' for k, v in fwd.items())
    req += '\r\n'

    ctx = ssl.create_default_context()
    raw = socket.create_connection((API_GW_HOST, API_GW_PORT), timeout=TIMEOUT)
    gw  = ctx.wrap_socket(raw, server_hostname=API_GW_HOST)
    try:
        gw.sendall(req.encode() + body)
        resp = b''
        while True:
            chunk = gw.recv(BUFFER_SIZE)
            if not chunk: break
            resp += chunk
    finally:
        gw.close()
    return resp

def handle(client, addr):
    try:
        client.settimeout(TIMEOUT)
        raw = b''
        while b'\r\n\r\n' not in raw:
            chunk = client.recv(BUFFER_SIZE)
            if not chunk: return
            raw += chunk
        parsed = _parse(raw)
        if not parsed: return
        method, target, headers, body = parsed
        if method == 'CONNECT':
            host, _, port = target.partition(':')
            try:
                remote = socket.create_connection((host, int(port or 443)), timeout=TIMEOUT)
                client.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                log.info(f'[CONNECT] {target}')
                _relay(client, remote)
            except Exception as e:
                client.sendall(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
            return
        log.info(f'[{addr[0]}] {method} {target}')
        try:
            resp = _forward(method, target, headers, body)
            client.sendall(resp)
        except Exception as e:
            log.warning(f'[gw error] {e}')
            client.sendall(b'HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n')
    except Exception as e:
        log.debug(f'[{addr}] {e}')
    finally:
        try: client.close()
        except: pass

def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((LOCAL_HOST, LOCAL_PORT))
    srv.listen(256)
    log.info(f'[*] listening on {LOCAL_HOST}:{LOCAL_PORT}')
    log.info(f'[*] egress via AWS API GW -> {API_GW_HOST}')
    while True:
        try:
            client, addr = srv.accept()
            threading.Thread(target=handle, args=(client, addr), daemon=True).start()
        except OSError: break

signal.signal(signal.SIGINT,  lambda s,f: sys.exit(0))
signal.signal(signal.SIGTERM, lambda s,f: sys.exit(0))
main()
