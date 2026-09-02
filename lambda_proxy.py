"""
lambda_proxy.py
───────────────────────────────────────────────────────────────────────────────
[context: AWS Lambda universal HTTP proxy | runtime: python3.12 | arch: x86_64]

AWS Lambda handler — universal HTTP egress proxy.
Each Lambda invocation fires from a different IP in AWS's us-east-1 pool.

Target URL carried in:
    1. query param   ?url=http://target.com/path
    2. header        X-Proxy-Target: http://target.com/path

Strips hop-by-hop headers both ways.
Forwards method, sanitized headers, and raw body verbatim.

Entry:        handler(event, context)
Privileges:   Lambda execution role (basic — no VPC needed)
Side effects: outbound HTTP from Lambda container's rotating IP
───────────────────────────────────────────────────────────────────────────────
"""

import json
import base64
import urllib.request
import urllib.error

# hop-by-hop headers — stripped from both request and response
_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host",
    "x-forwarded-for", "x-forwarded-proto", "x-forwarded-port",
    "x-proxy-target",
}


def handler(event, context):
    """
    *sits in the cloud, faceless, waiting for a URL to breathe life into it*
    Registers at entry: event["httpMethod"], event["headers"], event["body"]
    Stack: urllib.request.Request → urlopen → response → dict → API GW format
    """

    # ── resolve target URL ─────────────────────────────────────────────────────
    qs   = event.get("queryStringParameters") or {}
    hdrs = {k.lower(): v for k, v in (event.get("headers") or {}).items()}

    target = qs.get("url") or hdrs.get("x-proxy-target", "")
    if not target:
        return _err(400, "missing target — use ?url=http://... or X-Proxy-Target header")

    # decode percent-encoding if vps_proxy double-encoded it
    try:
        from urllib.parse import unquote
        target = unquote(target)
    except Exception:
        pass

    # ── build forwarded headers ────────────────────────────────────────────────
    fwd = {
        k: v for k, v in hdrs.items()
        if k not in _HOP
    }
    # keep a sane UA if none was forwarded
    fwd.setdefault("user-agent", "Mozilla/5.0 (X11; Linux x86_64) RotatingProxy/1.0")

    # ── body ──────────────────────────────────────────────────────────────────
    raw_body = event.get("body") or ""
    if event.get("isBase64Encoded") and raw_body:
        body_bytes = base64.b64decode(raw_body)
    elif isinstance(raw_body, str):
        body_bytes = raw_body.encode()
    else:
        body_bytes = raw_body or b""

    method = (event.get("httpMethod") or "GET").upper()

    # ── fire ──────────────────────────────────────────────────────────────────
    req = urllib.request.Request(
        target,
        data=body_bytes if body_bytes else None,
        headers=fwd,
        method=method,
    )
    req.add_unredirected_header("Host", _host_from_url(target))

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp_body  = resp.read()
            resp_hdrs  = {
                k: v for k, v in resp.headers.items()
                if k.lower() not in _HOP
            }
            return {
                "statusCode":      resp.status,
                "headers":         resp_hdrs,
                "body":            resp_body.decode(errors="replace"),
                "isBase64Encoded": False,
            }

    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        return {"statusCode": exc.code, "headers": {}, "body": body}

    except Exception as exc:
        return _err(502, str(exc))


# ── helpers ────────────────────────────────────────────────────────────────────

def _host_from_url(url: str) -> str:
    from urllib.parse import urlparse
    p = urlparse(url)
    return p.netloc or p.path


def _err(code: int, msg: str) -> dict:
    return {
        "statusCode": code,
        "headers":    {"Content-Type": "application/json"},
        "body":       json.dumps({"error": msg}),
    }
