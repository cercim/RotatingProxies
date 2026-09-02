# RotatingProxies

AWS API Gateway rotating proxy — different AWS IP on every request.

## Architecture
```
Client → VPS:8080 → AWS API GW → Lambda → Target
                        ↑
                  new AWS IP each hit
```

## Files
- `vps_proxy.py` — runs on your VPS, local HTTP proxy server
- `lambda_proxy.py` — deploy to AWS Lambda, universal HTTP egress
- `setup_vps.sh` — one-shot VPS setup script

## Quick start
```bash
# on VPS
python3 vps_proxy.py

# test rotation
curl -x http://YOUR_VPS:8080 http://httpbin.org/ip
```
