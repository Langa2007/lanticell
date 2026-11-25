# Origin Lockdown Guide

To prevent attackers from bypassing Lanticell and hitting your origin server directly, lock down your origin using **both** network controls and request authentication.

## 1. Network Firewall Lockdown

Restrict inbound HTTP/HTTPS (`80`/`443`) on your origin firewall (UFW, `nftables`, AWS Security Group, or hosting firewall) to **only** Lanticell's published gateway egress IP addresses.

Example with `nftables`:
```nft
add rule inet filter input tcp dport { 80, 443 } ip saddr != { <LANTICELL_GATEWAY_IPS> } drop
```

## 2. Origin Secret Header Verification

Lanticell injects a per-tenant `X-Lanticell-Origin-Secret` header on proxied requests. Configure your origin web server or application middleware to reject any request missing the expected secret.

Example NGINX check on the origin:
```nginx
if ($http_x_lanticell_origin_secret != "your-tenant-origin-secret") {
    return 403;
}
```

## 3. Mutual TLS (mTLS) — Recommended for Production

For high-assurance fintech and API workloads, configure origin mTLS so your origin rejects TLS connections not signed by the Lanticell gateway client CA.

## 4. Verify Lockdown

Use the Lanticell Control API or Dashboard **Verify Origin Lockdown** action, which checks whether your origin rejects unauthenticated direct probes.
