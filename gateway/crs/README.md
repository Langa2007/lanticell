# OWASP Core Rule Set (CRS) Pinning

- **Pinned Version:** `v4.10.0`
- **Source:** `https://github.com/coreruleset/coreruleset`

Do not vendor upstream CRS rules blindly. Every CRS upgrade must:
1. Update the pinned version here and in `gateway/coraza/setup/lanticell-base.conf`.
2. Run against `data/replay/attacks/` and `data/replay/benign/` to verify detection and false-positive targets.
3. Roll out via `monitor` mode canary before enabling `block` mode.
