#!/bin/sh
# Extract the uncompressed SM2 public key from the server_sign cert
# and write it as a 130-hex-char string (with '0x' prefix) to
# /work/run/server_sign_pub.hex. gm-tlcp's interop_client expects
# this format as its 2nd CLI argument.
#
# We use `openssl x509 -text` (NOT `openssl ec -pubin -text`) because
# the X.509 cert's embedded SubjectPublicKeyInfo is the only path that
# consistently parses SM2 across Ubuntu/Debian/openSSL versions.
set -e
apt-get update -qq
apt-get install -y -qq openssl ca-certificates python3 >/dev/null 2>&1

# Dump the cert's text representation, which includes the EC point.
openssl x509 -in /work/run/certs/server_sign.crt -text -noout -out /work/run/server_sign_pub.txt

# Parse with Python — way more robust than awk on multi-line
# colon-separated hex dumps.
python3 - <<'PYEOF'
import re, sys
text = open('/work/run/server_sign_pub.txt').read()
# Extract only lines between `pub:` and the next blank/non-hex line.
# Lines look like: `    04:a6:ee:...:12:` (the last `:` is optional).
# We want: capture `04:` marker + all continuation bytes.
lines = text.splitlines()
out = []
in_pub = False
for ln in lines:
    if re.match(r'^\s*pub:\s*$', ln):
        in_pub = True
        continue
    if not in_pub:
        continue
    # Match "<spaces>XX:XX:...:XX(:?)\s*" with each XX a hex byte.
    m = re.match(r'^\s+((?:[0-9a-fA-F]{2}:)+[0-9a-fA-F]{2}):?\s*$', ln)
    if not m:
        # Not a continuation line — stop.
        in_pub = False
        continue
    out.append(m.group(1).replace(':', ''))
hex_str = ''.join(out)
if len(hex_str) != 130:
    sys.stderr.write(f'ERROR: expected 130 hex chars, got {len(hex_str)}: {hex_str!r}\n')
    sys.exit(1)
with open('/work/run/server_sign_pub.hex', 'w') as f:
    f.write('0x' + hex_str + '\n')
print('wrote /work/run/server_sign_pub.hex')
print(open('/work/run/server_sign_pub.hex').read().strip())
print(f'len (hex chars, no prefix): {len(hex_str)}')
PYEOF
