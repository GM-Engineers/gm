#!/usr/bin/env bash
# Regenerate fresh SM2 sign + enc cert pair using standard OpenSSL
# (hitls req is a CSR generator, not a full openssl req clone).
#
# We need:
#   - server_sign.crt / .key (SM2 ECDSA-capable, used for sign + CV)
#   - server_enc.crt  / .key (SM2 ECDH-capable,   used for key exchange)
#   - ca.crt          (self-signed root, both sign/enc CA)
#
# Both PEM (for gm-tlcp's interop_client which prefers PEM) and DER
# (for hitls s_server -tlcp_sign_cert / -tlcp_enc_cert which prefers
#  DER per its docs) are produced.

set -uo pipefail

cd "$(dirname "$0")"

mkdir -p run/certs
mkdir -p openhitls-bin/test-certs/sm2_with_userid

# Build a minimal openssl.cnf for the cert generation. openHiTLS's
# hitls req doesn't need a full config; OpenSSL req does.
cat > run/openssl.cnf <<'EOF'
[ req ]
distinguished_name = req_distinguished_name
prompt = no
[ req_distinguished_name ]
C  = CN
ST = BJ
O  = gm-tlcp-interop
CN = server
EOF

docker run --rm \
    -v "$PWD:/work" -w /work \
    -e OPENSSL_CONF=/work/run/openssl.cnf \
    ubuntu:22.04 \
    bash -c '
        set -e
        apt-get update -qq
        apt-get install -y -qq openssl ca-certificates
        # Sign cert (SM2, used for signature + CertificateVerify).
        # Note: -pkeyopt ec_paramgen_curve:SM2 requires an OpenSSL
        # build with SM2 support (Ubuntu 22.04 has this).
        openssl req -x509 -newkey ec \
            -pkeyopt ec_paramgen_curve:SM2 \
            -keyout /work/run/certs/server_sign.key \
            -out    /work/run/certs/server_sign.crt \
            -days 3650 -nodes \
            -subj "/C=CN/ST=BJ/O=gm-tlcp-interop/CN=server sign"
        # Enc cert (SM2, used for ECDH key exchange).
        openssl req -x509 -newkey ec \
            -pkeyopt ec_paramgen_curve:SM2 \
            -keyout /work/run/certs/server_enc.key \
            -out    /work/run/certs/server_enc.crt \
            -days 3650 -nodes \
            -subj "/C=CN/ST=BJ/O=gm-tlcp-interop/CN=server enc"
        # Convert PEM → DER for hitls s_server (which prefers DER).
        openssl x509 -in  /work/run/certs/server_sign.crt -outform DER \
                       -out /work/run/certs/server_sign.der
        openssl x509 -in  /work/run/certs/server_enc.crt  -outform DER \
                       -out /work/run/certs/server_enc.der
        # Layout hitls demos expect: sm2_with_userid/{sign,enc,ca}.crt
        cp /work/run/certs/server_sign.der /work/openhitls-bin/test-certs/sm2_with_userid/sign.crt
        cp /work/run/certs/server_enc.der  /work/openhitls-bin/test-certs/sm2_with_userid/enc.crt
        cp /work/run/certs/server_sign.key /work/openhitls-bin/test-certs/sm2_with_userid/sign.key
        cp /work/run/certs/server_enc.key  /work/openhitls-bin/test-certs/sm2_with_userid/enc.key
        # Self-signed CA so the client can trust them.
        openssl req -x509 -newkey ec \
            -pkeyopt ec_paramgen_curve:SM2 \
            -keyout /work/openhitls-bin/test-certs/sm2_with_userid/ca.key \
            -out    /work/openhitls-bin/test-certs/sm2_with_userid/ca.crt \
            -days 3650 -nodes \
            -subj "/C=CN/ST=BJ/O=gm-tlcp-interop/CN=ca"
        echo
        echo "Cert summary:"
        ls -la /work/run/certs/ /work/openhitls-bin/test-certs/sm2_with_userid/
        # Verify certs parse and are SM2.
        for f in /work/run/certs/server_sign.crt \
                 /work/run/certs/server_enc.crt  \
                 /work/openhitls-bin/test-certs/sm2_with_userid/ca.crt; do
            echo "--- $f ---"
            openssl x509 -in "$f" -noout -subject -issuer -dates
        done
    '
