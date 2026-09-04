#!/usr/bin/env bash
# Regenerate fresh TLCP sign + enc certs using Tongsuo's openssl req.
# The shipped `tongsuo-bin/certs/sm2/*.crt` files expired in 2023, and
# Tongsuo's NTLS s_server refuses to handshake against expired certs.

set -uo pipefail

cd "$(dirname "$0")"

mkdir -p run/certs

# Copy the Tongsuo openssl.cnf next to the certs dir. Tongsuo's req
# looks for /opt/tongsuo/ssl/openssl.cnf by default; we override
# OPENSSL_CONF below to point at our copy.
CNF="$(pwd)/run/openssl.cnf"
cp Tongsuo-8.3.0/apps/openssl.cnf "$CNF"

docker run --rm \
    -v "$PWD:/work" -w /work \
    -e OPENSSL_CONF=/work/run/openssl.cnf \
    ubuntu:22.04 \
    bash -c "
        set -e
        /work/tongsuo-bin/openssl req -x509 -newkey ec \
            -pkeyopt ec_paramgen_curve:SM2 \
            -keyout /work/run/certs/server_sign.key \
            -out /work/run/certs/server_sign.crt \
            -days 3650 -nodes \
            -subj '/C=CN/ST=BJ/O=gm-tlcp-interop/CN=server sign'
        /work/tongsuo-bin/openssl req -x509 -newkey ec \
            -pkeyopt ec_paramgen_curve:SM2 \
            -keyout /work/run/certs/server_enc.key \
            -out /work/run/certs/server_enc.crt \
            -days 3650 -nodes \
            -subj '/C=CN/ST=BJ/O=gm-tlcp-interop/CN=server enc'
        ls -la /work/run/certs/
    "