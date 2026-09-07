#!/usr/bin/env bash
# Generate a client-side dual SM2 cert pair (sign + enc) signed by the
# openHiTLS bundled CA, so openHiTLS' s_server trusts it during
# mutual-auth ECDHE handshakes.
#
# Output (under run/client_certs/):
#   sign.crt / sign.key / sign.der / sign_pkcs8.pem
#   enc.crt  / enc.key  / enc.der  / enc_pkcs8.pem
#
# Required extension setup:
#   sign cert: digitalSignature, nonRepudiation + extendedKeyUsage = clientAuth
#   enc  cert: keyAgreement, keyEncipherment, dataEncipherment
#
# Both certs MUST chain to the openHiTLS CA at
#   openhitls-bin/test-certs/sm2_with_userid/ca.crt
# (which is what `run_interop.sh` / `run_mutual_auth.sh` pass via
#  `-CAfile` to hitls s_server).

set -euo pipefail

cd "$(dirname "$0")"

CA=/work/openhitls-bin/test-certs/sm2_with_userid/ca.crt
CA_KEY=/work/openhitls-bin/test-certs/sm2_with_userid/ca.key

mkdir -p run/client_certs

docker run --rm \
    -v "$PWD:/work" -w /work \
    ubuntu:22.04 \
    bash -c "
        set -e
        apt-get update -qq
        apt-get install -y -qq openssl ca-certificates

        # ---- sign cert (signature + CertificateVerify) ----
        openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:SM2 \
            -out /work/run/client_certs/sign.key
        openssl req -new -key /work/run/client_certs/sign.key \
            -out /work/run/client_certs/sign.csr \
            -subj '/C=CN/ST=BJ/O=gm-tlcp-interop/CN=client sign'
        cat > /tmp/sign_ext.cnf <<EOF
basicConstraints = CA: false
extendedKeyUsage = clientAuth
keyUsage = critical, digitalSignature, nonRepudiation
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF
        openssl x509 -req -in /work/run/client_certs/sign.csr \\
            -CA '$CA' -CAkey '$CA_KEY' \\
            -CAcreateserial -days 3650 \\
            -out /work/run/client_certs/sign.crt \\
            -extfile /tmp/sign_ext.cnf
        openssl pkcs8 -topk8 -nocrypt \\
            -in /work/run/client_certs/sign.key \\
            -out /work/run/client_certs/sign_pkcs8.pem
        openssl x509 -in /work/run/client_certs/sign.crt -outform DER \\
            -out /work/run/client_certs/sign.der

        # ---- enc cert (SM2 key agreement) ----
        openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:SM2 \\
            -out /work/run/client_certs/enc.key
        openssl req -new -key /work/run/client_certs/enc.key \\
            -out /work/run/client_certs/enc.csr \\
            -subj '/C=CN/ST=BJ/O=gm-tlcp-interop/CN=client enc'
        cat > /tmp/enc_ext.cnf <<EOF
basicConstraints = CA: false
keyUsage = critical, keyAgreement, keyEncipherment, dataEncipherment
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF
        openssl x509 -req -in /work/run/client_certs/enc.csr \\
            -CA '$CA' -CAkey '$CA_KEY' \\
            -CAcreateserial -days 3650 \\
            -out /work/run/client_certs/enc.crt \\
            -extfile /tmp/enc_ext.cnf
        openssl pkcs8 -topk8 -nocrypt \\
            -in /work/run/client_certs/enc.key \\
            -out /work/run/client_certs/enc_pkcs8.pem
        openssl x509 -in /work/run/client_certs/enc.crt -outform DER \\
            -out /work/run/client_certs/enc.der

        echo '--- verify both chain to CA ---'
        openssl verify -CAfile '$CA' /work/run/client_certs/sign.crt
        openssl verify -CAfile '$CA' /work/run/client_certs/enc.crt
        echo
        echo '--- sign cert extensions ---'
        openssl x509 -in /work/run/client_certs/sign.crt -noout \\
            -ext keyUsage,extendedKeyUsage,basicConstraints
        echo
        echo '--- enc cert extensions ---'
        openssl x509 -in /work/run/client_certs/enc.crt -noout \\
            -ext keyUsage,basicConstraints
    "

echo
echo "client certs written to $(pwd)/run/client_certs/"
ls -la run/client_certs/