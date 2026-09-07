#!/usr/bin/env bash
# Orchestrator for the gm-tlcp ↔ openHiTLS interop test, with a
# client certificate configured on the gm-tlcp side. This is the
# closest path to a complete handshake: openHiTLS unconditionally
# sends CertificateRequest for ECDHE suites, so a working ECDHE
# interop requires a client cert.
#
# Flow:
#   1. Ensure openhitls-srv-pub is up (start it if not).
#   2. Run gm-tlcp interop_client with the e011 suite + client cert +
#      bundled-openhitls sign pub.
#   3. Capture server log + client log to run/.
#
# The expected outcome (as of 2026-09-06) is:
#   - gm-tlcp successfully parses ServerHello + Certificate (dual)
#     + ServerKeyExchange + CertificateRequest + ServerHelloDone.
#   - gm-tlcp sends Certificate (sign + enc) + ClientKeyExchange +
#     CertificateVerify + ChangeCipherSpec + Finished.
#   - openHiTLS rejects ClientKeyExchange with `Decode Error` because
#     gm-tlcp's CKE body has a uint16 length prefix that openHiTLS
#     does not expect (see FINDINGS.md §"CKE wire format").
#
# So this script does NOT exit 0 — it exits non-zero and dumps both
# logs for analysis. Treat it as a reproducer, not a CI gate.

set -uo pipefail

cd "$(dirname "$0")"

PORT_HOST="${PORT_HOST:-52197}"
GM_TLCP_BIN="${GM_TLCP_BIN:-/Users/laozhang/Work/opensource/gm/target/debug/examples/interop_client}"
CLIENT_DIR="$(pwd)/run/client_certs"
TS="$(date +%Y%m%d-%H%M%S)"
SERVER_LOG="run/openhitls-server-mutualauth-${TS}.log"
CLIENT_LOG="run/gmtlcp-client-mutualauth-${TS}.log"

if [ ! -x "$GM_TLCP_BIN" ]; then
    echo "FAIL: gm-tlcp interop_client not found at $GM_TLCP_BIN"
    exit 1
fi
if [ ! -x openhitls-bin/bin/hitls ]; then
    echo "FAIL: openhitls-bin/bin/hitls missing. Run build_openhitls.sh first."
    exit 1
fi
if [ ! -f "$CLIENT_DIR/sign.der" ] || [ ! -f "$CLIENT_DIR/enc.der" ]; then
    echo "Client certs missing; running gen_client_certs.sh..."
    ./gen_client_certs.sh
fi
if [ ! -f run/bundled_sign_pub.hex ]; then
    echo "Server sign pub hex missing; running extract-pub.sh on bundled cert..."
    docker run --rm -v "$PWD:/work" ubuntu:22.04 /work/run/extract-pub.sh
fi

mkdir -p run

# Start openHiTLS s_server if not already running.
if ! docker ps --format '{{.Names}}' | grep -q '^openhitls-srv-pub$'; then
    echo "==> starting openHiTLS TLCP s_server on host port ${PORT_HOST}"
    docker rm -f openhitls-srv-pub 2>/dev/null
    docker run -d -p "${PORT_HOST}:${PORT_HOST}" --name openhitls-srv-pub \
        -v "$PWD:/work" -w /work \
        -e LD_LIBRARY_PATH=/work/openhitls-bin/root/usr/local/lib \
        ubuntu:22.04 \
        /work/openhitls-bin/bin/hitls s_server \
            -accept "0.0.0.0:${PORT_HOST}" -tlcp \
            -CAfile /work/openhitls-bin/test-certs/sm2_with_userid/ca.crt \
            -tlcp_sign_cert /work/openhitls-bin/test-certs/sm2_with_userid/sign.crt \
            -tlcp_sign_key  /work/openhitls-bin/test-certs/sm2_with_userid/sign.key \
            -tlcp_enc_cert  /work/openhitls-bin/test-certs/sm2_with_userid/enc.crt \
            -tlcp_enc_key   /work/openhitls-bin/test-certs/sm2_with_userid/enc.key \
            -noverify -state

    # Wait for the port to be ready.
    for _ in $(seq 1 30); do
        if nc -z 127.0.0.1 "${PORT_HOST}" 2>/dev/null; then
            sleep 0.2
            break
        fi
        sleep 0.5
    done
fi
if ! nc -z 127.0.0.1 "${PORT_HOST}" 2>/dev/null; then
    echo "FAIL: openHiTLS container never opened port ${PORT_HOST}"
    docker logs openhitls-srv-pub 2>&1 | tee "${SERVER_LOG}"
    exit 1
fi

SIGN_PUB=$(awk 'NR==1 { sub(/^0x/, ""); print }' run/bundled_sign_pub.hex)
if [ "${#SIGN_PUB}" != "130" ]; then
    echo "FAIL: SIGN_PUB_HEX must be 130 chars, got ${#SIGN_PUB}"
    exit 1
fi

echo "==> running gm-tlcp interop_client (e011 with client cert)"
echo "    sign pub (first 32 hex chars): ${SIGN_PUB:0:32}..."
"${GM_TLCP_BIN}" "${PORT_HOST}" "${SIGN_PUB}" e011 0 \
    "${CLIENT_DIR}/sign.der" \
    "${CLIENT_DIR}/enc.der" \
    "${CLIENT_DIR}/sign_pkcs8.pem" \
    "${CLIENT_DIR}/enc_pkcs8.pem" \
    > "${CLIENT_LOG}" 2>&1 &
CLIENT_PID=$!

sleep 6
if kill -0 "${CLIENT_PID}" 2>/dev/null; then
    kill -TERM "${CLIENT_PID}" 2>/dev/null
    sleep 1
    kill -KILL "${CLIENT_PID}" 2>/dev/null
fi

# Capture server log.
echo "==> openHiTLS server log:"
docker logs openhitls-srv-pub 2>&1 | tee "${SERVER_LOG}"

echo
echo "==> done. openHiTLS log: ${SERVER_LOG}, gm-tlcp log: ${CLIENT_LOG}"
echo
echo "--- gm-tlcp interop_client output ---"
cat "${CLIENT_LOG}"
echo
echo "--- openHiTLS s_server output ---"
cat "${SERVER_LOG}"

# Exit 0 iff gm-tlcp reported handshake OK.
if grep -q "handshake OK" "${CLIENT_LOG}"; then
    echo
    echo "==> RESULT: PASS (handshake completed both ways)"
    exit 0
else
    echo
    echo "==> RESULT: FAIL (see logs above + wire-traces/*.pcap)"
    exit 1
fi