#!/usr/bin/env bash
# Run an end-to-end openHiTLS TLCP <-> gm-tlcp interop test:
#
#   1. Start `hitls s_server -tlcp` in a Docker container listening
#      on a host port, with the SM2 sign + enc certs we generated.
#   2. Run gm-tlcp's `interop_client` (the Mach-O arm64 binary in
#      gm/target/debug/examples/) against that port.
#   3. Capture both sides' logs to run/.
#
# This is the no-client-cert variant — exercises only the static-ECC
# suites (e013, e053) which openHiTLS does not CertificateRequest.
# For the ECDHE suites (e011, e051) which require mutual auth, see
# `run_mutual_auth.sh`.
#
# Exit codes:
#   0 — gm-tlcp reports handshake OK AND the captured server log
#       shows a ServerHello back to the client.
#   1 — anything else.
set -uo pipefail

cd "$(dirname "$0")"

PORT_HOST="${PORT_HOST:-52197}"
CERTS_DIR="${CERTS_DIR:-run/certs}"
GM_TLCP_BIN="${GM_TLCP_BIN:-/Users/laozhang/Work/opensource/gm/target/debug/examples/interop_client}"
HOLD_SECONDS="${HOLD_SECONDS:-15}"
SUITE="${SUITE:-e013}"  # static ECC + CBC

if [ ! -x "$GM_TLCP_BIN" ]; then
    echo "FAIL: gm-tlcp interop_client not found at $GM_TLCP_BIN"
    echo "      (rebuild with: cargo build -p gm-tlcp --examples)"
    exit 1
fi
if [ ! -x openhitls-bin/bin/hitls ]; then
    echo "FAIL: openhitls-bin/bin/hitls not found. Run build_openhitls.sh first."
    exit 1
fi
if [ ! -f openhitls-bin/test-certs/sm2_with_userid/sign.crt ]; then
    echo "Bundled openHiTLS SM2 certs missing; did you run build_openhitls.sh?"
    exit 1
fi
if [ ! -f run/bundled_sign_pub.hex ]; then
    echo "Bundled server sign pub hex missing; running extract-pub.sh..."
    docker run --rm -v "$PWD:/work" ubuntu:22.04 /work/run/extract-pub.sh
fi

mkdir -p run
TS="$(date +%Y%m%d-%H%M%S)"
SERVER_LOG="run/openhitls-server-${TS}.log"
CLIENT_LOG="run/gmtlcp-client-${TS}.log"

# 130-char hex (strip "0x" prefix and newline) for gm-tlcp's
# interop_client second positional argument.
SIGN_PUB_HEX=$(awk 'NR==1 { sub(/^0x/, ""); print }' run/bundled_sign_pub.hex)
if [ "${#SIGN_PUB_HEX}" != "130" ]; then
    echo "FAIL: SIGN_PUB_HEX must be 130 chars, got ${#SIGN_PUB_HEX}"
    exit 1
fi

echo "==> starting openHiTLS TLCP s_server on host port ${PORT_HOST}"
# `-p 52197:52197` (publish mode) is required on macOS Docker Desktop —
# `--network host` does not propagate container-bound ports to the host
# loopback in a way that `nc -z 127.0.0.1 52197` can see. `-accept`
# expects `host:port` (a bare port returns `Invalid bind address`).
docker rm -f openhitls-srv 2>/dev/null
docker run -d -p "${PORT_HOST}:${PORT_HOST}" --name openhitls-srv \
    -v "$PWD:/work" -w /work \
    -e LD_LIBRARY_PATH=/work/openhitls-bin/root/usr/local/lib \
    ubuntu:22.04 \
    /work/openhitls-bin/bin/hitls s_server \
        -accept "0.0.0.0:${PORT_HOST}" \
        -tlcp \
        -CAfile /work/openhitls-bin/test-certs/sm2_with_userid/ca.crt \
        -tlcp_sign_cert /work/openhitls-bin/test-certs/sm2_with_userid/sign.crt \
        -tlcp_sign_key  /work/openhitls-bin/test-certs/sm2_with_userid/sign.key \
        -tlcp_enc_cert  /work/openhitls-bin/test-certs/sm2_with_userid/enc.crt \
        -tlcp_enc_key   /work/openhitls-bin/test-certs/sm2_with_userid/enc.key \
        -noverify -state

# Wait up to 15s for the port to be ready.
for i in $(seq 1 30); do
    if nc -z 127.0.0.1 "${PORT_HOST}" 2>/dev/null; then
        sleep 0.2  # settle a bit more
        break
    fi
    sleep 0.5
done
if ! nc -z 127.0.0.1 "${PORT_HOST}" 2>/dev/null; then
    echo "FAIL: openHiTLS container never opened port ${PORT_HOST}"
    docker logs openhitls-srv 2>&1 | tee "${SERVER_LOG}"
    docker rm -f openhitls-srv 2>/dev/null
    exit 1
fi

echo "==> running gm-tlcp interop_client (suite ${SUITE}) against port ${PORT_HOST}"
echo "    sign pub (first 32 hex chars): ${SIGN_PUB_HEX:0:32}..."
"${GM_TLCP_BIN}" "${PORT_HOST}" "${SIGN_PUB_HEX}" "${SUITE}" 0 \
    > "${CLIENT_LOG}" 2>&1 &
CLIENT_PID=$!

# Wait HOLD_SECONDS, then kill the client if still running.
sleep "${HOLD_SECONDS}"
if kill -0 "${CLIENT_PID}" 2>/dev/null; then
    kill -TERM "${CLIENT_PID}" 2>/dev/null
    wait "${CLIENT_PID}" 2>/dev/null
fi

# Capture the openHiTLS server log.
echo "==> openHiTLS server log:"
docker logs openhitls-srv 2>&1 | tee "${SERVER_LOG}"

# Cleanup container.
docker rm -f openhitls-srv 2>/dev/null

# Report.
echo
echo "==> done. openHiTLS log: ${SERVER_LOG}, gm-tlcp log: ${CLIENT_LOG}"
echo
echo "--- gm-tlcp interop_client output ---"
cat "${CLIENT_LOG}"
echo
echo "--- openHiTLS s_server output ---"
cat "${SERVER_LOG}"

# Exit 0 iff gm-tlcp reported handshake OK AND server sent a
# ServerHello (which means it processed our ClientHello).
if grep -q "handshake OK" "${CLIENT_LOG}" \
   && grep -q "ServerHello" "${SERVER_LOG}"; then
    echo
    echo "==> RESULT: PASS (handshake completed both ways)"
    exit 0
else
    echo
    echo "==> RESULT: FAIL (see logs above)"
    exit 1
fi