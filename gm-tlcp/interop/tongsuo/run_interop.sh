#!/usr/bin/env bash
# Launch Tongsuo s_server in Docker, wait for it to be ready, then
# run gm-tlcp's interop_client against it, capture both sides' logs,
# and exit. Everything happens in a single shell so the container
# doesn't get reaped when the parent shell ends.

set -uo pipefail

cd "$(dirname "$0")"

PORT_HOST="${PORT_HOST:-52195}"
PORT_CTR="${PORT_CTR:-52195}"
# Default: the public key from run/certs/server_sign.crt (regenerated
# fresh by gen_certs.sh; override via $CLIENT_PUB_HEX env var if you
# need a different cert).
CLIENT_PUB_HEX="${CLIENT_PUB_HEX:-04bed1599b7453171de61ccd64d7042c929df5434e6075dd7ec715713dcbb423bd31e3b0d91d2e3c38d360ed0db658e7e1c97ca7567423e262c2f209d3ae759d93}"
CLIENT_SUITES="${CLIENT_SUITES:-e013}"
GM_TLCP_BIN="${GM_TLCP_BIN:-/Users/laozhang/Work/opensource/gm/target/debug/examples/interop_client}"
GMSSL_COMPAT="${GMSSL_COMPAT:-0}"
HOLD_SECONDS="${HOLD_SECONDS:-15}"
CERTS_DIR="${CERTS_DIR:-run/certs}"

mkdir -p run
LOG="run/tongsuo-debug-$(date +%Y%m%d-%H%M%S).log"
CLIENT_LOG="run/client-$(date +%Y%m%d-%H%M%S).log"

# Start Tongsuo s_server in background. Use `docker run -d` (detached
# from this shell) so the container lifecycle is owned by Docker, not
# by our shell session.
docker rm -f tongsuo-srv 2>/dev/null
docker run -d --rm \
    --name tongsuo-srv \
    -p "${PORT_HOST}:${PORT_CTR}" \
    -v "$PWD:/work" -w /work ubuntu:22.04 \
    /work/tongsuo-bin/openssl s_server \
        -accept "${PORT_CTR}" \
        -cert "/work/${CERTS_DIR}/server_sign.crt" \
        -key "/work/${CERTS_DIR}/server_sign.key" \
        -enc_cert "/work/${CERTS_DIR}/server_enc.crt" \
        -enc_key "/work/${CERTS_DIR}/server_enc.key" \
        -enable_ntls -tls1_2 -msg >/dev/null

# Wait up to 10s for the port to be ready.
for i in $(seq 1 20); do
    if nc -z 127.0.0.1 "${PORT_HOST}" 2>/dev/null; then
        break
    fi
    sleep 0.5
done

if ! nc -z 127.0.0.1 "${PORT_HOST}" 2>/dev/null; then
    echo "FAIL: Tongsuo container never opened port ${PORT_HOST}"
    docker logs tongsuo-srv 2>&1
    docker rm -f tongsuo-srv 2>/dev/null
    exit 1
fi

# Run the gm-tlcp client. The shell holding this script will not exit
# until the client does (or HOLD_SECONDS elapses), so the container
# stays alive.
echo "==> running gm-tlcp interop_client (PORT=${PORT_HOST}, suites=${CLIENT_SUITES}, compat=${GMSSL_COMPAT})"
GM_TLCP_GMSSL_COMPAT="${GMSSL_COMPAT}" \
    "${GM_TLCP_BIN}" "${PORT_HOST}" "${CLIENT_PUB_HEX}" "${CLIENT_SUITES}" "${GMSSL_COMPAT}" \
    > "${CLIENT_LOG}" 2>&1 &
CLIENT_PID=$!

# Wait HOLD_SECONDS, then kill the client if still running.
sleep "${HOLD_SECONDS}"
if kill -0 "${CLIENT_PID}" 2>/dev/null; then
    kill -TERM "${CLIENT_PID}" 2>/dev/null
    wait "${CLIENT_PID}" 2>/dev/null
fi

# Capture Tongsuo logs.
echo "==> Tongsuo server log:"
docker logs tongsuo-srv 2>&1 | tee "${LOG}"

# Clean up.
echo "==> client log:"
cat "${CLIENT_LOG}"

# Kill container.
docker rm -f tongsuo-srv 2>/dev/null
echo
echo "==> done. Tongsuo log: ${LOG}, client log: ${CLIENT_LOG}"