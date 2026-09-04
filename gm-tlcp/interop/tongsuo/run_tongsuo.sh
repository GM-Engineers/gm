#!/usr/bin/env bash
# Run Tongsuo s_server / s_client inside an ephemeral Linux container.
#
# Why Docker and not native execution?
# 1. The Tongsuo binary built by build_tongsuo.sh is a Linux static ELF
#    (cross-compiling for Darwin is brittle because ./config's assembly
#    + perl probes are Linux-centric).
# 2. Tongsuo's TLCP server has no known macOS bug (unlike GmSSL), but
#    we keep behavior identical to how GmSSL interop is exercised —
#    one environment, one process model.
#
# Subcommands:
#   server <host_port> [tongsuo_args...]
#       Launch Tongsuo s_server -ntls and forward <host_port> into the
#       container where Tongsuo listens on the same port.
#   client <server_host> <server_port> [tongsuo_args...]
#       Launch Tongsuo s_client -ntls and connect to <server_host>:
#       <server_port>.
#   shell
#       Drop into a bash shell inside the container for manual testing.
#
# Example (run from host terminal A):
#   ./run_tongsuo.sh server 52189 -cert /work/certs/sm2/server_sign.crt \
#       -key /work/certs/sm2/server_sign.key \
#       -enc_cert /work/certs/sm2/server_enc.crt \
#       -enc_key /work/certs/sm2/server_enc.key \
#       -enable_ntls -tls1_2
# (Tongsuo uses -enable_ntls / -tls1_2 flags; the certs/ dir is
#  pre-populated from Tongsuo's own test/certs/sm2 set.)

set -euo pipefail

cd "$(dirname "$0")"
WORKDIR="$(pwd)"

# Sanity: binary must exist (build_tongsuo.sh must have been run).
if [ ! -f tongsuo-bin/openssl ]; then
    echo "error: tongsuo-bin/openssl not found. Run build_tongsuo.sh first."
    exit 1
fi

# What the user asked us to do.
SUBCOMMAND="${1:-}"
if [ -z "$SUBCOMMAND" ]; then
    sed -n '2,30p' "$0"
    exit 1
fi
shift

# Common docker invocation bits. -i keeps stdin open so users can pipe
# input; -t allocates a tty when we have one; --rm cleans up afterwards.
# --network host would be simpler but on macOS Docker Desktop it shares
# the host's network namespace, which means "localhost" inside the
# container == "localhost" on the host. So we use that.
COMMON_ARGS=(
    --rm
    --network host
    -i
    -v "$WORKDIR:/work"
    -w /work
    ubuntu:22.04
)

# Mount our local openssl + a minimal runtime. The Tongsuo binary is
# static, so Ubuntu's userspace is enough.
case "$SUBCOMMAND" in
    server)
        HOST_PORT="${1:?usage: $0 server <host_port> [args...]}"
        shift
        # Tongsuo's s_server -accept listens inside the container. With
        # --network host, the container can bind directly on the host
        # port, so the address is the same.
        docker run "${COMMON_ARGS[@]}" \
            /work/tongsuo-bin/openssl s_server \
                -accept "${HOST_PORT}" \
                -enable_ntls \
                "$@"
        ;;

    client)
        SERVER_HOST="${1:?usage: $0 client <host> <port> [args...]}"
        SERVER_PORT="${2:?usage: $0 client <host> <port> [args...]}"
        shift 2
        docker run "${COMMON_ARGS[@]}" \
            /work/tongsuo-bin/openssl s_client \
                -connect "${SERVER_HOST}:${SERVER_PORT}" \
                -enable_ntls \
                "$@"
        ;;

    shell)
        # Drop into a bash shell inside the container. Useful for
        # `openssl s_server -msg -debug` to capture a hex dump of the
        # wire during interop testing.
        docker run "${COMMON_ARGS[@]}" -t \
            bash
        ;;

    *)
        echo "unknown subcommand: $SUBCOMMAND"
        echo "valid: server, client, shell"
        exit 1
        ;;
esac