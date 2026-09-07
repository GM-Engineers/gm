#!/usr/bin/env bash
# Build openHiTLS in an ephemeral Linux container.
# Output: ./openhitls-bin/ — install/ tree with hitls_cli + libhitls_*
#
# Why an ephemeral container instead of building on macOS?
# openHiTLS is a large C/CMake build (BSL + Crypto + TLS + PKI + Auth
# components). Cross-compiling for Darwin from a Linux container is
# brittle; building Linux static libs in a Linux container gives a
# reproducible artifact that the test harness can run in Docker.
#
# Pin to a known-good commit / tag so subsequent Tongsuo patches don't
# break the build. Update COMMIT below to refresh.

set -euo pipefail

cd "$(dirname "$0")"
WORKDIR="$(pwd)"
mkdir -p openhitls-bin

# Use gitcode mirror (openHiTLS's official canonical location).
# Refs: https://gitcode.com/openhitls/openhitls
#
# Branches available: main, feature, openhitls-0.1, openhitls-0.2,
# openhitls-0.3. We pin to `main` because the TLCP demos at
# testcode/demo/tlcp_{client,server}.c are kept up-to-date there.
OPENHITLS_REPO="https://gitcode.com/openhitls/openhitls.git"
OPENHITLS_BRANCH="main"
TARBALL_NAME="openhitls-${OPENHITLS_BRANCH}.tar.gz"
HOST_TARBALL="/tmp/${TARBALL_NAME}"

# 1. Download a tarball on the HOST (macOS Docker container github.com
#    connectivity is sometimes flaky; the host is more reliable).
if [ ! -s "$HOST_TARBALL" ]; then
    echo "downloading openHiTLS ${OPENHITLS_BRANCH} tarball to $HOST_TARBALL ..."
    # gitcode does not provide a /archive/master.tar.gz URL directly via
    # curl; clone shallow + tar.
    TMPDIR_DL="$(mktemp -d)"
    # --no-xattrs strips macOS AppleDouble / com.apple.provenance
    # extended-attribute blobs that gcc in the Linux container would
    # otherwise try to compile (as `._*.c` files) and fail with
    # `stray '\xx' in program` errors.
    git clone --depth 1 --branch "$OPENHITLS_BRANCH" "$OPENHITLS_REPO" "$TMPDIR_DL/openhitls"
    # Also strip any `._*` files that slipped in via macOS' tar.
    find "$TMPDIR_DL/openhitls" -name '._*' -delete 2>/dev/null || true
    COPYFILE_DISABLE=1 tar -C "$TMPDIR_DL" --no-xattrs -czf "$HOST_TARBALL" openhitls
    rm -rf "$TMPDIR_DL"
fi
ls -lh "$HOST_TARBALL"
cp "$HOST_TARBALL" "./${TARBALL_NAME}"

# 2. Build inside a fresh Ubuntu container. Bind-mount so outputs
#    land directly on the host.
docker run --rm \
    -v "$WORKDIR:/work" \
    -w /work \
    ubuntu:22.04 \
    bash -c "
        set -e
        apt-get update -qq
        apt-get install -y -qq build-essential cmake git ca-certificates
        tar xzf '${TARBALL_NAME}'
        cd openhitls
        mkdir -p build && cd build
        # -DHITLS_BUILD_PROFILE=full — enable every protocol + cipher
        # -DHITLS_BUILD_EXE=ON    — build hitls_cli (the demo binary we need)
        # -DCMAKE_BUILD_TYPE=Release — match the gm-tlcp Gmssl interop CI
        cmake -DHITLS_BUILD_PROFILE=full -DHITLS_BUILD_EXE=ON \
              -DCMAKE_BUILD_TYPE=Release ..
        make -j\$(nproc)
        # Install into a local prefix so the artifact is self-contained.
        make install DESTDIR=/work/openhitls-bin/root
        # Stage the binary at a stable path for the test harness.
        mkdir -p /work/openhitls-bin/bin
        # openHiTLS installs the unified CLI as `hitls` (NOT `hitls_cli`).
        # It supports `s_server` / `s_client` with a `-tlcp` flag — see
        # `hitls s_server -help` for the full TLCP option set
        # (`-tlcp_sign_cert`, `-tlcp_enc_cert`, etc.).
        if [ -f /work/openhitls-bin/root/usr/local/bin/hitls ]; then
            cp /work/openhitls-bin/root/usr/local/bin/hitls \
               /work/openhitls-bin/bin/hitls
        fi
        # Also keep the libs and certs directory for completeness.
        cp -R /work/openhitls-bin/root/usr/local/lib /work/openhitls-bin/lib || true
        # Verify the binary runs (LD_LIBRARY_PATH is needed because
        # the .so files are in /work/openhitls-bin/root/usr/local/lib).
        LD_LIBRARY_PATH=/work/openhitls-bin/root/usr/local/lib \
            /work/openhitls-bin/bin/hitls help >/dev/null \
            && echo 'openhitls: hitls help OK' \
            || echo 'openhitls: hitls help FAILED'
    "

if [ ! -x openhitls-bin/bin/hitls ]; then
    echo "build failed: openhitls-bin/bin/hitls missing"
    exit 1
fi

echo
echo "openHiTLS built at $(pwd)/openhitls-bin/"
file openhitls-bin/bin/hitls
ls -lh openhitls-bin/bin/hitls
echo "TLCP-capable libs:"
ls -lh openhitls-bin/lib/libhitls_tls.so 2>/dev/null || true
echo "Test certs:"
ls -la openhitls-bin/test-certs/sm2_with_userid 2>/dev/null || echo "  (none — gen_certs.sh will regenerate)"
