#!/usr/bin/env bash
# Build Tongsuo with NTLS support inside an ephemeral Linux container.
# Output: ./tongsuo-bin/openssl (static binary) + ./tongsuo-bin/certs/.
#
# Why an ephemeral container instead of building on macOS? Tongsuo's
# ./config script depends on Linux make conventions and the build
# artifacts aren't reliably portable to Darwin (assembly + perl paths).
# A single-shot container gives us a clean reproducible build.
#
# Resulting ./tongsuo-bin/openssl supports the `enable_ntls` /
# `-sign_cert` / `-enc_cert` command-line flags required by TLCP.

set -euo pipefail

# Pin Tongsuo to a stable release. 8.3.0 ships mature NTLS+TLCP.
TONGSUO_VERSION="8.3.0"
TONGSUO_TARBALL="Tongsuo-${TONGSUO_VERSION}.tar.gz"

cd "$(dirname "$0")"
WORKDIR="$(pwd)"
mkdir -p tongsuo-bin

# 1. Download the Tongsuo tarball on the HOST (macOS Docker containers
#    sometimes have flaky network access to github.com — the host is
#    more reliable). If the file already exists we skip the download.
HOST_TARBALL="/tmp/${TONGSUO_TARBALL}"
if [ ! -s "$HOST_TARBALL" ]; then
    echo "downloading Tongsuo ${TONGSUO_VERSION} tarball to $HOST_TARBALL ..."
    curl -fsSL -o "$HOST_TARBALL" \
        "https://github.com/Tongsuo-Project/Tongsuo/archive/refs/tags/${TONGSUO_VERSION}.tar.gz"
fi
ls -lh "$HOST_TARBALL"
# Copy it next to the script so the container can pick it up.
cp "$HOST_TARBALL" "./${TONGSUO_TARBALL}"

# 2. Build Tongsuo inside a fresh Ubuntu container. We bind-mount the
#    script's directory so the build outputs land directly on the host.
docker run --rm \
    -v "$WORKDIR:/work" \
    -w /work \
    ubuntu:22.04 \
    bash -c "
        set -e
        apt-get update -qq
        apt-get install -y -qq build-essential perl git ca-certificates
        tar xzf '${TONGSUO_TARBALL}'
        cd 'Tongsuo-${TONGSUO_VERSION}'
        # enable-ntls: include NTLS protocol implementation.
        # no-shared: build static libssl/libcrypto so apps/openssl is
        #            self-contained (we can copy it out without rpaths).
        ./config enable-ntls no-shared --prefix=/opt/tongsuo -static
        make -j\$(nproc) build_libs
        make -j\$(nproc) apps/openssl
        # Copy the artifacts onto the bind-mounted host dir.
        cp apps/openssl /work/tongsuo-bin/openssl
        # Tongsuo ships test SM2 certs under test/certs/sm2 — grab them.
        if [ -d test/certs/sm2 ]; then
            mkdir -p /work/tongsuo-bin/certs
            cp -R test/certs/sm2 /work/tongsuo-bin/certs/sm2
        else
            echo 'warning: Tongsuo test/certs/sm2 not found in tarball'
        fi
        chmod +x /work/tongsuo-bin/openssl
    "

if [ ! -f tongsuo-bin/openssl ]; then
    echo "build failed: tongsuo-bin/openssl missing"
    exit 1
fi
# Note: this is a Linux static ELF — it can't be executed on macOS
# directly. Use run_tongsuo.sh to launch it inside Docker.
echo "Tongsuo built at $(pwd)/tongsuo-bin/openssl"
file tongsuo-bin/openssl
ls -lh tongsuo-bin/openssl
echo "Certs:"
ls tongsuo-bin/certs/sm2 2>/dev/null || echo "  (none — will regenerate below)"