#!/bin/bash
set -euo pipefail

# Instala bpfilter de forma no interactiva para PraesidiumFirewall.
# Install bpfilter non-interactively for PraesidiumFirewall.

REPO_URL="https://github.com/AndryHalcons/bpfilter"
BPFILTER_DIR="${BPFILTER_DIR:-/home/praesidium/bpfilter}"
BUILD_DIR="${BUILD_DIR:-$BPFILTER_DIR/build}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
BFCLI_PATH="$BUILD_DIR/output/sbin/bfcli"
BPFILTER_PATH="$BUILD_DIR/output/sbin/bpfilter"

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

# Verifica version de kernel suficiente para el uso previsto de BPF.
# Verify kernel version is sufficient for the intended BPF usage.
check_kernel() {
    local kernel_version major minor
    kernel_version="$(uname -r | cut -d '-' -f1)"
    major="$(echo "$kernel_version" | cut -d '.' -f1)"
    minor="$(echo "$kernel_version" | cut -d '.' -f2)"

    if [ "$major" -lt 6 ] || { [ "$major" -eq 6 ] && [ "$minor" -lt 6 ]; }; then
        fail "Kernel $kernel_version no compatible. Se recomienda 6.6 o superior. / Kernel $kernel_version not compatible. 6.6 or higher recommended."
    fi

    echo "Kernel $kernel_version compatible. / Compatible kernel."
}

# Verifica libbpf mediante pkg-config porque bpfilter se enlaza contra libbpf.
# Verify libbpf through pkg-config because bpfilter links against libbpf.
check_libbpf() {
    local libbpf_version libbpf_major libbpf_minor

    command -v pkg-config >/dev/null 2>&1 || fail "pkg-config/pkgconf no está instalado. / pkg-config/pkgconf is not installed."
    pkg-config --exists libbpf || fail "libbpf no está instalado o no se detecta con pkg-config. / libbpf is not installed or not detected via pkg-config."

    libbpf_version="$(pkg-config --modversion libbpf)"
    libbpf_major="$(echo "$libbpf_version" | cut -d '.' -f1)"
    libbpf_minor="$(echo "$libbpf_version" | cut -d '.' -f2)"

    if [ "$libbpf_major" -lt 1 ] || { [ "$libbpf_major" -eq 1 ] && [ "$libbpf_minor" -lt 2 ]; }; then
        fail "libbpf version $libbpf_version no compatible. Se recomienda 1.2 o superior. / libbpf version $libbpf_version not compatible. 1.2 or higher recommended."
    fi

    echo "libbpf version $libbpf_version compatible. / Compatible libbpf version."
}

# Verifica paquetes reales instalados. Evita paquetes virtuales en Ubuntu.
# Verify real installed packages. Avoid virtual packages on Ubuntu.
check_packages() {
    local required_packages missing pkg
    required_packages=(
        autoconf automake bison clang clang-tidy clang-format cmake doxygen flex furo g++ git iproute2 iputils-ping
        lcov libbenchmark-dev libbpf-dev libc6-dev linux-libc-dev libcmocka-dev libgit2-dev libnl-3-dev libtool linux-tools-common
        make pkgconf procps python3-breathe python3-dateutil python3-git python3-pip python3-scapy python3-sphinx
        sed xxd
    )

    missing=()
    for pkg in "${required_packages[@]}"; do
        dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed" || missing+=("$pkg")
    done

    if [ "${#missing[@]}" -ne 0 ]; then
        echo "Faltan dependencias reales para compilar bpfilter: / Missing real dependencies to build bpfilter:" >&2
        printf '  - %s\n' "${missing[@]}" >&2
        exit 1
    fi

    echo "Todas las dependencias de bpfilter están instaladas. / All bpfilter dependencies are installed."
}

# Clona o actualiza el arbol fuente de bpfilter de forma idempotente.
# Clone or update the bpfilter source tree idempotently.
prepare_source() {
    mkdir -p "$(dirname "$BPFILTER_DIR")"

    if [ ! -d "$BPFILTER_DIR" ]; then
        echo "Clonando bpfilter desde $REPO_URL... / Cloning bpfilter from $REPO_URL..."
        git clone "$REPO_URL" "$BPFILTER_DIR"
        return
    fi

    if [ ! -d "$BPFILTER_DIR/.git" ]; then
        fail "$BPFILTER_DIR existe pero no es un repositorio git. / $BPFILTER_DIR exists but is not a git repository."
    fi

    echo "Actualizando bpfilter en $BPFILTER_DIR... / Updating bpfilter in $BPFILTER_DIR..."
    git -C "$BPFILTER_DIR" fetch --tags origin
    git -C "$BPFILTER_DIR" pull --ff-only origin HEAD
}

# Compila bpfilter con CMake y falla si los binarios esperados no aparecen.
# Build bpfilter with CMake and fail if expected binaries are not produced.
build_bpfilter() {
    local jobs
    jobs="$(nproc 2>/dev/null || echo 2)"

    mkdir -p "$BUILD_DIR"
    echo "Generando sistema de compilación con CMake... / Generating CMake build system..."
    cmake -S "$BPFILTER_DIR" -B "$BUILD_DIR"

    echo "Compilando bpfilter con $jobs jobs... / Building bpfilter with $jobs jobs..."
    cmake --build "$BUILD_DIR" --parallel "$jobs" --verbose

    [ -x "$BFCLI_PATH" ] || fail "No se generó bfcli en $BFCLI_PATH. / bfcli was not generated at $BFCLI_PATH."
    [ -x "$BPFILTER_PATH" ] || fail "No se generó bpfilter en $BPFILTER_PATH. / bpfilter was not generated at $BPFILTER_PATH."
}

# Instala los binarios compilados y verifica que quedan en PATH.
# Install compiled binaries and verify they are available in PATH.
install_binaries() {
    install -d -m 0755 "$INSTALL_DIR"
    install -m 0755 "$BFCLI_PATH" "$INSTALL_DIR/bfcli"
    install -m 0755 "$BPFILTER_PATH" "$INSTALL_DIR/bpfilter"

    command -v bfcli >/dev/null 2>&1 || fail "bfcli no queda disponible en PATH. / bfcli is not available in PATH."
    command -v bpfilter >/dev/null 2>&1 || fail "bpfilter no queda disponible en PATH. / bpfilter is not available in PATH."

    echo "bpfilter instalado en $INSTALL_DIR. / bpfilter installed in $INSTALL_DIR."
    bfcli --version || true
}

main() {
    echo "Verificando requisitos para bpfilter... / Checking bpfilter requirements..."
    check_kernel
    check_libbpf
    check_packages
    prepare_source
    build_bpfilter
    install_binaries
}

main "$@"
