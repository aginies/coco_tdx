# =============================================================================
# SLES / openSUSE adapter (zypper + rpm)
# =============================================================================
# The proven behavior for SLE 15/16 and openSUSE. Package names are the actual
# SLE 16.1 names (verify with: zypper se <term>). Hook contract: see
# lib/distros/_detect.sh.
#
# All sles_* variables/functions are consumed cross-file via indirection
# (${!v} / "${DISTRO_ID}_<hook>") in lib/distros/_detect.sh, so single-file
# "unused variable" warnings are false positives.
# shellcheck disable=SC2034

sles_pkg_manager="zypper"

# Package sets by role (word lists; call sites word-split them on purpose).
# Host needs the Quote Provider Library (QPL) + provider to fetch PCK
# collateral from PCS/PCCS, plus the quote-verify library for local
# verification.
sles_pkgs_dcap_host="suse-libsgx-dcap-default-qpl libdcap_quoteprov1 libsgx_dcap_quoteverify1"
sles_pkgs_qgs="suse-tdx-qgs"
sles_pkgs_trustee="trustee suse-libsgx-dcap-quoteverify-devel libtdx_attest1 libsgx_tdx_logic1"
sles_pkgs_guest_libs="libtdx_attest1 suse-libtdx-attest-devel libsgx_tdx_logic1 libdcap_quoteprov1 suse-libsgx-dcap-default-qpl trustee"
sles_pkgs_libvirt="libvirt-daemon-driver-qemu libvirt-client"
sles_pkgs_qemu="qemu"
sles_pkgs_virt_customize="libguestfs-tools"
sles_pkgs_ovmf="qemu-ovmf-x86_64 edk2-ovmf"
sles_pkgs_grpcurl="grpcurl"

# SUSE packaging layout.
sles_qgs_bin="/usr/libexec/qgs"
sles_kbs_bin="/usr/libexec/kbs" # symlink to /usr/libexec/trustee/kbs (created by setup)
sles_kbs_client_bin="/usr/libexec/trustee/kbs-client"
sles_grpc_as_bin="/usr/libexec/grpc-as"
sles_trustee_needs_symlinks=1 # units reference /usr/libexec/<name>, pkg ships /usr/libexec/trustee/<name>
sles_ovmf_fwdir="/usr/share/qemu/firmware"

sles_pkg_refresh() { run zypper refresh; }
sles_pkg_installed() { rpm -q "$1" >/dev/null 2>&1; }
sles_pkg_install() { run zypper in -y "$@"; }
sles_pkg_list_all() { rpm -qa 2>/dev/null || true; }

# SLE refreshes the system trust store. Two generations of tooling:
# - SLES 15: update-ca-trust regenerates /etc/pki/tls/certs/ca-bundle.crt
#   from /etc/pki/ca-trust/source/anchors/.
# - SLES 16.1: Debian-style ca-certificates; update-ca-certificates
#   regenerates /etc/ssl/certs (hashed) + /var/lib/ca-certificates/
#   from the p11-kit store (`trust extract --filter=ca-anchors`). A
#   ca-certificates.path unit also triggers this asynchronously when
#   /etc/pki/trust changes; running it explicitly avoids the race.
sles_ca_trust_refresh() {
    if command -v update-ca-trust >/dev/null 2>&1; then
        run update-ca-trust
    elif command -v update-ca-certificates >/dev/null 2>&1; then
        run update-ca-certificates
    else
        log "no trust store refresh tool found; p11-kit DB is the system store"
        return 0
    fi
}

# Remote command that reads a CA certificate from stdin and installs it into
# every guest trust store: the anchor dir (SLES 15), the p11-kit DB
# (`trust anchor` — read by rustls, and the source the SLES 16.1 OpenSSL
# store is generated from), then refreshes the OpenSSL store for curl/DCAP
# (update-ca-trust on SLES 15, update-ca-certificates on SLES 16.1, direct
# append to the legacy bundle as a last resort).
sles_ca_trust_cmd="A=/etc/pki/ca-trust/source/anchors/pccs-root-ca.pem; sudo mkdir -p \$(dirname \"\$A\") && sudo install -m 0644 /dev/stdin \"\$A\" && (sudo trust anchor \"\$A\" 2>/dev/null || true) && if command -v update-ca-trust >/dev/null 2>&1; then sudo update-ca-trust; elif command -v update-ca-certificates >/dev/null 2>&1; then sudo update-ca-certificates; else f=\$(awk '/BEGIN CERT/{f=1;next}/END CERT/{f=0}f' \"\$A\" | head -1); grep -qF \"\$f\" /etc/pki/tls/certs/ca-bundle.crt 2>/dev/null || sudo tee -a /etc/pki/tls/certs/ca-bundle.crt < \"\$A\" >/dev/null; fi"

sles_grub_tdx_hint() {
    echo "Mandatory: add 'kvm_intel.tdx' to the kernel command line (GRUB_CMDLINE_LINUX), regenerate GRUB config, reboot"
}

# Regular (non-TDX) pflash OVMF: first firmware descriptor with a flash device
# that does not advertise TDX. Requires jq (matches the previous behavior:
# without jq no firmware is selected and libvirt autoselection is used).
sles_ovmf_regular_probe() {
    command -v jq >/dev/null 2>&1 || return 1
    local f dev bin
    for f in /usr/share/qemu/firmware/*.json; do
        [[ -f "$f" ]] || continue
        # Skip TDX firmware descriptors
        if jq -e '(.features // []) | any(test("tdx";"i"))' "$f" >/dev/null 2>&1; then
            continue
        fi
        dev=$(jq -r '.mapping.device // empty' "$f" 2>/dev/null)
        if [[ "$dev" == "flash" ]]; then
            bin=$(jq -r '.mapping.executable.filename // .mapping.filename // empty' "$f" 2>/dev/null)
            if [[ -n "$bin" && -f "$bin" ]]; then
                echo "$bin"
                return 0
            fi
        fi
    done
    return 1
}

# Scan SLE's QEMU firmware descriptors for a TDX-capable OVMF.
# Prints "descriptor|binary" on success, returns 1 otherwise.
sles_ovmf_tdx_probe() {
    local fwdir="$sles_ovmf_fwdir" f bin
    [[ -d "$fwdir" ]] || return 1
    for f in "$fwdir"/*.json; do
        [[ -f "$f" ]] || continue
        # Does this descriptor advertise TDX in its features list?
        if command -v jq >/dev/null 2>&1; then
            jq -e '(.features // []) | any(test("tdx";"i"))' "$f" >/dev/null 2>&1 || continue
            # TDX OVMF maps as a single stateless image (mapping.filename,
            # device "memory"); pflash firmwares use mapping.executable.filename.
            bin=$(jq -r '.mapping.executable.filename // .mapping.filename // empty' "$f" 2>/dev/null)
        else
            grep -qi 'tdx' "$f" || continue
            bin=$(grep -oP '"filename"\s*:\s*"\K[^"]+' "$f" | head -1)
        fi
        [[ -n "$bin" ]] || continue
        echo "${f}|${bin}"
        return 0
    done
    return 1
}

# Install packages inside the guest over ssh (single round-trip
# missing-check). Same idea as install_pkgs, but remote.
sles_guest_pkg_install() {
    ssh_guest "missing=; for p in $*; do rpm -q \$p >/dev/null 2>&1 || missing=\"\$missing \$p\"; done
if [ -z \"\$missing\" ]; then echo 'Already installed: $*'; else echo \"Installing:\$missing\"; sudo zypper refresh; sudo zypper in -y \$missing; fi"
}
