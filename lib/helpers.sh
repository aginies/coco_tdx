# =============================================================================
# 3. GENERIC HELPERS
# =============================================================================

require_root() {
    if ((EUID != 0)); then
        die "This command requires root. Re-run with sudo."
    fi
}

require_cmd() {
    local cmd
    for cmd in "$@"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            die "Required command not found: ${cmd}"
        fi
    done
}

# Ensure grpcurl is available on the host (used to communicate with CoCo-AS gRPC service).
# Automatically downloads and installs the official prebuilt binary if missing.
ensure_grpcurl() {
    if command -v grpcurl >/dev/null 2>&1; then
        return 0
    fi
    for cand in "/usr/local/bin/grpcurl" "${HOME}/.local/bin/grpcurl" "/usr/bin/grpcurl"; do
        if [[ -x "$cand" ]]; then
            local dir
            dir=$(dirname "$cand")
            export PATH="${dir}:$PATH"
            return 0
        fi
    done

    # Prefer the distribution package (SLE ships grpcurl); fall back to the
    # official prebuilt binary if the package is not (yet) available.
    local grpcurl_pkgs
    grpcurl_pkgs=$(distro_pkgs grpcurl)
    if [[ -n "$grpcurl_pkgs" ]]; then
        log "grpcurl not found; trying the distribution package first..."
        # shellcheck disable=SC2046  # deliberate word-splitting of the package list
        if install_pkgs $grpcurl_pkgs && command -v grpcurl >/dev/null 2>&1; then
            log "grpcurl installed via package manager"
            return 0
        fi
        warn "Distribution package for grpcurl unavailable; falling back to prebuilt binary"
    fi

    log "grpcurl not found; installing official prebuilt release..."
    local install_dir="/usr/local/bin"
    local use_sudo=""
    if [[ "$EUID" -ne 0 ]]; then
        if sudo -n true 2>/dev/null; then
            use_sudo="sudo"
        else
            install_dir="${HOME}/.local/bin"
            mkdir -p "$install_dir"
            export PATH="${install_dir}:${PATH}"
        fi
    fi

    local grpcurl_ver="1.9.3"
    local grpcurl_url="https://github.com/fullstorydev/grpcurl/releases/download/v${grpcurl_ver}/grpcurl_${grpcurl_ver}_linux_x86_64.tar.gz"
    local tmp_tar
    tmp_tar=$(mktemp /tmp/grpcurl.XXXXXX.tar.gz)
    if curl -sSL -o "$tmp_tar" "$grpcurl_url" 2>/dev/null && [[ -s "$tmp_tar" ]]; then
        $use_sudo tar -xz -C "$install_dir" -f "$tmp_tar" grpcurl 2>/dev/null || tar -xz -C "$install_dir" -f "$tmp_tar" grpcurl
        $use_sudo chmod 0755 "${install_dir}/grpcurl" 2>/dev/null || chmod 0755 "${install_dir}/grpcurl"
        rm -f "$tmp_tar"
        if command -v grpcurl >/dev/null 2>&1 || [[ -x "${install_dir}/grpcurl" ]]; then
            export PATH="${install_dir}:${PATH}"
            log "Installed grpcurl to ${install_dir}/grpcurl"
            return 0
        fi
    fi
    rm -f "$tmp_tar"

    # Fallback to go install if go is available
    if command -v go >/dev/null 2>&1; then
        log "Attempting to install grpcurl via go install..."
        GOBIN="$install_dir" go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest >/dev/null 2>&1 || true
        if command -v grpcurl >/dev/null 2>&1 || [[ -x "${install_dir}/grpcurl" ]]; then
            export PATH="${install_dir}:${PATH}"
            log "Installed grpcurl via go"
            return 0
        fi
    fi

    die "grpcurl is required to communicate with CoCo-AS gRPC. Install the package
  $(distro_pkg_manager) in grpcurl
or the prebuilt binary:
  curl -sSL https://github.com/fullstorydev/grpcurl/releases/download/v1.9.3/grpcurl_1.9.3_linux_x86_64.tar.gz | sudo tar -xz -C /usr/local/bin grpcurl"
}

# Ensure the CoCo-AS attestation.proto file is accessible for grpcurl
# (since production gRPC servers usually disable the reflection API).
ensure_attestation_proto() {
    local candidate_dirs=(
        "${SCRIPT_DIR}/protos"
        "${SCRIPT_DIR}"
        "/etc/trustee/protos"
        "/etc/trustee"
        "/usr/share/trustee/protos"
        "/usr/share/trustee"
        "/tmp/trustee-protos"
    )
    for dir in "${candidate_dirs[@]}"; do
        if [[ -f "${dir}/attestation.proto" ]]; then
            PROTO_DIR="$dir"
            break
        fi
    done

    # Write embedded proto if not found on disk
    if [[ -z "$PROTO_DIR" || ! -f "${PROTO_DIR}/attestation.proto" ]]; then
        mkdir -p /tmp/trustee-protos
        cat >/tmp/trustee-protos/attestation.proto <<'EOF'
syntax = "proto3";

package attestation;

message AttestationRequest {
    repeated IndividualAttestationRequest verification_requests = 1;
    repeated string policy_ids = 2;
}

message IndividualAttestationRequest {
    string tee = 1;
    string evidence = 3;
    oneof runtime_data {
        string raw_runtime_data = 4;
        string structured_runtime_data = 5;
    }
    oneof init_data {
        string init_data_digest = 6;
        string init_data_toml = 7;
    }
    string runtime_data_hash_algorithm = 8;
}

message AttestationResponse {
    string attestation_token = 1;
}

message SetPolicyRequest {
    string policy_id = 1;
    string policy = 2;
}
message SetPolicyResponse {}

message ChallengeRequest {
    map<string, string> inner = 1;
}
message ChallengeResponse {
    string attestation_challenge = 1;
}

service AttestationService {
    rpc AttestationEvaluate(AttestationRequest) returns (AttestationResponse) {};
    rpc SetAttestationPolicy(SetPolicyRequest) returns (SetPolicyResponse) {};
    rpc GetAttestationChallenge(ChallengeRequest) returns (ChallengeResponse) {};
}
EOF
        PROTO_DIR="/tmp/trustee-protos"
    fi

    # Ensure reference.proto is also available in PROTO_DIR
    if [[ ! -f "${PROTO_DIR}/reference.proto" ]]; then
        if [[ -f "${SCRIPT_DIR}/protos/reference.proto" ]]; then
            cp "${SCRIPT_DIR}/protos/reference.proto" "${PROTO_DIR}/" 2>/dev/null || true
        elif [[ -f "/etc/trustee/reference.proto" ]]; then
            cp "/etc/trustee/reference.proto" "${PROTO_DIR}/" 2>/dev/null || true
        else
            mkdir -p "${PROTO_DIR}"
            cat >"${PROTO_DIR}/reference.proto" <<'EOF'
syntax = "proto3";

package reference;

message ReferenceValueQueryRequest {
    string reference_value_id = 1;
}

message ReferenceValueQueryResponse {
    optional string reference_value_results = 1;
}

message ReferenceValueRegisterRequest {
    string message = 1;
}

message ReferenceValueRegisterResponse {}

service ReferenceValueProviderService {
    rpc QueryReferenceValue(ReferenceValueQueryRequest) returns (ReferenceValueQueryResponse) {};
    rpc RegisterReferenceValue(ReferenceValueRegisterRequest) returns (ReferenceValueRegisterResponse) {};
}
EOF
        fi
    fi
    return 0
}

# Poll a TCP port until it listens or timeout expires.
# wait_for_port <host> <port> [timeout_seconds]
wait_for_port() {
    local host="$1" port="$2" timeout="${3:-30}"
    local elapsed=0
    while ! (echo >"/dev/tcp/${host}/${port}") 2>/dev/null; do
        if ((elapsed >= timeout)); then
            return 1
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    return 0
}

# Run a command on the guest, either locally or via ssh.
# Accepts a single command string (executed through a shell on the target).
ssh_guest() {
    local cmd="$*"
    if [[ -z "$GUEST_IP" ]]; then
        _log "CMD" "[guest:local] ${cmd}"
        bash -c "$cmd"
    else
        _log "CMD" "[guest:${GUEST_USER}@${GUEST_IP}] ${cmd}"
        ssh -i "$SSH_KEY" \
            -o StrictHostKeyChecking=accept-new \
            -o ConnectTimeout=10 \
            -o BatchMode=yes \
            "${GUEST_USER}@${GUEST_IP}" "$cmd"
    fi
}
kbs_url() {
    if [[ -n "$KBS_URL" ]]; then
        echo "$KBS_URL"
    else
        echo "http://${KBS_HOST}:${KBS_PORT}"
    fi
}

# Ensure the KBS service user (coco_kbs) can traverse TRUSTEE_DIR to read the
# admin public key and policy. The private key stays root-only (0600).
confirm() {
    local prompt="${1:-Continue?}"
    if ((FORCE)); then
        return 0
    fi
    if [[ ! -t 0 ]]; then
        die "Confirmation required but stdin is not a tty. Re-run with -f/--force."
    fi
    local answer
    read -r -p "${prompt} [y/N] " answer
    [[ "$answer" =~ ^[Yy]$ ]]
}
# Install only the packages that are actually missing (host). Keeps re-runs
# quiet and avoids a network round-trip when the stack is already in place.
# Metadata is refreshed at most once per run, and only if something needs
# installing. Distro-specific via the lib/distros/ adapter.
PKG_REFRESHED=0
install_pkgs() {
    local pkg missing=()
    for pkg in "$@"; do
        distro_pkg_installed "$pkg" || missing+=("$pkg")
    done
    if ((${#missing[@]} == 0)); then
        log "Already installed: $*"
        return 0
    fi
    log "Installing missing packages: ${missing[*]}"
    if ((! PKG_REFRESHED)); then
        distro_pkg_refresh
        PKG_REFRESHED=1
    fi
    distro_pkg_install "${missing[@]}"
}

# Same idea, inside the guest over ssh (or locally when no GUEST_IP is set).
# The guest distro is detected once over ssh — it may differ from the host.
install_pkgs_guest() {
    guest_distro_pkg_install "$@"
}

# Probe whether a kbs-client binary was built with the tdx-attester feature.
# A build WITH the feature compiles in the TDX attester, which references
# /dev/tdx_guest; a build WITHOUT it instead carries the string
# "`tdx-attester` feature is not enabled!". Static probe: no TD, network,
# or binutils required.
kbs_client_supports_tdx() { # host-side: kbs_client_supports_tdx <local-bin>
    [[ -x "$1" ]] || return 1
    grep -aq '/dev/tdx_guest' "$1"
}

kbs_client_supports_tdx_guest() { # guest-side: kbs_client_supports_tdx_guest <guest-path>
    ssh_guest "test -x '$1' && grep -aq '/dev/tdx_guest' '$1'"
}

# Build a TDX-enabled kbs-client on the HOST (needs Rust) and ship it to the guest.
# The SLE 'trustee' package kbs-client is built WITHOUT the TDX attester, so it
# falls back to a fake "Sample Attester" and real TDX attestation fails. Building
# from upstream with --features tdx-attester produces a client that reads
# /dev/tdx_guest + TSM_REPORTS and produces a real TD quote.
build_kbs_client_tdx() {
    local host_bin="${TRUSTEE_BUILD_DIR}/target/release/kbs-client"
    if [[ -x "$host_bin" ]] && kbs_client_supports_tdx "$host_bin"; then
        log "Reusing previously built kbs-client: $host_bin"
    else
        if [[ -x "$host_bin" ]]; then
            warn "Existing ${host_bin} lacks the tdx-attester feature — rebuilding"
        fi
        require_cmd cargo git
        log "Building TDX-enabled kbs-client from source (needs Rust toolchain)"
        if [[ ! -d "${TRUSTEE_BUILD_DIR}/.git" ]]; then
            run git clone --depth 1 "$TRUSTEE_REPO" "$TRUSTEE_BUILD_DIR"
        fi
        # Long compile; run with a generous timeout.
        if ! (cd "$TRUSTEE_BUILD_DIR" && cargo build -p kbs-client --locked --release --features tdx-attester); then
            die "kbs-client build failed. Check Rust toolchain (rustc >= 1.95) and network access to crates.io + github."
        fi
    fi
    [[ -x "$host_bin" ]] || die "Built kbs-client not found at $host_bin"
    kbs_client_supports_tdx "$host_bin" ||
        die "Built kbs-client at $host_bin has no TDX attester (tdx-attester feature not applied?)"
    log "Shipping kbs-client to guest: ${KBS_CLIENT_GUEST}"
    ssh_guest "sudo install -m 0755 /dev/stdin ${KBS_CLIENT_GUEST}" <"$host_bin"
    ssh_guest "test -x ${KBS_CLIENT_GUEST}" || die "Failed to install ${KBS_CLIENT_GUEST} in guest"
    kbs_client_supports_tdx_guest "$KBS_CLIENT_GUEST" ||
        die "Guest ${KBS_CLIENT_GUEST} has no TDX attester after install (corrupted transfer?)"
    log "TDX-enabled kbs-client installed in guest: ${KBS_CLIENT_GUEST}"
}

# Find a TDX-capable OVMF firmware (distro-specific probe, see lib/distros/).
# Prints "descriptor|binary" on success, returns 1 otherwise.
find_tdx_ovmf() {
    distro_ovmf_tdx_probe
}

probe_collateral_url() {
    local url="$1"
    # 1. Try Intel PCS lightweight endpoint (HTTP 200, no auth required)
    local probe_url="${url%/}/tcbevaluationdatanumbers"
    if curl -s -f --max-time 10 "$probe_url" >/dev/null 2>&1; then
        return 0
    fi
    # 2. Try QE identity endpoint
    local qe_probe="${url%/}/qe/identity"
    if curl -s -f --max-time 10 "$qe_probe" >/dev/null 2>&1; then
        return 0
    fi
    # 3. Fallback: check if server responds with valid HTTP status (200, 400, 401, 404)
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$url" 2>/dev/null || echo "000")
    if [[ "$code" == "200" || "$code" == "400" || "$code" == "404" || "$code" == "401" ]]; then
        return 0
    fi
    return 1
}

collateral_url() {
    if [[ "$COLLATERAL_MODE" == "pccs" ]]; then
        [[ -n "$PCCS_URL" ]] || die "PCCS mode requires a PCCS endpoint (--pccs-url)"
        echo "$PCCS_URL"
    else
        echo "$PCS_URL"
    fi
}

# Method 1: use the global Intel PCS directly as the collateral source.
# No local setup needed; QCNL/CoCo-AS point straight at PCS_URL.
ensure_libvirt() {
    if virsh -c qemu:///system version >/dev/null 2>&1; then
        log "libvirt reachable on qemu:///system"
        return 0
    fi

    local unit started=0
    for unit in virtqemud.socket virtnetworkd.socket virtstoraged.socket; do
        if systemctl list-unit-files "$unit" >/dev/null 2>&1 &&
            systemctl cat "$unit" >/dev/null 2>&1; then
            warn "libvirt not reachable, enabling ${unit}"
            run systemctl enable --now "$unit"
            started=1
        fi
    done

    if ((! started)); then
        warn "No modular libvirt sockets found, trying monolithic libvirtd.service"
        run systemctl enable --now libvirtd.service
    fi

    virsh -c qemu:///system version >/dev/null 2>&1 ||
        die "libvirt still unreachable on qemu:///system.
Install the QEMU driver ($(distro_pkg_manager) in $(distro_pkgs libvirt))
and check: systemctl status virtqemud.socket virtqemud.service"
}

# setup-vm needs virt-customize (guestfs-tools) to inject the SSH key into
# the guest disk offline. A TDX guest has no host-side console, so a missing
# tool here would leave the VM unreachable — install it instead of degrading
# to a manual step.
ensure_virt_customize() {
    command -v virt-customize >/dev/null 2>&1 && return 0
    log "virt-customize missing — installing $(distro_pkgs virt_customize)"
    install_pkgs $(distro_pkgs virt_customize)
    command -v virt-customize >/dev/null 2>&1 ||
        die "virt-customize still not available after install.
Install $(distro_pkgs virt_customize) manually ($(distro_pkg_manager)), then re-run."
}

detect_guest_ip() {
    [[ -n "$GUEST_IP" ]] && return 0
    if ! command -v virsh >/dev/null 2>&1; then
        die "--guest-ip is required (virsh not available for auto-detection). Usage: ${SCRIPT_NAME} <cmd> --guest-ip <IP>"
    fi
    local running_vms
    running_vms=$(virsh list --name 2>/dev/null | grep -v '^$')
    if [[ -z "$running_vms" ]]; then
        die "No running VMs found. Start a VM first, or use --guest-ip <IP>."
    fi
    echo ""
    echo "Running VMs:"
    local i=1 vm ip
    local -a vm_names=() vm_ips=()
    while IFS= read -r vm; do
        [[ -z "$vm" ]] && continue
        ip=$(virsh domifaddr "$vm" 2>/dev/null | awk '/ipv4/ {print $4}' | cut -d/ -f1 | head -1 || true)
        vm_names+=("$vm")
        vm_ips+=("${ip:-unknown}")
        echo "  ${i}) ${vm}  [${ip:-no IP detected}]"
        ((i++))
    done <<<"$running_vms"
    echo ""
    if ((${#vm_names[@]} == 1)); then
        GUEST_IP="${vm_ips[0]}"
        log "Auto-detected guest: ${vm_names[0]} (IP: ${GUEST_IP})"
    else
        if [[ ! -t 0 ]]; then
            die "Interactive selection requires a tty. Re-run with --guest-ip <IP>."
        fi
        local choice
        read -r -p "Enter VM number: " choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && ((choice >= 1 && choice <= ${#vm_names[@]})); then
            local idx=$((choice - 1))
            GUEST_IP="${vm_ips[$idx]}"
            log "Selected guest: ${vm_names[$idx]} (IP: ${GUEST_IP})"
        else
            die "Invalid selection. Re-run with --guest-ip <IP>."
        fi
    fi
    if [[ -z "$GUEST_IP" || "$GUEST_IP" == "unknown" ]]; then
        die "No IP detected for the selected VM. Check the guest (agent/ARP) or pass --guest-ip <IP>."
    fi
}

# Run the 6 QGS host-side pre-flight checks, recording PASS/FAIL/WARN into
# CHECK_RESULTS. Caller must reset CHECK_RESULTS=() before calling and render
# with print_results afterwards. Resolves GUEST_VM_NAME from GUEST_IP.
