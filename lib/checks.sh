# =============================================================================
# 4. CAPABILITY CHECKS (read-only probes)
# =============================================================================

# Each check_* function: prints "PASS|FAIL|WARN: message" and returns 0/1.
# Results collected in CHECK_RESULTS array by cmd_check.

CHECK_RESULTS=()

record() {
    local status="$1" msg="$2" hint="${3:-}"
    CHECK_RESULTS+=("${status}|${msg}|${hint}")
}

# Render CHECK_RESULTS as a table. Sets RESULT_FAILS to the number of FAIL rows.
# (Returns 0 so it never trips 'set -e' / the ERR trap on a nonzero count.)
RESULT_FAILS=0
print_results() {
    # Colorize the STATUS column when writing to a terminal (respect NO_COLOR).
    local c_pass="" c_fail="" c_warn="" c_reset=""
    if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
        c_pass=$'\e[32m'       # green
        c_fail=$'\e[31m'       # red
        c_warn=$'\e[38;5;208m' # orange (256-color; falls back gracefully)
        c_reset=$'\e[0m'
    fi

    echo
    printf '%-6s %-52s %s\n' "STATUS" "CHECK" "HINT"
    printf '%-6s %-52s %s\n' "------" "-----" "----"
    local status msg hint entry color
    RESULT_FAILS=0
    for entry in "${CHECK_RESULTS[@]}"; do
        IFS='|' read -r status msg hint <<<"$entry"
        case "$status" in
        PASS) color="$c_pass" ;;
        FAIL) color="$c_fail" ;;
        WARN) color="$c_warn" ;;
        *) color="" ;;
        esac
        printf '%s%-6s%s %-52s %s\n' "$color" "$status" "$c_reset" "$msg" "$hint"
        [[ "$status" == "FAIL" ]] && RESULT_FAILS=$((RESULT_FAILS + 1))
    done
    echo
    return 0
}

# Validate a JSON file. rc 0 = valid, 1 = invalid, 2 = no validator available.
json_valid() {
    local f="$1" rc
    if command -v jq >/dev/null 2>&1; then
        jq . "$f" >/dev/null 2>&1
        rc=$?
        # jq exits 2/5 on parse errors; normalize any failure to 1.
        if ((rc == 0)); then
            return 0
        fi
        return 1
    elif command -v python3 >/dev/null 2>&1; then
        python3 -m json.tool "$f" >/dev/null 2>&1
    else
        return 2
    fi
}

check_cpu_tdx() {
    # Host advertises 'tdx_host_platform'; a guest advertises 'tdx_guest'.
    # As a fallback, kvm_intel.tdx=Y also proves TDX is active on the host.
    if grep -qwE 'tdx_host_platform|tdx_guest' /proc/cpuinfo 2>/dev/null; then
        record "PASS" "CPU/kernel reports TDX (tdx_host_platform/tdx_guest flag)"
    elif [[ "$(cat /sys/module/kvm_intel/parameters/tdx 2>/dev/null)" == "Y" ]]; then
        record "PASS" "TDX active on host (kvm_intel.tdx=Y)"
    else
        record "FAIL" "CPU does NOT report TDX support" \
            "Check CPU is Intel Emerald Rapids+ and TDX enabled in BIOS (F2/Del at POST)"
    fi
}

check_kvm() {
    if [[ -c /dev/kvm ]]; then
        local perms
        perms=$(stat -c '%A %U:%G' /dev/kvm)
        record "PASS" "KVM available: /dev/kvm (${perms})"
    else
        record "FAIL" "KVM not available: /dev/kvm missing" \
            "Enable VT-x in BIOS, check 'lsmod | grep kvm', reload kvm_intel"
    fi
}

# libvirt is modular since SLE 16 / libvirt 5.7: the monolithic libvirtd.service
# is replaced by per-driver daemons (virtqemud, virtnetworkd, virtstoraged),
# normally socket-activated. The functional probe below covers both layouts —
# a successful qemu:///system connection IS "libvirt is running".
check_libvirt() {
    if ! command -v virsh >/dev/null 2>&1; then
        record "WARN" "libvirt client not installed (virsh missing)" \
            "$(distro_pkg_manager) in $(distro_pkgs libvirt) (required for setup-vm)"
        return
    fi
    if virsh -c qemu:///system version >/dev/null 2>&1; then
        record "PASS" "libvirt running: qemu:///system reachable"
        return
    fi
    # Unreachable: report the installed layout and its unit state.
    local unit state sock sock_state
    for unit in virtqemud.service libvirtd.service; do
        if systemctl cat "$unit" >/dev/null 2>&1; then
            state=$(systemctl is-active "$unit" 2>/dev/null || true)
            sock="${unit%.service}.socket"
            sock_state="n/a"
            if systemctl cat "$sock" >/dev/null 2>&1; then
                sock_state=$(systemctl is-active "$sock" 2>/dev/null || true)
            fi
            if [[ "$state" == "active" || "$sock_state" == "active" ]]; then
                record "WARN" "libvirt units present but qemu:///system unreachable (service=${state:-inactive}, socket=${sock_state})" \
                    "journalctl -u ${unit} -n 50; systemctl status ${sock}"
            else
                record "FAIL" "libvirt not running (${unit}=${state:-inactive}, ${sock}=${sock_state})" \
                    "sudo systemctl enable --now ${sock} (modular) or ${unit} (monolithic)"
            fi
            return
        fi
    done
    record "FAIL" "No libvirt daemon installed (virtqemud.service / libvirtd.service missing)" \
        "$(distro_pkg_manager) in $(distro_pkgs libvirt)"
}

check_qemu() {
    if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
        record "FAIL" "qemu-system-x86_64 not installed" "$(distro_pkg_manager) in $(distro_pkgs qemu)"
        return
    fi
    local ver
    ver=$(qemu-system-x86_64 --version 2>/dev/null | head -1 | grep -oP '\d+\.\d+' | head -1 || true)
    if [[ -z "$ver" ]]; then
        record "FAIL" "QEMU version unparseable" "Check: qemu-system-x86_64 --version"
        return
    fi
    local major="${ver%%.*}"
    if ((major >= 8)); then
        record "PASS" "QEMU version OK: ${ver} (>= 8.0)"
    else
        record "FAIL" "QEMU too old: ${ver} (need >= 8.0)" "Update qemu package"
    fi
}

check_qemu_tdx() {
    if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
        record "WARN" "QEMU TDX machine support: skipped (qemu missing)"
        return
    fi
    # TDX is a QEMU *object* (tdx-guest), not a machine type. -machine help
    # never lists it; probe the object list instead.
    if qemu-system-x86_64 -object help 2>&1 | grep -qi 'tdx-guest'; then
        record "PASS" "QEMU supports TDX (tdx-guest object)"
    else
        record "FAIL" "QEMU has no TDX support (no tdx-guest object)" \
            "Reinstall qemu with TDX target (package: $(distro_pkgs qemu))"
    fi
}

# Locate a TDX-capable OVMF via the QEMU firmware descriptors. Echoes
# "<descriptor>|<ovmf_binary>" for the first TDX firmware found; rc 1 if none.
#
# TDX firmware is mapped into guest RAM and loaded with QEMU '-bios' (a ROM
# loader), NOT pflash. The SLE 16.1 descriptor points at
# ovmf-x86_64-tdx-secureboot.bin, which is the correct (and proven working)
# TDX OVMF — see sles16.0-test-tdx-working.xml.
check_ovmf_tdx() {
    local fwdir
    fwdir=$(distro_ovmf_fwdir)
    if [[ ! -d "$fwdir" ]]; then
        record "WARN" "QEMU firmware descriptor dir missing: ${fwdir}" \
            "Install edk2/OVMF ($(distro_pkgs ovmf))"
        return
    fi
    local hit desc bin
    if hit=$(find_tdx_ovmf); then
        desc="${hit%%|*}"
        bin="${hit##*|}"
        if [[ -f "$bin" ]]; then
            record "PASS" "TDX OVMF present: ${bin}" "descriptor: ${desc}"
        else
            record "FAIL" "TDX firmware descriptor points to missing OVMF: ${bin}" \
                "Install the OVMF package providing ${bin} (from ${desc})"
        fi
    else
        record "FAIL" "No TDX-capable OVMF firmware descriptor in ${fwdir}" \
            "Install a TDX-enabled edk2/OVMF (descriptor must list the intel-tdx feature)"
    fi
}

# Host-side TDX readiness. NOTE: tdx_guest / /dev/tdx-guest are GUEST-only
# (they exist inside a Trust Domain, never on the host). The host uses the
# kvm_intel TDX support + an initialized TDX module.
#
# The 'kvm_intel.tdx' kernel-cmdline parameter IS mandatory: without it,
# QEMU/libvirt fail at launch and report that TDX is not supported. The
# kernel log ('TDX-Module initialized') confirms the module is up; the
# tdx_host_platform CPU flag is checked separately in check_cpu_tdx.
check_host_tdx() {
    local tdx_param
    tdx_param=$(cat /sys/module/kvm_intel/parameters/tdx 2>/dev/null || echo "N")

    # Kernel-log confirmation. dmesg can be restricted (kernel.dmesg_restrict);
    # fall back to journalctl -k.
    local klog
    klog=$({ dmesg 2>/dev/null || journalctl -k --no-pager 2>/dev/null; } | grep -i 'virt/tdx' || true)
    if grep -qi 'TDX-Module initialized' <<<"$klog" && [[ "$tdx_param" == "Y" ]]; then
        record "PASS" "Host TDX ready (kvm_intel.tdx=Y, TDX module initialized)"
    elif [[ "$tdx_param" == "Y" ]]; then
        record "PASS" "KVM TDX enabled (kvm_intel.tdx=Y; kernel log not readable here)"
    else
        record "FAIL" "kvm_intel.tdx not set (kvm_intel.tdx=${tdx_param}) — QEMU/libvirt will refuse TDX" \
            "$(distro_grub_tdx_hint)"
    fi
}

check_dcap_pkgs() {
    local count
    count=$(distro_pkg_list_all | grep -cEi 'dcap|sgx|tdx|qpl' || true)
    if [[ "${count:-0}" -gt 0 ]]; then
        record "PASS" "DCAP/SGX packages installed (${count} packages)"
    else
        record "WARN" "No DCAP packages found" "$(distro_pkg_manager) in $(distro_pkgs dcap_host) (setup-host)"
    fi
}

check_qgs() {
    if ! systemctl cat qgsd.service >/dev/null 2>&1; then
        record "WARN" "QGS service (qgsd.service) not installed" "$(distro_pkg_manager) in $(distro_pkgs qgs) (setup-qgs)"
        return
    fi
    if [[ "$(systemctl is-active qgsd.service 2>/dev/null)" == "active" ]]; then
        record "PASS" "QGS service (qgsd.service) is running"
    else
        record "FAIL" "QGS service (qgsd.service) not running" \
            "journalctl -u qgsd.service -n 50; check /etc/sgx_default_qcnl.conf"
        return
    fi

    # QGS must run in unix-socket mode, not TCP. The default SUSE unit uses
    # -p=4050 (TCP) which QEMU's tdx-guest object cannot use.
    local qg_args
    qg_args=$(systemctl show qgsd.service -p Environment --value 2>/dev/null | tr ';' '\n' | grep QGSD_ARGS || true)
    if grep -q -- '-p=' <<<"$qg_args"; then
        record "FAIL" "QGS running in TCP mode (-p= found in QGSD_ARGS)" \
            "sudo ${SCRIPT_NAME} setup-qgs (overrides QGSD_ARGS to unix-socket mode)"
    elif [[ -z "$qg_args" ]]; then
        record "WARN" "QGS QGSD_ARGS not set (using unit default, may be TCP mode)" \
            "sudo ${SCRIPT_NAME} setup-qgs"
    fi

    # Socket file must exist and be a real socket (not a stale symlink).
    if [[ -S "${QGS_SOCKET}" ]]; then
        record "PASS" "QGS socket present: ${QGS_SOCKET}"
    elif [[ -L "${QGS_SOCKET}" ]]; then
        record "FAIL" "QGS socket is a stale symlink (points to missing file)" \
            "rm ${QGS_SOCKET} && systemctl restart qgsd.service"
    else
        record "FAIL" "QGS socket missing: ${QGS_SOCKET}" \
            "journalctl -u qgsd.service -n 30; check QGS is in socket mode"
    fi

    # QEMU user must be able to access the socket (qgsd:qgsd mode 640).
    if id qgsd >/dev/null 2>&1 && id qemu >/dev/null 2>&1; then
        if ! id -nG qemu | tr ' ' '\n' | grep -qx qgsd; then
            record "FAIL" "qemu user not in qgsd group (cannot access QGS socket)" \
                "usermod -aG qgsd qemu (then restart VMs)"
        fi
    fi

    # QCNL config at the path QGS actually reads.
    if [[ -f /etc/sgx_default_qcnl.conf ]]; then
        record "PASS" "QCNL config present: /etc/sgx_default_qcnl.conf"
    else
        record "FAIL" "QCNL config missing: /etc/sgx_default_qcnl.conf" \
            "sudo ${SCRIPT_NAME} setup-qgs"
    fi
}

check_trustee() {
    local svc
    local missing=()
    # trustee.service (SUSE) is the unified tenant-side binary; it is redundant
    # with grpc-as+kbs+rvps and its unit is broken (ConditionPathExists=/etc/trustee.json
    # is never satisfied and ExecStart lacks the required 'run' subcommand).
    # It is NOT part of the required stack.
    for svc in grpc-as.service kbs.service rvps.service; do
        if ! systemctl cat "$svc" >/dev/null 2>&1; then
            missing+=("$svc (not installed)")
        elif [[ "$(systemctl is-active "$svc" 2>/dev/null)" != "active" ]]; then
            missing+=("$svc (not running)")
        fi
    done
    if ((${#missing[@]} == 0)); then
        record "PASS" "Trustee stack running (grpc-as, kbs, rvps)"
    else
        local trustee_pkg
        trustee_pkg=$(distro_pkgs trustee | awk '{print $1}')
        record "WARN" "Trustee stack incomplete: ${missing[*]}" \
            "$(distro_pkg_manager) in ${trustee_pkg}; setup-trustee command"
    fi

    if command -v grpcurl >/dev/null 2>&1; then
        record "PASS" "grpcurl available (for host-side attestation)"
    else
        record "WARN" "grpcurl not installed (needed for host-side attest command)" \
            "$(distro_pkg_manager) in grpcurl (or prebuilt: curl -sSL https://github.com/fullstorydev/grpcurl/releases/download/v1.9.3/grpcurl_1.9.3_linux_x86_64.tar.gz | sudo tar -xz -C /usr/local/bin grpcurl)"
    fi
}

check_ports() {
    if ss -tln 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${COCO_AS##*:}$"; then
        record "PASS" "CoCo-AS listening on port ${COCO_AS##*:}"
    else
        record "WARN" "CoCo-AS port ${COCO_AS##*:} not listening" "Start grpc-as.service (setup-trustee)"
    fi
    if ss -tln 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${KBS_PORT}$"; then
        record "PASS" "KBS listening on port ${KBS_PORT}"
    else
        record "WARN" "KBS port ${KBS_PORT} not listening" "Start kbs.service (setup-trustee)"
    fi
}

check_collateral_net() {
    local url
    url=$(collateral_url)
    if probe_collateral_url "$url"; then
        record "PASS" "Network reach to collateral source (${COLLATERAL_MODE}): ${url}"
    else
        record "WARN" "Cannot reach collateral source (${COLLATERAL_MODE}): ${url}" \
            "PCS: allow outbound HTTPS; PCCS: start the local PCCS (--pccs-url)"
    fi
}

check_platform_validity() {
    local pccs_check="${SCRIPT_DIR}/pccs-check.sh"
    if [[ ! -x "$pccs_check" ]]; then
        if command -v pccs-check.sh >/dev/null 2>&1; then
            pccs_check="pccs-check.sh"
        else
            record "WARN" "pccs-check.sh not found (cannot perform deep platform validity check)" \
                "Place pccs-check.sh alongside tdx-attest.sh or install in PATH"
            return
        fi
    fi

    local args=("check" "--auto" "--tdx")
    if [[ "$COLLATERAL_MODE" == "pccs" ]]; then
        args+=("--pccs-url" "$PCCS_URL")
    else
        args+=("--pccs-url" "$PCS_URL")
    fi

    log "Probing platform validity via ${pccs_check} ${args[*]}..."
    local out
    if out=$("$pccs_check" "${args[@]}" 2>&1); then
        local detected_source
        detected_source=$(echo "$out" | grep -m1 'Source:' | sed 's/.*Source:[ \t]*//' || true)
        local fmspc
        fmspc=$(echo "$out" | grep -m1 'FMSPC:' | sed 's/.*FMSPC:[ \t]*//' || true)
        record "PASS" "Platform collateral validity verified on ${COLLATERAL_MODE^^} (${fmspc:-unknown}${detected_source:+, $detected_source})"
    else
        local reason
        reason=$(echo "$out" | grep -m1 '\[ERROR\]' | sed 's/\[ERROR\][ \t]*//' || echo "Platform validation failed")
        record "WARN" "Platform collateral check returned warnings/errors: ${reason}" \
            "Run './pccs-check.sh check --auto --tdx' for diagnostic output"
    fi
}

cmd_check_platform() {
    log "=== Checking TDX platform validity against Intel PCS/PCCS ==="
    step "Auto-discover platform identifiers and verify TCB status & collateral" \
        "Queries local PCK certs / PCKIDRetrievalTool / CPU model to populate FMSPC and verify against PCS."
    local pccs_check="${SCRIPT_DIR}/pccs-check.sh"
    if [[ ! -x "$pccs_check" ]]; then
        if command -v pccs-check.sh >/dev/null 2>&1; then
            pccs_check="pccs-check.sh"
        else
            die "pccs-check.sh not found. Ensure pccs-check.sh is in the same directory as tdx-attest.sh."
        fi
    fi

    local args=("check" "--auto" "--tdx")
    if [[ "$COLLATERAL_MODE" == "pccs" ]]; then
        args+=("--pccs-url" "$PCCS_URL")
    else
        args+=("--pccs-url" "$PCS_URL")
    fi

    log "Executing: ${pccs_check} ${args[*]}"
    local rc=0
    "$pccs_check" "${args[@]}" || rc=$?
    if ((rc != 0)); then
        trap - ERR
        return $rc
    fi
    return 0
}

cmd_register_platform() {
    log "=== Registering TDX platform with Intel SGX Registration Service ==="
    step "Automated platform manifest extraction and registration" \
        "Extracts hardware manifest via PCKIDRetrievalTool/UEFI, converts hex to binary, and submits to Intel Registration Service."
    local pccs_check="${SCRIPT_DIR}/pccs-check.sh"
    if [[ ! -x "$pccs_check" ]]; then
        if command -v pccs-check.sh >/dev/null 2>&1; then
            pccs_check="pccs-check.sh"
        else
            die "pccs-check.sh not found. Ensure pccs-check.sh is in the same directory as tdx-attest.sh."
        fi
    fi

    local args=("register")
    if [[ -n "$SUBSCRIPTION_KEY" ]]; then
        args+=("--subscription" "$SUBSCRIPTION_KEY")
    fi
    if [[ -n "$CSV_FILE" ]]; then
        args+=("--csv" "$CSV_FILE")
    fi

    log "Executing: ${pccs_check} ${args[*]}"
    local rc=0
    "$pccs_check" "${args[@]}" || rc=$?
    if ((rc != 0)); then
        trap - ERR
        return $rc
    fi
    return 0
}

cmd_check() {
    log "=== TDX host capability check ==="
    step "Probe host for TDX readiness (read-only, no changes made)" \
        "Checks CPU/BIOS TDX, KVM, libvirt, QEMU, kernel module, DCAP pkgs, QGS/Trustee services, ports, collateral source (PCS/PCCS) reachability."
    CHECK_RESULTS=()

    check_cpu_tdx
    check_kvm
    check_libvirt
    check_qemu
    check_qemu_tdx
    check_ovmf_tdx
    check_host_tdx
    check_dcap_pkgs
    check_qgs
    check_trustee
    check_ports
    check_collateral_net
    if ((CHECK_PLATFORM)); then
        check_platform_validity
    fi

    local fails=0
    print_results
    fails=$RESULT_FAILS

    if ((fails > 0)); then
        warn "${fails} check(s) FAILED. See hints above (doc: Troubleshooting sections)."
        trap - ERR
        return 1
    fi
    log "All checks passed (warnings, if any, are non-fatal)."
    return 0
}

# =============================================================================
# 4b. CONFIG VERIFICATION (deep post-setup validation)
# =============================================================================
#
# 'verify' double-checks that everything written/started by the setup steps is
# actually correct and consistent: config files exist, parse, and point at the
# same endpoints; services run; ports listen; libraries resolve; the VM domain
# really has TDX launchSecurity + vsock. Read-only, safe to run repeatedly.

# Check a config file exists, then optionally validate JSON syntax.
verify_conf_file() {
    local label="$1" path="$2" kind="${3:-text}"
    if [[ ! -f "$path" ]]; then
        record "FAIL" "${label} missing: ${path}" "Run the matching setup-* command"
        return
    fi
    if [[ "$kind" == "json" ]]; then
        local rc=0
        json_valid "$path" || rc=$?
        case $rc in
        0) record "PASS" "${label} present and valid JSON: ${path}" ;;
        1) record "FAIL" "${label} is INVALID JSON: ${path}" "Re-run setup-* or fix by hand" ;;
        2) record "WARN" "${label} present (JSON not validated: install jq or python3): ${path}" ;;
        *) record "FAIL" "${label} is INVALID JSON: ${path}" "Re-run setup-* or fix by hand" ;;
        esac
    else
        record "PASS" "${label} present: ${path}"
    fi
}

# Confirm a config file contains an expected substring.
verify_conf_contains() {
    local label="$1" path="$2" needle="$3" hint="${4:-}"
    if [[ -f "$path" ]] && grep -qF "$needle" "$path"; then
        record "PASS" "${label}: found '${needle}'"
    else
        record "FAIL" "${label}: '${needle}' not found in ${path}" "$hint"
    fi
}

verify_service() {
    local svc="$1"
    if ! systemctl cat "$svc" >/dev/null 2>&1; then
        record "FAIL" "${svc} not installed" "Run the matching setup-* command"
        return
    fi
    local state
    state=$(systemctl is-active "$svc" 2>/dev/null || true)
    state="${state:-inactive}"
    if [[ "$state" == "active" ]]; then
        record "PASS" "${svc} is active"
    else
        record "FAIL" "${svc} is ${state}" "journalctl -u ${svc} -n 50"
    fi
}

verify_port() {
    local label="$1" port="$2" hint="$3"
    if ss -tln 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${port}$"; then
        record "PASS" "${label} listening on port ${port}"
    else
        record "FAIL" "${label} port ${port} not listening" "$hint"
    fi
}

# Confirm the collateral endpoint is consistent across QCNL config and
# CoCo-AS config.
verify_collateral_consistency() {
    local qcnl_url as_url
    qcnl_url=$(grep -oP '"pccs_url"\s*:\s*"\K[^"]+' "$QCNL_ETC_CONF" 2>/dev/null || true)
    as_url=$(grep -oP '"collateral_service"\s*:\s*"\K[^"]+' "$GRPC_AS_CONF" 2>/dev/null || true)
    if [[ -z "$qcnl_url" || -z "$as_url" ]]; then
        record "WARN" "Collateral consistency: could not read both URLs" \
            "QCNL=${qcnl_url:-?} CoCo-AS=${as_url:-?}"
        return
    fi
    if [[ "$qcnl_url" == "$as_url" ]]; then
        record "PASS" "Collateral endpoint consistent (QGS and CoCo-AS): ${qcnl_url}"
    else
        record "WARN" "Collateral endpoint MISMATCH: QGS=${qcnl_url} CoCo-AS=${as_url}" \
            "Both should point at the same source; re-run setup with one --collateral/--pccs-url"
    fi
}

# Confirm the KBS points at the configured CoCo-AS address.
verify_kbs_as_addr() {
    verify_conf_contains "KBS -> CoCo-AS addr" "$KBS_CONF" "http://${COCO_AS}" \
        "kbs.json as_addr must match --coco-as (${COCO_AS})"
}

verify_grpc_as_libs() {
    local grpc_as_bin
    grpc_as_bin=$(distro_grpc_as_bin)
    if [[ ! -f "$grpc_as_bin" ]]; then
        record "WARN" "grpc-as binary not found: ${grpc_as_bin}" "setup-trustee"
        return
    fi
    local missing
    missing=$(ldd "$grpc_as_bin" 2>/dev/null | grep 'not found' || true)
    if [[ -z "$missing" ]]; then
        record "PASS" "grpc-as dynamic libraries all resolve"
    else
        record "FAIL" "grpc-as has unresolved libraries" \
            "$(echo "$missing" | tr '\n' ' ')"
    fi
}

# Confirm the VM domain really has TDX launchSecurity + a vsock device.
verify_vm_tdx() {
    if ! command -v virsh >/dev/null 2>&1; then
        record "WARN" "virsh not available; skipping VM TDX checks" ""
        return
    fi
    if ! virsh dominfo "$VM_NAME" >/dev/null 2>&1; then
        record "WARN" "VM '${VM_NAME}' not defined; skipping VM TDX checks" "setup-vm"
        return
    fi
    local xml
    xml=$(virsh dumpxml "$VM_NAME" 2>/dev/null || true)
    if grep -q "launchSecurity type='tdx'" <<<"$xml"; then
        record "PASS" "VM '${VM_NAME}' has launchSecurity type='tdx'"
    else
        record "FAIL" "VM '${VM_NAME}' has NO TDX launchSecurity" \
            "Re-create with setup-vm (guest will not be a real TD)"
    fi
    local loader_type
    loader_type=$(grep -oP "<loader[^>]*type='\K[^']+" <<<"$xml" 2>/dev/null || true)
    if [[ "$loader_type" == "rom" ]]; then
        record "PASS" "VM '${VM_NAME}' has ROM loader (TDX firmware)"
    else
        record "FAIL" "VM '${VM_NAME}' loader type: '${loader_type:-none}' (expected 'rom')" \
            "TDX OVMF must be a ROM loader; pflash requires readonly memslot which TDX private memory does not support"
    fi
    if grep -q "<vsock" <<<"$xml"; then
        record "PASS" "VM '${VM_NAME}' has a vsock device (quote path)"
    else
        record "FAIL" "VM '${VM_NAME}' has NO vsock device" \
            "Quote generation over vsock will fail; re-run setup-vm"
    fi
}

cmd_verify() {
    log "=== Verifying attestation configuration ==="
    step "Double-check every config written by the setup steps is correct" \
        "Validates config files (existence + JSON syntax), endpoint consistency, running services, listening ports, grpc-as libraries, and VM TDX/vsock. Read-only."
    CHECK_RESULTS=()

    # --- Config files exist and parse ---
    verify_conf_file "QCNL run config" "$QCNL_RUN_CONF" json
    verify_conf_file "QCNL persistent conf" "$QCNL_ETC_CONF" json
    verify_conf_file "QCNL package conf" "$QCNL_PKG_CONF" json
    if [[ -f "$QCNL_PKG_CONF" ]]; then
        local perms
        perms=$(stat -c "%a" "$QCNL_PKG_CONF" 2>/dev/null || stat -f "%OLp" "$QCNL_PKG_CONF" 2>/dev/null || echo "")
        if [[ "$perms" =~ [4567]$ ]]; then
            record "PASS" "QCNL package conf is world-readable (${perms})"
        else
            record "FAIL" "QCNL package conf permissions (${perms:-unknown}) may block non-root services (e.g. coco_as)" \
                "Run: chmod 644 ${QCNL_PKG_CONF}"
        fi
    fi
    verify_conf_file "CoCo-AS config" "$GRPC_AS_CONF" json
    verify_conf_file "RVPS config" "$RVPS_CONF" json
    verify_conf_file "KBS config" "$KBS_CONF" text

    # --- Config content is consistent ---
    verify_conf_contains "CoCo-AS DCAP verifier" "$GRPC_AS_CONF" '"dcap_verifier"' \
        "CoCo-AS must use the dcap_verifier for TDX quotes"
    verify_kbs_as_addr
    verify_collateral_consistency

    # --- Secret delivery (KBS) plumbing ---
    if [[ -f "$KBS_ADMIN_KEY" && -f "$KBS_ADMIN_PUB" ]]; then
        record "PASS" "KBS admin keypair present: ${KBS_ADMIN_KEY}"
    else
        record "FAIL" "KBS admin keypair missing" "setup-trustee generates it (needed for secret-set)"
    fi
    # Admin auth wiring depends on the authorization_mode: the LAB template
    # uses InsecureAllowAll (no key referenced in kbs.json); only
    # AuthenticatedAuthorization requires auth_public_key to point at the pub key.
    if [[ -f "$KBS_CONF" ]] && grep -qF '"authorization_mode": "InsecureAllowAll"' "$KBS_CONF"; then
        record "PASS" "KBS admin auth: InsecureAllowAll (LAB setting, no admin key required)"
    else
        verify_conf_contains "KBS admin key wired" "$KBS_CONF" "$KBS_ADMIN_PUB" \
            "kbs.json [admin] auth_public_key must point at ${KBS_ADMIN_PUB}"
    fi
    if [[ -f "$KBS_POLICY" ]]; then
        record "PASS" "KBS resource policy present: ${KBS_POLICY}"
    else
        record "WARN" "KBS resource policy file missing" "setup-trustee writes ${KBS_POLICY}"
    fi
    # --- Guest kbs-client has the TDX attester (only when a guest is reachable) ---
    if [[ -n "$GUEST_IP" ]] && ssh_guest "true" 2>/dev/null; then
        if kbs_client_supports_tdx_guest "$KBS_CLIENT_GUEST"; then
            record "PASS" "Guest kbs-client has TDX attester: ${KBS_CLIENT_GUEST}"
        elif ssh_guest "test -x $(guest_distro_kbs_client_bin)" 2>/dev/null; then
            record "WARN" "Guest kbs-client lacks TDX attester (package sample fallback)" \
                "Run 'setup-guest' to build + install the TDX-enabled client"
        else
            record "WARN" "No kbs-client found in guest" \
                "Run 'setup-guest' or install the 'trustee' package"
        fi
    fi

    # --- Host TDX plumbing (guest-only nodes like /dev/tdx-guest are NOT here) ---
    check_host_tdx
    check_ovmf_tdx

    # --- Services running ---
    verify_service qgsd.service
    verify_service grpc-as.service
    verify_service kbs.service
    verify_service rvps.service

    # --- Ports listening ---
    verify_port "CoCo-AS" "${COCO_AS##*:}" "Start grpc-as.service (setup-trustee)"
    verify_port "KBS" "${KBS_PORT}" "Start kbs.service (setup-trustee)"

    # --- Libraries resolve ---
    verify_grpc_as_libs

    # --- VM really is a TD ---
    verify_vm_tdx

    # --- Collateral source reachable ---
    local coll_url
    coll_url=$(collateral_url)
    if probe_collateral_url "$coll_url"; then
        record "PASS" "Collateral source reachable (${COLLATERAL_MODE}): ${coll_url}"
    else
        record "WARN" "Collateral source not reachable (${COLLATERAL_MODE}): ${coll_url}" \
            "PCS: check outbound HTTPS; PCCS: check the local PCCS service"
    fi

    local fails=0
    print_results
    fails=$RESULT_FAILS

    if ((fails > 0)); then
        warn "${fails} configuration check(s) FAILED. Fix the items above, then re-run 'verify'."
        trap - ERR
        return 1
    fi
    log "Attestation configuration verified: all critical checks passed."
    return 0
}
