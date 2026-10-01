# =============================================================================
# 5. HOST SETUP
# =============================================================================

# --- Collateral source: two methods ------------------------------------------
#
# PCK collateral (PCK cert, CRLs, TCB info) can come from two places:
#   Method 1 (pcs):  the global Intel PCS directly — always authoritative, but
#                    every fetch goes over the public internet.
#   Method 2 (pccs): a local PCCS, which *caches* PCS data. Before the PCCS
#                    can be used, its root CA must be obtained from PCS (the
#                    "initial CA") and trusted; afterwards attestation
#                    collateral traffic stays on the local network.

# Method 1: use the global Intel PCS directly as the collateral source.
# No local setup needed; QCNL/CoCo-AS point straight at PCS_URL.
collateral_via_pcs() {
    log "Collateral source: global PCS (${PCS_URL})"
}

# Method 2: use a local PCCS cache. The PCCS serves collateral over HTTPS
# with a certificate that must chain to a root CA trusted by BOTH consumers:
#   - CoCo-AS (rustls via rustls-platform-verifier) reads the p11-kit
#     "System Trust" token — on SUSE that is populated via `trust anchor`
#   - curl / QCNL / DCAP C clients verify against the OpenSSL CA bundle
# A self-signed leaf is NOT acceptable: rustls rejects self-signed
# end-entity certs (CaUsedAsEndEntity) and any chain whose issuer is not a
# trusted anchor (UnknownIssuer).
# If --deploy-pccs is set, the local PCCS server is deployed (or repaired):
# suse-sgx-dcap-pccs package, pccs.service, CA + leaf chain, trust anchors.
collateral_via_pccs() {
    [[ -n "$PCCS_URL" ]] || die "PCCS mode requires a PCCS endpoint (--pccs-url)"
    log "Collateral source: local PCCS (${PCCS_URL})"
    if [[ "${DEPLOY_PCCS:-no}" == "yes" ]]; then
        # Deploy/repair first: it generates the CA + leaf and anchors the CA,
        # so it must run before any other CA handling.
        deploy_pccs_server
    else
        ensure_pccs_root_ca
    fi
}

# Decide which root CA an EXISTING (not deployed-by-us) PCCS uses and trust
# it: --pccs-ca file, a previously installed $PCCS_ROOT_CA, or a fetch from
# Intel PCS via --pccs-id. Plain HTTP endpoints need no CA.
ensure_pccs_root_ca() {
    # Plain HTTP does not require a TLS root CA
    if [[ "$PCCS_URL" =~ ^http:// ]]; then
        log "PCCS endpoint uses plain HTTP (${PCCS_URL}); TLS root CA not required"
        return 0
    fi

    # If custom CA specified via --pccs-ca, install it
    if [[ -n "$PCCS_CA" ]]; then
        [[ -s "$PCCS_CA" ]] || die "PCCS CA file specified by --pccs-ca does not exist or is empty: ${PCCS_CA}"
        log "Installing custom PCCS root CA from: ${PCCS_CA}"
        mkdir -p "$(dirname "$PCCS_ROOT_CA")"
        cp "$PCCS_CA" "$PCCS_ROOT_CA"
        chmod 644 "$PCCS_ROOT_CA"
        ensure_ca_trusted "$PCCS_ROOT_CA"
        return 0
    fi

    if [[ -s "$PCCS_ROOT_CA" ]]; then
        log "PCCS root CA already installed: ${PCCS_ROOT_CA}"
        ensure_ca_trusted "$PCCS_ROOT_CA"   # idempotent; covers missing anchors
        return 0
    fi

    # If PCCS_ID is given, try fetching the PCCS root CA from Intel PCS.
    if [[ -n "$PCCS_ID" ]]; then
        log "Fetching PCCS root CA (pccs_id=${PCCS_ID})..."
        local tmp
        tmp=$(mktemp)
        if curl -fsSL --max-time 15 "${PCS_URL%/}/pccs/${PCCS_ID}/pccsroot" -o "$tmp" 2>/dev/null; then
            mkdir -p "$(dirname "$PCCS_ROOT_CA")"
            if grep -q 'BEGIN CERTIFICATE' "$tmp"; then
                cp "$tmp" "$PCCS_ROOT_CA"
            else
                openssl x509 -inform DER -in "$tmp" -out "$PCCS_ROOT_CA"
            fi
            rm -f "$tmp"
            chmod 644 "$PCCS_ROOT_CA"
            ensure_ca_trusted "$PCCS_ROOT_CA"
            log "PCCS root CA installed and trusted: ${PCCS_ROOT_CA}"
            return 0
        fi
        rm -f "$tmp"
        warn "Could not fetch PCCS root CA via ${PCS_URL%/}/pccs/${PCCS_ID}/pccsroot."
    fi

    warn "No PCCS root CA available (no --pccs-ca, no --pccs-id, none installed)."
    warn "If the PCCS uses a private/self-signed CA, CoCo-AS will reject its"
    warn "TLS chain (UnknownIssuer). Supply the CA with --pccs-ca <file>, or"
    warn "use --deploy-pccs to generate and anchor one automatically."
}

# Anchor a CA into every trust store on this system. CoCo-AS (rustls via
# rustls-platform-verifier) reads the p11-kit "System Trust" token; curl,
# QCNL and the DCAP C libraries verify against the OpenSSL CA bundle. Both
# must contain the CA or one side of the attestation flow fails.
# Idempotent: re-anchoring the same certificate creates no duplicates.
ensure_ca_trusted() {
    local ca_file="$1"
    [[ -s "$ca_file" ]] || die "CA file not found or empty: $ca_file"
    local cn
    cn=$(openssl x509 -in "$ca_file" -noout -subject -nameopt sep_multiline 2>/dev/null \
         | sed -n 's/^ *CN *= *//p' | head -1)
    cn="${cn:-pccs-root-ca}"

    # 1. p11-kit system trust store (CoCo-AS / rustls).
    #    On SUSE, `trust anchor` writes a .p11-kit object into /etc/pki/trust/.
    if command -v trust >/dev/null 2>&1; then
        local trust_out
        trust_out=$(trust list 2>/dev/null || true)
        # NOTE: capture first — `trust list | grep -q` is unreliable under
        # pipefail (grep -q exits early, producer gets SIGPIPE, pipeline fails).
        if grep -q "label: ${cn}" <<<"$trust_out"; then
            log "Root CA already anchored in p11-kit store (label: ${cn})"
        else
            log "Anchoring root CA into p11-kit store (trust anchor) ..."
            run trust anchor "$ca_file" \
                || warn "trust anchor failed — CoCo-AS may reject the PCCS TLS chain"
        fi
    else
        warn "p11-kit 'trust' tool not found; cannot anchor CA for rustls/CoCo-AS"
    fi

    # 2. Distro anchor directory + refresh (update-ca-trust-based distros;
    #    SLES 16.1 ships p11-kit-tools only, where the refresh is a no-op).
    local anchor_dir="/etc/pki/ca-trust/source/anchors"
    if [[ -d "$anchor_dir" ]]; then
        local name
        name=$(echo "$cn" | tr ' ' '_' | tr '[:upper:]' '[:lower:]')
        install -m 0644 "$ca_file" "${anchor_dir}/${name}.pem"
        distro_ca_trust_refresh || warn "trust store refresh failed (continuing)"
    fi

    # 3. OpenSSL CA bundle (curl, QCNL, DCAP C clients). No tool regenerates
    #    this file on SLES 16.1, so append the certificate directly.
    local bundle="/etc/pki/tls/certs/ca-bundle.crt"
    if [[ -f "$bundle" ]]; then
        local marker
        marker=$(awk '/BEGIN CERT/{f=1;next}/END CERT/{f=0}f' "$ca_file" | head -1)
        if grep -qF "$marker" "$bundle"; then
            log "Root CA already in OpenSSL bundle"
        else
            log "Appending root CA to OpenSSL bundle ($bundle) ..."
            cat "$ca_file" >> "$bundle"
        fi
    fi
}

# Ensure the local PCCS has a proper CA + leaf certificate chain:
#   - root CA:  /var/lib/pccs/pccs-ca.pem  (CA:TRUE, keyCertSign+cRLSign)
#   - leaf:     /var/lib/pccs/file.crt     (CA:FALSE, SAN 127.0.0.1, serverAuth)
# The PCCS server reads the leaf from the HTTPS_file_crt / HTTPS_private_pem
# config keys (/var/lib/pccs/file.crt + private.pem). The CA private key is
# kept at /var/lib/pccs/pccs-ca.key so the leaf can be re-signed later.
# Idempotent: an existing leaf that already chains to the existing CA is kept.
ensure_pccs_cert_chain() {
    # --- Root CA -----------------------------------------------------------
    if [[ -f "$PCCS_SERVER_CA" && -f "$PCCS_SERVER_CA_KEY" ]] \
        && openssl x509 -in "$PCCS_SERVER_CA" -noout >/dev/null 2>&1 \
        && openssl rsa -in "$PCCS_SERVER_CA_KEY" -noout -check >/dev/null 2>&1; then
        log "PCCS root CA already present ($PCCS_SERVER_CA)"
    else
        log "Generating local PCCS root CA ($PCCS_SERVER_CA) ..."
        openssl genrsa -out "$PCCS_SERVER_CA_KEY" 2048 2>/dev/null
        openssl req -x509 -new -key "$PCCS_SERVER_CA_KEY" -sha256 -days 3650 \
            -subj "/C=US/O=coco_tdx/CN=Local PCCS Root CA" \
            -addext "basicConstraints=critical,CA:TRUE" \
            -addext "keyUsage=critical,keyCertSign,cRLSign" \
            -out "$PCCS_SERVER_CA" 2>/dev/null
    fi

    # --- Server leaf (regenerate only if it does not chain to the CA) ------
    if [[ -f "$PCCS_SERVER_CERT" && -f "$PCCS_SERVER_KEY" ]] \
        && openssl verify -CAfile "$PCCS_SERVER_CA" "$PCCS_SERVER_CERT" >/dev/null 2>&1; then
        log "PCCS server certificate already chains to the local CA"
    else
        log "Generating PCCS server certificate (leaf signed by local CA) ..."
        if [[ ! -f "$PCCS_SERVER_KEY" ]] \
            || ! openssl rsa -in "$PCCS_SERVER_KEY" -noout -check >/dev/null 2>&1; then
            openssl genrsa -out "$PCCS_SERVER_KEY" 2048 2>/dev/null
        fi
        local csr="${PCCS_SERVER_CERT}.csr" ext
        openssl req -new -key "$PCCS_SERVER_KEY" -subj "/CN=127.0.0.1" -out "$csr" 2>/dev/null
        ext=$(mktemp)
        cat > "$ext" <<'EOF'
subjectAltName=DNS:127.0.0.1,IP:127.0.0.1
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EOF
        openssl x509 -req -in "$csr" -CA "$PCCS_SERVER_CA" -CAkey "$PCCS_SERVER_CA_KEY" \
            -CAcreateserial -days 3650 -sha256 -extfile "$ext" \
            -out "$PCCS_SERVER_CERT" 2>/dev/null
        rm -f "$ext" "$csr"
    fi

    chown -R pccs:pccs "$PCCS_SERVER_DIR" 2>/dev/null || true
    chmod 600 "$PCCS_SERVER_CA_KEY" "$PCCS_SERVER_KEY"
    chmod 644 "$PCCS_SERVER_CA" "$PCCS_SERVER_CERT"
}

# Verify the PCCS TLS chain end-to-end: live handshake + verification against
# the local CA. This is the check that catches the "leaf not signed by the
# anchored CA" failure mode (UnknownIssuer in the CoCo-AS logs).
verify_pccs_tls() {
    local port=8081
    if [[ -f "$PCCS_CONFIG_FILE" ]]; then
        port=$(sed -n 's/.*"HTTPS_PORT"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' \
               "$PCCS_CONFIG_FILE" | head -1)
    fi
    port="${port:-8081}"
    local out
    if ! out=$(echo | openssl s_client -connect "127.0.0.1:${port}" \
               -CAfile "$PCCS_SERVER_CA" 2>/dev/null); then
        warn "TLS handshake with PCCS on 127.0.0.1:${port} failed (service not up?)"
        return 1
    fi
    if grep -q "Verify return code: 0 (ok)" <<<"$out"; then
        log "PCCS TLS chain verified: leaf (SAN 127.0.0.1) -> local CA, code 0 (ok)"
        return 0
    fi
    error "PCCS TLS verification FAILED — CoCo-AS will reject the chain:"
    grep -E "Verify return code|verify error" <<<"$out" | head -3
    error "Fix: re-run with --deploy-pccs (regenerates CA + leaf and re-anchors)."
    return 1
}

# Deploy (or repair) a local PCCS server for air-gapped / offline attestation.
# The suse-sgx-dcap-pccs package ships a self-signed leaf that is NOT usable
# as-is: rustls requires a proper leaf (CA:FALSE + SAN) signed by a root CA
# anchored in the p11-kit system trust store. This function:
#   1. installs the package (if missing)
#   2. ensures the config exists (upstream.json -> default.json)
#   3. generates/repairs the CA + leaf chain (idempotent)
#   4. anchors the CA in p11-kit + the OpenSSL bundle
#   5. (re)starts pccs and, if present, grpc-as — rustls loads the native
#      trust store at process start, so an anchor added later is invisible
#      to a running CoCo-AS until it is restarted
#   6. verifies the live TLS chain
# Safe to re-run: a healthy deployment is left untouched apart from a service
# restart; a broken one (e.g. self-signed leaf) is repaired in place.
deploy_pccs_server() {
    log "Deploying local PCCS server ..."

    # 1. Package.
    if ! rpm -q suse-sgx-dcap-pccs >/dev/null 2>&1; then
        log "Installing suse-sgx-dcap-pccs package..."
        zypper in -y suse-sgx-dcap-pccs || die "Failed to install suse-sgx-dcap-pccs"
    fi

    # 2. Config (template -> active). The packaged default uses the sqlite
    #    cache at /var/lib/pccs/pckcache.db, the Intel PCS upstream, lazy
    #    fill and a daily refresh schedule.
    if [[ ! -f "$PCCS_CONFIG_FILE" && -f /usr/libexec/suse-sgx-dcap-pccs/config/upstream.json ]]; then
        log "Copying PCCS config template: upstream.json -> default.json"
        cp /usr/libexec/suse-sgx-dcap-pccs/config/upstream.json "$PCCS_CONFIG_FILE"
    fi

    # 3. MariaDB (soft dependency: the unit is After=mariadb.service and the
    #    mysql config option needs it; the packaged default uses sqlite).
    if ! systemctl is-active --quiet mariadb.service 2>/dev/null; then
        log "Starting MariaDB (PCCS dependency)..."
        systemctl enable --now mariadb.service || warn "MariaDB failed to start; PCCS may not work with the mysql config"
    fi

    # 4. Certificate chain (CA + leaf).
    ensure_pccs_cert_chain

    # 5. Trust anchors (p11-kit for rustls/CoCo-AS, OpenSSL bundle for the rest).
    ensure_ca_trusted "$PCCS_SERVER_CA"

    # 6. (Re)start the service so it picks up the leaf, then CoCo-AS so it
    #    re-reads the native trust store.
    log "Starting PCCS server (pccs.service) ..."
    systemctl enable --now pccs.service || die "Failed to start pccs.service (unit is pccs.service, not pccs-server.service)"
    local units
    units=$(systemctl list-unit-files 2>/dev/null || true)
    if grep -q '^grpc-as\.service' <<<"$units"; then
        log "Restarting grpc-as (rustls caches the trust store at startup) ..."
        systemctl restart grpc-as.service || warn "grpc-as restart failed"
    fi

    # 7. End-to-end TLS verification (retry: the service needs a moment).
    local ok=0
    for _ in 1 2 3 4 5; do
        if verify_pccs_tls; then ok=1; break; fi
        sleep 2
    done
    ((ok)) || die "PCCS is running but its TLS chain does not verify — see messages above"

    log "Local PCCS ready at https://127.0.0.1:8081 (CA: $PCCS_SERVER_CA)"
    log "Note: with CachingFillMode=LAZY the PCCS fetches missing collateral"
    log "from Intel PCS on first request — warm the cache while online"
    log "(e.g. ./pccs-check.sh tcb --tdx --pccs-url $PCCS_URL) before going offline."
}

# Select the collateral source (method 1 = PCS, method 2 = PCCS) and prepare
# whatever it needs (root CA for PCCS). Called before writing QCNL/CoCo-AS
# configs so they always point at a usable endpoint.
setup_collateral_source() {
    case "$COLLATERAL_MODE" in
    pcs) collateral_via_pcs ;;
    pccs) collateral_via_pccs ;;
    *) die "Invalid --collateral '${COLLATERAL_MODE}' (must be 'pcs' or 'pccs')" ;;
    esac
}

# Write QCNL config to /run/dcap/qcnl.conf (and optionally /etc/dcap/).
# The pccs_url field points at whichever collateral source is selected (global
# PCS or local PCCS cache); the field name is DCAP's, even when it points at
# the global PCS.
# Effective use_secure_cert value for a QCNL config pointing at <url>:
# explicit --insecure wins; in 'auto' mode plain-HTTP endpoints disable it.
qcnl_secure_cert() {
    local url="$1"
    if [[ "$USE_SECURE_CERT" == "false" || ("$USE_SECURE_CERT" == "auto" && "$url" =~ ^http://) ]]; then
        echo "false"
    else
        echo "true"
    fi
}

write_qcnl_conf() {
    local target="${1:-$QCNL_RUN_CONF}"
    local url
    url=$(collateral_url)
    local secure
    secure=$(qcnl_secure_cert "$url")
    log "Writing QCNL config to ${target} (collateral=${COLLATERAL_MODE}, pccs_url=${url}, use_secure_cert=${secure})"
    mkdir -p "$(dirname "$target")"
    cat >"$target" <<EOF
{
  "pccs_url": "${url}",
  "collateral_service": "${url}",
  "use_secure_cert": ${secure},
  "retry_times": 6,
  "retry_delay": 10,
  "pck_cache_expire_hours": 168,
  "verify_collateral_cache_expire_hours": 168,
  "local_cache_only": false,
  "tcb_update_type": "early"
}
EOF
    chmod 644 "$target"
}

cmd_setup_host() {
    require_root
    require_cmd "$(distro_pkg_manager)"
    log "=== Setting up TDX host (DCAP stack) ==="
    step "Install DCAP stack, verify host TDX, write QCNL config, start libvirt" \
        "Enables the host to fetch PCK collateral from the selected source (PCS or PCCS); confirms the TDX module is initialized on the host (tdx_guest/dev nodes are guest-side, not on the host)."

    log "Checking DCAP attestation stack (QPL + quote provider + verify lib)"
    # shellcheck disable=SC2046  # deliberate word-splitting of the package list
    install_pkgs $(distro_pkgs dcap_host)

    # NOTE: do NOT modprobe tdx_guest here — that module is guest-only and
    # exists inside a TD. On the host, TDX comes from kvm_intel + the SEAM/TDX
    # module initialized at boot.
    log "Verifying host TDX (initialized TDX module; kvm_intel.tdx is MANDATORY)"
    local tdx_param tdx_count
    tdx_param=$(cat /sys/module/kvm_intel/parameters/tdx 2>/dev/null || echo "N")
    tdx_count=$(dmesg 2>/dev/null | grep -ci 'TDX-Module initialized' || true)
    if [[ "${tdx_count:-0}" -gt 0 ]]; then
        log "Host TDX module initialized (per dmesg)"
    elif [[ "$tdx_param" == "Y" ]]; then
        log "KVM TDX enabled (kvm_intel.tdx=Y)"
    else
        warn "Could not confirm host TDX (kvm_intel.tdx=${tdx_param}, no 'TDX-Module initialized' in dmesg)."
        warn "kvm_intel.tdx is MANDATORY in the kernel command line, otherwise QEMU/libvirt refuse TDX."
        warn "Add it via GRUB_CMDLINE_LINUX, regenerate the GRUB config, and reboot. Check BIOS TDX + SEAM loader: dmesg | grep -i tdx"
    fi

    # Always (re)write the config so the selected collateral source (PCS or
    # PCCS) is what QGS/DCAP actually use, not a stale package default.
    setup_collateral_source
    log "Writing QCNL config from the selected collateral source"
    mkdir -p /run/dcap
    write_qcnl_conf "$QCNL_RUN_CONF"

    log "Verifying installed DCAP packages"
    run distro_pkg_list_all | grep -Ei 'dcap|sgx|tdx|qpl' || warn "No DCAP packages matched"

    log "Ensuring libvirt is running (needed later by setup-vm)"
    if command -v virsh >/dev/null 2>&1; then
        ensure_libvirt
    else
        warn "virsh not installed; skipping libvirt check."
    fi

    log "Ensuring grpcurl is available for remote attestation"
    ensure_grpcurl || warn "grpcurl installation deferred"

    log "Host setup complete."
}

cmd_setup_qgs() {
    require_root
    require_cmd "$(distro_pkg_manager)" systemctl
    log "=== Setting up QGS (TD Quoting Generation Service) ==="
    step "Install + persist + start QGS (qgsd.service)" \
        "QGS turns a guest TD Report into a signed Quote over vsock; runs on the host."

    local qgs_bin
    qgs_bin=$(distro_qgs_bin)
    log "Checking $(distro_pkgs qgs)"
    # shellcheck disable=SC2046  # deliberate word-splitting of the package list
    install_pkgs $(distro_pkgs qgs)

    if [[ ! -f "$qgs_bin" ]]; then
        die "QGS binary ${qgs_bin} not found after install"
    fi
    log "QGS binary present: ${qgs_bin}"

    # QGS must run in unix-socket mode (not TCP). The default SUSE unit uses
    # QGSD_ARGS="--no-daemon -p=4050 -n=4" which makes QGS listen on TCP 4050,
    # but QEMU's tdx-guest object connects to a unix socket. Override the unit
    # to drop the -p flag so QGS uses /run/tdx-qgs/qgs.socket.
    log "Configuring QGS for unix-socket mode (overriding TCP port)"
    mkdir -p /etc/systemd/system/qgsd.service.d
    cat >/etc/systemd/system/qgsd.service.d/override.conf <<'EOF'
[Service]
Environment=QGSD_ARGS="--no-daemon -n=4"
EOF
    run systemctl daemon-reload

    # Remove stale symlink left by previous QGS versions (qgs.socket -> qgs).
    # QGS in socket mode creates qgs.socket directly; a symlink to a
    # non-existent 'qgs' file blocks socket creation.
    if [[ -L "${QGS_SOCKET}" ]]; then
        log "Removing stale symlink ${QGS_SOCKET}"
        rm -f "${QGS_SOCKET}"
    fi

    # QEMU runs as user 'qemu' and must be able to connect to the QGS socket
    # (owned by qgsd:qgsd, mode 640). Add qemu to the qgsd group.
    if id qgsd >/dev/null 2>&1; then
        if id qemu >/dev/null 2>&1; then
            if ! id -nG qemu | tr ' ' '\n' | grep -qx qgsd; then
                log "Adding qemu user to qgsd group (socket access)"
                run usermod -aG qgsd qemu
            fi
        else
            warn "qemu user not found; skipping group addition"
        fi
    fi

    setup_collateral_source
    log "Writing QCNL config (QGS reads /etc/sgx_default_qcnl.conf)"
    write_qcnl_conf "$QCNL_PKG_CONF"
    # Also write to /run/dcap and /etc/dcap for other DCAP consumers
    mkdir -p /run/dcap /etc/dcap
    run cp "$QCNL_PKG_CONF" "$QCNL_RUN_CONF"
    run cp "$QCNL_PKG_CONF" "$QCNL_ETC_CONF"

    if id qgsd >/dev/null 2>&1 && getent group sgx_prv >/dev/null 2>&1; then
        run chown -R qgsd:sgx_prv /run/dcap
        run chown qgsd:sgx_prv "$QCNL_PKG_CONF" "$QCNL_ETC_CONF" "$QCNL_RUN_CONF"
        run chmod 644 "$QCNL_PKG_CONF" "$QCNL_ETC_CONF" "$QCNL_RUN_CONF"
    else
        warn "qgsd user or sgx_prv group missing; skipping ownership change"
    fi
    run chmod 750 /run/dcap

    log "Creating tmpfiles rule for /run/dcap"
    if id qgsd >/dev/null 2>&1 && getent group sgx_prv >/dev/null 2>&1; then
        cat >/etc/tmpfiles.d/dcap.conf <<'EOF'
d /run/dcap 0750 qgsd sgx_prv -
EOF
        run systemd-tmpfiles --create
    else
        warn "qgsd user or sgx_prv group missing; skipping tmpfiles rule for /run/dcap"
    fi

    log "Creating qgsd-setup.service (restore QCNL config at boot)"
    cat >/etc/systemd/system/qgsd-setup.service <<'EOF'
[Unit]
Description=Setup QGS QCNL configuration
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/usr/bin/cp /etc/sgx_default_qcnl.conf /run/dcap/qcnl.conf
ExecStart=/usr/bin/chown qgsd:sgx_prv /run/dcap/qcnl.conf
ExecStart=/usr/bin/chmod 640 /run/dcap/qcnl.conf

[Install]
WantedBy=multi-user.target
EOF
    run systemctl daemon-reload
    run systemctl enable --now qgsd-setup.service || warn "qgsd-setup.service failed to start (qgsd/sgx_prv missing?); restore /run/dcap/qcnl.conf manually at boot"

    log "Enabling and starting qgsd.service"
    run systemctl enable --now qgsd.service

    if [[ "$(systemctl is-active qgsd.service)" == "active" ]]; then
        log "QGS service is running"
    else
        error "QGS service failed to start. Last log lines:"
        journalctl -u qgsd.service -n 20 --no-pager || true
        die "qgsd.service not active"
    fi

    log "QGS setup complete."
}

cmd_setup_trustee() {
    require_root
    require_cmd "$(distro_pkg_manager)" systemctl
    log "=== Setting up Trustee (attestation + secret delivery) ==="
    step "Install + configure + start CoCo-AS, KBS, RVPS (trustee)" \
        "CoCo-AS verifies Quotes and issues an EAR token; KBS gates secret delivery behind attestation; RVPS holds reference values. Generates a KBS admin key so 'secret-set' can push secrets."

    log "Checking trustee + DCAP verification libraries"
    # shellcheck disable=SC2046  # deliberate word-splitting of the package list
    install_pkgs $(distro_pkgs trustee)

    # Some distros (SUSE) install the trustee binaries under
    # /usr/libexec/trustee/ but the systemd units reference /usr/libexec/<name>.
    # Create symlinks so the units work (see <id>_trustee_needs_symlinks).
    if [[ "$(distro_trustee_needs_symlinks)" == "1" ]]; then
        log "Linking trustee binaries to /usr/libexec/ (service units expect them there)"
        local bin
        local trustee_dir
        trustee_dir=$(dirname "$(distro_kbs_client_bin)")
        for bin in grpc-as kbs rvps trustee; do
            local src="${trustee_dir}/${bin}"
            local dst="/usr/libexec/${bin}"
            if [[ -f "$src" && ! -e "$dst" ]]; then
                run ln -sf "$src" "$dst"
                log "  ${dst} -> ${src}"
            elif [[ -f "$dst" ]]; then
                log "  ${dst} already present"
            else
                warn "Binary not found: ${src} (and no ${dst})"
            fi
        done
    fi

    log "Checking grpc-as dynamic library dependencies"
    local grpc_as_bin
    grpc_as_bin=$(distro_grpc_as_bin)
    if [[ -f "$grpc_as_bin" ]]; then
        local missing
        missing=$(ldd "$grpc_as_bin" 2>/dev/null | grep 'not found' || true)
        if [[ -n "$missing" ]]; then
            error "Missing libraries for grpc-as:"
            echo "$missing" >&2
            die "Install missing DCAP libraries and retry"
        fi
    fi

    setup_collateral_source
    local as_collateral
    as_collateral=$(collateral_url)
    log "Writing CoCo-AS config: $GRPC_AS_CONF"
    mkdir -p "$AS_STORAGE_DIR"
    if id coco_as >/dev/null 2>&1; then
        run chown coco_as:coco_as "$AS_STORAGE_DIR"
    fi
    # Persistent signer so grpc-as serves a stable JWKS endpoint for KBS.
    ensure_as_signer_key
    cat >"$GRPC_AS_CONF" <<EOF
{
  "storage_backend": {
    "storage_type": "LocalFs",
    "backends": {
      "local_fs": {
        "dir_path": "${AS_STORAGE_DIR}"
      }
    }
  },
  "rvps_config": {
    "type": "BuiltIn"
  },
  "attestation_token_broker": {
    "duration_min": 5,
    "issuer_name": "CoCo-Attestation-Service",
    "verbose_token": true,
    "signer": {
      "key_path": "${AS_SIGNER_KEY}",
      "cert_path": "${AS_SIGNER_CERT}"
    }
  },
  "verifier_config": {
    "dcap_verifier": {
      "collateral_service": "${as_collateral}",
      "use_secure_cert": true,
      "tcb_update_type": "early"
    }
  }
}
EOF
    if id coco_as >/dev/null 2>&1; then
        run chown coco_as:coco_as "$GRPC_AS_CONF"
    fi
    run chmod 600 "$GRPC_AS_CONF"

    # Admin keypair + resource policy: required for KBS to accept secrets and to
    # gate their release on attestation.
    ensure_kbs_admin_key
    write_resource_policy

    log "Writing KBS config: $KBS_CONF"
    # SECURITY NOTE: the following settings are LAB/development defaults ONLY.
    #   - insecure_http = true        : no TLS on the KBS HTTP listener
    #   - authorization_mode = InsecureAllowAll : ANY client that passes
    #     attestation can read ANY resource — no per-resource auth checks.
    #     In production, replace with AuthenticatedAuthorization + bearer_jwt
    #     and tighten the resource policy (write_resource_policy).
    #   - insecure_http + InsecureAllowAll together mean: anyone who can
    #     reach the KBS port (0.0.0.0) and pass a valid EAR token can
    #     read every secret. Never expose this port to untrusted networks.
    # For production: provide TLS certs (insecure_http=false), use
    # AuthenticatedAuthorization, and write a restrictive rego policy.
    # SUSE kbs.service expects /etc/kbs.json (ConditionPathExists + --config-file).
    # trusted_jwk_sets must be file:// or https:// (http:// is rejected). We fetch
    # the CoCo-AS JWKS to a local file after grpc-as starts (see below).
    cat >"$KBS_CONF" <<EOF
{
  "http_server": {
    "sockets": ["0.0.0.0:${KBS_PORT}"],
    "insecure_http": true
  },
  "admin": {
    "authorization_mode": "InsecureAllowAll"
  },
  "attestation_token": {
    "trusted_jwk_sets": ["file://${KBS_JWKS_FILE}"],
    "trusted_certs_paths": ["${AS_SIGNER_CERT}"]
  },
  "attestation_service": {
    "type": "coco_as_grpc",
    "as_addr": "http://${COCO_AS}"
  },
  "policy_engine": {
    "policy_path": "${KBS_POLICY}"
  },
  "storage_backend": {
    "storage_type": "LocalFs",
    "backends": {
      "local_fs": {
        "dir_path": "${AS_STORAGE_DIR}/kbs"
      }
    }
  },
  "plugins": [
    {
      "name": "resource",
      "storage_backend_type": "kvstorage"
    }
  ]
}
EOF
    if id coco_kbs >/dev/null 2>&1; then
        run chown coco_kbs:coco_kbs "$KBS_CONF"
        run chown coco_kbs:coco_kbs "$KBS_ADMIN_PUB" "$KBS_POLICY" 2>/dev/null || true
    fi
    run chmod 600 "$KBS_CONF"
    mkdir -p "${AS_STORAGE_DIR}/kbs" "${AS_STORAGE_DIR}/rvps"
    if id coco_kbs >/dev/null 2>&1; then
        run chown coco_kbs:coco_kbs "${AS_STORAGE_DIR}/kbs"
    fi
    if id coco_rvps >/dev/null 2>&1; then
        run chown coco_rvps:coco_rvps "${AS_STORAGE_DIR}/rvps"
    fi

    log "Writing RVPS config: $RVPS_CONF"
    cat >"$RVPS_CONF" <<EOF
{
  "storage_type": "LocalFs",
  "storage_dir": "${AS_STORAGE_DIR}/rvps"
}
EOF
    if id coco_rvps >/dev/null 2>&1; then
        run chown coco_rvps:coco_rvps "$RVPS_CONF"
    fi
    run chmod 600 "$RVPS_CONF"

    log "Starting Trustee services"
    # SUSE kbs.service ExecStart omits --config-file; override it to point at
    # /etc/kbs.json (the unit's ConditionPathExists already checks this file).
    mkdir -p /etc/systemd/system/kbs.service.d
    cat >/etc/systemd/system/kbs.service.d/override.conf <<EOF
[Service]
ExecStart=
ExecStart=$(distro_kbs_bin) --config-file /etc/kbs.json
EOF
    # SUSE grpc-as.service sets GRPC_AS_OPTIONS="--config ..." but ExecStart does
    # not expand it, and the CLI flag is --config-file (not --config). So grpc-as
    # runs with no config file -> default config -> ephemeral signer -> no JWKS
    # endpoint. Override ExecStart to pass the config explicitly.
    mkdir -p /etc/systemd/system/grpc-as.service.d
    cat >/etc/systemd/system/grpc-as.service.d/override.conf <<EOF
[Service]
ExecStart=
ExecStart=$(distro_grpc_as_bin) --config-file /etc/grpc-as.json
Environment=QCNL_CONF_PATH=/etc/sgx_default_qcnl.conf
EOF
    if [[ -n "${https_proxy:-${HTTPS_PROXY:-}}" ]]; then
        cat >>/etc/systemd/system/grpc-as.service.d/override.conf <<EOF
Environment="HTTPS_PROXY=${https_proxy:-$HTTPS_PROXY}"
Environment="https_proxy=${https_proxy:-$HTTPS_PROXY}"
EOF
    fi

    if id coco_as >/dev/null 2>&1; then
        run mkdir -p /var/lib/coco_as
        run chown -R coco_as:coco_as /var/lib/coco_as
        if getent group sgx_prv >/dev/null 2>&1; then
            run usermod -aG sgx_prv coco_as 2>/dev/null || true
        fi
        if getent group sgx >/dev/null 2>&1; then
            run usermod -aG sgx coco_as 2>/dev/null || true
        fi
    fi
    run chmod 644 "$QCNL_PKG_CONF" "$QCNL_ETC_CONF" 2>/dev/null || true
    run systemctl daemon-reload

    # Start services in dependency order. KBS needs the CoCo-AS JWKS file to
    # exist before it starts (KBS loads trusted_jwk_sets at startup), so start
    # rvps + grpc-as first, fetch the JWKS, then start kbs + trustee.
    # grpc-as is restarted (not just started) so it picks up the new ExecStart
    # override and signer config; a stale process would keep the old config.
    local svc
    if systemctl cat rvps.service >/dev/null 2>&1; then
        run systemctl enable --now rvps.service
    else
        warn "Service unit not found, skipping: rvps.service"
    fi
    if systemctl cat grpc-as.service >/dev/null 2>&1; then
        run systemctl enable --now grpc-as.service
        run systemctl restart grpc-as.service
    else
        warn "Service unit not found, skipping: grpc-as.service"
    fi

    # Wait for grpc-as to actually listen (KBS connects to it for attestation).
    log "Waiting for CoCo-AS to listen on ${COCO_AS}"
    if ! wait_for_port 127.0.0.1 "${COCO_AS##*:}" 30; then
        warn "CoCo-AS not listening on ${COCO_AS} after 30s; KBS attestation will fail"
    fi

    # The JWKS was already derived from the signer public key in
    # ensure_as_signer_key() (this grpc-as build does not serve the
    # /.well-known/jwks.json endpoint). Verify it is in place before KBS starts.
    if [[ ! -s "$KBS_JWKS_FILE" ]]; then
        warn "JWKS file missing or empty: ${KBS_JWKS_FILE}. KBS token verification will fail."
    else
        log "JWKS in place at ${KBS_JWKS_FILE}"
    fi

    # Now start kbs (KBS needs the JWKS file to exist).
    # trustee.service is intentionally NOT started: it is the SUSE unified
    # tenant-side binary, redundant with grpc-as+kbs+rvps, and its unit is
    # broken (ConditionPathExists=/etc/trustee.json never satisfied, ExecStart
    # lacks the required 'run' subcommand). Disable it so it stops logging
    # "skipped, unmet condition" at every boot.
    if systemctl cat kbs.service >/dev/null 2>&1; then
        run systemctl enable --now kbs.service
    else
        warn "Service unit not found, skipping: kbs.service"
    fi
    if systemctl cat trustee.service >/dev/null 2>&1; then
        run systemctl disable trustee.service 2>/dev/null || true
    fi

    log "Verifying Trustee stack"
    for svc in grpc-as.service kbs.service rvps.service; do
        local state
        state=$(systemctl is-active "$svc" 2>/dev/null || true)
        state="${state:-unknown}"
        log "  ${svc}: ${state}"
    done
    ss -tln 2>/dev/null | grep -E "[:.](${COCO_AS##*:}|${KBS_PORT})\b" || warn "Expected ports not listening yet"

    # Push the resource policy into the running KBS so secret release is governed.
    # Admin mode is InsecureAllowAll (LAB), so no auth token is needed;
    # kbs-client sends unauthenticated admin requests.
    local kbs_client_bin
    kbs_client_bin="$(resolve_kbs_client_bin)"
    if [[ -x "$kbs_client_bin" ]]; then
        log "Waiting for KBS to listen on ${KBS_PORT}"
        if wait_for_port 127.0.0.1 "${KBS_PORT}" 30; then
            log "Uploading resource policy to KBS"
            # Local upload: this runs on the host itself, so use 127.0.0.1
            # (kbs_url() resolves to the libvirt NAT gateway IP, reachable
            # only from guests, not from the host).
            run "$kbs_client_bin" --url "http://127.0.0.1:${KBS_PORT}" config \
                set-resource-policy --policy-file "$KBS_POLICY" ||
                warn "Policy upload failed; set it later with kbs-client set-resource-policy"
        else
            warn "KBS not listening after 30s; upload policy later (see 'secret-set')"
        fi
    else
        warn "kbs-client not found (looked in \$PATH and ${kbs_client_bin}); install it to push policy/secrets"
    fi

    ensure_attestation_proto
    if [[ -d /etc/trustee && -w /etc/trustee ]]; then
        cp "${PROTO_DIR}/attestation.proto" /etc/trustee/attestation.proto 2>/dev/null || true
        cp "${PROTO_DIR}/reference.proto" /etc/trustee/reference.proto 2>/dev/null || true
    fi

    log "Trustee setup complete. Store a secret with: ${SCRIPT_NAME} secret-set --file <f>"
}

# Ensure the KBS service user (coco_kbs) can traverse TRUSTEE_DIR to read the
# admin public key and policy. The private key stays root-only (0600).
prepare_trustee_dir() {
    mkdir -p "$TRUSTEE_DIR"
    if getent group coco_kbs >/dev/null 2>&1; then
        run chown root:coco_kbs "$TRUSTEE_DIR"
        run chmod 750 "$TRUSTEE_DIR"
    else
        # coco_kbs group absent: fall back to world-traversable (lab only).
        run chmod 755 "$TRUSTEE_DIR"
    fi
}

# Generate the KBS admin keypair (used by kbs-client to push policy + secrets).
ensure_kbs_admin_key() {
    prepare_trustee_dir
    if [[ -f "$KBS_ADMIN_KEY" && -f "$KBS_ADMIN_PUB" ]]; then
        log "KBS admin keypair already exists: ${KBS_ADMIN_KEY}"
        return 0
    fi
    require_cmd openssl
    log "Generating KBS admin keypair (ed25519): ${KBS_ADMIN_KEY}"
    run openssl genpkey -algorithm ed25519 -out "$KBS_ADMIN_KEY"
    run openssl pkey -in "$KBS_ADMIN_KEY" -pubout -out "$KBS_ADMIN_PUB"
    run chmod 600 "$KBS_ADMIN_KEY" # private: admin/kbs-client only, never KBS
    run chmod 644 "$KBS_ADMIN_PUB" # public: readable by coco_kbs (KBS reads it)
}

# Generate the CoCo-AS token signer key pair (persistent EC P-256) and derive
# the JWKS file KBS uses to verify attestation tokens. This grpc-as build
# (0.20.0~git60.435ed3c) does not serve the /.well-known/jwks.json endpoint
# (added in a later version), so the JWKS is derived directly from the public
# key here. Without a persistent signer, grpc-as uses an ephemeral key and
# KBS cannot verify tokens across restarts.
ensure_as_signer_key() {
    mkdir -p "$AS_SIGNER_DIR"
    if id coco_as >/dev/null 2>&1; then
        run chown coco_as:coco_as "$AS_SIGNER_DIR"
    fi
    run chmod 700 "$AS_SIGNER_DIR"
    if [[ -f "$AS_SIGNER_KEY" && -f "$AS_SIGNER_PUB" && -f "$AS_SIGNER_CERT" && -f "$KBS_JWKS_FILE" ]] &&
        [[ -s "$KBS_JWKS_FILE" ]]; then
        log "CoCo-AS signer keypair + JWKS already exist: ${AS_SIGNER_KEY}"
        return 0
    fi
    require_cmd openssl
    if [[ ! -f "$AS_SIGNER_KEY" || ! -f "$AS_SIGNER_PUB" ]]; then
        log "Generating CoCo-AS signer keypair (EC P-256): ${AS_SIGNER_KEY}"
        run openssl ecparam -name prime256v1 -genkey -noout -out "$AS_SIGNER_KEY"
        run openssl pkey -in "$AS_SIGNER_KEY" -pubout -out "$AS_SIGNER_PUB"
    fi
    run chmod 600 "$AS_SIGNER_KEY" # private: coco_as only
    run chmod 644 "$AS_SIGNER_PUB" # public: JWKS consumers
    if id coco_as >/dev/null 2>&1; then
        run chown coco_as:coco_as "$AS_SIGNER_KEY" "$AS_SIGNER_PUB"
    fi
    # Self-signed cert for the signer key. This KBS version verifies
    # header-embedded JWKs only against an x5c chain that chains to
    # attestation_token.trusted_certs_paths; without a cert, every RCAR
    # handshake fails with "neither trusted jwk set nor trusted pem public
    # key works". The cert lives in $TRUSTEE_DIR (readable by coco_kbs/KBS);
    # coco_as needs group traversal of the 750 root:coco_kbs directory.
    prepare_trustee_dir
    if [[ -f "$AS_SIGNER_CERT" ]]; then
        log "CoCo-AS signer cert already exists: ${AS_SIGNER_CERT}"
    else
        log "Generating self-signed CoCo-AS signer cert: ${AS_SIGNER_CERT}"
        run openssl req -new -x509 -key "$AS_SIGNER_KEY" \
            -subj "/CN=CoCo-AS" -days 3650 -out "$AS_SIGNER_CERT"
    fi
    run chmod 644 "$AS_SIGNER_CERT"
    if id coco_as >/dev/null 2>&1; then
        run chown coco_as:coco_as "$AS_SIGNER_CERT"
        if getent group coco_kbs >/dev/null 2>&1; then
            id -nG coco_as | tr ' ' '\n' | grep -qx coco_kbs ||
                run usermod -aG coco_kbs coco_as
        fi
    fi
    # Derive the JWKS (JWK Set) JSON from the public key for KBS token
    # verification. The JWKS holds the EC P-256 x/y coordinates (base64url).
    log "Deriving JWKS from signer public key: ${KBS_JWKS_FILE}"
    local hexstr x y
    hexstr=$(openssl pkey -pubin -in "$AS_SIGNER_PUB" -text -noout 2>/dev/null | awk '
        /^pub:/ {f=1; next}
        f {
          line=$0
          gsub(/^[ \t]+|[ \t]+$/,"",line)
          if (line ~ /^[0-9a-f:]+$/) { gsub(/:/,"",line); hex=hex line }
          else if (line != "") { exit }
        }
        END { print hex }')
    # Uncompressed point: 04 || X (32 bytes) || Y (32 bytes)
    x="${hexstr:2:64}"
    y="${hexstr:66:64}"
    if [[ ${#x} -ne 64 || ${#y} -ne 64 ]]; then
        die "Failed to parse EC public key coordinates from ${AS_SIGNER_PUB}"
    fi
    local x_b64 y_b64
    x_b64=$(echo "$x" | xxd -r -p | b64url_encode)
    y_b64=$(echo "$y" | xxd -r -p | b64url_encode)
    mkdir -p "$(dirname "$KBS_JWKS_FILE")"
    cat >"$KBS_JWKS_FILE" <<EOF
{
  "keys": [
    {
      "kty": "EC",
      "crv": "P-256",
      "alg": "ES256",
      "x": "${x_b64}",
      "y": "${y_b64}"
    }
  ]
}
EOF
    if id coco_kbs >/dev/null 2>&1; then
        run chown coco_kbs:coco_kbs "$KBS_JWKS_FILE"
    fi
    run chmod 640 "$KBS_JWKS_FILE"
}

# Write a permissive resource-access policy (LAB DEFAULT: allow all).
# Tighten this to gate secrets on real TDX claims before production use.
write_resource_policy() {
    log "Writing KBS resource policy (allow-all, LAB ONLY): ${KBS_POLICY}"
    prepare_trustee_dir
    cat >"$KBS_POLICY" <<'REGO'
package policy

# LAB DEFAULT: allow any attester to read any resource once attestation
# succeeds. Replace with checks on input claims (e.g. tdx.report.mrtd)
# for real secret gating.
default allow = true
REGO
    run chmod 644 "$KBS_POLICY" # readable by coco_kbs (KBS loads it)
}
