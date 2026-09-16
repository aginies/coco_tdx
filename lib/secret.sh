# =============================================================================
# 7b. SECRET DELIVERY (KBS)
# =============================================================================
#
# Trustee delivers secrets only after a client attests successfully. The host
# admin stores a secret in the KBS (secret-set); a guest inside a TD fetches it
# (secret-get), which triggers attestation + policy evaluation transparently.

cmd_secret_set() {
    require_root
    log "=== Storing secret in KBS: ${SECRET_PATH} ==="
    step "Upload a secret to the KBS as admin" \
        "Stores the file at resource path '${SECRET_PATH}'. The KBS releases it only to clients that pass attestation + resource policy."

    # kbs-client ships in the trustee package (not in $PATH), so resolve the
    # full path via the distro adapter.
    local kbs_client_bin
    kbs_client_bin="$(command -v kbs-client 2>/dev/null || true)"
    [[ -n "$kbs_client_bin" ]] || kbs_client_bin="$(distro_kbs_client_bin)"
    [[ -x "$kbs_client_bin" ]] || die "kbs-client not found (looked in \$PATH and ${kbs_client_bin}). Install the 'trustee' package first."

    if [[ -z "$SECRET_FILE" ]]; then
        die "secret-set requires --file <path> (the secret to store)"
    fi
    if [[ ! -f "$SECRET_FILE" ]]; then
        die "Secret file not found: ${SECRET_FILE}"
    fi

    # Admin mode is InsecureAllowAll (LAB); no auth token needed.
    run "$kbs_client_bin" --url "$(kbs_url)" config \
        set-resource --path "$SECRET_PATH" --resource-file "$SECRET_FILE"

    log "Secret stored at ${SECRET_PATH}."
    log "Retrieve from inside a TD guest with:"
    log "  ${SCRIPT_NAME} secret-get --guest-ip <IP> --path ${SECRET_PATH}"
}

cmd_secret_get() {
    detect_guest_ip
    log "=== Fetching secret from KBS (with attestation): ${SECRET_PATH} ==="

    local url
    url=$(kbs_url)

    if [[ "$SECRET_MODE" == "host" ]]; then
        # Option D: host-side. Attest via grpcurl to get the EAR token, then
        # fetch the resource from the KBS REST API with the token as bearer.
        # No in-guest kbs-client or Rust build needed.
        step "Host-side: attest to CoCo-AS, then fetch resource from KBS REST" \
            "Fetches a fresh Quote over ssh, submits via grpcurl, then GETs /kbs/v0/resource/${SECRET_PATH} with the EAR token as bearer."
        require_cmd curl
        attest_get_ear_token
        log "Fetching resource from KBS: ${url}/kbs/v0/resource/${SECRET_PATH}"
        local out
        if [[ -n "$SECRET_FILE" ]]; then
            log "Saving secret to: ${SECRET_FILE}"
            # Direct curl (not via run) so the EAR token is not printed in the CMD log.
            if ! curl -fsS -H "Authorization: Bearer ${EAR_TOKEN}" \
                "${url}/kbs/v0/resource/${SECRET_PATH}" >"$SECRET_FILE"; then
                die "Secret retrieval failed. Check attestation (attest cmd) and KBS resource policy."
            fi
            log "Secret written to ${SECRET_FILE}."
        else
            log "Retrieving secret to stdout (text secrets only; use --file for binary data)"
            if out=$(curl -fsS -H "Authorization: Bearer ${EAR_TOKEN}" \
                "${url}/kbs/v0/resource/${SECRET_PATH}"); then
                echo "$out"
                log "=== SECRET DELIVERY SUCCESS: attestation passed, secret released ==="
            else
                die "Secret retrieval failed. Check attestation (attest cmd) and KBS resource policy."
            fi
        fi
        return 0
    fi

    # Option A (default): in-guest kbs-client.
    step "From inside the TD, fetch a KBS secret" \
        "Runs kbs-client on the guest: it attests to CoCo-AS via KBS, then downloads resource '${SECRET_PATH}' if policy allows."

    # kbs-client must run inside the TD guest so its evidence is a real TD quote.
    # Prefer the TDX-enabled build (setup-guest ships it to ${KBS_CLIENT_GUEST});
    # the SLE 'trustee' package kbs-client lacks the TDX attester (sample fallback).
    local kbs_bin=""
    if ssh_guest "test -x ${KBS_CLIENT_GUEST}"; then
        if kbs_client_supports_tdx_guest "$KBS_CLIENT_GUEST"; then
            kbs_bin="${KBS_CLIENT_GUEST}"
        else
            warn "${KBS_CLIENT_GUEST} exists but was built WITHOUT the tdx-attester feature."
            warn "Re-run 'setup-guest' to rebuild + reinstall the TDX-enabled client."
        fi
    fi
    if [[ -z "$kbs_bin" ]]; then
        local guest_pkg_client
        guest_pkg_client=$(guest_distro_kbs_client_bin)
        if ssh_guest "test -x ${guest_pkg_client}"; then
            kbs_bin="${guest_pkg_client}"
            warn "Using package kbs-client (${guest_pkg_client}) — no TDX attester."
            warn "Run 'setup-guest' to build + install the TDX-enabled client."
        else
            log "kbs-client not found in guest — installing 'trustee' package"
            # shellcheck disable=SC2046  # deliberate word-splitting of the package list
            install_pkgs_guest $(guest_distro_pkgs trustee)
            kbs_bin="${guest_pkg_client}"
            warn "Installed package kbs-client has no TDX attester (sample fallback)."
        fi
    fi

    local out
    if [[ -n "$SECRET_FILE" ]]; then
        log "Saving secret to (guest path): ${SECRET_FILE}"
        ssh_guest "${kbs_bin} --url '${url}' get-resource --path '${SECRET_PATH}' > '${SECRET_FILE}'" ||
            die "Secret retrieval failed. Check attestation (attest cmd) and KBS policy."
        log "Secret written to ${SECRET_FILE} on the guest."
    else
        log "Retrieving secret to stdout (text secrets only; use --file for binary data)"
        if out=$(ssh_guest "${kbs_bin} --url '${url}' get-resource --path '${SECRET_PATH}'"); then
            echo "$out"
            log "=== SECRET DELIVERY SUCCESS: attestation passed, secret released ==="
        else
            die "Secret retrieval failed. Check attestation (attest cmd) and KBS resource policy."
        fi
    fi
}
