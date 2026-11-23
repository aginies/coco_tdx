# =============================================================================
# 7. REMOTE ATTESTATION
# =============================================================================

# Fetch a fresh TD quote from the guest, submit it to CoCo-AS via grpcurl, and
# return the EAR JWT in the global EAR_TOKEN. Returns 0 on success, 1 on failure.
# Shared by cmd_attest (allow-check) and secret-get --mode host (KBS REST fetch).
# Evaluate a given base64 TDX quote against CoCo-AS and set EAR_TOKEN.
# Does NOT touch the guest — the quote is supplied by the caller, so the same
# quote can be re-evaluated (e.g. right after RVPS registration) without
# generating a fresh one. This matters because test_tdx_attest extends
# RTMR2/RTMR3 on every run, so a fresh quote would carry a different rtmr_2
# and fail to match the value just enrolled.
# Optional second argument: structured runtime data JSON (e.g.
# '{"tee-pubkey":"..."}'). When given, it is sent as runtime_data so the EAR
# token carries the matching attester_runtime_data claims (KBS needs the
# tee-pubkey claim to release resources); the quote's report_data must then
# equal sha384(canonical JSON) zero-padded to 64 bytes.
# Print recent grpc-as logs, skipping Rust backtrace frames so the actual
# panic message ("thread ... panicked at ...") and service state changes stay
# visible instead of being pushed out by ~100 "N: 0x... - <unknown>" lines.
show_grpc_as_logs() {
    local lines="${1:-30}"
    error "=== CoCo-AS logs (journalctl -u grpc-as.service, backtrace frames filtered) ==="
    journalctl -u grpc-as.service -n 2000 --no-pager 2>/dev/null \
        | grep -vE 'grpc-as\[[0-9]+\]: +[0-9]+: +0x[0-9a-f]+ - |grpc-as\[[0-9]+\]: +at ' \
        | tail -n "$lines" >&2 || true
    grpc_as_known_issue_hints
}

# Recognise known grpc-as failure signatures in the current service run and
# print a targeted hint.
grpc_as_known_issue_hints() {
    local since logs ver
    since=$(systemctl show -p ActiveEnterTimestamp --value grpc-as.service 2>/dev/null || true)
    logs=$(journalctl -u grpc-as.service ${since:+--since "$since"} -n 2000 --no-pager 2>/dev/null || true)
    if grep -q 'Client::new(): reqwest::Error { kind: Builder' <<<"$logs"; then
        ver=$(rpm -q --qf '%{VERSION}' trustee 2>/dev/null || echo unknown)
        error "Known issue: grpc-as panics building its HTTPS client (reqwest/OpenSSL init),"
        error "before the quote is even verified. Seen with trustee ${ver}; 0.22 works."
        error "Workaround: '${SCRIPT_NAME} collateral-offline' (file:// collateral, no HTTPS client),"
        error "or downgrade trustee to 0.22. See TRUSTEE-0.23-GRPC-AS-PANIC.md."
    elif grep -q 'LazyLock instance has previously been poisoned' <<<"$logs"; then
        error "grpc-as is in a poisoned state after an earlier panic — restart it: systemctl restart grpc-as.service"
    fi
}

# Verify grpc-as.service is active and CoCo-AS port is reachable before
# sending a request. On failure, explain why (crashed vs stopped) and show
# the relevant logs. Returns 0 if ready, 1 otherwise.
grpc_as_preflight() {
    local host="${COCO_AS%:*}" port="${COCO_AS##*:}"
    # Only check the local unit when CoCo-AS is local.
    if [[ "$host" == "127.0.0.1" || "$host" == "localhost" ]] \
        && systemctl cat grpc-as.service >/dev/null 2>&1; then
        local state result
        state=$(systemctl is-active grpc-as.service 2>/dev/null || true)
        if [[ "$state" != "active" ]]; then
            result=$(systemctl show -p Result --value grpc-as.service 2>/dev/null || true)
            error "grpc-as.service is ${state:-unknown} (last result: ${result:-unknown})"
            show_grpc_as_logs 40
            if journalctl -u grpc-as.service -n 2000 --no-pager 2>/dev/null | grep -q 'panicked at'; then
                error "grpc-as panicked earlier — see the 'panicked at' line above for the cause."
            fi
            error "Start it with: systemctl start grpc-as.service (then re-run attest)"
            return 1
        fi
    fi
    if ! timeout 3 bash -c "exec 3<>/dev/tcp/${host}/${port}" 2>/dev/null; then
        error "CoCo-AS ${COCO_AS} is not accepting connections"
        show_grpc_as_logs 40
        return 1
    fi
    return 0
}

attest_evaluate_quote() {
    local quote_b64="$1"
    local runtime_data_json="${2:-}"
    require_cmd base64
    ensure_grpcurl
    ensure_attestation_proto

    [[ -n "$quote_b64" ]] || die "Empty quote passed to attest_evaluate_quote"

    log "Building attestation request JSON (Trustee 0.20 format)"
    # CoCo-AS TDX verifier expects TdxEvidence JSON: {"quote": "<base64_quote>"}
    # The JSON bytes are then encoded using URL-safe base64 without padding (RFC 4648 §5).
    local tdx_evidence_json="{\"quote\":\"${quote_b64}\"}"
    local evidence_b64
    evidence_b64=$(printf '%s' "$tdx_evidence_json" | b64url_encode)

    local runtime_data_block=""
    if [[ -n "$runtime_data_json" ]]; then
        # Escape the inner JSON so it is a valid JSON string value. The proto
        # oneof runtime_data is mapped in JSON by the set field's name
        # (structured_runtime_data), not the oneof name.
        local escaped_json=${runtime_data_json//\"/\\\"}
        runtime_data_block=$(printf ',\n    "structured_runtime_data": "%s"' "$escaped_json")
    fi

    local req_file
    req_file=$(mktemp /tmp/tdx-attest-req.XXXXXX)
    cat >"$req_file" <<EOF
{
  "verification_requests": [
    {
      "tee": "tdx",
      "evidence": "${evidence_b64}"${runtime_data_block}
    }
  ],
  "policy_ids": ["default"]
}
EOF

    if ! grpc_as_preflight; then
        rm -f "$req_file"
        die "CoCo-AS is not running — cannot attest."
    fi

    local response=""
    log "Sending request via grpcurl to ${COCO_AS}"
    if ! response=$(grpcurl -plaintext \
        -import-path "$PROTO_DIR" \
        -proto attestation.proto \
        -d @ \
        "${COCO_AS}" attestation.AttestationService/AttestationEvaluate <"$req_file" 2>&1); then
        error "grpcurl call failed:"
        echo "$response" >&2
        rm -f "$req_file"
        echo "" >&2
        show_grpc_as_logs
        die "Attestation request failed."
    fi
    rm -f "$req_file"

    log "CoCo-AS response:"
    echo "$response"

    log "Extracting EAR token"
    EAR_TOKEN=$(echo "$response" | grep -ioP '"attestation[_-]?token"\s*:\s*"\K[^"]+' || true)
    if [[ -z "$EAR_TOKEN" ]]; then
        error "No attestation token in response:"
        echo "$response" >&2
        die "CoCo-AS did not return a token"
    fi
    return 0
}

# Fetch a fresh quote from the guest and evaluate it. The fetched quote is
# stored in LAST_QUOTE_B64 so it can be re-evaluated without a new guest
# round-trip (see attest_evaluate_quote).
attest_get_ear_token() {
    require_cmd base64
    require_cmd ssh

    log "Generating fresh quote on guest"
    if ! guest_generate_quote; then
        # The TD report was produced but the QGS round-trip failed. Run the
        # host-side QGS diagnostics (as setup-guest does) so the failure is
        # explained instead of left opaque.
        diagnose_quote_generation
        return 1
    fi

    log "Fetching quote (base64)"
    local quote_b64
    quote_b64=$(ssh_guest "base64 -w0 ${GUEST_WORKDIR}/quote.dat")
    [[ -n "$quote_b64" ]] || die "Empty quote from guest"
    log "Quote length: ${#quote_b64} chars (base64)"

    LAST_QUOTE_B64="$quote_b64"
    attest_evaluate_quote "$quote_b64"
}

# Like attest_get_ear_token, but binds the quote to a TEE public key so the
# resulting EAR token carries attester_runtime_data tee-pubkey (required by
# KBS to release resources). The CoCo-AS TDX verifier expects the quote's
# report_data to equal sha384(canonical JSON runtime data) zero-padded to 64
# bytes, so we write that digest into the guest before generating the quote
# with tdx-quote-gen. Argument: the tee-pubkey as a canonical JSON object
# (sorted keys, compact), e.g.
# {"alg":"ECDH-ES+A256KW","crv":"P-256","kty":"EC","x":"...","y":"..."}.
# It must be canonical because the AS hashes the canonical JSON of the
# runtime data to derive the expected report_data.
attest_get_ear_token_with_tee_key() {
    local tee_pubkey_json="$1"
    [[ -n "$tee_pubkey_json" ]] || die "attest_get_ear_token_with_tee_key requires the tee-pubkey (canonical JSON object)"
    require_cmd base64 ssh openssl

    # Canonical JSON (serde_json_canonicalizer: compact, sorted keys) of the
    # structured runtime data; single key, so the layout is unambiguous.
    local structured
    structured="{\"tee-pubkey\":${tee_pubkey_json}}"
    local digest
    digest=$(printf '%s' "$structured" | openssl dgst -sha384 -hex | awk '{print $NF}')
    # sha384 = 48 bytes; TDX report_data is 64 bytes, zero-padded.
    local report_data_hex="${digest}00000000000000000000000000000000"

    log "Binding quote to TEE key (report_data = sha384(runtime data))"
    # test_tdx_attest always uses random report data, so use tdx-quote-gen
    # (installed by setup-guest) which binds the given 64-byte report data.
    ssh_guest "cd ${GUEST_WORKDIR} && ${TDX_QUOTE_GEN_GUEST} ${report_data_hex} quote.dat" ||
        die "Failed to generate a quote bound to the TEE key. Is ${TDX_QUOTE_GEN_GUEST} installed in the guest? Re-run: setup-guest --guest-ip <GUEST_IP>"

    log "Fetching quote (base64)"
    local quote_b64
    quote_b64=$(ssh_guest "base64 -w0 ${GUEST_WORKDIR}/quote.dat")
    [[ -n "$quote_b64" ]] || die "Empty quote from guest"

    LAST_QUOTE_B64="$quote_b64"
    attest_evaluate_quote "$quote_b64" "$structured"
}

# Decode the payload segment (2nd dot-separated part) of a JWT: base64url ->
# base64 (re-padding as needed) -> JSON text on stdout.
jwt_decode_payload() {
    local token="$1" payload
    payload=$(echo "$token" | cut -d. -f2)
    payload="${payload//-/+}"
    payload="${payload//_//}"
    case $((${#payload} % 4)) in
    2) payload+="==" ;;
    3) payload+="=" ;;
    esac
    echo "$payload" | base64 -d 2>/dev/null
}

# test_tdx_attest extends RTMR2/RTMR3 on every run; warn that in-guest
# secret-get (kbs-client) cannot pass CC-eventlog replay until the guest
# reboots.
warn_rtmr3_extended() {
    warn "Quote fetch ran test_tdx_attest, which EXTENDS RTMR2/RTMR3 at runtime."
    warn "In-guest 'secret-get' (kbs-client) now fails CC-eventlog replay until the guest reboots."
    warn "Use 'secret-get --mode host' (no reboot needed) or reboot the guest first."
}

register_rvps_reference_values() {
    local mr_td="$1" rtmr_1="$2" rtmr_2="$3" xfam="$4"
    ensure_attestation_proto

    local sample_dict_json=""
    if command -v python3 >/dev/null 2>&1; then
        sample_dict_json=$(python3 -c "
import json
print(json.dumps({
    'mr_td': ['$mr_td'],
    'rtmr_1': ['$rtmr_1'],
    'rtmr_2': ['$rtmr_2'],
    'xfam': ['$xfam']
}))
")
    else
        sample_dict_json="{\"mr_td\":[\"${mr_td}\"],\"rtmr_1\":[\"${rtmr_1}\"],\"rtmr_2\":[\"${rtmr_2}\"],\"xfam\":[\"${xfam}\"]}"
    fi

    local prov_b64=""
    prov_b64=$(echo -n "$sample_dict_json" | base64 | tr -d '\r\n')

    local req_file
    req_file=$(mktemp /tmp/tdx-rvps-req.XXXXXX)
    if command -v python3 >/dev/null 2>&1; then
        python3 -c "
import json
msg = {
    'version': '0.1.0',
    'type': 'sample',
    'payload': '$prov_b64'
}
print(json.dumps({'message': json.dumps(msg)}))
" >"$req_file"
    else
        local msg_inner="{\"version\":\"0.1.0\",\"type\":\"sample\",\"payload\":\"${prov_b64}\"}"
        local escaped_msg
        escaped_msg=$(echo -n "$msg_inner" | sed 's/"/\\"/g')
        cat >"$req_file" <<EOF
{"message":"${escaped_msg}"}
EOF
    fi

    log "Registering reference values in RVPS (${COCO_AS}):"
    log "  mr_td:  $mr_td"
    log "  rtmr_1: $rtmr_1"
    log "  rtmr_2: $rtmr_2"
    log "  xfam:   $xfam"

    local resp=""
    if ! resp=$(grpcurl -plaintext \
        -import-path "$PROTO_DIR" \
        -proto reference.proto \
        -d @ \
        "${COCO_AS}" reference.ReferenceValueProviderService/RegisterReferenceValue <"$req_file" 2>&1); then
        error "Failed to register reference values in RVPS:"
        echo "$resp" >&2
        rm -f "$req_file"
        return 1
    fi
    rm -f "$req_file"
    log "RVPS registration succeeded."
    return 0
}

query_rvps_reference_value() {
    local id="${1:-mr_td}"
    ensure_attestation_proto
    local req="{\"reference_value_id\":\"${id}\"}"
    log "Querying RVPS (${COCO_AS}) for reference value '${id}'..."
    local resp=""
    if ! resp=$(echo "$req" | grpcurl -plaintext \
        -import-path "$PROTO_DIR" \
        -proto reference.proto \
        -d @ \
        "${COCO_AS}" reference.ReferenceValueProviderService/QueryReferenceValue 2>&1); then
        error "QueryReferenceValue failed:"
        echo "$resp" >&2
        return 1
    fi
    echo "$resp"
    return 0
}

# Extract fields from a decoded EAR JWT payload (stdin), supporting both
# claim layouts:
#   trustee <= 0.22: submods.cpu0."ear.status",
#                    "ear.veraison.annotated-evidence".tdx.{quote,tcb_status}
#   trustee >= 0.23 (EAR draft-04): submods.cpu0.ear_status,
#                    ear_attester_claims.claims.{quote,tcb_status}
# Prints one space-separated line in the order of the field names given as
# arguments (ear_status tcb_status tee_type, or any quote body field such as
# mr_td / rtmr_0..3 / xfam / mr_seam); missing fields print as "-".
ear_fields() {
    python3 -I -c '
import sys, json
try:
    d = json.loads(sys.stdin.read())
except Exception:
    sys.exit(0)
sub = d.get("submods", {}).get("cpu0", {})
old = sub.get("ear.veraison.annotated-evidence", {}).get("tdx", {})
new = sub.get("ear_attester_claims", {}).get("claims", {})
ev = new or old
quote = ev.get("quote", {})
vals = {
    "ear_status": sub.get("ear_status") or sub.get("ear.status") or d.get("ear_status", ""),
    "tcb_status": ev.get("tcb_status", ""),
    "tee_type": quote.get("header", {}).get("tee_type", ""),
}
body = quote.get("body", {})
print(" ".join((vals[k] if k in vals else body.get(k, "")) or "-" for k in sys.argv[1:]))
' "$@"
}

# Turn the "-" placeholders printed by ear_fields back into empty strings
# (in the caller's variables) so the grep fallbacks below still apply.
_ear_unset_dashes() {
    local v
    for v in "$@"; do
        [[ "${!v}" == "-" ]] && printf -v "$v" '%s' ""
    done
    return 0
}

cmd_query_rv() {
    local id="${RV_ID:-mr_td}"
    query_rvps_reference_value "$id"
}

cmd_register_rv() {
    detect_guest_ip
    log "=== Registering TDX Reference Values in RVPS: ${GUEST_IP} -> ${COCO_AS} ==="
    step "Fetch guest quote and enroll measurements into RVPS" \
        "Fetches a fresh Quote, decodes TDX measurements (mr_td, rtmr_1, rtmr_2, xfam), and registers them into RVPS so EAR appraisal passes."

    if ! attest_get_ear_token; then
        die "Quote generation or evaluation failed — see diagnostics above."
    fi
    local token="$EAR_TOKEN"
    local jwt_json=""
    jwt_json=$(jwt_decode_payload "$token") || jwt_json=""

    local mr_td="" rtmr_1="" rtmr_2="" xfam=""
    if command -v python3 >/dev/null 2>&1; then
        read -r mr_td rtmr_1 rtmr_2 xfam < <(ear_fields mr_td rtmr_1 rtmr_2 xfam <<<"$jwt_json")
        _ear_unset_dashes mr_td rtmr_1 rtmr_2 xfam
    fi
    if [[ -z "$mr_td" ]]; then
        mr_td=$(echo "$jwt_json" | grep -oP '"mr_td"\s*:\s*"\K[^"]+' | head -n1 || true)
    fi
    if [[ -z "$rtmr_1" ]]; then
        rtmr_1=$(echo "$jwt_json" | grep -oP '"rtmr_1"\s*:\s*"\K[^"]+' | head -n1 || true)
    fi
    if [[ -z "$rtmr_2" ]]; then
        rtmr_2=$(echo "$jwt_json" | grep -oP '"rtmr_2"\s*:\s*"\K[^"]+' | head -n1 || true)
    fi
    if [[ -z "$xfam" ]]; then
        xfam=$(echo "$jwt_json" | grep -oP '"xfam"\s*:\s*"\K[^"]+' | head -n1 || true)
    fi

    if [[ -z "$mr_td" || -z "$rtmr_1" || -z "$rtmr_2" || -z "$xfam" ]]; then
        die "Could not extract TDX measurements from guest quote"
    fi

    if ! register_rvps_reference_values "$mr_td" "$rtmr_1" "$rtmr_2" "$xfam"; then
        die "Failed to register reference values in RVPS"
    fi

    echo ""
    log "============================================================================="
    log "               RVPS REFERENCE VALUES SUCCESSFULLY ENROLLED"
    log "============================================================================="
    log "  mr_td:  $mr_td"
    log "  rtmr_1: $rtmr_1"
    log "  rtmr_2: $rtmr_2"
    log "  xfam:   $xfam"
    log "============================================================================="
    log "Now re-run './tdx-attest.sh attest --guest-ip ${GUEST_IP}' to verify ear.status = affirming."
    warn_rtmr3_extended
}

cmd_attest() {
    detect_guest_ip
    log "=== Remote attestation: ${GUEST_IP} -> CoCo-AS ${COCO_AS} ==="
    step "Send the guest Quote to CoCo-AS and verify the EAR token" \
        "Fetches a fresh Quote over ssh, submits it via grpcurl, then checks Intel PCS verification and appraisal status."

    if ! attest_get_ear_token; then
        die "Quote generation or evaluation failed — see diagnostics above."
    fi
    local token="$EAR_TOKEN"

    log "Decoding EAR JWT payload"
    local jwt_json=""
    if command -v python3 >/dev/null 2>&1; then
        jwt_json=$(jwt_decode_payload "$token" | python3 -m json.tool) || jwt_json=""
        [[ -n "$jwt_json" ]] && echo "$jwt_json"
    else
        jwt_json=$(jwt_decode_payload "$token") || jwt_json=""
        [[ -n "$jwt_json" ]] && echo "$jwt_json"
    fi
    [[ -n "$jwt_json" ]] || warn "Could not decode JWT payload"

    log "Checking CoCo-AS service log"
    journalctl -u grpc-as.service -n 20 --no-pager 2>/dev/null || true

    local ear_status="" tcb_status="" tee_type="" mr_td="" rtmr_0="" rtmr_1="" rtmr_2="" rtmr_3="" xfam="" mr_seam=""
    if command -v python3 >/dev/null 2>&1; then
        read -r ear_status tcb_status tee_type mr_td rtmr_0 rtmr_1 rtmr_2 rtmr_3 xfam mr_seam < <(
            ear_fields ear_status tcb_status tee_type mr_td rtmr_0 rtmr_1 rtmr_2 rtmr_3 xfam mr_seam <<<"$jwt_json"
        )
        _ear_unset_dashes ear_status tcb_status tee_type mr_td rtmr_0 rtmr_1 rtmr_2 rtmr_3 xfam mr_seam
    fi

    if [[ -z "$ear_status" ]]; then
        ear_status=$(echo "$jwt_json" | grep -oP '"ear[._]status"\s*:\s*"\K[^"]+' | head -n1 || true)
    fi
    if [[ -z "$tcb_status" ]]; then
        tcb_status=$(echo "$jwt_json" | grep -oP '"tcb_status"\s*:\s*"\K[^"]+' | head -n1 || true)
    fi
    if [[ -z "$tee_type" ]]; then
        tee_type=$(echo "$jwt_json" | grep -oP '"tee_type"\s*:\s*"\K[^"]+' | head -n1 || true)
    fi
    if [[ -z "$mr_td" ]]; then
        mr_td=$(echo "$jwt_json" | grep -oP '"mr_td"\s*:\s*"\K[^"]+' | head -n1 || true)
    fi
    if [[ -z "$rtmr_0" ]]; then
        rtmr_0=$(echo "$jwt_json" | grep -oP '"rtmr_0"\s*:\s*"\K[^"]+' | head -n1 || true)
    fi
    if [[ -z "$rtmr_1" ]]; then
        rtmr_1=$(echo "$jwt_json" | grep -oP '"rtmr_1"\s*:\s*"\K[^"]+' | head -n1 || true)
    fi
    if [[ -z "$rtmr_2" ]]; then
        rtmr_2=$(echo "$jwt_json" | grep -oP '"rtmr_2"\s*:\s*"\K[^"]+' | head -n1 || true)
    fi
    if [[ -z "$rtmr_3" ]]; then
        rtmr_3=$(echo "$jwt_json" | grep -oP '"rtmr_3"\s*:\s*"\K[^"]+' | head -n1 || true)
    fi
    if [[ -z "$xfam" ]]; then
        xfam=$(echo "$jwt_json" | grep -oP '"xfam"\s*:\s*"\K[^"]+' | head -n1 || true)
    fi
    if [[ -z "$mr_seam" ]]; then
        mr_seam=$(echo "$jwt_json" | grep -oP '"mr_seam"\s*:\s*"\K[^"]+' | head -n1 || true)
    fi

    if ((REGISTER_RV)); then
        log "Registering guest reference values in RVPS (--register-rv specified)..."
        if register_rvps_reference_values "$mr_td" "$rtmr_1" "$rtmr_2" "$xfam"; then
            # Re-evaluate the SAME quote that was just registered (not a fresh
            # one). test_tdx_attest extends RTMR2/RTMR3 on every run, so a fresh
            # quote would carry a different rtmr_2 and fail to match the value
            # we just enrolled in RVPS.
            log "Re-evaluating the same registered quote to obtain updated EAR token..."
            attest_evaluate_quote "$LAST_QUOTE_B64"
            token="$EAR_TOKEN"
            jwt_json=$(jwt_decode_payload "$token") || jwt_json=""
            if command -v python3 >/dev/null 2>&1; then
                ear_status=$(ear_fields ear_status <<<"$jwt_json")
                [[ "$ear_status" == "-" ]] && ear_status=""
            else
                ear_status=$(echo "$jwt_json" | grep -oP '"ear[._]status"\s*:\s*"\K[^"]+' | head -n1 || true)
            fi
        fi
        warn_rtmr3_extended
    fi

    echo ""
    log "============================================================================="
    log "                       TDX REMOTE ATTESTATION REPORT"
    log "============================================================================="
    log "  Hardware Verification (Intel DCAP / PCS v4):"
    log "    TCB Status:             ${tcb_status:-Unknown}"
    log "    TEE Type:               ${tee_type:-Unknown} (0x81000000 = Intel TDX)"
    [[ -n "$mr_seam" ]] && log "    TDX Module (MRSEAM):    ${mr_seam:0:32}..."
    log "  Guest Launch Measurements:"
    [[ -n "$mr_td" ]] && log "    MRTD (TD Build):        ${mr_td:0:32}..."
    [[ -n "$rtmr_0" ]] && log "    RTMR 0 (TDVF config):       ${rtmr_0:0:32}..."
    [[ -n "$rtmr_1" ]] && log "    RTMR 1 (Bootloader/Kernel): ${rtmr_1:0:32}..."
    [[ -n "$rtmr_2" ]] && log "    RTMR 2 (Cmdline/Initrd):    ${rtmr_2:0:32}..."
    [[ -n "$rtmr_3" ]] && log "    RTMR 3 (Runtime/Guest OS):  ${rtmr_3:0:32}..."
    [[ -n "$xfam" ]] && log "    XFAM (Features):        ${xfam}"
    log "  Trustee Appraisal Result (RVPS):"
    log "    EAR Status:             ${ear_status:-Unknown}"
    log "============================================================================="
    echo ""

    if [[ "$ear_status" == "affirming" ]] || echo "$jwt_json" | grep -qE '"allow"[[:space:]]*:[[:space:]]*true'; then
        log "=== ATTESTATION SUCCESS: ear.status = affirming ==="
        log "Intel DCAP hardware verification AND Trustee appraisal passed!"
        trap - ERR
        return 0
    elif [[ -n "$tcb_status" && "$tcb_status" != "Revoked" ]]; then
        log "=== HARDWARE ATTESTATION SUCCESS: Quote verified by Intel PCS (TCB: ${tcb_status}) ==="
        if [[ "$ear_status" == "contraindicated" ]]; then
            warn "Appraisal status is 'contraindicated' because reference values are not enrolled in RVPS."
            warn "To register current guest measurements in RVPS and achieve 'affirming' status, run:"
            warn "  $0 attest --guest-ip ${GUEST_IP} --register-rv"
            warn "  or: $0 register-rv --guest-ip ${GUEST_IP}"
        fi
        trap - ERR
        return 0
    else
        error "=== ATTESTATION FAILED: Invalid or rejected attestation token ==="
        error "Check grpc-as logs and collateral service connectivity."
        trap - ERR
        return 1
    fi
}

# Run test_tdx_attest on the guest, capturing its output. On failure, print
# the error in red with an uppercase FAILED prefix ("Failed to get the quote"
# becomes "FAILED: get the quote") and return the command's exit code.
guest_generate_quote() {
    local out rc=0
    out=$(ssh_guest "cd ${GUEST_WORKDIR} && test_tdx_attest" 2>&1) || rc=$?
    if ((rc != 0)); then
        # Strip the [CMD] log line(s) captured from ssh_guest itself (they are
        # still written to the log file by _log).
        local msg
        msg=$(grep -vE '^\[[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\] \[' <<<"$out" || true)
        msg="${msg:-no output from test_tdx_attest}"
        msg="${msg/Failed to get the quote/FAILED: get the quote}"
        echo "$(red "$msg")" >&2
    fi
    return "$rc"
}

# Run the full host-side quote-failure diagnosis: the 6 QGS pre-flight checks
# (rendered as a PASS/FAIL table) followed by the qgsd journal signature
# analysis (diagnose_quote_failure). Returns 0 if a known cause was identified
# in the journal, 1 otherwise.
diagnose_quote_generation() {
    # shellcheck disable=SC2034  # CHECK_RESULTS consumed by print_results
    CHECK_RESULTS=()
    qgs_preflight_checks
    print_results
    diagnose_quote_failure
}

# After a quote-generation failure, inspect the host QGS journal for known
# failure signatures and explain the most likely cause:
#   1. Malformed pccs_url (CURL error 3 / QPL 0xb003): QCNL appends the API
#      endpoint ('pckcert') directly to pccs_url, so a URL missing the
#      '/sgx/certification/v4/' path and trailing slash produces a request
#      like 'https://host:portpckcert?...' that curl rejects.
#   2. PCK certificate not found (HTTP 404): on dev platforms the TDX
#      module's QEID is often not registered in Intel PCS.
#   3. Collateral service unreachable (CURL 5/6/7, DNS failure, refused).
# Returns 0 if a cause was detected and explained, 1 otherwise.
diagnose_quote_failure() {
    local recent full qeid qcnl_url
    full=$(journalctl -u qgsd --since "10 min ago" --no-pager 2>/dev/null | tail -200 || true)
    [[ -n "$full" ]] || return 1
    # Narrow to the last request cycle (QGS logs 'Added a new connection' at
    # the start of each) so stale errors from earlier cycles don't mask the
    # current one.
    recent=$(awk '/Added a new connection/{buf=""} {buf = buf $0 "\n"} END {printf "%s", buf}' <<<"$full")
    [[ -n "$recent" ]] || recent="$full"

    # 1. Malformed request URL: pccs_url lacks the API path / trailing slash.
    if grep -qE 'Encountered CURL error: \(3\)|Failed to get quote config. Error code is 0xb003' <<<"$recent"; then
        qcnl_url=$(grep -oP '"pccs_url"\s*:\s*"\K[^"]+' "$QCNL_PKG_CONF" 2>/dev/null || true)
        warn "Quote failure cause: QCNL built a malformed request URL (CURL error 3)."
        warn "QCNL appends the API endpoint ('pckcert') directly to pccs_url, which is currently:"
        warn "  ${qcnl_url:-<not found in ${QCNL_PKG_CONF}>}"
        warn "It must be the full PCS v4 API base with a trailing slash, e.g.:"
        warn "  https://127.0.0.1:8081/sgx/certification/v4/                 (local PCCS)"
        warn "  https://api.trustedservices.intel.com/sgx/certification/v4/   (global PCS)"
        warn "Fix: re-run 'setup-host' (rewrites the QCNL config), or edit ${QCNL_PKG_CONF}."
        return 0
    fi

    # 2. PCS has no PCK certificate for this platform (HTTP 404).
    if grep -qE '\[QCNL\] HTTP status code: 404|No certificate data for this platform' <<<"$recent"; then
        qeid=$(grep -oE 'qeid=[0-9A-Fa-f]{32}' <<<"$recent" | head -1 | cut -d= -f2 || true)
        warn "Quote failure cause: QGS could not fetch the PCK certificate from PCS (HTTP 404)."
        warn "PCS holds no PCK certificate for this platform's TDX module${qeid:+ (QEID ${qeid})}."
        warn "This is the signature of a dev/pre-release TDX module, or a version Intel has not yet ingested into PCS."
        warn "No query/config change fixes it. To proceed:"
        warn "  - update the platform TDX module (BIOS/firmware) to a PCS-registered version, or"
        warn "  - use a local PCCS with manually-provisioned PCK collateral (re-run with --collateral pccs)."
        return 0
    fi

    # 3. Collateral service unreachable (service down / no network).
    if grep -qE 'Encountered CURL error: \([567]\)|Could not resolve host|Connection refused' <<<"$recent"; then
        warn "Quote failure cause: QCNL could not reach the collateral service."
        warn "Check pccs_url in ${QCNL_PKG_CONF}; for a local PCCS check 'systemctl status pccs',"
        warn "for global PCS check outbound HTTPS from the host."
        return 0
    fi

    return 1
}

# Disable suspend/hibernate in the guest. TDX Trust Domains cannot hibernate:
# the hibernate image would be unmeasured/unencrypted, breaking attestation,
# and resume-from-disk is unsupported. Mask the sleep targets and ignore the
# hardware sleep keys in logind.
disable_suspend_guest() {
    ssh_guest "sudo bash -s" <<'EOF'
set -e
systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target
mkdir -p /etc/systemd/logind.conf.d
cat > /etc/systemd/logind.conf.d/tdx-no-suspend.conf <<'CONF'
[Login]
HandleSuspendKey=ignore
HandleHibernateKey=ignore
HandleLidSwitch=ignore
CONF
systemctl try-restart systemd-logind || true
EOF
}
