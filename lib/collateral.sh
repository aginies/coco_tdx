# =============================================================================
# 7c. OFFLINE DCAP COLLATERAL (CoCo-AS file:// backend)
# =============================================================================
#
# Trustee >= 0.23 verifies TDX quotes with a native Rust collateral client
# (deps/verifier/src/intel_dcap/pcs.rs) instead of the QCNL C library. Its
# HTTPS backend builds a reqwest client inside a LazyLock with
# reqwest::Client::new(), which PANICS (instead of returning an error) when
# the TLS backend fails to initialise — seen on SLES 16.1 with trustee
# 0.23.0~git0.564a3ba5:
#   Client::new(): reqwest::Error { kind: Builder, source: Normal(ErrorStack([])) }
# The panic poisons the LazyLock, so every later request panics too.
#
# The file:// backend never touches that client. This module fetches the
# collateral on the host with curl (system OpenSSL, works fine), assembles
# the JSON layout the verifier expects (the Intel PCS Client Tool format:
# {"collaterals": {...}}, see PcsCollaterals in collateral_service.rs),
# and points CoCo-AS at it:
#   verifier_config.dcap_verifier.collateral_service = file://<path>
#
# Collateral expires (TCB info / QE identity nextUpdate, CRLs), so the file
# must be refreshed periodically: re-run 'collateral-offline'.
# 'collateral-online' switches CoCo-AS back to the PCS/PCCS URL.

# Extract the FMSPC (6 bytes, hex) from a TDX quote file: the PCK leaf
# certificate is the first PEM block of the quote's certification data; the
# FMSPC is the OCTET STRING following OID 1.2.840.113741.1.13.1.4.
quote_fmspc() {
    local quote_file="$1"
    python3 -I - "$quote_file" <<'PY'
import base64, re, sys
data = open(sys.argv[1], "rb").read()
m = re.search(rb"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", data, re.S)
if not m:
    sys.exit("no PCK certificate in quote certification data")
der = base64.b64decode(b"".join(m.group(1).split()))
oid = bytes.fromhex("060a2a864886f84d010d0104")  # OID 1.2.840.113741.1.13.1.4
i = der.find(oid)
if i < 0 or der[i + len(oid)] != 0x04 or der[i + len(oid) + 1] != 0x06:
    sys.exit("FMSPC extension not found in PCK certificate")
start = i + len(oid) + 2
print(der[start:start + 6].hex().upper())
PY
}

# Determine the FMSPC: --fmspc if given, otherwise from a fresh guest quote.
resolve_fmspc() {
    if [[ -n "$FMSPC" ]]; then
        [[ "$FMSPC" =~ ^[0-9a-fA-F]{12}$ ]] || die "Invalid --fmspc '${FMSPC}' (must be 12 hex chars)"
        echo "${FMSPC^^}"
        return 0
    fi
    detect_guest_ip >&2
    log "No --fmspc given: extracting it from a fresh guest quote (${GUEST_IP})" >&2
    guest_generate_quote >&2 || die "Quote generation on guest failed (pass --fmspc to skip the guest)"
    local tmp fmspc
    tmp=$(mktemp /tmp/tdx-quote.XXXXXX)
    ssh_guest "base64 -w0 ${GUEST_WORKDIR}/quote.dat" 2>/dev/null | base64 -d >"$tmp" \
        || { rm -f "$tmp"; die "Could not fetch quote from guest"; }
    fmspc=$(quote_fmspc "$tmp") || { rm -f "$tmp"; die "Could not extract FMSPC from quote"; }
    rm -f "$tmp"
    echo "$fmspc"
}

# curl wrapper: fetch URL into <dir>/<name>.body (+ .hdr). Returns curl rc.
_coll_fetch() {
    local dir="$1" name="$2" url="$3"
    log "  GET ${url}"
    curl -sS -f --max-time 30 -D "${dir}/${name}.hdr" -o "${dir}/${name}.body" "$url"
}

# Fetch all collateral for <fmspc> from <source_url> (a PCS/PCCS v4 base) and
# write the assembled JSON to <out_file>.
build_offline_collateral() {
    local fmspc="$1" source_url="$2" out_file="$3"
    require_cmd curl python3

    # Endpoints are built from the server root (scheme://host[:port]/), same
    # as the trustee verifier does.
    local root
    root=$(sed -E 's#^(https?://[^/]+).*#\1/#' <<<"$source_url")
    local is_pcs=0
    [[ "$root" == "https://api.trustedservices.intel.com/" ]] && is_pcs=1

    local dir
    dir=$(mktemp -d /tmp/tdx-collateral.XXXXXX)
    # Runs in a $(...) subshell: EXIT cleans up on success and on die.
    # shellcheck disable=SC2064
    trap "rm -rf '$dir'" EXIT

    log "Fetching DCAP collateral for FMSPC ${fmspc} from ${root}"
    local upd tee
    for upd in standard early; do
        for tee in tdx sgx; do
            _coll_fetch "$dir" "${tee}_tcb_${upd}" \
                "${root}${tee}/certification/v4/tcb?fmspc=${fmspc}&update=${upd}" \
                || { [[ "$tee/$upd" == "tdx/standard" ]] && die "TDX TCB info fetch failed (FMSPC ${fmspc} unknown to ${root}?)"; \
                     warn "  optional ${tee} TCB info (${upd}) not available"; }
            _coll_fetch "$dir" "${tee}_qe_${upd}" \
                "${root}${tee}/certification/v4/qe/identity?update=${upd}" \
                || { [[ "$tee/$upd" == "tdx/standard" ]] && die "TD QE identity fetch failed"; \
                     warn "  optional ${tee} QE identity (${upd}) not available"; }
        done
    done
    local ca
    for ca in processor platform; do
        _coll_fetch "$dir" "pckcrl_${ca}" \
            "${root}sgx/certification/v4/pckcrl?ca=${ca}&encoding=der" \
            || die "PCK CRL (${ca}) fetch failed"
    done
    if ((is_pcs)); then
        _coll_fetch "$dir" rootcacrl "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der" \
            || die "Intel Root CA CRL fetch failed"
    else
        _coll_fetch "$dir" rootcacrl "${root}sgx/certification/v4/rootcacrl" \
            || die "Root CA CRL fetch failed"
    fi

    log "Assembling collateral JSON"
    python3 -I - "$dir" "$fmspc" "$out_file" <<'PY' || die "Failed to assemble collateral JSON"
import json, os, re, string, sys
d, fmspc, out = sys.argv[1], sys.argv[2], sys.argv[3]

def body(name):
    p = os.path.join(d, name + ".body")
    return open(p, "rb").read() if os.path.exists(p) and os.path.getsize(p) else None

def header(name, key):
    p = os.path.join(d, name + ".hdr")
    if not os.path.exists(p):
        return None
    for line in open(p, encoding="latin-1"):
        k, _, v = line.partition(":")
        if k.strip().lower() == key.lower():
            return v.strip()
    return None

def js(name):
    b = body(name)
    return json.loads(b) if b else None

def hexcrl(name):
    # PCS returns DER; PCCS may return hex text already.
    b = body(name)
    t = b.strip()
    if t and all(chr(c) in string.hexdigits for c in t):
        return t.decode().lower()
    return b.hex()

entry = {"fmspc": fmspc.lower()}
for tee in ("tdx", "sgx"):
    for upd, suffix in (("standard", ""), ("early", "_early")):
        v = js(f"{tee}_tcb_{upd}")
        if v:
            entry[f"{tee}_tcbinfo{suffix}"] = v

col = {
    "tcbinfos": [entry],
    "pckcacrl": {"processorCrl": hexcrl("pckcrl_processor"),
                 "platformCrl": hexcrl("pckcrl_platform")},
    "certificates": {
        "TCB-Info-Issuer-Chain": header("tdx_tcb_standard", "TCB-Info-Issuer-Chain")
            or header("tdx_tcb_standard", "SGX-TCB-Info-Issuer-Chain"),
        "SGX-Enclave-Identity-Issuer-Chain": header("tdx_qe_standard", "SGX-Enclave-Identity-Issuer-Chain"),
        "SGX-PCK-Certificate-Issuer-Chain": {
            "PROCESSOR": header("pckcrl_processor", "SGX-PCK-CRL-Issuer-Chain"),
            "PLATFORM": header("pckcrl_platform", "SGX-PCK-CRL-Issuer-Chain"),
        },
    },
    "rootcacrl": hexcrl("rootcacrl"),
}
for tee, key in (("sgx", "qeidentity"), ("tdx", "tdqeidentity")):
    for upd, suffix in (("standard", ""), ("early", "_early")):
        v = js(f"{tee}_qe_{upd}")
        if v:
            col[key + suffix] = v

missing = [k for k, v in (
    ("TCB-Info-Issuer-Chain", col["certificates"]["TCB-Info-Issuer-Chain"]),
    ("SGX-Enclave-Identity-Issuer-Chain", col["certificates"]["SGX-Enclave-Identity-Issuer-Chain"]),
    ("SGX-PCK-CRL-Issuer-Chain", all(col["certificates"]["SGX-PCK-Certificate-Issuer-Chain"].values())),
) if not v]
if missing:
    sys.exit("missing response headers: " + ", ".join(missing))

tmp = out + ".tmp"
with open(tmp, "w") as f:
    json.dump({"collaterals": col}, f)
os.replace(tmp, out)

# Report the earliest nextUpdate so the operator knows when to refresh.
dates = []
for k, v in entry.items():
    if k.endswith(("tcbinfo", "tcbinfo_early")):
        dates.append(v["tcbInfo"]["nextUpdate"])
for k in ("qeidentity", "qeidentity_early", "tdqeidentity", "tdqeidentity_early"):
    if k in col:
        dates.append(col[k]["enclaveIdentity"]["nextUpdate"])
print(min(dates) if dates else "")
PY
}

# Set verifier_config.dcap_verifier.collateral_service in grpc-as.json,
# preserving ownership/permissions, then restart grpc-as.
set_as_collateral_service() {
    local url="$1"
    [[ -f "$GRPC_AS_CONF" ]] || die "${GRPC_AS_CONF} not found — run setup-trustee first"
    log "Setting CoCo-AS collateral_service = ${url}"
    python3 -I - "$GRPC_AS_CONF" "$url" <<'PY' || die "Failed to update ${GRPC_AS_CONF}"
import json, os, sys
path, url = sys.argv[1], sys.argv[2]
cfg = json.load(open(path))
dv = cfg.setdefault("verifier_config", {}).setdefault("dcap_verifier", {})
dv["collateral_service"] = url
dv.setdefault("tcb_update_type", "early")
st = os.stat(path)
tmp = path + ".tmp"
with open(tmp, "w") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")
os.chmod(tmp, st.st_mode & 0o7777)
os.chown(tmp, st.st_uid, st.st_gid)
os.replace(tmp, path)
PY
    run systemctl restart grpc-as.service
    if ! wait_for_port 127.0.0.1 "${COCO_AS##*:}" 30; then
        show_grpc_as_logs 40
        die "CoCo-AS not listening on ${COCO_AS} after restart"
    fi
}

cmd_collateral_offline() {
    require_root
    require_cmd curl python3 systemctl
    log "=== Offline DCAP collateral for CoCo-AS ==="
    step "Fetch DCAP collateral on the host and point CoCo-AS at it (file://)" \
        "Works around the trustee >= 0.23 HTTPS collateral client panic; the file must be refreshed before it expires."

    local fmspc source_url next_update
    fmspc=$(resolve_fmspc) || die "Could not determine FMSPC"
    log "FMSPC: ${fmspc}"
    source_url=$(collateral_url)

    mkdir -p "$(dirname "$DCAP_COLLATERAL_FILE")"
    next_update=$(build_offline_collateral "$fmspc" "$source_url" "$DCAP_COLLATERAL_FILE") \
        || die "Building offline collateral failed"
    chmod 0644 "$DCAP_COLLATERAL_FILE"
    if id coco_as >/dev/null 2>&1; then
        chown -R coco_as:coco_as "$(dirname "$DCAP_COLLATERAL_FILE")"
    fi
    log "Collateral written: ${DCAP_COLLATERAL_FILE}"

    set_as_collateral_service "file://${DCAP_COLLATERAL_FILE}"

    log "CoCo-AS now verifies quotes with offline collateral."
    if [[ -n "$next_update" ]]; then
        warn "Collateral nextUpdate: ${next_update} — re-run '${SCRIPT_NAME} collateral-offline --fmspc ${fmspc}' before then."
    fi
    log "Next: ${SCRIPT_NAME} attest"
}

cmd_collateral_online() {
    require_root
    require_cmd python3 systemctl
    log "=== Switch CoCo-AS back to online collateral ==="
    set_as_collateral_service "$(collateral_url)"
    log "CoCo-AS collateral_service restored to $(collateral_url)"
}
