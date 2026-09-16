#!/usr/bin/env bash
# =============================================================================
# pccs-check.sh — check platform validity on Intel PCCS (Provisioning Certification Service)
#
# Intel PCS (Provisioning Certification Service) / PCCS v4 API endpoints:
#   GET /tcb?fmspc=...             — SGX TCB info
#   GET /tdx/certification/v4/tcb?fmspc=... — TDX TCB info
#   GET /pckcert?...               — Get PCK certificate
#   GET /pckcerts?...              — Get all PCK certificates
#   GET /pckcrl?ca=...             — Get revocation list
#   GET /qe/identity               — Get QE enclave identity (SGX or TDX)
#   GET /qve/identity              — Get QVE enclave identity (SGX)
#   GET /qae/identity              — Get QAE enclave identity (SGX)
#   GET /tcbevaluationdatanumbers  — Get TCB evaluation data numbers
#   GET /collateral?fmspc=...      — Fetch full collateral (PCCS/Azure cache)
#
# Usage: pccs-check.sh <command> [options]
#
# Commands:
#   tcb        Check TCB status for a given FMSPC (SGX)
#   tcbinfo    Get TCB info (SGX or TDX)
#   pckcert    Get PCK certificate (GET by PPID or POST by Platform Manifest)
#   pckcerts   Get all PCK certificates for all TCB levels
#   pckcrl     Get revocation list
#   qe-identity Get QE / QVE / QAE enclave identity
#   collateral Fetch full collateral (TCB info + PCK cert chain)
#   check      Quick platform validity check (TCB + CRL + PCK cert)
#
# Options:
#   --fmspc HEX       FMSPC value (6 bytes, 12 hex chars) — required for tcb/pckcert
#   --ppid HEX        Encrypted PPID (384 bytes, 768 hex chars)
#   --cpusvn HEX      CPU SVN (16 bytes, 32 hex chars)
#   --pcesvn HEX      PCE SVN (2 bytes, 4 hex chars, little-endian)
#   --pceid HEX       PCE-ID (2 bytes, 4 hex chars, little-endian)
#   --platform-manifest HEX  Platform Manifest (hex-encoded) — for multi-socket
#   --cert-file PATH  PCK certificate file (PEM/DER) — extracts FMSPC automatically
#   --tdx             Use TDX TCB info endpoint
#   --update-early    Request early TCB Info update
#   --ca TYPE         CRL CA type: processor|platform
#   --encoding FORM   CRL encoding: pem|der (default: pem)
#   --subscription KEY API subscription key (Ocp-Apim-Subscription-Key)
#   --verbose         Print full API response
#   --help            Show this help
#
# Examples:
#   # Extract FMSPC from a PCK certificate and check TCB status
#   sudo pccs-check.sh tcb --cert-file /var/lib/sgx/pck.cert
#
#   # Check TCB status with explicit FMSPC
#   pccs-check.sh tcb --fmspc 012345
#
#   # Get PCK certificate using encrypted PPID
#   pccs-check.sh pckcert --ppid <768-hex-chars> --cpusvn <32-hex-chars> \
#       --pcesvn <4-hex-chars> --pceid <4-hex-chars>
#
#   # Get revocation list
#   pccs-check.sh pckcrl --ca platform
#
#   # Get TDX TCB info
#   pccs-check.sh tcbinfo --fmspc 012345 --tdx
#
#   # Quick platform validity check
#   sudo pccs-check.sh check --cert-file /var/lib/sgx/pck.cert
#
# =============================================================================

set -Eeuo pipefail

readonly SCRIPT_NAME="$(basename "$0")"
readonly DEFAULT_PCCS_URL="https://api.trustedservices.intel.com/sgx/certification/v4/"

# Defaults
PCCS_URL="${PCCS_URL:-$DEFAULT_PCCS_URL}"
COMMAND=""
FMSPC=""
ENCRYPTED_PPID=""
CPUSVN=""
PCESVN=""
PCEID=""
PLATFORM_MANIFEST=""
CERT_FILE=""
CSV_FILE=""
MANIFEST_FILE=""
CHECK_TDX=0
UPDATE_EARLY=0
CRL_CA=""
CRL_ENCODING="pem"
VERBOSE=0
SUBSCRIPTION_KEY=""
ENCLAVE_TYPE="qe"
AUTO_DETECT=0
AUTO_DETECT_SOURCE=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Resolve base URL according to SGX vs TDX and custom PCCS endpoints
get_pccs_base_url() {
    local base="${PCCS_URL%/}"
    if [[ "$base" != *"/certification/v4"* ]]; then
        if ((CHECK_TDX)); then
            base="${base}/tdx/certification/v4/"
        else
            base="${base}/sgx/certification/v4/"
        fi
    else
        if ((CHECK_TDX)); then
            base="${base/\/sgx\//\/tdx\/}/"
        else
            base="${base}/"
        fi
    fi
    echo "$base" | sed -E 's#([^:])//+#\1/#g'
}

# =============================================================================
# HELP
# =============================================================================

usage() {
    cat <<EOF
Usage: $SCRIPT_NAME <command> [options]

Check platform validity on Intel PCCS (Provisioning Certification Service v4).

Commands:
  tcb              Check TCB status for a given FMSPC
  pckcert          Get PCK certificate (GET by PPID or POST by Platform Manifest)
  pckcerts         Get all PCK certificates for all TCB levels
  pckcrl           Get PCK Certificate Revocation List
  tcbinfo          Get TCB info (SGX or TDX)
  qe-identity      Get QE / QVE / QAE enclave identity
  collateral       Fetch full collateral (TCB info + PCK cert chain)
  check            Quick platform validity check (TCB + CRL + PCK cert)
  qcnl             Validate local QCNL config, permissions, and collateral endpoints
  register         Register platform manifest with Intel SGX Registration Service

Options:
  --auto            Automatically detect platform parameters (PCK cert, PCKIDRetrievalTool, CSV, CPU)
  --fmspc HEX       FMSPC value (6 bytes, 12 hex chars)
  --ppid HEX        Encrypted PPID (384 bytes, 768 hex chars, base16)
  --cpusvn HEX      CPU SVN (16 bytes, 32 hex chars)
  --pcesvn HEX      PCE SVN (2 bytes, 4 hex chars, little-endian)
  --pceid HEX       PCE-ID (2 bytes, 4 hex chars, little-endian)
  --platform-manifest HEX  Platform Manifest (hex-encoded)
  --manifest-file PATH Binary or hex manifest file
  --csv PATH        Path to PCKIDRetrievalTool CSV output
  --cert-file PATH  PCK certificate file (PEM/DER) — extracts FMSPC
  --pccs-url URL    Base PCCS/PCS URL (default: Intel PCS v4)
  --enclave-type TYPE Enclave identity type: qe|qve|qae (default: qe)
  --tdx             Use TDX endpoints (e.g. TDX TCB info, TD_QE identity)
  --update-early    Request early TCB Info update
  --ca TYPE         CRL CA type: processor|platform
  --encoding FORM   CRL encoding: pem|der (default: pem)
  --subscription KEY API subscription key (Ocp-Apim-Subscription-Key)
  --verbose         Print full API response
  --help            Show this help

Note: If --fmspc or --cert-file are omitted, the script automatically searches for
cached PCK certificates, PCKIDRetrievalTool outputs, or probes the host CPU.

Examples:
  # Quick platform validity check (auto-detects platform parameters)
  pccs-check.sh check --auto --tdx

  # Register platform manifest automatically with Intel SGX Registration Service
  sudo pccs-check.sh register --subscription "YOUR_PRIMARY_KEY"

  # Register using specific CSV output
  sudo pccs-check.sh register --csv /tmp/pckid_retrieval.csv --subscription "YOUR_PRIMARY_KEY"

  # Check TCB status for auto-detected platform
  pccs-check.sh tcb --tdx

  # Extract FMSPC from PCK cert and check TCB
  sudo $SCRIPT_NAME tcb --cert-file /var/lib/sgx/pck.cert

  # Quick validity check with explicit cert
  sudo $SCRIPT_NAME check --cert-file /var/lib/sgx/pck.cert

  # Get SGX QE identity
  $SCRIPT_NAME qe-identity

  # Get TDX QE (TD_QE) identity
  $SCRIPT_NAME qe-identity --tdx

  # Get QVE identity
  $SCRIPT_NAME qe-identity --enclave-type qve

  # Get TDX TCB info
  $SCRIPT_NAME tcbinfo --fmspc 00A06D080000 --tdx

  # Get revocation list
  $SCRIPT_NAME pckcrl --ca platform

EOF
    exit 0
}

# =============================================================================
# LOGGING
# =============================================================================

log_info() { printf "${GREEN}[OK]${NC} %s\n" "$*"; }
log_warn() { printf "${YELLOW}[WARN]${NC} %s\n" "$*"; }
log_error() { printf "${RED}[ERROR]${NC} %s\n" "$*" >&2; }
log_section() { printf "\n${BLUE}=== %s ===${NC}\n\n" "$*"; }

# =============================================================================
# ARGUMENT PARSING
# =============================================================================

parse_args() {
    if (($# == 0)); then
        usage
    fi

    if [[ "$1" == -* ]]; then
        COMMAND="check"
    else
        COMMAND="$1"
        shift
    fi

    while (($# > 0)); do
        case "$1" in
        --auto)
            AUTO_DETECT=1
            shift
            ;;
        --fmspc)
            FMSPC="$2"
            shift 2
            ;;
        --ppid)
            ENCRYPTED_PPID="$2"
            shift 2
            ;;
        --cpusvn)
            CPUSVN="$2"
            shift 2
            ;;
        --pcesvn)
            PCESVN="$2"
            shift 2
            ;;
        --pceid)
            PCEID="$2"
            shift 2
            ;;
        --platform-manifest)
            PLATFORM_MANIFEST="$2"
            shift 2
            ;;
        --manifest-file)
            MANIFEST_FILE="$2"
            shift 2
            ;;
        --csv)
            CSV_FILE="$2"
            shift 2
            ;;
        --cert-file)
            CERT_FILE="$2"
            shift 2
            ;;
        --pccs-url)
            PCCS_URL="$2"
            shift 2
            ;;
        --enclave-type)
            ENCLAVE_TYPE="$2"
            shift 2
            ;;
        --tdx)
            CHECK_TDX=1
            shift
            ;;
        --update-early)
            UPDATE_EARLY=1
            shift
            ;;
        --ca)
            CRL_CA="$2"
            shift 2
            ;;
        --encoding)
            CRL_ENCODING="$2"
            shift 2
            ;;
        --subscription)
            SUBSCRIPTION_KEY="$2"
            shift 2
            ;;
        --verbose)
            VERBOSE=1
            shift
            ;;
        --help | -h) usage ;;
        *)
            log_error "Unknown option: $1"
            usage
            ;;
        esac
    done
}

# =============================================================================
# CERTIFICATE PARSING
# =============================================================================

# Extract FMSPC from a PCK certificate.
# FMSPC is encoded in the certificate subject as OID 2.16.840.1.74410 (1.3.6.1.4.1.93139.2.1).
# It appears as "FMSPC: <hex>" in openssl subject output.
extract_fmspc_from_cert() {
    local cert_file="$1"

    if [[ ! -f "$cert_file" ]]; then
        log_error "Certificate file not found: ${cert_file}"
        return 1
    fi

    if command -v openssl >/dev/null 2>&1; then
        # Primary: Intel PCK SGX Extension OID 1.2.840.113741.1.13.1.4
        # (ASN.1 DER: 2A864886F84D010D0104 0406 <6-byte-FMSPC>)
        local asn1_dump
        asn1_dump=$(openssl asn1parse -in "$cert_file" 2>/dev/null || true)
        local fmspc
        fmspc=$(echo "$asn1_dump" | grep -oP '(?i)2A864886F84D010D01040406\K[0-9a-fA-F]{12}' | head -1 || true)
        if [[ -n "$fmspc" ]]; then
            echo "$fmspc"
            return 0
        fi

        # Try to extract FMSPC from certificate subject
        local subject
        subject=$(openssl x509 -in "$cert_file" -noout -subject 2>/dev/null || true)

        if [[ -n "$subject" ]]; then
            # FMSPC is in format: /.../FMSPC:012345/...
            fmspc=$(echo "$subject" | grep -oP 'FMSPC:\K[0-9a-fA-F]+' || true)
            if [[ -n "$fmspc" ]]; then
                echo "$fmspc"
                return 0
            fi
        fi

        # Fallback: try to read issuer field
        local issuer
        issuer=$(openssl x509 -in "$cert_file" -noout -issuer 2>/dev/null || true)
        fmspc=$(echo "$issuer" | grep -oP 'FMSPC:\K[0-9a-fA-F]+' || true)
        if [[ -n "$fmspc" ]]; then
            echo "$fmspc"
            return 0
        fi

        # Final fallback: extract from full certificate text
        local cert_text
        cert_text=$(openssl x509 -in "$cert_file" -noout -text 2>/dev/null || true)
        fmspc=$(echo "$cert_text" | grep -i 'fmspc' -A1 | grep -oP '[0-9a-fA-F]{12}' | head -1 || true)
        if [[ -n "$fmspc" ]]; then
            echo "$fmspc"
            return 0
        fi
    fi

    log_error "Could not extract FMSPC from certificate: ${cert_file}"
    return 1
}

# =============================================================================
# AUTOMATIC PLATFORM DISCOVERY & HELPERS
# =============================================================================

# Convert hex string to binary file portably (xxd, python3, perl, or printf)
hex_to_bin() {
    local hex="$1"
    local outfile="$2"
    hex=$(echo "$hex" | tr -d '[:space:]"')
    [[ -n "$hex" ]] || return 1

    if command -v xxd >/dev/null 2>&1; then
        echo "$hex" | xxd -r -p >"$outfile"
    elif command -v python3 >/dev/null 2>&1; then
        python3 -c "import sys, binascii; sys.stdout.buffer.write(binascii.unhexlify(sys.argv[1].strip()))" "$hex" >"$outfile" 2>/dev/null
    elif command -v perl >/dev/null 2>&1; then
        perl -e 'print pack("H*", $ARGV[0])' "$hex" >"$outfile" 2>/dev/null
    else
        (
            local i
            for ((i = 0; i < ${#hex}; i += 2)); do
                printf "\\x${hex:$i:2}"
            done
        ) >"$outfile"
    fi
    [[ -s "$outfile" ]]
}

# Parse a PCK ID retrieval CSV file (generated by PCKIDRetrievalTool).
# Typical columns: EncryptedPPID,PCE_ID,CPUSVN,PCE_ISVSVN,QE_ID,PLATFORM_MANIFEST,FMSPC
parse_pckid_csv() {
    local file="$1"
    [[ -f "$file" && -r "$file" ]] || return 1
    local line
    local found=0
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "$line" || "$line" =~ ^# ]] && continue
        if [[ "$line" =~ ^[Ee]ncryptedPPID || "$line" =~ ^PCE_ID || "$line" =~ ^PLATFORM ]]; then
            continue
        fi
        local csv_ppid csv_pceid csv_cpusvn csv_pcesvn csv_qeid csv_manifest csv_fmspc
        IFS=',' read -r csv_ppid csv_pceid csv_cpusvn csv_pcesvn csv_qeid csv_manifest csv_fmspc <<<"$line"
        # Trim whitespace or trailing CR
        csv_ppid=$(echo "${csv_ppid:-}" | tr -d '[:space:]')
        csv_pceid=$(echo "${csv_pceid:-}" | tr -d '[:space:]')
        csv_cpusvn=$(echo "${csv_cpusvn:-}" | tr -d '[:space:]')
        csv_pcesvn=$(echo "${csv_pcesvn:-}" | tr -d '[:space:]')
        csv_manifest=$(echo "${csv_manifest:-}" | tr -d '[:space:]')
        csv_fmspc=$(echo "${csv_fmspc:-}" | tr -d '[:space:]')

        [[ -z "$ENCRYPTED_PPID" && -n "$csv_ppid" ]] && ENCRYPTED_PPID="$csv_ppid"
        [[ -z "$PCEID" && -n "$csv_pceid" ]] && PCEID="$csv_pceid"
        [[ -z "$CPUSVN" && -n "$csv_cpusvn" ]] && CPUSVN="$csv_cpusvn"
        [[ -z "$PCESVN" && -n "$csv_pcesvn" ]] && PCESVN="$csv_pcesvn"
        [[ -z "$PLATFORM_MANIFEST" && -n "$csv_manifest" ]] && PLATFORM_MANIFEST="$csv_manifest"
        [[ -z "$FMSPC" && -n "$csv_fmspc" ]] && FMSPC="$csv_fmspc"

        if [[ -n "$PLATFORM_MANIFEST" || -n "$ENCRYPTED_PPID" || -n "$CPUSVN" || -n "$FMSPC" ]]; then
            found=1
            break
        fi
    done <"$file"

    if ((found)); then
        if [[ -z "$FMSPC" ]]; then
            try_detect_cpu_fmspc >/dev/null 2>&1 || true
        fi
        return 0
    fi
    return 1
}

# Search standard filesystem paths for existing PCK ID retrieval CSV output
try_find_existing_csv() {
    local csv_candidates=()
    [[ -n "$CSV_FILE" ]] && csv_candidates+=("$CSV_FILE")
    csv_candidates+=(
        "/tmp/pckid_retrieval.csv"
        "/tmp/pckid_manifest.csv"
        "/tmp/pckid_retrieval_auto.csv"
        "/tmp/pckid.csv"
        "./pckid_retrieval.csv"
        "./pckid.csv"
        "/var/cache/pckid_retrieval.csv"
    )
    for csv in "${csv_candidates[@]}"; do
        if [[ -f "$csv" && -r "$csv" ]]; then
            if parse_pckid_csv "$csv"; then
                AUTO_DETECT_SOURCE="CSV file (${csv})"
                return 0
            fi
        fi
    done
    return 1
}

# Try running Intel PCKIDRetrievalTool to query hardware directly
try_run_pckid_tool() {
    local tool=""
    for candidate in "PCKIDRetrievalTool" \
        "/usr/bin/PCKIDRetrievalTool" \
        "/usr/local/bin/PCKIDRetrievalTool" \
        "/opt/intel/sgx-dcap-pck-id-retrieval-tool/PCKIDRetrievalTool"; do
        if command -v "$candidate" >/dev/null 2>&1; then
            tool="$candidate"
            break
        elif [[ -x "$candidate" ]]; then
            tool="$candidate"
            break
        fi
    done

    [[ -n "$tool" ]] || return 1

    local out_csv="/tmp/pckid_retrieval_auto.csv"
    local run_cmd=("$tool" "-f" "$out_csv")
    if [[ "$EUID" -ne 0 ]]; then
        if sudo -n true 2>/dev/null; then
            run_cmd=("sudo" "$tool" "-f" "$out_csv")
        else
            log_warn "Found PCKIDRetrievalTool at ${tool}, but requires root/sudo privileges"
            return 1
        fi
    fi

    log_info "Running PCKIDRetrievalTool (${run_cmd[*]})..."
    if "${run_cmd[@]}" >/dev/null 2>&1 && [[ -s "$out_csv" ]]; then
        if parse_pckid_csv "$out_csv"; then
            AUTO_DETECT_SOURCE="PCKIDRetrievalTool (${out_csv})"
            return 0
        fi
    fi
    return 1
}

# Search standard filesystem paths for existing PCK certificate files
try_find_cached_cert() {
    local cert_candidates=(
        "/var/lib/sgx/pck.cert"
        "/var/lib/sgx/pck_cert.pem"
        "/var/cache/pccs/pck.cert"
        "/run/dcap/pck.cert"
        "/tmp/pck.cert"
        "/tmp/pck.pem"
    )
    for c in "${cert_candidates[@]}"; do
        if [[ -f "$c" && -r "$c" ]]; then
            local extracted
            extracted=$(extract_fmspc_from_cert "$c" 2>/dev/null || true)
            if [[ -n "$extracted" ]]; then
                CERT_FILE="$c"
                FMSPC="$extracted"
                AUTO_DETECT_SOURCE="Cached PCK certificate (${c})"
                return 0
            fi
        fi
    done
    return 1
}

# Try reading from local PCCS SQLite cache database
try_find_pccs_db() {
    command -v sqlite3 >/dev/null 2>&1 || return 1
    local db_paths=(
        "/opt/intel/sgx-dcap-pccs/pccs_server.db"
        "/var/lib/pccs/pccs_server.db"
        "/var/cache/pccs/pccs.db"
    )
    for db in "${db_paths[@]}"; do
        if [[ -f "$db" && -r "$db" ]]; then
            local db_fmspc
            db_fmspc=$(sqlite3 "$db" "SELECT fmspc FROM platforms WHERE fmspc IS NOT NULL AND length(fmspc)=12 LIMIT 1;" 2>/dev/null || true)
            if [[ -z "$db_fmspc" ]]; then
                db_fmspc=$(sqlite3 "$db" "SELECT fmspc FROM pck_certs WHERE fmspc IS NOT NULL AND length(fmspc)=12 LIMIT 1;" 2>/dev/null || true)
            fi
            if [[ -n "$db_fmspc" && "$db_fmspc" =~ ^[0-9a-fA-F]{12}$ ]]; then
                FMSPC="$db_fmspc"
                AUTO_DETECT_SOURCE="Local PCCS database (${db})"
                return 0
            fi
        fi
    done
    return 1
}

# Try inspecting /proc/cpuinfo on Intel hosts to determine processor family/model
try_detect_cpu_fmspc() {
    [[ -r /proc/cpuinfo ]] || return 1
    local vendor model family stepping model_name
    vendor=$(grep -m1 '^vendor_id' /proc/cpuinfo | awk '{print $3}' || true)
    if [[ "$vendor" != "GenuineIntel" ]]; then
        return 1
    fi

    family=$(grep -m1 '^cpu family' /proc/cpuinfo | awk '{print $4}' || true)
    model=$(grep -m1 '^model\s*:' /proc/cpuinfo | awk '{print $3}' || true)
    stepping=$(grep -m1 '^stepping' /proc/cpuinfo | awk '{print $3}' || true)
    model_name=$(grep -m1 '^model name' /proc/cpuinfo | cut -d: -f2- | sed -e 's/^[ \t]*//' || true)

    # Server model numbers (family 6):
    case "$model" in
    143) # Sapphire Rapids (SPR) - 0x8F
        FMSPC="50806F000000"
        CHECK_TDX=1
        AUTO_DETECT_SOURCE="Intel CPU: Sapphire Rapids (${model_name})"
        ;;
    207) # Emerald Rapids (EMR) - 0xCF
        FMSPC="B0C06F000000"
        CHECK_TDX=1
        AUTO_DETECT_SOURCE="Intel CPU: Emerald Rapids (${model_name})"
        ;;
    106) # Ice Lake-SP (ICX) - 0x6A
        FMSPC="00606A000000"
        AUTO_DETECT_SOURCE="Intel CPU: Ice Lake (${model_name})"
        ;;
    173 | 175) # Granite Rapids (GNR) / Sierra Forest (SRF)
        # Xeon 6700P / Granite Rapids stepping 1 uses FMSPC 70A06D070000
        if [[ "$stepping" == "1" ]] || [[ "$model_name" =~ 67[0-9]{2} ]]; then
            FMSPC="70A06D070000"
        else
            FMSPC="00A06D080000"
        fi
        CHECK_TDX=1
        AUTO_DETECT_SOURCE="Intel CPU: Xeon 6 (${model_name})"
        ;;
    *)
        return 1
        ;;
    esac
    return 0
}

# Main platform parameter auto-population entrypoint.
auto_detect_platform() {
    # If user provided FMSPC explicitly, we're done
    if [[ -n "$FMSPC" ]]; then
        return 0
    fi

    # If user provided a CERT_FILE explicitly, extract FMSPC
    if [[ -n "$CERT_FILE" ]]; then
        local extracted
        extracted=$(extract_fmspc_from_cert "$CERT_FILE" 2>/dev/null || true)
        if [[ -n "$extracted" ]]; then
            FMSPC="$extracted"
            log_info "Extracted FMSPC from provided certificate: ${FMSPC}"
            return 0
        fi
    fi

    log_info "Auto-populating platform parameters..."

    # 1. Look for existing PCK ID retrieval CSV
    if try_find_existing_csv; then
        local msg="Auto-detected platform via ${AUTO_DETECT_SOURCE}"
        [[ -n "$FMSPC" ]] && msg+=": FMSPC=${FMSPC}"
        log_info "$msg"
        [[ -n "$PLATFORM_MANIFEST" ]] && log_info "  Manifest: Found (${#PLATFORM_MANIFEST} chars)"
        [[ -n "$CPUSVN" ]] && log_info "  CPUSVN:   ${CPUSVN}"
        [[ -n "$PCESVN" ]] && log_info "  PCESVN:   ${PCESVN}"
        [[ -n "$PCEID" ]] && log_info "  PCEID:    ${PCEID}"
        return 0
    fi

    # 2. Look for cached PCK certificate files
    if try_find_cached_cert; then
        log_info "Auto-detected platform via ${AUTO_DETECT_SOURCE}: FMSPC=${FMSPC}"
        return 0
    fi

    # 3. Try running PCKIDRetrievalTool if installed
    if try_run_pckid_tool; then
        log_info "Auto-detected platform via ${AUTO_DETECT_SOURCE}: FMSPC=${FMSPC}"
        [[ -n "$CPUSVN" ]] && log_info "  CPUSVN:   ${CPUSVN}"
        [[ -n "$PCESVN" ]] && log_info "  PCESVN:   ${PCESVN}"
        [[ -n "$PCEID" ]] && log_info "  PCEID:    ${PCEID}"
        return 0
    fi

    # 4. Try local PCCS database
    if try_find_pccs_db; then
        log_info "Auto-detected platform via ${AUTO_DETECT_SOURCE}: FMSPC=${FMSPC}"
        return 0
    fi

    # 5. Try host CPU detection from /proc/cpuinfo
    if try_detect_cpu_fmspc; then
        log_info "Auto-detected platform via ${AUTO_DETECT_SOURCE}: FMSPC=${FMSPC}"
        return 0
    fi

    return 1
}

require_fmspc() {
    if [[ -z "$FMSPC" ]]; then
        auto_detect_platform || true
    fi

    if [[ -z "$FMSPC" ]]; then
        log_error "Could not auto-detect platform FMSPC."
        echo "Tried the following discovery methods:"
        echo "  1. Cached PCK certs: /var/lib/sgx/*.cert, /var/cache/pccs/*.cert, /run/dcap/*.cert"
        echo "  2. CSV retrieval cache: /tmp/pckid_retrieval.csv, ./pckid.csv"
        echo "  3. Intel PCKIDRetrievalTool hardware probe"
        echo "  4. Local PCCS cache database: /opt/intel/sgx-dcap-pccs/pccs_server.db"
        local vendor cpu_desc
        vendor=$(grep -m1 '^vendor_id' /proc/cpuinfo 2>/dev/null | awk '{print $3}' || echo "unknown")
        cpu_desc=$(grep -m1 '^model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed -e 's/^[ \t]*//' || echo "")
        echo "  5. Intel Xeon CPU detection in /proc/cpuinfo (detected: ${vendor} ${cpu_desc})"
        echo ""
        echo "Provide parameters manually using:"
        echo "  --fmspc <12-hex-chars>   (e.g., --fmspc 00A06D080000)"
        echo "  --cert-file <path>       (path to PCK certificate file)"
        exit 1
    fi
}

# =============================================================================
# HTTP HELPERS
# =============================================================================

# Query PCCS API. Single curl call captures both body and HTTP code.
# Sets global: PCCS_HTTP_CODE, PCCS_RESPONSE
pccs_get() {
    local url="$1"
    local tmpfile
    tmpfile=$(mktemp)

    PCCS_HTTP_CODE=$(curl -s -o "$tmpfile" -w "%{http_code}" -m 30 \
        -X GET \
        ${SUBSCRIPTION_KEY:+-H "Ocp-Apim-Subscription-Key: ${SUBSCRIPTION_KEY}"} \
        "$url" 2>/dev/null) || PCCS_HTTP_CODE="000"

    PCCS_RESPONSE=$(cat "$tmpfile")
    rm -f "$tmpfile"
}

pccs_post() {
    local url="$1"
    local data="$2"
    local tmpfile
    tmpfile=$(mktemp)

    PCCS_HTTP_CODE=$(curl -s -o "$tmpfile" -w "%{http_code}" -m 30 \
        -X POST \
        -H "Content-Type: application/json" \
        ${SUBSCRIPTION_KEY:+-H "Ocp-Apim-Subscription-Key: ${SUBSCRIPTION_KEY}"} \
        -d "$data" \
        "$url" 2>/dev/null) || PCCS_HTTP_CODE="000"

    PCCS_RESPONSE=$(cat "$tmpfile")
    rm -f "$tmpfile"
}

# =============================================================================
# TCB CHECK
# =============================================================================

# Check TCB status for a given FMSPC
cmd_tcb() {
    require_fmspc

    local base_url
    base_url=$(get_pccs_base_url)

    log_section "TCB Status Check for FMSPC: ${FMSPC}"
    log_info "PCS endpoint: ${base_url}tcb"

    local url="${base_url}tcb?fmspc=${FMSPC}"

    if ((UPDATE_EARLY)); then
        url+="&update=early"
        log_info "Requesting early TCB Info update"
    fi

    log_info "Fetching TCB info from PCS..."
    pccs_get "$url"

    if [[ "$PCCS_HTTP_CODE" == "200" ]]; then
        log_info "TCB info retrieved (HTTP ${PCCS_HTTP_CODE})"

        if ((VERBOSE)); then
            echo ""
            echo "=== Full TCB Info Response ==="
            if command -v jq >/dev/null 2>&1; then
                echo "$PCCS_RESPONSE" | jq . 2>/dev/null || echo "$PCCS_RESPONSE"
            else
                echo "$PCCS_RESPONSE"
            fi
            echo "=============================="
        else
            # Parse and display TCB status summary
            if command -v jq >/dev/null 2>&1; then
                local tcb_eval_data_num update_date tcb_levels
                tcb_eval_data_num=$(echo "$PCCS_RESPONSE" | jq -r '.tcbInfo.tcbEvaluationDataNumber // .tcbEvaluationDataNumber // "N/A"' 2>/dev/null || echo "N/A")
                update_date=$(echo "$PCCS_RESPONSE" | jq -r '.tcbInfo.issueDate // .tcbInfo.nextUpdate // .updateDate // "N/A"' 2>/dev/null || echo "N/A")
                tcb_levels=$(echo "$PCCS_RESPONSE" | jq -r '(.tcbInfo.tcbLevels // .tcbLevels) | length' 2>/dev/null || echo "0")

                echo ""
                log_info "TCB Evaluation Data Number: ${tcb_eval_data_num}"
                log_info "Update Date: ${update_date}"
                log_info "TCB Levels available: ${tcb_levels}"
                echo ""

                # Show TCB levels
                echo "TCB Levels:"
                echo "-----------"
                printf '%-6s %-14s %-12s %s\n' "PCESVN" "STATUS" "DATE" "WARNING"
                printf '%-6s %-14s %-12s %s\n' "------" "------" "----" "-------"

                echo "$PCCS_RESPONSE" | jq -r '(.tcbInfo.tcbLevels // .tcbLevels)[] | "\(.tcb.pcesvn // .tcbm // "-")|\(.tcbStatus)|\(.tcbDate // "-")|\(.warning // "")"' 2>/dev/null |
                    while IFS='|' read -r pcesvn status tcb_date warning; do
                        local color="$NC"
                        case "$status" in
                        "UpToDate") color="$GREEN" ;;
                        "BelowMin") color="$RED" ;;
                        *) color="$YELLOW" ;;
                        esac
                        printf '%-6s ' "$pcesvn"
                        printf "${color}%-14s${NC} " "$status"
                        printf '%-12s ' "${tcb_date:0:10}"
                        if [[ -n "$warning" && "$warning" != "null" ]]; then
                            printf "${color}[WARNING: %s]${NC}\n" "$warning"
                        else
                            printf "\n"
                        fi
                    done

                echo ""
                log_info "TCB check complete"
            else
                echo "$PCCS_RESPONSE"
            fi
        fi
    elif [[ "$PCCS_HTTP_CODE" == "404" ]]; then
        log_error "FMSPC ${FMSPC} not found in PCCS (HTTP 404)"
        log_error "Platform may not be registered or FMSPC is incorrect"
        return 1
    elif [[ "$PCCS_HTTP_CODE" == "410" ]]; then
        log_error "TCB Info has been updated. Old data is gone (HTTP 410)."
        log_error "Re-fetch without --update-early to get current TCB Info"
        return 1
    else
        log_error "Failed to get TCB info (HTTP ${PCCS_HTTP_CODE})"
        if [[ -n "$PCCS_RESPONSE" ]]; then
            echo "$PCCS_RESPONSE" | head -5
        fi
        return 1
    fi
}

# =============================================================================
# PCK CERTIFICATE
# =============================================================================

cmd_pckcert() {
    log_section "PCK Certificate Request"

    if [[ -z "$PLATFORM_MANIFEST" && -z "$ENCRYPTED_PPID" ]]; then
        auto_detect_platform || true
    fi

    # Method 1: POST with Platform Manifest (multi-socket)
    if [[ -n "$PLATFORM_MANIFEST" ]]; then

        local body
        body=$(jq -n \
            --arg manifest "$PLATFORM_MANIFEST" \
            --arg cpusvn "${CPUSVN:-}" \
            --arg pcesvn "${PCESVN:-}" \
            --arg pceid "${PCEID:-}" \
            '{
                platformManifest: $manifest,
                cpusvn: ($cpusvn | if . == "" then empty else . end),
                pcesvn: ($pcesvn | if . == "" then empty else . end),
                pceid: ($pceid | if . == "" then empty else . end)
            }' 2>/dev/null) || body="{\"platformManifest\": \"${PLATFORM_MANIFEST}\"}"

        log_info "Sending Platform Manifest to PCCS..."
        pccs_post "${PCCS_URL}pckcert" "$body"

        if [[ "$PCCS_HTTP_CODE" == "200" ]]; then
            log_info "PCK Certificate retrieved (HTTP ${PCCS_HTTP_CODE})"
            echo ""
            echo "$PCCS_RESPONSE"
            echo ""
            log_info "Certificate saved to stdout (PEM format)"
        else
            log_error "Failed to get PCK cert (HTTP ${PCCS_HTTP_CODE})"
            echo "$PCCS_RESPONSE" | head -5
            return 1
        fi
        return 0
    fi

    # Method 2: GET with encrypted PPID (single-socket or registered multi-socket)
    if [[ -n "$ENCRYPTED_PPID" ]]; then
        log_info "Using encrypted PPID (single-socket platform)"

        local url="${PCCS_URL}pckcert?encrypted_ppid=${ENCRYPTED_PPID}"

        if [[ -n "$CPUSVN" ]]; then
            url+="&cpusvn=${CPUSVN}"
        fi
        if [[ -n "$PCESVN" ]]; then
            url+="&pcesvn=${PCESVN}"
        fi
        if [[ -n "$PCEID" ]]; then
            url+="&pceid=${PCEID}"
        fi

        log_info "Fetching PCK certificate from PCCS..."
        pccs_get "$url"

        if [[ "$PCCS_HTTP_CODE" == "200" ]]; then
            log_info "PCK Certificate retrieved (HTTP ${PCCS_HTTP_CODE})"
            echo ""
            echo "$PCCS_RESPONSE"
            echo ""
            log_info "Certificate saved to stdout (PEM format)"
        else
            log_error "Failed to get PCK cert (HTTP ${PCCS_HTTP_CODE})"
            if [[ -n "$PCCS_RESPONSE" ]]; then
                echo "$PCCS_RESPONSE" | head -5
            fi
            return 1
        fi
        return 0
    fi

    log_error "No platform identity provided. Use --ppid (encrypted) or --platform-manifest"
    exit 1
}

# =============================================================================
# PCK CERTIFICATES (ALL TCB LEVELS)
# =============================================================================

cmd_pckcerts() {
    log_section "All PCK Certificates (All TCB Levels)"

    if [[ -z "$PLATFORM_MANIFEST" && -z "$ENCRYPTED_PPID" ]]; then
        auto_detect_platform || true
    fi

    if [[ -n "$PLATFORM_MANIFEST" ]]; then
        log_info "Using Platform Manifest for all TCB levels"

        local body
        body=$(jq -n \
            --arg manifest "$PLATFORM_MANIFEST" \
            --arg pceid "${PCEID:-}" \
            '{
                platformManifest: $manifest,
                pceid: ($pceid | if . == "" then empty else . end)
            }' 2>/dev/null) || body="{\"platformManifest\": \"${PLATFORM_MANIFEST}\"}"

        pccs_post "${PCCS_URL}pckcerts" "$body"

        if [[ "$PCCS_HTTP_CODE" == "200" ]]; then
            log_info "PCK Certificates retrieved (HTTP ${PCCS_HTTP_CODE})"
            if ((VERBOSE)); then
                echo "$PCCS_RESPONSE" | jq . 2>/dev/null || echo "$PCCS_RESPONSE"
            else
                echo "$PCCS_RESPONSE" | jq -r '.[] | "TCBm: \(.tcbm), Cert: \(.cert[:80])..."' 2>/dev/null || echo "$PCCS_RESPONSE"
            fi
        else
            log_error "Failed to get PCK certs (HTTP ${PCCS_HTTP_CODE})"
            echo "$PCCS_RESPONSE" | head -5
            return 1
        fi
        return 0
    fi

    if [[ -n "$ENCRYPTED_PPID" ]]; then
        log_info "Using encrypted PPID for all TCB levels"
        local url="${PCCS_URL}pckcerts?encrypted_ppid=${ENCRYPTED_PPID}"
        if [[ -n "$PCEID" ]]; then
            url+="&pceid=${PCEID}"
        fi

        pccs_get "$url"

        if [[ "$PCCS_HTTP_CODE" == "200" ]]; then
            log_info "PCK Certificates retrieved (HTTP ${PCCS_HTTP_CODE})"
            if ((VERBOSE)); then
                echo "$PCCS_RESPONSE" | jq . 2>/dev/null || echo "$PCCS_RESPONSE"
            else
                echo "$PCCS_RESPONSE" | jq -r '.[] | "TCBm: \(.tcbm), Cert: \(.cert[:80])..."' 2>/dev/null || echo "$PCCS_RESPONSE"
            fi
        else
            log_error "Failed to get PCK certs (HTTP ${PCCS_HTTP_CODE})"
            echo "$PCCS_RESPONSE" | head -5
            return 1
        fi
        return 0
    fi

    log_error "No platform identity provided. Use --ppid or --platform-manifest"
    exit 1
}

# =============================================================================
# PCK CRL (REVOCATION LIST)
# =============================================================================

cmd_pckcrl() {
    if [[ -z "$CRL_CA" ]]; then
        log_info "No CA type specified (--ca), defaulting to 'processor'"
        CRL_CA="processor"
    fi

    log_section "PCK Certificate Revocation List"
    log_info "CA Type: ${CRL_CA}"
    log_info "Encoding: ${CRL_ENCODING}"

    local url="${PCCS_URL}pckcrl?ca=${CRL_CA}"
    if [[ "$CRL_ENCODING" != "pem" ]]; then
        url+="&encoding=${CRL_ENCODING}"
    fi

    log_info "Fetching CRL from PCCS..."
    pccs_get "$url"

    if [[ "$PCCS_HTTP_CODE" == "200" ]]; then
        log_info "CRL retrieved (HTTP ${PCCS_HTTP_CODE})"
        echo ""
        echo "$PCCS_RESPONSE"
        echo ""
        log_info "CRL saved to stdout"
    else
        log_error "Failed to get CRL (HTTP ${PCCS_HTTP_CODE})"
        if [[ -n "$PCCS_RESPONSE" ]]; then
            echo "$PCCS_RESPONSE" | head -5
        fi
        return 1
    fi
}

# =============================================================================
# TCB INFO (SGX or TDX)
# =============================================================================

cmd_tcbinfo() {
    require_fmspc

    local base_url
    base_url=$(get_pccs_base_url)

    log_section "TCB Info"
    log_info "FMSPC: ${FMSPC}"

    local url="${base_url}tcb?fmspc=${FMSPC}"
    if ((UPDATE_EARLY)); then
        url+="&update=early"
    fi
    log_info "Endpoint: ${url}"

    pccs_get "$url"

    if [[ "$PCCS_HTTP_CODE" == "200" ]]; then
        log_info "TCB Info retrieved (HTTP ${PCCS_HTTP_CODE})"
        if ((VERBOSE)); then
            echo ""
            echo "=== Full TCB Info ==="
            if command -v jq >/dev/null 2>&1; then
                echo "$PCCS_RESPONSE" | jq . 2>/dev/null || echo "$PCCS_RESPONSE"
            else
                echo "$PCCS_RESPONSE"
            fi
            echo "===================="
        else
            if command -v jq >/dev/null 2>&1; then
                local data_num update_date level_count
                data_num=$(echo "$PCCS_RESPONSE" | jq -r '.tcbInfo.tcbEvaluationDataNumber // .tcbEvaluationDataNumber // "N/A"' 2>/dev/null || echo "N/A")
                update_date=$(echo "$PCCS_RESPONSE" | jq -r '.tcbInfo.issueDate // .tcbInfo.nextUpdate // .updateDate // "N/A"' 2>/dev/null || echo "N/A")
                level_count=$(echo "$PCCS_RESPONSE" | jq -r '(.tcbInfo.tcbLevels // .tcbLevels) | length' 2>/dev/null || echo "0")
                log_info "TCB Evaluation Data Number: ${data_num}"
                log_info "Update Date: ${update_date}"
                log_info "TCB Levels: ${level_count}"
            else
                echo "$PCCS_RESPONSE"
            fi
        fi
    elif [[ "$PCCS_HTTP_CODE" == "404" ]]; then
        log_error "FMSPC ${FMSPC} not found in PCCS (HTTP 404)"
        return 1
    else
        log_error "Failed to get TCB Info (HTTP ${PCCS_HTTP_CODE})"
        if [[ -n "$PCCS_RESPONSE" ]]; then
            echo "$PCCS_RESPONSE" | head -5
        fi
        return 1
    fi
}

# =============================================================================
# QE / QVE / QAE IDENTITY
# =============================================================================

cmd_qe_identity() {
    log_section "Enclave Identity"

    local base_url
    base_url=$(get_pccs_base_url)

    local target_type="${ENCLAVE_TYPE:-qe}"
    target_type=$(echo "$target_type" | tr '[:upper:]' '[:lower:]')

    local endpoint=""
    local desc=""

    case "$target_type" in
    qe)
        endpoint="qe/identity"
        if ((CHECK_TDX)); then
            desc="TDX Quoting Enclave (TD_QE)"
        else
            desc="SGX Quoting Enclave (QE)"
        fi
        ;;
    qve)
        endpoint="qve/identity"
        desc="SGX Quote Verification Enclave (QVE)"
        ;;
    qae)
        endpoint="qae/identity"
        desc="SGX Quote Application Enclave (QAE)"
        ;;
    *)
        log_error "Unknown enclave type: ${target_type} (valid: qe, qve, qae)"
        return 1
        ;;
    esac

    local url="${base_url}${endpoint}"
    if ((UPDATE_EARLY)); then
        url+="?update=early"
    fi

    log_info "Fetching ${desc} identity..."
    log_info "Endpoint: ${url}"
    pccs_get "$url"

    if [[ "$PCCS_HTTP_CODE" == "200" ]]; then
        log_info "Enclave identity retrieved (HTTP ${PCCS_HTTP_CODE})"
        if ((VERBOSE)); then
            echo ""
            echo "=== Full Response ==="
            if command -v jq >/dev/null 2>&1; then
                echo "$PCCS_RESPONSE" | jq . 2>/dev/null || echo "$PCCS_RESPONSE"
            else
                echo "$PCCS_RESPONSE"
            fi
            echo "==================="
        else
            if command -v jq >/dev/null 2>&1; then
                local enc_id enc_ver issue_date next_update eval_num mrsigner isvprodid tcb_count latest_status
                enc_id=$(echo "$PCCS_RESPONSE" | jq -r '.enclaveIdentity.id // .id // "N/A"')
                enc_ver=$(echo "$PCCS_RESPONSE" | jq -r '.enclaveIdentity.version // .version // "N/A"')
                issue_date=$(echo "$PCCS_RESPONSE" | jq -r '.enclaveIdentity.issueDate // "N/A"')
                next_update=$(echo "$PCCS_RESPONSE" | jq -r '.enclaveIdentity.nextUpdate // "N/A"')
                eval_num=$(echo "$PCCS_RESPONSE" | jq -r '.enclaveIdentity.tcbEvaluationDataNumber // "N/A"')
                mrsigner=$(echo "$PCCS_RESPONSE" | jq -r '.enclaveIdentity.mrsigner // "N/A"')
                isvprodid=$(echo "$PCCS_RESPONSE" | jq -r '.enclaveIdentity.isvprodid // "N/A"')
                tcb_count=$(echo "$PCCS_RESPONSE" | jq -r '(.enclaveIdentity.tcbLevels // .tcbLevels) | length // 0')
                latest_status=$(echo "$PCCS_RESPONSE" | jq -r '(.enclaveIdentity.tcbLevels[0].tcbStatus // .tcbLevels[0].tcbStatus) // "N/A"')

                echo ""
                printf "  %-26s %s\n" "Enclave ID:" "${enc_id}"
                printf "  %-26s %s\n" "Identity Version:" "${enc_ver}"
                printf "  %-26s %s\n" "MRSIGNER:" "${mrsigner}"
                printf "  %-26s %s\n" "ISV Product ID:" "${isvprodid}"
                printf "  %-26s %s\n" "TCB Evaluation Data Num:" "${eval_num}"
                printf "  %-26s %s\n" "Issue Date:" "${issue_date}"
                printf "  %-26s %s\n" "Next Update:" "${next_update}"
                printf "  %-26s %s\n" "TCB Levels Count:" "${tcb_count}"
                printf "  %-26s %s\n" "Latest TCB Status:" "${latest_status}"
                echo ""
            else
                echo "$PCCS_RESPONSE"
            fi
        fi
    else
        log_error "Failed to get enclave identity (HTTP ${PCCS_HTTP_CODE})"
        if [[ -n "$PCCS_RESPONSE" ]]; then
            echo "$PCCS_RESPONSE" | head -5
        fi
        return 1
    fi
}

# =============================================================================
# COLLATERAL FETCH
# =============================================================================

cmd_collateral() {
    log_section "Collateral Fetch (TCB Info + PCK Cert Chain)"
    require_fmspc

    local base_url
    base_url=$(get_pccs_base_url)

    local url="${base_url}collateral?fmspc=${FMSPC}"
    if ((UPDATE_EARLY)); then
        url+="&update=early"
    fi

    log_info "Fetching collateral from: ${url}"
    pccs_get "$url"

    if [[ "$PCCS_HTTP_CODE" == "200" ]]; then
        log_info "Collateral retrieved (HTTP ${PCCS_HTTP_CODE})"
        if ((VERBOSE)); then
            echo ""
            echo "=== Full Collateral Response ==="
            if command -v jq >/dev/null 2>&1; then
                echo "$PCCS_RESPONSE" | jq . 2>/dev/null || echo "$PCCS_RESPONSE"
            else
                echo "$PCCS_RESPONSE"
            fi
            echo "================================"
        else
            if command -v jq >/dev/null 2>&1; then
                log_info "TCB Info: $(echo "$PCCS_RESPONSE" | jq -r '.tcbInfo // "N/A" | if . == "N/A" then "not included" else "included" end')"
                log_info "PCK Cert Chain: $(echo "$PCCS_RESPONSE" | jq -r '.pckCertChain // "N/A" | if . == "N/A" then "not included" else "included" end')"
                log_info "PCK CRL: $(echo "$PCCS_RESPONSE" | jq -r '.pckCrl // "N/A" | if . == "N/A" then "not included" else "included" end')"
                log_info "Root CRL: $(echo "$PCCS_RESPONSE" | jq -r '.rootCrl // "N/A" | if . == "N/A" then "not included" else "included" end')"
                log_info "QE Identity: $(echo "$PCCS_RESPONSE" | jq -r '.qeIdentity // "N/A" | if . == "N/A" then "not included" else "included" end')"
            else
                echo "$PCCS_RESPONSE"
            fi
        fi
    elif [[ "$PCCS_HTTP_CODE" == "404" ]]; then
        log_error "Failed to get collateral (HTTP 404)"
        log_warn "Note: Aggregated /collateral endpoints are served by local PCCS caches or cloud providers (Azure), not direct Intel PCS"
        return 1
    else
        log_error "Failed to get collateral (HTTP ${PCCS_HTTP_CODE})"
        if [[ -n "$PCCS_RESPONSE" ]]; then
            echo "$PCCS_RESPONSE" | head -5
        fi
        return 1
    fi
}

# =============================================================================
# QUICK PLATFORM CHECK
# =============================================================================

cmd_check() {
    local exit_code=0
    local base_url
    base_url=$(get_pccs_base_url)

    require_fmspc

    echo "============================================"
    echo " Intel PCCS Platform Validity Check"
    echo " FMSPC: ${FMSPC}"
    if [[ -n "$AUTO_DETECT_SOURCE" ]]; then
        echo " Source: ${AUTO_DETECT_SOURCE}"
    fi
    echo "============================================"
    echo ""

    # Check 1: TCB status
    log_section "1. TCB Status Check"
    local tcb_url="${base_url}tcb?fmspc=${FMSPC}"
    if ((UPDATE_EARLY)); then
        tcb_url+="&update=early"
    fi
    pccs_get "$tcb_url"

    if [[ "$PCCS_HTTP_CODE" == "200" ]]; then
        log_info "TCB info available"
        if command -v jq >/dev/null 2>&1; then
            local data_num
            data_num=$(echo "$PCCS_RESPONSE" | jq -r '.tcbInfo.tcbEvaluationDataNumber // .tcbEvaluationDataNumber // "N/A"' 2>/dev/null || echo "N/A")
            log_info "TCB Evaluation Data Number: ${data_num}"

            # Check if platform TCB is up to date
            local current_tcbm
            if [[ -n "$CPUSVN" && -n "$PCESVN" ]]; then
                current_tcbm="${CPUSVN}${PCESVN}"
                local status
                status=$(echo "$PCCS_RESPONSE" | jq -r --arg tcbm "$current_tcbm" \
                    '(.tcbInfo.tcbLevels // .tcbLevels)[] | select(.tcbm == $tcbm) | .tcbStatus' 2>/dev/null || echo "")
                if [[ "$status" == "UpToDate" ]]; then
                    log_info "Platform TCB status: Up to date"
                elif [[ "$status" == "BelowMin" ]]; then
                    log_warn "Platform TCB status: Below minimum (TCB recovery needed)"
                    exit_code=1
                else
                    log_warn "Platform TCB status: ${status:-unknown}"
                fi
            else
                local top_status top_pcesvn top_date
                top_status=$(echo "$PCCS_RESPONSE" | jq -r '(.tcbInfo.tcbLevels // .tcbLevels)[0].tcbStatus // "N/A"' 2>/dev/null || echo "N/A")
                top_pcesvn=$(echo "$PCCS_RESPONSE" | jq -r '(.tcbInfo.tcbLevels // .tcbLevels)[0].tcb.pcesvn // "N/A"' 2>/dev/null || echo "N/A")
                top_date=$(echo "$PCCS_RESPONSE" | jq -r '(.tcbInfo.tcbLevels // .tcbLevels)[0].tcbDate // "N/A"' 2>/dev/null || echo "N/A")
                log_info "Latest PCS TCB level for this platform: ${top_status} (PCESVN: ${top_pcesvn}, Date: ${top_date})"
            fi
        fi
    elif [[ "$PCCS_HTTP_CODE" == "404" ]]; then
        log_error "FMSPC ${FMSPC} not found in PCCS"
        exit_code=1
    else
        log_error "TCB check failed (HTTP ${PCCS_HTTP_CODE})"
        exit_code=1
    fi

    # Check 2: CRL (revocation)
    log_section "2. Revocation List Check"
    for ca_type in processor platform; do
        local crl_url="${PCCS_URL}pckcrl?ca=${ca_type}"
        pccs_get "$crl_url"
        if [[ "$PCCS_HTTP_CODE" == "200" ]]; then
            log_info "CRL available for CA: ${ca_type}"
        else
            log_warn "CRL not available for CA: ${ca_type} (HTTP ${PCCS_HTTP_CODE})"
        fi
    done

    # Check 3: PCK certificate (if cert file provided)
    if [[ -n "$CERT_FILE" ]]; then
        log_section "3. PCK Certificate Check"
        if command -v openssl >/dev/null 2>&1; then
            local cert_subject cert_issuer cert_dates
            cert_subject=$(openssl x509 -in "$CERT_FILE" -noout -subject 2>/dev/null || true)
            cert_issuer=$(openssl x509 -in "$CERT_FILE" -noout -issuer 2>/dev/null || true)
            cert_dates=$(openssl x509 -in "$CERT_FILE" -noout -dates 2>/dev/null || true)

            if [[ -n "$cert_subject" ]]; then
                log_info "Certificate subject: $(echo "$cert_subject" | sed 's/subject=//')"
            fi
            if [[ -n "$cert_issuer" ]]; then
                log_info "Certificate issuer: $(echo "$cert_issuer" | sed 's/issuer=//')"
            fi
            if [[ -n "$cert_dates" ]]; then
                log_info "Certificate dates:"
                echo "$cert_dates" | sed 's/^/  /'
            fi

            # Check if certificate is valid (not expired)
            if openssl x509 -in "$CERT_FILE" -noout -checkend 0 2>/dev/null; then
                log_info "Certificate is currently valid (not expired)"
            else
                log_error "Certificate has expired!"
                exit_code=1
            fi

            # Check if certificate will expire within 30 days
            if openssl x509 -in "$CERT_FILE" -noout -checkend $((30 * 86400)) 2>/dev/null; then
                log_info "Certificate is valid for at least 30 more days"
            else
                log_warn "Certificate expires within 30 days"
            fi
        else
            log_warn "openssl not found, skipping certificate validation"
        fi
    fi

    # Check 4: PCCS reachability (use TCB endpoint as it always returns 400 for invalid FMSPC)
    log_section "4. PCCS Reachability"
    pccs_get "${base_url}tcb"
    if [[ "$PCCS_HTTP_CODE" == "200" || "$PCCS_HTTP_CODE" == "400" || "$PCCS_HTTP_CODE" == "401" ]]; then
        log_info "PCCS is reachable (HTTP ${PCCS_HTTP_CODE})"
    else
        log_error "Cannot reach PCCS (HTTP ${PCCS_HTTP_CODE})"
        exit_code=1
    fi

    echo ""
    if ((exit_code == 0)); then
        log_info "Platform validity check complete: ALL CHECKS PASSED"
    else
        log_error "Platform validity check complete: SOME CHECKS FAILED"
    fi

    return $exit_code
}

# =============================================================================
# QCNL CONFIGURATION & PERMISSION DIAGNOSTICS
# =============================================================================

cmd_qcnl() {
    log_section "DCAP QCNL Configuration & Permissions Diagnostic"
    local config_files=("/etc/sgx_default_qcnl.conf" "/etc/dcap/qcnl.conf" "/run/dcap/qcnl.conf" "./sgx_default_qcnl.conf" "./qcnl.conf")
    local found=0
    local exit_code=0

    for cfg in "${config_files[@]}"; do
        if [[ -f "$cfg" ]]; then
            found=1
            echo "--- Checking config file: $cfg ---"
            if command -v jq >/dev/null 2>&1; then
                if jq . "$cfg" >/dev/null 2>&1; then
                    log_info "JSON syntax: VALID"
                else
                    log_error "JSON syntax: INVALID JSON"
                    exit_code=1
                    continue
                fi
            fi

            local owner perms
            owner=$(stat -c "%U:%G" "$cfg" 2>/dev/null || stat -f "%Su:%Sg" "$cfg" 2>/dev/null || echo "unknown")
            perms=$(stat -c "%a" "$cfg" 2>/dev/null || stat -f "%OLp" "$cfg" 2>/dev/null || echo "unknown")
            log_info "Ownership: ${owner}, Permissions: ${perms}"

            if [[ "$perms" =~ [4567]$ ]]; then
                log_info "World-readable: YES (${perms})"
            else
                log_warn "World-readable: NO (${perms}). Non-root services like 'coco_as' (CoCo-AS) will fail to read this file and trigger SGX_QL_NETWORK_ERROR (0xe019)!"
                log_warn "Fix with: sudo chmod 644 ${cfg}"
                exit_code=1
            fi

            local pccs_url collateral_url
            if command -v jq >/dev/null 2>&1; then
                pccs_url=$(jq -r '.pccs_url // empty' "$cfg" 2>/dev/null)
                collateral_url=$(jq -r '.collateral_service // empty' "$cfg" 2>/dev/null)
            else
                pccs_url=$(grep -oP '"pccs_url"\s*:\s*"\K[^"]+' "$cfg" 2>/dev/null || true)
                collateral_url=$(grep -oP '"collateral_service"\s*:\s*"\K[^"]+' "$cfg" 2>/dev/null || true)
            fi

            log_info "pccs_url: ${pccs_url:-<NOT SET>}"
            if [[ -n "$collateral_url" ]]; then
                log_info "collateral_service: ${collateral_url}"
            else
                log_warn "collateral_service: NOT SET (recommended to explicitly set to ${pccs_url:-PCS URL})"
            fi

            local test_url="${collateral_url:-$pccs_url}"
            if [[ -n "$test_url" ]]; then
                local qve_url="${test_url%/}/qve/identity"
                local qve_code
                qve_code=$(curl -s -o /dev/null -w "%{http_code}" "$qve_url" 2>/dev/null || echo "000")
                if [[ "$qve_code" == "200" ]]; then
                    log_info "Reachability (${qve_url}): HTTP 200 OK"
                else
                    log_error "Reachability (${qve_url}): HTTP ${qve_code} (Network or URL issue)"
                    exit_code=1
                fi
            fi
            echo ""
        fi
    done

    if ((! found)); then
        log_error "No QCNL configuration file found among: ${config_files[*]}"
        exit_code=1
    fi

    if id coco_as >/dev/null 2>&1; then
        echo "--- Checking CoCo-AS (coco_as) user privileges ---"
        if id -nG coco_as | grep -qw "sgx_prv"; then
            log_info "User 'coco_as' is a member of group 'sgx_prv'"
        else
            log_warn "User 'coco_as' is NOT in group 'sgx_prv'. If QCNL files are group-restricted, CoCo-AS will fail."
            log_warn "Fix with: sudo usermod -aG sgx_prv coco_as"
        fi
        if [[ -f /etc/systemd/system/grpc-as.service.d/override.conf ]]; then
            if grep -q "QCNL_CONF_PATH" /etc/systemd/system/grpc-as.service.d/override.conf; then
                log_info "grpc-as service has QCNL_CONF_PATH configured"
            else
                log_warn "grpc-as override does not set QCNL_CONF_PATH"
            fi
        fi
    fi

    return $exit_code
}

# =============================================================================
# PLATFORM REGISTRATION (Intel SGX Registration Service)
# =============================================================================

cmd_register() {
    auto_detect_platform

    if [[ -z "$SUBSCRIPTION_KEY" ]]; then
        log_error "Intel Registration Service primary key required. Specify --subscription <key>"
        return 1
    fi

    local manifest_bin=""
    local tmp_manifest=0

    if [[ -n "$MANIFEST_FILE" && -f "$MANIFEST_FILE" ]]; then
        manifest_bin="$MANIFEST_FILE"
    elif [[ -n "$PLATFORM_MANIFEST" ]]; then
        manifest_bin="/tmp/platform_manifest_$$.bin"
        if ! hex_to_bin "$PLATFORM_MANIFEST" "$manifest_bin"; then
            log_error "Failed to decode PLATFORM_MANIFEST hex string"
            return 1
        fi
        tmp_manifest=1
    elif [[ -f "/tmp/platform_manifest.bin" ]]; then
        manifest_bin="/tmp/platform_manifest.bin"
    else
        # Try retrieving manifest in non-enclave mode if PCKIDRetrievalTool is available
        local tool=""
        for candidate in "PCKIDRetrievalTool" "/opt/intel/sgx-dcap-pck-id-retrieval-tool/PCKIDRetrievalTool"; do
            if command -v "$candidate" >/dev/null 2>&1 || [[ -x "$candidate" ]]; then
                tool="$candidate"
                break
            fi
        done
        if [[ -n "$tool" ]]; then
            local hostname_id
            hostname_id=$(hostname -s 2>/dev/null || echo "host")
            log_info "Querying UEFI platform manifest via non-enclave mode (${tool} -platform_id ${hostname_id})..."
            local out_csv="/tmp/pckid_manifest.csv"
            local run_cmd=("$tool" "-platform_id" "$hostname_id" "-f" "$out_csv")
            ((EUID != 0)) && run_cmd=("sudo" "${run_cmd[@]}")
            if "${run_cmd[@]}" >/dev/null 2>&1 && [[ -s "$out_csv" ]]; then
                if parse_pckid_csv "$out_csv" && [[ -n "$PLATFORM_MANIFEST" ]]; then
                    manifest_bin="/tmp/platform_manifest_$$.bin"
                    if hex_to_bin "$PLATFORM_MANIFEST" "$manifest_bin"; then
                        tmp_manifest=1
                    fi
                fi
            fi
        fi
    fi

    if [[ -z "$manifest_bin" || ! -f "$manifest_bin" || ! -s "$manifest_bin" ]]; then
        log_error "No Platform Manifest found."
        echo ""
        echo "Check what was generated by PCKIDRetrievalTool:"
        echo "  head -n 2 /tmp/pckid_retrieval.csv"
        return 1
    fi

    log_info "Submitting Platform Manifest ($(wc -c <"$manifest_bin" | tr -d ' ') bytes) to Intel Registration Service..."
    local reg_url="https://api.trustedservices.intel.com/sgx/registration/v1/platform"
    local response_file="/tmp/intel_reg_resp_$$.txt"
    local http_code
    http_code=$(curl -s -w "%{http_code}" -o "$response_file" \
        -X POST "$reg_url" \
        -H "Content-Type: application/octet-stream" \
        -H "Ocp-Apim-Subscription-Key: ${SUBSCRIPTION_KEY}" \
        --data-binary @"$manifest_bin")

    if [[ "$http_code" == "201" ]]; then
        local ppid
        ppid=$(cat "$response_file" | tr -d '[:space:]"')
        log_info "Platform registered successfully! (HTTP 201 Created)"
        echo "  Registered PPID: ${ppid}"
        echo "  Intel PCS will now provision PCK certificates for this platform."
        echo ""
        log_info "Validating platform reachability on Intel PCS..."
        cmd_check --tdx || true
    elif [[ "$http_code" == "200" ]]; then
        log_info "Platform registration succeeded (HTTP 200)"
        cat "$response_file"
        echo ""
        log_info "Validating platform reachability on Intel PCS..."
        cmd_check --tdx || true
    else
        log_error "Platform registration failed (HTTP ${http_code})"
        cat "$response_file"
        echo ""
        echo "Check your subscription key and ensure it is for the 'Intel® Software Guard Extensions Registration Service'."
    fi

    rm -f "$response_file"
    ((tmp_manifest)) && rm -f "$manifest_bin"
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    parse_args "$@"

    case "$COMMAND" in
    tcb) cmd_tcb ;;
    pckcert) cmd_pckcert ;;
    pckcerts) cmd_pckcerts ;;
    pckcrl) cmd_pckcrl ;;
    tcbinfo) cmd_tcbinfo ;;
    qe-identity) cmd_qe_identity ;;
    collateral) cmd_collateral ;;
    check) cmd_check ;;
    qcnl) cmd_qcnl ;;
    register) cmd_register ;;
    help | --help | -h) usage ;;
    *)
        log_error "Unknown command: ${COMMAND}"
        echo ""
        usage
        ;;
    esac
}

main "$@"
