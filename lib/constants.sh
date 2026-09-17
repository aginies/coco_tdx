# =============================================================================
# 1. CONSTANTS & DEFAULTS
# =============================================================================
# NOTE: This file defines shared state consumed by functions across all other
# lib/*.sh files. SC2034 "appears unused" warnings from static analysis are
# expected and suppressed below — these variables are consumed cross-file.
# shellcheck disable=SC2034,SC2155

readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_VERSION="1.0.0"
# SCRIPT_DIR is defined in the main script before sourcing these files.

# Platform check & registration
CHECK_PLATFORM=0
SUBSCRIPTION_KEY=""
CSV_FILE=""

# VM defaults
VM_NAME="tdx-guest"
VM_NO_TDX=0
VM_NO_TDX_NAME="nontdx-guest"
VM_DISPLAY_NAME=""
VM_MEM=16384 # MiB (16 GB)
VM_CPU=4
VM_DISK="32G"
VM_DISK_PATH="/var/lib/libvirt/images/tdx-guest.qcow2"
VM_XML_PATH="/var/lib/libvirt/tdx-guest.xml"
VM_NO_TDX_DISK_PATH="/var/lib/libvirt/images/nontdx-guest.qcow2"
VM_NO_TDX_XML_PATH="/var/lib/libvirt/nontdx-guest.xml"
# VNC listen address for the guest display. 0.0.0.0 so a remote VNC client
# can see the installer (matches the proven working reference); use
# 127.0.0.1 to keep VNC host-local only.
VNC_LISTEN="0.0.0.0"
# VM creation engine: auto (virt-install if available, else generated XML),
# virt (force virt-install), xml (force generated XML)
VM_CREATOR="auto"
# setup-vm: print the virt-install command without executing
DRY_RUN=0
CONVERT_VM_NAME=""
# QGS unix socket (libvirt default). SUSE qgsd listens here.
QGS_SOCKET="/var/run/tdx-qgs/qgs.socket"

# Attestation endpoints
# PCS (Platform Certification Service): Intel's global, authoritative service
# for PCK certificates / TCB info. Method 1 ('--collateral pcs') points QCNL
# and CoCo-AS directly at it.
PCS_URL="${PCS_URL:-https://api.trustedservices.intel.com/sgx/certification/v4/}"
# PCCS (Platform Configuration and Certification Service): a local/regional
# *cache* of PCS. Method 2 ('--collateral pccs') uses a local caching service.
PCCS_URL="http://127.0.0.1:8081"
# Optional path to custom PCCS root CA certificate (for HTTPS self-signed)
PCCS_CA=""
# PCCS identifier (optional identifier if used by custom deployments)
PCCS_ID=""
# Whether QCNL should enforce TLS certificate validation (auto, true, false)
USE_SECURE_CERT="auto"
# Collateral source: pcs (method 1, global) or pccs (method 2, local cache).
COLLATERAL_MODE="pcs"
# grpc-as defaults to 127.0.0.1:3000 when the config has no listen field (SUSE
# package behavior). Override with --coco-as for other topologies.
COCO_AS="127.0.0.1:3000"
KBS_PORT=8080
# KBS address reachable by BOTH host and guest. virbr0 gateway works for the
# libvirt 'default' network. Override with --kbs-url for other topologies.
KBS_HOST="192.168.122.1"
KBS_URL="" # derived from KBS_HOST:KBS_PORT if empty

# Secret delivery (KBS) defaults
SECRET_PATH="default/test/secret"
SECRET_FILE=""
# secret-get mode:
#   guest = run kbs-client inside the TD (needs the TDX-enabled build)
#   host  = host-side attest (grpcurl) + KBS REST curl (no build needed)
SECRET_MODE="guest"
# Populated by attest_get_ear_token() with the EAR JWT from CoCo-AS.
EAR_TOKEN=""
# Last base64 TDX quote fetched from the guest (set by attest_get_ear_token).
# Reused by the --register-rv flow to re-evaluate the SAME quote instead of
# generating a fresh one — test_tdx_attest extends RTMR2/RTMR3 on every run,
# so a fresh quote would carry a different rtmr_2.
LAST_QUOTE_B64=""
# kbs-client location inside the guest.
# The distro 'trustee' package ships a kbs-client WITHOUT TDX attester (falls
# back to fake "Sample Attester"). We build a TDX-enabled one from source and
# install it here; the package version is the fallback (its path is
# distro-specific — see lib/distros/).
KBS_CLIENT_GUEST="/usr/local/bin/kbs-client-tdx"
# Upstream sources for building the TDX-enabled kbs-client
TRUSTEE_REPO="https://github.com/confidential-containers/trustee.git"
TRUSTEE_BUILD_DIR="/root/trustee-build"

# Guest access
GUEST_IP=""
GUEST_WORKDIR="/root/tdx-attest"
SSH_KEY="$HOME/.ssh/id_ed25519"
GUEST_ISO=""
GUEST_USER="root"

# Logging
LOG_FILE="/var/log/tdx-attest.log"
DEBUG=0
QUIET=0
FORCE=0
REGISTER_RV=0
RV_ID=""

# NOTE: package names and distro-specific binary paths live in the
# distribution adapter (lib/distros/<id>.sh), not here.

# Paths
readonly QCNL_RUN_CONF="/run/dcap/qcnl.conf"
readonly QCNL_ETC_CONF="/etc/dcap/qcnl.conf"
# Default QCNL config shipped by the QPL package.
readonly QCNL_PKG_CONF="/etc/sgx_default_qcnl.conf"
# PCCS root CA (method 2): fetched from PCS, added to the system trust store.
readonly PCCS_ROOT_CA="/etc/pki/ca-trust/source/anchors/intel-pccs-root-ca.pem"
readonly GRPC_AS_CONF="/etc/grpc-as.json"
readonly KBS_CONF="/etc/kbs.json"
# CoCo-AS JWKS fetched to a local file; KBS only accepts file:// or https:// for
# trusted_jwk_sets (http:// is rejected).
readonly KBS_JWKS_FILE="/etc/trustee/jwks.json"
readonly RVPS_CONF="/etc/rvps.json"
readonly AS_STORAGE_DIR="/var/lib/attestation-service/storage"

# Trustee / KBS admin material (for secret delivery)
readonly TRUSTEE_DIR="/etc/trustee"
readonly KBS_ADMIN_KEY="${TRUSTEE_DIR}/kbs-admin.key"
readonly KBS_ADMIN_PUB="${TRUSTEE_DIR}/kbs-admin.pub"
readonly KBS_POLICY="${TRUSTEE_DIR}/resource-policy.rego"

# CoCo-AS token signer (persistent EC key pair). Without a signer, grpc-as
# generates an ephemeral key and does not serve the JWKS endpoint, so KBS
# cannot verify attestation tokens. Stored under the AS storage dir (owned by
# coco_as) because /etc/trustee is 750 root:coco_kbs and coco_as cannot
# traverse it.
readonly AS_SIGNER_DIR="${AS_STORAGE_DIR}/signer"
readonly AS_SIGNER_KEY="${AS_SIGNER_DIR}/as-signer.key"
readonly AS_SIGNER_PUB="${AS_SIGNER_DIR}/as-signer.pub"
