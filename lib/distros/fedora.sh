# =============================================================================
# Fedora / RHEL adapter — STUB (not implemented yet)
# =============================================================================
# Hook contract: see lib/distros/_detect.sh. Expected implementation:
#   - dnf-based pkg_* functions (dnf makecache / dnf install -y / rpm -q)
#   - pkgs_<role>: qemu-kvm, edk2-ovmf, libvirt-daemon-driver-qemu, ...
#   - QGS, Trustee and TDX-OVMF are NOT packaged for Fedora upstream — those
#     roles need source-build strategies (cf. build_kbs_client_tdx in
#     lib/helpers.sh as the precedent).
# The main script refuses to start on a stub adapter; the hooks below die
# loudly as defense in depth.

fedora_stub=1
fedora_pkg_manager() { echo "dnf"; }
fedora_pkg_refresh() { die "Fedora/RHEL adapter is not implemented yet (lib/distros/fedora.sh is a stub)"; }
fedora_pkg_installed() { die "Fedora/RHEL adapter is not implemented yet (lib/distros/fedora.sh is a stub)"; }
fedora_pkg_install() { die "Fedora/RHEL adapter is not implemented yet (lib/distros/fedora.sh is a stub)"; }
fedora_pkg_list_all() { die "Fedora/RHEL adapter is not implemented yet (lib/distros/fedora.sh is a stub)"; }
fedora_ovmf_tdx_probe() { die "Fedora/RHEL adapter is not implemented yet (lib/distros/fedora.sh is a stub)"; }
fedora_ovmf_regular_probe() { die "Fedora/RHEL adapter is not implemented yet (lib/distros/fedora.sh is a stub)"; }
fedora_grub_tdx_hint() { die "Fedora/RHEL adapter is not implemented yet (lib/distros/fedora.sh is a stub)"; }
fedora_ca_trust_refresh() { die "Fedora/RHEL adapter is not implemented yet (lib/distros/fedora.sh is a stub)"; }
fedora_guest_pkg_install() { die "Fedora/RHEL adapter is not implemented yet (lib/distros/fedora.sh is a stub)"; }
