# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.1.1] - 2026-09-29

### Changed
- **Refactoring (no behavior change):** duplicated logic extracted into
  shared helpers — `jwt_decode_payload`, `warn_rtmr3_extended`,
  `b64url_encode`, `resolve_kbs_client_bin`, `qcnl_secure_cert`,
  `resolve_pccs_check`, `platform_check_args`, QGS socket/qemu-group state
  probes, and a shared interactive VM picker used by `detect_guest_ip`
  and `convert-tdx`.
- **Unified XML patching:** the ~80-line embedded Python from `convert-tdx`
  now runs through `tools/patch_vm_xml.py --rom-loader` — one tested
  implementation for both TDX XML paths (virt-install and convert-tdx).
  Output is byte-identical to the previous behavior (golden-file verified).
- Untracked generated `style.css` (produced by `convert_doc.py`; the
  embedded copy remains the single source of truth) and added it to
  `.gitignore`.

### Fixed
- `convert-tdx`: the "No VMs found" error is now reachable — previously
  an empty VM list produced a confusing `VM '' not found` instead.
- `convert-tdx` on an already-TDX VM is now idempotent instead of emitting
  duplicate `launchSecurity`/`vsock` elements that made `virsh define`
  fail and roll back.

### Removed
- `161_C1.xml` (unreferenced reference VM XML; `tdx-guest.xml` remains the
  working reference for the generated-XML path).

## [1.1.0] - 2026-09-29

### Added
- **`secret-get` host mode (RCAR):** `--mode host` generates a TEE-key-bound
  quote on the host and decrypts the JWE there — no guest event log, no guest
  reboot required (works even after `test_tdx_attest` has extended RTMR 3).
- **`setup-vm` virt-install engine:** virt-install 5.x-compatible flags
  (`--osinfo`, ROM loader injected via `--xml`), with automatic fallback to
  the generated-XML engine when virt-install is unavailable.
- **TDX installer flow:** direct installer kernel boot via `--location`,
  TDX post-patch applied *before* first boot, persistent installer
  kernel/initrd (survives virt-install's temp-file cleanup).
- **`tools/patch_vm_xml.py`:** the TDX XML post-patch (launchSecurity policy
  + QGS socket, vsock, memtune hard_limit, resource partition, pm
  suspend-disabled, qemu-commandline de-duplication) extracted from the
  shell script into a standalone, unit-testable tool.
- **`pccs-check.sh`:** TDX quote generation support.
- **`setup-guest`:** adds the Virtualization:SGX repo inside the guest and
  aligns guest packages with `zypper dup --allow-vendor-change`.
- **VNC:** fixed default port 5900, automatic bump to the next free port
  when in use, listens on `0.0.0.0` by default.
- `CHANGELOG.md` and `.gitignore` (pycache, local AI session exports).

### Changed
- `setup-vm`: ensures guestfs-tools is present; injected guest allows root
  login for the setup flow.
- Embedded `attestation.proto` is now written to `/var/tmp/trustee-protos`
  instead of world-writable `/tmp`.
- `setup-host`: the generated `kbs.json` now carries an explicit SECURITY
  NOTE documenting that `insecure_http` + `InsecureAllowAll` + `0.0.0.0`
  bind are LAB/development defaults only.
- README: Appendix moved before Troubleshooting, air-gapped setup renumbered
  as Step 12, RTMR/EAR sections condensed, `setup-guest` added to the
  quick start, probe count corrected (13, or 14 with `--check-platform`).
- CSP: stylesheet moved to an external `style.css` file.

### Fixed
- `secret-get`: uses the packaged `kbs-client` (version-aligned attester);
  JWKS/x5c token verification fixed.
- `setup-vm` (virt-install 5.x): TDX double-init (`KVM_TDX_INIT_VCPU
  EINVAL`) fixed by stripping the duplicated `-object tdx-guest` /
  `-machine confidential-guest-support` qemu-commandline args.
- `detect_guest_ip`: handles an empty `virsh list` gracefully.
- `setup-host`: defines the missing `distro_kbs_bin` hook; policy upload
  uses localhost.
- `convert_doc.py`: table rows are split on unescaped pipes only — the
  TDX-module row (code span containing `\|`) no longer renders as 4
  misaligned cells in `README.html`.
- Release tarball now ships `tools/` (`patch_vm_xml.py`, `tdx-quote-gen.c`),
  which the virt-install VM path and `setup-guest` require at runtime.

## [1.0.0]
Initial version (untagged baseline): end-to-end Intel TDX attestation setup
and testing — host stack (DCAP/QGS/Trustee), TDX VM creation, in-guest
attestation, and KBS secret delivery.
