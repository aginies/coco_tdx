# =============================================================================
# 6. VM SETUP
# =============================================================================
# NOTE: CHECK_RESULTS is used by print_results() in checks.sh — SC2034 from
# static analysis is a false positive (cross-file usage).
# shellcheck disable=SC2034

# libvirt is modular since SLE 16 / libvirt 5.7: libvirtd.service is replaced by
# per-driver daemons (virtqemud, virtnetworkd, virtstoraged), normally socket
# activated. Only fall back to the monolithic libvirtd on older systems.
generate_vm_xml() {
    local xml_path="$1"
    local uuid ovmf_bin ovmf_hit
    uuid=$(uuidgen)

    # Resolve the TDX OVMF binary path for the explicit <loader>.
    ovmf_bin=""
    if ovmf_hit=$(find_tdx_ovmf); then
        ovmf_bin="${ovmf_hit##*|}"
    fi

    if ((VM_NO_TDX)); then
        log "Generating NON-TDX VM XML: ${xml_path} (uuid=${uuid}, test mode)"
    else
        log "Generating VM XML: ${xml_path} (uuid=${uuid}, ovmf=${ovmf_bin:-auto})"
    fi

    # --- TDX mode: mirrors the proven working config
    #     (sles16.0-test-tdx-working.xml, a virt-install --location direct kernel boot):
    #   -bios OVMF.fd                 -> <loader type='rom' format='raw'>OVMF.fd</loader>
    #   -confidential-guest-support=tdx -> <launchSecurity type='tdx'/> (auto)
    #   -object tdx-guest,id=tdx      -> <launchSecurity type='tdx'/> (auto)
    #   memfd + split irqchip         -> auto-added by libvirt for TDX (do NOT set
    #                                    <memoryBacking> or <ioapic driver='qemu'/>
    #                                    explicitly; the working example omits both)
    #
    # The TDX OVMF is a memory-mapped image (device "memory" in the firmware
    # descriptor) loaded via QEMU '-bios', which libvirt expresses as a ROM
    # loader: <loader type='rom' format='raw'>. It must NOT be a pflash loader —
    # pflash requires a readonly memslot, which TDX private memory does not
    # support. A pflash loader makes libvirt's firmware autoselection reject the
    # TDX firmware and fall back to a non-TDX OVMF, so the guest is not launched
    # as a real TD and the installer never appears.
    #
    # Video: use virtio (not VGA). The working example uses <video><model
    # type='virtio'/>. VGA on a TDX TD with the secureboot OVMF does not reliably
    # bring up a display for the ISO installer; virtio video + serial console is
    # the proven path.

    local loader_line=""
    local memfd_line=""
    local ioapic_line=""
    local launchsec_line=""
    local vsock_line=""
    local rng_line=""
    local firmware_attr=""
    local memtune_line=""
    local resource_line=""
    local extra_devices=""

    if ((VM_NO_TDX)); then
        # --- Non-TDX mode: regular UEFI VM for testing without TDX hardware ---
        # Use regular pflash OVMF (not the TDX memory-mapped one).
        # libvirt firmware autoselection will pick the best UEFI firmware.
        local regular_ovmf=""
        if regular_ovmf=$(distro_ovmf_regular_probe); then
            loader_line="    <loader type='pflash' readonly='yes'>${regular_ovmf}</loader>"
        else
            loader_line="    <loader type='pflash' readonly='yes'/>"
        fi
        # Non-TDX needs explicit memory backing (file, not memfd)
        memfd_line="  <memoryBacking>
    <type type='file'/>
  </memoryBacking>"
        # Non-TDX needs ioapic for proper interrupt handling
        ioapic_line="    <ioapic driver='qemu'/>"
        # No launchSecurity for non-TDX
        launchsec_line=""
        # No vsock needed for non-TDX (no quote generation)
        vsock_line=""
        # No TDX-specific rng, use regular
        rng_line="    <rng model='virtio'>
      <backend model='random'>/dev/urandom</backend>
    </rng>"
        firmware_attr=""
    else
        # TDX mode
        if [[ -n "$ovmf_bin" ]]; then
            loader_line="    <loader type='rom' format='raw' stateless='yes'>${ovmf_bin}</loader>"
        else
            loader_line="    <loader type='rom' format='raw' stateless='yes'/>"
        fi
        # TDX: memfd is auto-added by libvirt, do NOT set explicitly
        memfd_line=""
        # TDX: split irqchip is auto, do NOT set ioapic explicitly
        ioapic_line=""
        # TDX: include launchSecurity
        launchsec_line="  <launchSecurity type='tdx'>
    <policy>0x10000000</policy>
    <quoteGenerationService path='${QGS_SOCKET}'/>
  </launchSecurity>"
        # TDX: include vsock for quote generation
        vsock_line="    <vsock model='virtio'>
      <cid auto='yes'/>
    </vsock>"
        # TDX: include rng
        rng_line="    <rng model='virtio'>
      <backend model='random'>/dev/urandom</backend>
    </rng>"
        # No firmware attr: explicit <loader> makes it redundant
        firmware_attr=""
        # TDX: hard memory limit slightly above guest RAM (firmware + overhead)
        local mem_hard_limit
        mem_hard_limit=$(((VM_MEM * 1024) + 369090))
        memtune_line="  <memtune>
    <hard_limit unit='KiB'>${mem_hard_limit}</hard_limit>
  </memtune>"
        # TDX: resource partition (matches working reference)
        resource_line="  <resource>
    <partition>/machine</partition>
  </resource>"
        # TDX: extra devices matching working reference (USB, inputs, audio,
        # watchdog, QGA channel)
        extra_devices="    <controller type='usb' index='0' model='qemu-xhci' ports='15'/>
    <input type='tablet' bus='usb'>
      <address type='usb' bus='0' port='1'/>
    </input>
    <input type='mouse' bus='ps2'/>
    <input type='keyboard' bus='ps2'/>
    <audio id='1' type='none'/>
    <watchdog model='itco' action='reset'/>
    <channel type='unix'>
      <source mode='bind' path='/run/libvirt/qemu/channel/domain-${VM_NAME}/org.qemu.guest_agent.0'/>
      <target type='virtio' name='org.qemu.guest_agent.0'/>
    </channel>"
    fi

    cat >"$xml_path" <<EOF
<domain type='kvm'>
  <name>${VM_DISPLAY_NAME:-${VM_NAME}}</name>
  <uuid>${uuid}</uuid>
  <memory unit='MiB'>${VM_MEM}</memory>
  <currentMemory unit='MiB'>${VM_MEM}</currentMemory>
${memtune_line}
${memfd_line}
  <vcpu placement='static'>${VM_CPU}</vcpu>
  <cpu mode='host-passthrough' check='none' migratable='off'/>
${resource_line}
  <os${firmware_attr}>
    <type arch='x86_64' machine='q35'>hvm</type>
${loader_line}
    <boot dev='cdrom'/>
    <boot dev='hd'/>
  </os>
  <features>
    <acpi/>
    <apic/>
${ioapic_line}
  </features>
  <clock offset='utc'>
    <timer name='rtc' tickpolicy='catchup'/>
    <timer name='pit' tickpolicy='delay'/>
    <timer name='hpet' present='no'/>
  </clock>
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>destroy</on_reboot>
  <on_crash>destroy</on_crash>
  <pm>
    <suspend-to-mem enabled='no'/>
    <suspend-to-disk enabled='no'/>
  </pm>
${launchsec_line}
  <devices>
    <emulator>/usr/bin/qemu-system-x86_64</emulator>
    <controller type='sata' index='0'>
      <alias name='sata0'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x1f' function='0x2'/>
    </controller>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='${VM_DISK_PATH}'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <interface type='network'>
      <source network='default'/>
      <model type='virtio'/>
    </interface>
    <serial type='pty'>
      <target type='isa-serial' port='0'>
        <model name='isa-serial'/>
      </target>
    </serial>
    <console type='pty'>
      <target type='serial' port='0'/>
    </console>
    <graphics type='vnc' port='${VNC_PORT}' listen='${VNC_LISTEN:-0.0.0.0}'>
      <listen type='address' address='${VNC_LISTEN:-0.0.0.0}'/>
    </graphics>
    <video>
      <model type='virtio' heads='1' primary='yes'/>
    </video>
${vsock_line}
${extra_devices}
    <memballoon model='virtio'/>
${rng_line}
  </devices>
</domain>
EOF
}

# =============================================================================
# virt-install based VM creation (alternative to generate_vm_xml)
# =============================================================================
virt_install_available() {
    command -v virt-install >/dev/null 2>&1
}

# Major version of virt-install (e.g. "5.1.0" -> 5). 5.x is a breaking
# release: --bios/-bios/--firmware were removed, --osinfo became mandatory,
# and the raw --xml XPath option was added (used to inject the TDX ROM loader).
virt_install_major() {
    local ver
    ver=$(virt-install --version 2>/dev/null | head -1 | grep -oE '^[0-9]+' || true)
    echo "${ver:-0}"
}

# Derive a libosinfo ID from the guest ISO file name (virt-install 5.x
# requires --osinfo). Prints nothing when the ISO name is not recognizable;
# the caller then falls back to --osinfo detect=on,require=off.
virt_install_osinfo() {
    local base up
    base=$(basename -- "${GUEST_ISO:-}")
    up=$(tr '[:lower:]' '[:upper:]' <<<"${base}")
    case "${up}" in
    *SLES*16.1*) echo "sles16.1" ;;
    *SLES*16*) echo "sles16" ;;
    *SLES*15*SP7*) echo "sles15sp7" ;;
    *SLES*15*SP6*) echo "sles15sp6" ;;
    *SLES*15*SP5*) echo "sles15sp5" ;;
    *LEAP*16.1*) echo "opensuse16.1" ;;
    *LEAP*15.6*) echo "opensuse15.6" ;;
    *) : ;;
    esac
}

# Choose the VM creation engine: "virt" (virt-install) or "xml" (generated XML).
# Falls back to XML when virt-install is unavailable, forced off, or when no
# installer ISO is given (virt-install path attaches it via --cdrom).
choose_vm_creator() {
    local want="${VM_CREATOR}"
    if [[ -z "${GUEST_ISO}" && "${want}" != "xml" ]]; then
        log "No --guest-iso given; using generated XML (ISO can be attached later)."
        echo "xml"
        return 0
    fi
    case "${want}" in
    xml)
        echo "xml"
        ;;
    virt)
        if virt_install_available; then
            echo "virt"
        else
            warn "virt-install not found (package: python3-virtinst); falling back to generated XML."
            echo "xml"
        fi
        ;;
    *) # auto
        if virt_install_available; then
            echo "virt"
        else
            log "virt-install not found; using generated XML."
            echo "xml"
        fi
        ;;
    esac
}

# Is TCP port $1 in use (listening) on this host?
vnc_port_in_use() {
    if command -v ss >/dev/null 2>&1; then
        ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]${1}$"
    else
        (exec 3<>"/dev/tcp/127.0.0.1/${1}") 2>/dev/null
    fi
}

# Ensure the VNC port is actually free on the host; libvirt fails the whole
# domain start with "Failed to reserve port" otherwise. If VNC_PORT is taken,
# walk up to the next free port (override with --vnc-port).
ensure_vnc_port() {
    local port="$1" i
    if ! vnc_port_in_use "${port}"; then
        return 0
    fi
    for i in $(seq 1 10); do
        if ! vnc_port_in_use "$((port + i))"; then
            warn "VNC port ${port} is in use on the host; using $((port + i)) instead (override with --vnc-port)."
            VNC_PORT=$((port + i))
            return 0
        fi
    done
    die "VNC port ${port} (and the next 10 ports) are in use on the host.
Stop a VM using it or re-run with --vnc-port <PORT>."
}

# Build the virt-install command in the global VIRT_INSTALL_CMD array.
# virt-install defines AND starts the domain; cmd_setup_vm then destroys it,
# applies the TDX XML patch (launchSecurity policy/QGS, vsock, memtune,
# resource partition, pm), re-defines and starts it again — so all TDX bits
# are in effect from a clean boot (the installer just reboots).
build_virt_install_cmd() {
    local disk_spec="path=${VM_DISK_PATH},format=qcow2"
    local vi_major
    vi_major=$(virt_install_major)
    # virt-install size= expects a bare GiB number, not qemu-img-style units
    # like "32G" ("could not convert string to float").
    local vi_size="${VM_DISK}"
    if [[ "${vi_size}" =~ ^([0-9]+)([A-Za-z]?)$ ]]; then
        local d_n="${BASH_REMATCH[1]}" d_u="${BASH_REMATCH[2]}"
        case "${d_u}" in
        [Tt]) vi_size=$((d_n * 1024)) ;;
        [Mm]) vi_size=$((d_n / 1024)) ;;
        [Gg] | "") vi_size="${d_n}" ;;
        esac
    fi
    if [[ ! -f "${VM_DISK_PATH}" ]]; then
        disk_spec="${disk_spec},size=${vi_size}"
    fi
    if ((vi_major >= 5)); then
        # 5.x generic fallback (no OS detected) defaults to i440fx/ide/e1000/vga
        # — pin the proven virtio disk explicitly.
        disk_spec="${disk_spec},bus=virtio"
    fi
    # shellcheck disable=SC2054  # false positive: multi-line array literal
    local cmd=(virt-install
        --name "${VM_DISPLAY_NAME}"
        --memory "${VM_MEM}"
        --vcpus "${VM_CPU}"
        --disk "${disk_spec}"
        --cpu host-passthrough
        --network network=default,model=virtio
        --graphics "vnc,listen=${VNC_LISTEN:-0.0.0.0},port=${VNC_PORT}"
        --video virtio
        --boot fd
        --noautoconsole
        --wait 1
    )
    if ((vi_major >= 5)); then
        # virt-install 5.x requires --osinfo. Derive a libosinfo ID from the
        # ISO name when recognizable (and present in this virt-install's list),
        # otherwise let virt-install detect it without failing.
        local osinfo
        osinfo=$(virt_install_osinfo)
        if [[ -n "${osinfo}" ]] && virt-install --osinfo list 2>/dev/null | grep -qx "${osinfo}"; then
            cmd+=(--osinfo "${osinfo}")
        else
            cmd+=(--osinfo detect=on,require=off)
        fi
    fi
    if ((VM_NO_TDX)); then
        # No firmware flag: libvirt firmware autoselection picks pflash OVMF + NVRAM.
        :
    else
        local ovmf_hit ovmf_bin=""
        if ovmf_hit=$(find_tdx_ovmf); then
            ovmf_bin="${ovmf_hit##*|}"
        fi
        if [[ -z "${ovmf_bin}" ]]; then
            die "No TDX OVMF firmware found; cannot build virt-install command."
        fi
        if ((vi_major >= 5)); then
            # virt-install 5.x removed --bios/-bios/--firmware. TDX still
            # requires a ROM loader (<loader type='rom'>), never pflash —
            # inject it with the raw --xml XPath option, and pin the proven
            # q35 machine type regardless of osinfo defaults.
            cmd+=(--machine q35)
            cmd+=(--xml xpath.create=./os/loader
                --xml ./os/loader/@type=rom
                --xml ./os/loader/@format=raw
                --xml ./os/loader/@stateless=yes
                --xml "xpath.set=./os/loader,xpath.value=${ovmf_bin}")
        else
            # TDX requires a ROM loader (<loader type='rom'>), never pflash. The
            # firmware flag name differs across virt-install versions, so probe
            # --help and pick the one this build supports.
            local vi_help="" firmware_args=()
            if virt_install_available; then
                vi_help=$(virt-install --help 2>&1) || true
                if grep -qE -- '--bios([=[:space:]]|$)' <<<"${vi_help}"; then
                    firmware_args=(--bios "${ovmf_bin}")
                elif grep -qE -- '(^|[[:space:]])-bios([=[:space:]]|$)' <<<"${vi_help}"; then
                    firmware_args=(-bios "${ovmf_bin}")
                elif grep -qE -- '--firmware([=[:space:]]|$)' <<<"${vi_help}"; then
                    firmware_args=(--firmware "path=${ovmf_bin},type=bios")
                else
                    # Build the diagnostic first: a command substitution embedded
                    # directly in a multi-line double-quoted die message is
                    # fragile across bash versions.
                    local fw_diag
                    fw_diag=$(grep -inE 'bios|firmware' <<<"${vi_help}" | head -5 | sed 's/^/    /')
                    [[ -n "${fw_diag}" ]] || fw_diag="    (none)"
                    die "virt-install exposes no recognizable firmware option (--bios/-bios/--firmware).
'virt-install --help' lines mentioning bios/firmware:
${fw_diag}
Check 'virt-install --help' / 'virt-install --version', or use --no-virt-install to fall back to the generated XML engine."
                fi
            else
                # virt-install not installed (dry-run preview only): classic flag.
                firmware_args=(-bios "${ovmf_bin}")
            fi
            cmd+=("${firmware_args[@]}")
        fi
        # The tdx-guest object + confidential-guest-support machine flag go via
        # qemu-commandline (mirrors the proven working virt-install TDX config).
        cmd+=(--qemu-commandline="-object tdx-guest,id=tdx -machine confidential-guest-support=tdx")
    fi
    # Absolute ISO path: a relative --cdrom would be stored relative to the
    # current working directory and break on later boots.
    local iso_path="${GUEST_ISO}"
    if [[ -f "${iso_path}" ]]; then
        iso_path=$(realpath -- "${iso_path}" 2>/dev/null || echo "${iso_path}")
    fi
    cmd+=(--cdrom "${iso_path}")
    VIRT_INSTALL_CMD=("${cmd[@]}")
}

# Post-define XML patch for the virt-install path. virt-install has no flags
# for the SUSE/TDX-specific bits, so they are added here (same style as
# edit_vm_xml_tdx). Element positions follow the libvirt canonical order
# (see the working tdx-guest.xml reference).
# Usage: patch_vm_xml_tdx <input_xml> <output_xml>
patch_vm_xml_tdx() {
    local input_xml="$1" output_xml="$2"
    python3 - "$input_xml" "$output_xml" "$QGS_SOCKET" "$((VM_MEM * 1024 + 369090))" <<'PYEOF'
import sys, xml.etree.ElementTree as ET

input_xml, output_xml, qgs_socket = sys.argv[1], sys.argv[2], sys.argv[3]
mem_hard_limit = int(sys.argv[4])
ET.register_namespace('', '')
tree = ET.parse(input_xml)
root = tree.getroot()

# 1. launchSecurity: ensure TDX policy + QGS socket. libvirt may auto-add a
#    bare <launchSecurity type='tdx'/> from the machine flag; make it explicit.
ls = root.find('launchSecurity')
if ls is None:
    ls = ET.Element('launchSecurity', {'type': 'tdx'})
    root.append(ls)  # canonical position: after <devices>
else:
    ls.set('type', 'tdx')
for tag in ('policy', 'quoteGenerationService'):
    for el in ls.findall(tag):
        ls.remove(el)
ET.SubElement(ls, 'policy').text = '0x10000000'
ET.SubElement(ls, 'quoteGenerationService', {'path': qgs_socket})

# 2. vsock (quote generation over vsock)
devices = root.find('devices')
if devices is not None and devices.find('vsock') is None:
    vsock = ET.Element('vsock', {'model': 'virtio'})
    ET.SubElement(vsock, 'cid', {'auto': 'yes'})
    devices.append(vsock)

# 3. memtune hard_limit (firmware + overhead headroom), after currentMemory
for mb in root.findall('memtune'):
    root.remove(mb)
mt = ET.Element('memtune')
ET.SubElement(mt, 'hard_limit', {'unit': 'KiB'}).text = str(mem_hard_limit)
children = list(root)
idx = next((i for i, c in enumerate(children) if c.tag == 'currentMemory'), 1)
root.insert(idx + 1, mt)

# 4. resource partition /machine, after vcpu
if root.find('resource') is None:
    res = ET.Element('resource')
    ET.SubElement(res, 'partition').text = '/machine'
    children = list(root)
    idx = next((i for i, c in enumerate(children) if c.tag == 'vcpu'), 2)
    root.insert(idx + 1, res)

# 5. pm: TDX cannot hibernate — disable suspend-to-mem/disk, before <devices>
pm = root.find('pm')
if pm is None:
    pm = ET.Element('pm')
    if devices is not None:
        root.insert(list(root).index(devices), pm)
    else:
        root.append(pm)
for tag in ('suspend-to-mem', 'suspend-to-disk'):
    el = pm.find(tag)
    if el is None:
        el = ET.SubElement(pm, tag)
    el.set('enabled', 'no')

# 6. qemu:commandline: with <launchSecurity type='tdx'> present, libvirt
#    itself adds the tdx-guest object + confidential-guest-support machine
#    flag. The explicit -object/-machine args virt-install left in the
#    qemu-commandline would duplicate them and break TD init (KVM_TDX_INIT_
#    VCPU EINVAL), so strip that pair (keep any other commandline args).
NS = '{http://libvirt.org/schemas/domain/qemu/1.0}'
for cl in root.findall(NS + 'commandline'):
    args = cl.findall(NS + 'arg')
    for i, arg in enumerate(args):
        v = arg.get('value', '')
        if v in ('-object', '-machine') and i + 1 < len(args):
            nv = args[i + 1].get('value', '')
            if (v == '-object' and nv.startswith('tdx-guest,')) or \
               (v == '-machine' and nv.startswith('confidential-guest-support=')):
                cl.remove(arg)
                cl.remove(args[i + 1])
    if not cl.findall(NS + 'arg'):
        root.remove(cl)

tree.write(output_xml, xml_declaration=True, encoding='unicode')
PYEOF
}

# Inject the SSH key (and disable suspend) into the guest disk via
# virt-customize. The VM must be off. Uses VM_DISK_PATH / SSH_KEY / GUEST_USER.
inject_ssh_key_disk() {
    if command -v virt-customize >/dev/null 2>&1; then
        log "Injecting SSH key into guest image via virt-customize"
        local pub_key
        pub_key=$(cat "${SSH_KEY}.pub")
        run virt-customize -a "$VM_DISK_PATH" \
            --run-command "mkdir -p /root/.ssh && chmod 700 /root/.ssh" \
            --run-command "touch /root/.ssh/authorized_keys; grep -qxF '${pub_key}' /root/.ssh/authorized_keys || echo '${pub_key}' >> /root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys" \
            --run-command "mkdir -p /etc/systemd/system && for t in sleep.target suspend.target hibernate.target hybrid-sleep.target; do ln -sf /dev/null /etc/systemd/system/\$t; done" \
            --run-command "mkdir -p /etc/systemd/logind.conf.d && printf '[Login]\nHandleSuspendKey=ignore\nHandleHibernateKey=ignore\nHandleLidSwitch=ignore\n' > /etc/systemd/logind.conf.d/tdx-no-suspend.conf"
        log "SSH key injected (user: ${GUEST_USER})"
        log "Suspend/hibernate disabled in guest image (TDX requirement)"
    else
        warn "virt-customize not available ($(distro_pkg_manager) in $(distro_pkgs guest_libs))"
        warn "Inject the SSH key manually after first boot, or use the console."
    fi
}

ensure_ssh_key() {
    if [[ -f "$SSH_KEY" ]]; then
        log "SSH key already exists: $SSH_KEY"
        return 0
    fi
    log "Generating SSH key: $SSH_KEY"
    mkdir -p "$(dirname "$SSH_KEY")"
    chmod 700 "$(dirname "$SSH_KEY")"
    run ssh-keygen -t ed25519 -N '' -f "$SSH_KEY" -C "tdx-attest-$(date +%Y%m%d)"
    log "SSH key created: $SSH_KEY"
}

cmd_setup_vm() {
    # Determine display name for this mode
    if ((VM_NO_TDX)); then
        VM_DISPLAY_NAME="${VM_NO_TDX_NAME}"
        VM_DISK_PATH="${VM_NO_TDX_DISK_PATH}"
        VM_XML_PATH="${VM_NO_TDX_XML_PATH}"
    else
        VM_DISPLAY_NAME="${VM_NAME}"
    fi
    # Dry run: print the virt-install command without touching the system
    # (no root, no virsh, no virt-install required).
    if ((DRY_RUN)); then
        if [[ "${VM_CREATOR}" == "xml" ]]; then
            die "--no-virt-install was given; --dry-run only previews the virt-install path."
        fi
        if [[ -z "${GUEST_ISO}" ]]; then
            die "--dry-run builds the virt-install command, which needs --guest-iso."
        fi
        build_virt_install_cmd
        if ! virt_install_available; then
            warn "virt-install is not installed on this host — a real run would fall back to the generated XML engine."
        fi
        echo ""
        echo "  virt-install command (DRY RUN — not executed):"
        printf '    %s\n' "${VIRT_INSTALL_CMD[@]}"
        echo ""
        if ((VM_NO_TDX)); then
            log "Non-TDX mode: no TDX post-patch would be applied."
        else
            log "Post-define TDX patch would add: launchSecurity policy+QGS, vsock, memtune hard_limit, resource partition, pm suspend disabled."
        fi
        return 0
    fi
    require_root
    require_cmd virsh qemu-img uuidgen ssh-keygen
    ensure_vnc_port "${VNC_PORT}"
    log "=== Setting up ${VM_DISPLAY_NAME} (${VM_CPU} vCPU, ${VM_MEM} MiB) ==="
    if ((VM_NO_TDX)); then
        step "Create + define + start a NON-TDX libvirt guest (test mode)" \
            "Builds qcow2 disk and domain XML (regular UEFI, no launchSecurity, no vsock), then boots for OS install. NOT a Trust Domain."
        warn "This VM is NOT a TDX Trust Domain. No attestation possible."
        warn "Use for testing VM installation, networking, SSH key injection, etc."
    else
        step "Create + define + start a TDX-enabled libvirt guest" \
            "Creates the guest (virt-install if available, else generated XML: launchSecurity tdx, UEFI, vsock), then boots for OS install."
    fi

    # Confirm a TDX OVMF exists; the explicit <loader> in the XML points at it.
    local ovmf_hit
    if ((VM_NO_TDX)); then
        log "Non-TDX mode: skipping TDX OVMF check."
    else
        if ovmf_hit=$(find_tdx_ovmf); then
            log "TDX OVMF firmware: ${ovmf_hit##*|} (descriptor: ${ovmf_hit%%|*})"
        else
            die "No TDX OVMF firmware descriptor found in $(distro_ovmf_fwdir).
Install a TDX-enabled edk2/OVMF ($(distro_pkgs ovmf)), then re-run."
        fi
        # Verify QEMU actually has the tdx-guest object before defining
        if ! qemu-system-x86_64 -object help 2>&1 | grep -qi 'tdx-guest'; then
            die "QEMU has no TDX support (no tdx-guest object).
Reinstall qemu with TDX target (package: $(distro_pkgs qemu))."
        fi
        log "QEMU supports TDX (tdx-guest object present)"
    fi

    ensure_libvirt

    if virsh dominfo "$VM_DISPLAY_NAME" >/dev/null 2>&1; then
        warn "VM '${VM_DISPLAY_NAME}' already exists."
        if confirm "Destroy + undefine VM '${VM_DISPLAY_NAME}' and continue?"; then
            log "Destroying VM ${VM_DISPLAY_NAME}"
            run virsh destroy "$VM_DISPLAY_NAME" || true
            log "Undefining VM ${VM_DISPLAY_NAME}"
            if virsh undefine "$VM_DISPLAY_NAME" 2>/dev/null; then
                log "VM undefined"
            elif confirm "VM has NVRAM. Undefine with --nvram (removes firmware variables)?"; then
                run virsh undefine --nvram "$VM_DISPLAY_NAME"
            else
                die "Cannot undefine VM with NVRAM. Run 'clean' or manually: virsh undefine --nvram ${VM_DISPLAY_NAME}"
            fi
        else
            die "VM '${VM_DISPLAY_NAME}' still exists. Use 'clean' first or change --vm-name."
        fi
    fi

    # disk_has_os: a reused disk likely holds an installed OS (virt-customize can
    # mount it); a freshly created disk is empty (nothing to customize).
    local disk_has_os=0
    if [[ -f "$VM_DISK_PATH" ]]; then
        warn "Disk already exists, reusing: ${VM_DISK_PATH}"
        disk_has_os=1
    fi

    ensure_ssh_key

    local creator
    creator=$(choose_vm_creator)

    if [[ "$creator" == "virt" ]]; then
        # --- virt-install path -------------------------------------------------
        build_virt_install_cmd
        echo ""
        echo "  virt-install command:"
        printf '    %s\n' "${VIRT_INSTALL_CMD[@]}"
        echo ""
        if [[ ! -f "$VM_DISK_PATH" ]]; then
            log "virt-install will create qcow2 disk: ${VM_DISK_PATH} (${VM_DISK})"
            mkdir -p "$(dirname "$VM_DISK_PATH")"
        fi
        log "Creating VM with virt-install (defines + starts the domain)"
        if ! run "${VIRT_INSTALL_CMD[@]}"; then
            # virt-install exits 1 when --wait times out while the domain is
            # still running — expected here: the installer needs manual work
            # and the domain is deliberately left up. Continue if it's alive.
            local vi_state
            vi_state=$(virsh domstate "$VM_DISPLAY_NAME" 2>/dev/null || true)
            if [[ "${vi_state}" == "running" ]]; then
                warn "virt-install exited non-zero (--wait timeout), but the domain is running. Continuing."
            else
                die "virt-install failed and the domain is not running (state: ${vi_state:-unknown}). See output above."
            fi
        fi
        log "Destroying domain to apply the TDX patch, then re-starting (installer reboots)"
        run virsh destroy "$VM_DISPLAY_NAME" || true
        if ((disk_has_os)); then
            inject_ssh_key_disk
        else
            warn "Fresh empty disk — skipping virt-customize (nothing to mount yet)."
            warn "Install the OS from the ISO first, then inject the SSH key post-install:"
            warn "  virt-customize -a ${VM_DISK_PATH} --ssh-inject ${GUEST_USER}:file:${SSH_KEY}.pub"
            warn "Suspend/hibernate will be disabled automatically by 'setup-guest' after install."
        fi
        local pre_xml post_xml
        pre_xml=$(mktemp /tmp/tdx-vm-pre-XXXXXX.xml)
        post_xml=$(mktemp /tmp/tdx-vm-post-XXXXXX.xml)
        run virsh dumpxml "$VM_DISPLAY_NAME" >"$pre_xml"
        if ((VM_NO_TDX)); then
            cp "$pre_xml" "$post_xml"
        else
            if ! patch_vm_xml_tdx "$pre_xml" "$post_xml"; then
                die "TDX XML patch failed. Pre-patch XML kept: ${pre_xml}"
            fi
            log "TDX patch applied (diff):"
            diff "$pre_xml" "$post_xml" | sed 's/^/    /' || true
        fi
        log "Re-defining VM with patched XML"
        run virsh define "$post_xml"
        rm -f "$pre_xml" "$post_xml"
        log "Starting VM"
        run virsh start "$VM_DISPLAY_NAME"
        sleep 2
        run virsh dominfo "$VM_DISPLAY_NAME"
    else
        # --- Generated XML path -------------------------------------------------
        log "Creating qcow2 disk: ${VM_DISK_PATH} (${VM_DISK})"
        mkdir -p "$(dirname "$VM_DISK_PATH")"
        if ((disk_has_os)); then
            : # reusing existing disk
        else
            run qemu-img create -f qcow2 "$VM_DISK_PATH" "$VM_DISK"
        fi

        log "Storing VM XML definition: ${VM_XML_PATH}"
        generate_vm_xml "$VM_XML_PATH"

        if ((disk_has_os)); then
            inject_ssh_key_disk
        else
            warn "Fresh empty disk — skipping virt-customize (nothing to mount yet)."
            warn "Install the OS from the ISO first, then inject the SSH key post-install:"
            warn "  virt-customize -a ${VM_DISK_PATH} --ssh-inject ${GUEST_USER}:file:${SSH_KEY}.pub"
            warn "Suspend/hibernate will be disabled automatically by 'setup-guest' after install."
        fi

        log "Defining VM"
        run virsh define "$VM_XML_PATH"

        # Attach the installer ISO with --config so it persists to the (not-yet-running)
        # domain definition; a live attach-disk would fail before 'virsh start'.
        if [[ -n "$GUEST_ISO" ]]; then
            log "Attaching installer ISO: $GUEST_ISO"
            if ! run virsh attach-disk "$VM_DISPLAY_NAME" "$GUEST_ISO" hdc \
                --type cdrom --mode readonly --config; then
                warn "ISO attach failed; attach manually: virsh attach-disk ${VM_DISPLAY_NAME} ${GUEST_ISO} hdc --type cdrom --config"
            fi
        else
            warn "No --guest-iso provided. Attach the SLE installer ISO manually before first boot."
        fi

        log "Starting VM"
        echo ""
        echo "  VM XML (${VM_XML_PATH}):"
        sed 's/^/    /' "$VM_XML_PATH"
        echo ""
        echo "  Command: virsh start ${VM_DISPLAY_NAME}"
        echo ""
        if ((! FORCE)) && [[ -t 0 ]]; then
            read -r -p "  Press Enter to start the VM (or Ctrl+C to abort): " _
        fi
        run virsh start "$VM_DISPLAY_NAME"
        sleep 2
        run virsh dominfo "$VM_DISPLAY_NAME"
    fi

    if ((VM_NO_TDX)); then
        cat <<NEXT

=== VM started (NON-TDX, test mode). MANUAL GUEST INSTALLATION REQUIRED ===

1. Open the console and install SLE from the ISO:

    virsh console ${VM_DISPLAY_NAME}

2. After install + reboot, find the guest IP (DHCP on default network):

    virsh net-dhcp-leases default

3. SSH into the guest:

    ssh -i ${SSH_KEY} ${GUEST_USER}@<GUEST_IP>

NOTE: This VM is NOT a TDX Trust Domain. No attestation, no vsock, no launchSecurity.

NEXT
    else
        cat <<NEXT

=== VM started. MANUAL GUEST INSTALLATION REQUIRED ===

1. Open the console and install SLE 16.1 (or 15 SP7 / 16.0) from the ISO:

    virsh console ${VM_DISPLAY_NAME}

   Or use the VNC display (video) — VNC listens on ${VNC_LISTEN}:${VNC_PORT}:

    virsh vncdisplay ${VM_DISPLAY_NAME}   # shows :N
    vncclient <HOST_IP>:<N>

2. During install: ensure kernel is 6.1+ (default on SLE 16.1).

3. After install + reboot, find the guest IP (DHCP on default network):

    virsh net-dhcp-leases default

4. Then run the guest setup and attestation:

    sudo tdx-attest.sh setup-guest --guest-ip <GUEST_IP>
    sudo tdx-attest.sh attest      --guest-ip <GUEST_IP>

NEXT
    fi
    log "VM setup complete."
}

# Edit a libvirt domain XML in-place to add TDX support.
# Preserves all existing elements (disk, network, graphics, video, UUID, MAC, etc.).
# Changes: loader pflash->rom (stateless), removes nvram/memoryBacking/ioapic,
# adds launchSecurity + vsock.
# Usage: edit_vm_xml_tdx <input_xml> <output_xml> <tdx_ovmf_bin> <qgs_socket>
edit_vm_xml_tdx() {
    local input_xml="$1" output_xml="$2" ovmf_bin="$3" qgs_socket="$4"
    python3 - "$input_xml" "$output_xml" "$ovmf_bin" "$qgs_socket" <<'PYEOF'
import sys, xml.etree.ElementTree as ET

input_xml, output_xml, ovmf_bin, qgs_socket = sys.argv[1:5]
ET.register_namespace('', '')
tree = ET.parse(input_xml)
root = tree.getroot()

# 1. <os>: remove firmware attr and <firmware> element
os_el = root.find('os')
if os_el is not None:
    if 'firmware' in os_el.attrib:
        del os_el.attrib['firmware']
    for fw in os_el.findall('firmware'):
        os_el.remove(fw)

# 2. <loader>: replace pflash with stateless rom
loader = os_el.find('loader') if os_el is not None else None
if loader is not None:
    for child in list(os_el):
        if child.tag == 'loader':
            os_el.remove(child)
    new_loader = ET.Element('loader', {'type': 'rom', 'format': 'raw', 'stateless': 'yes'})
    new_loader.text = ovmf_bin
    os_el.insert(1, new_loader)

# 3. Remove <nvram> from <os> (TDX OVMF is stateless, no NVRAM)
if os_el is not None:
    for nvram in os_el.findall('nvram'):
        os_el.remove(nvram)

# 4. Remove <memoryBacking>
for mb in root.findall('memoryBacking'):
    root.remove(mb)

# 5. Remove <ioapic> from <features>
features = root.find('features')
if features is not None:
    for ioapic in features.findall('ioapic'):
        features.remove(ioapic)

# 6. Add <launchSecurity> before <devices>
devices = root.find('devices')
ls = ET.Element('launchSecurity', {'type': 'tdx'})
ET.SubElement(ls, 'policy').text = '0x10000000'
ET.SubElement(ls, 'quoteGenerationService', {'path': qgs_socket})
if devices is not None:
    root.insert(list(root).index(devices), ls)
else:
    root.append(ls)

# 7. Add <vsock> in <devices> (before <memballoon>)
if devices is not None:
    vsock = ET.Element('vsock', {'model': 'virtio'})
    ET.SubElement(vsock, 'cid', {'auto': 'yes'})
    memballoon = devices.find('memballoon')
    if memballoon is not None:
        devices.insert(list(devices).index(memballoon), vsock)
    else:
        devices.append(vsock)

# 8. <pm>: force suspend-to-mem and suspend-to-disk disabled (TDX cannot hibernate)
pm = root.find('pm')
if pm is None:
    pm = ET.Element('pm')
    if devices is not None:
        root.insert(list(root).index(devices), pm)
    else:
        root.append(pm)
for tag in ('suspend-to-mem', 'suspend-to-disk'):
    el = pm.find(tag)
    if el is None:
        el = ET.SubElement(pm, tag)
    el.set('enabled', 'no')

tree.write(output_xml, xml_declaration=True, encoding='unicode')
PYEOF
}

cmd_convert_tdx() {
    require_root
    require_cmd virsh python3
    log "=== Converting VM to TDX ==="
    step "Convert an existing (non-TDX) libvirt VM to a TDX Trust Domain in-place" \
        "Edits the domain XML: pflash->ROM loader, adds launchSecurity+vsock, removes memoryBacking/ioapic, disables suspend-to-mem/disk. Preserves disk, network, MAC, graphics, video, UUID."

    # Resolve target VM name (mandatory)
    local vm_name="${CONVERT_VM_NAME:-}"
    if [[ -z "$vm_name" ]]; then
        # Auto-detect: list all VMs and prompt user to choose
        if command -v virsh >/dev/null 2>&1; then
            local vm_list
            vm_list=$(virsh list --all --name 2>/dev/null)
            local vm_count
            vm_count=$(wc -l <<<"$vm_list")
            if [[ "$vm_count" -gt 0 ]]; then
                echo ""
                echo "Available VMs:"
                local i=1
                while IFS= read -r vm; do
                    [[ -z "$vm" ]] && continue
                    echo "  ${i}) ${vm}"
                    ((i++))
                done <<<"$vm_list"
                echo ""
                if ((vm_count == 1)); then
                    vm_name=$(echo "$vm_list" | head -1)
                    log "Auto-detected single VM: ${vm_name}"
                else
                    if [[ ! -t 0 ]]; then
                        die "Interactive selection requires a tty. Re-run with --convert-vm <NAME>."
                    fi
                    local choice
                    read -r -p "Enter VM number to convert: " choice
                    if [[ "$choice" =~ ^[0-9]+$ ]] && ((choice >= 1 && choice <= vm_count)); then
                        vm_name=$(echo "$vm_list" | sed -n "${choice}p")
                    else
                        die "Invalid selection. Re-run with --convert-vm <NAME>."
                    fi
                fi
            else
                die "No VMs found on this system. Use --convert-vm <NAME> if the VM is on a different host."
            fi
        else
            die "--convert-vm NAME is required for convert-tdx (virsh not available for auto-detection). Usage: ${SCRIPT_NAME} convert-tdx --convert-vm <VM_NAME>"
        fi
    fi

    # Preconditions
    if ! virsh dominfo "$vm_name" >/dev/null 2>&1; then
        die "VM '${vm_name}' not found. Check: virsh list --all"
    fi
    local state
    state=$(virsh domstate "$vm_name" 2>/dev/null || echo "unknown")
    if [[ "$state" == "running" ]]; then
        die "To convert VM '${vm_name}' to TDX it must be stopped first.
Shut it down, then re-run:
  virsh shutdown ${vm_name}
  sudo ${SCRIPT_NAME} convert-tdx --convert-vm ${vm_name}"
    fi

    ensure_libvirt

    local ovmf_hit ovmf_bin
    if ovmf_hit=$(find_tdx_ovmf); then
        ovmf_bin="${ovmf_hit##*|}"
        log "TDX OVMF firmware: ${ovmf_bin}"
    else
        die "No TDX OVMF firmware found in $(distro_ovmf_fwdir). Install a TDX-enabled edk2/OVMF ($(distro_pkgs ovmf)) first."
    fi

    if systemctl is-active qgsd.service >/dev/null 2>&1; then
        log "QGS service is running"
    else
        warn "QGS service (qgsd.service) not running. Quote generation will fail until it starts. Run: ${SCRIPT_NAME} setup-qgs"
    fi

    # Check current loader type
    local cur_xml cur_loader
    cur_xml=$(virsh dumpxml "$vm_name" 2>/dev/null || true)
    cur_loader=$(grep -oP '<loader[^>]*type="\K[^"]+' <<<"$cur_xml" 2>/dev/null || true)
    if [[ "$cur_loader" == "rom" ]]; then
        warn "VM already has a ROM loader (may already be TDX). Continuing."
    elif [[ "$cur_loader" == "pflash" ]]; then
        log "Current loader: pflash (will convert to ROM)"
    else
        warn "Current loader type: '${cur_loader:-unknown}'. Proceeding with conversion."
    fi

    # Backup
    local backup_path="/var/lib/libvirt/${vm_name}.xml.bak"
    log "Backing up VM XML: ${backup_path}"
    mkdir -p /var/lib/libvirt
    run virsh dumpxml "$vm_name" >"$backup_path"

    # Edit XML
    local tmp_xml
    tmp_xml=$(mktemp /tmp/tdx-convert-XXXXXX.xml)
    log "Editing VM XML for TDX (preserving disk, network, MAC, graphics, video, UUID)"
    if ! edit_vm_xml_tdx "$backup_path" "$tmp_xml" "$ovmf_bin" "$QGS_SOCKET"; then
        error "XML edit failed. Generated XML kept for inspection: ${tmp_xml}"
        die "TDX conversion failed. Generated XML: ${tmp_xml}"
    fi

    # Apply (rollback to backup on failure)
    log "Defining VM with TDX configuration"
    if ! run virsh define "$tmp_xml"; then
        error "Define failed. Rolling back to backup."
        run virsh define "$backup_path" || warn "Rollback also failed. Restore manually: virsh define ${backup_path}"
        error "Generated TDX XML kept for inspection: ${tmp_xml}"
        die "TDX conversion failed. VM restored to previous state. Generated XML: ${tmp_xml}"
    fi
    rm -f "$tmp_xml"

    # Verify
    local new_xml
    new_xml=$(virsh dumpxml "$vm_name" 2>/dev/null || true)
    if grep -q "launchSecurity type='tdx'" <<<"$new_xml"; then
        log "VM has launchSecurity type='tdx'"
    else
        error "VM missing launchSecurity type='tdx' after conversion"
    fi
    if grep -q "<vsock" <<<"$new_xml"; then
        log "VM has vsock device"
    else
        error "VM missing vsock device after conversion"
    fi
    if grep -q "suspend-to-mem enabled='no'" <<<"$new_xml" && grep -q "suspend-to-disk enabled='no'" <<<"$new_xml"; then
        log "VM has suspend-to-mem and suspend-to-disk disabled"
    else
        error "VM missing <pm> suspend-to-mem/suspend-to-disk enabled='no' after conversion. TDX guests must not hibernate."
    fi

    # Show diff
    log "Changes applied (diff):"
    diff "$backup_path" <(virsh dumpxml "$vm_name" 2>/dev/null) | sed 's/^/    /' || true

    cat <<NEXT

=== VM '${vm_name}' converted to TDX ===

Backup: ${backup_path}

Next steps:
  1. Start the VM:              virsh start ${vm_name}
  2. Install/verify guest OS:   virsh console ${vm_name}
  3. Setup guest attestation:   sudo ${SCRIPT_NAME} setup-guest --guest-ip <IP>
  4. Run attestation:           sudo ${SCRIPT_NAME} attest --guest-ip <IP>

NOTE: The guest must have a TDX-capable kernel (6.1+) and the tdx_guest module.
NEXT
    log "Conversion complete."
}

# List all VMs with status and IP address.
cmd_show_vm_info() {
    require_cmd virsh
    echo ""
    printf "%-30s %-12s %-18s\n" "NAME" "STATE" "IP"
    printf "%-30s %-12s %-18s\n" "----" "-----" "--"
    local vm state ip
    while IFS= read -r vm; do
        [[ -z "$vm" ]] && continue
        state=$(virsh domstate "$vm" 2>/dev/null || echo "unknown")
        ip="—"
        if [[ "$state" == "running" ]]; then
            ip=$(virsh domifaddr "$vm" 2>/dev/null | awk '/ipv4/ {print $4}' | cut -d/ -f1 | head -1 || true)
            ip="${ip:-no IP detected}"
        fi
        printf "%-30s %-12s %-18s\n" "$vm" "$state" "$ip"
    done < <(virsh list --all --name 2>/dev/null)
    echo ""
}

# Auto-detect guest IP from running VMs if GUEST_IP is not set.
# Lists running VMs with their IPs, auto-selects if only one, prompts otherwise.
# Sets GUEST_IP on success; dies on failure.
qgs_preflight_checks() {
    # 1. QGS must run in unix-socket mode: QGSD_ARGS must NOT contain -p=
    local qgsd_args
    qgsd_args=$(systemctl show qgsd.service -p Environment --value 2>/dev/null | tr ' ' '\n' | grep -oP 'QGSD_ARGS=\K.*' | tr '"' '\n' || true)
    if [[ -n "$qgsd_args" && "$qgsd_args" == *"-p="* ]]; then
        record "FAIL" "QGS in TCP mode: QGSD_ARGS contains -p= (must be unix-socket only)" \
            "Run: sudo ${SCRIPT_NAME} setup-qgs (writes override.conf dropping -p=)"
    else
        record "PASS" "QGS unix-socket mode: QGSD_ARGS has no -p= flag"
    fi

    # 2. QGS socket must exist and be a real socket (not a stale symlink)
    if [[ -S "${QGS_SOCKET}" ]]; then
        record "PASS" "QGS socket present: ${QGS_SOCKET}"
    elif [[ -L "${QGS_SOCKET}" ]]; then
        record "FAIL" "QGS socket is a stale symlink: ${QGS_SOCKET}" \
            "Remove it and restart: rm ${QGS_SOCKET} && systemctl restart qgsd.service"
    else
        record "FAIL" "QGS socket missing: ${QGS_SOCKET}" \
            "Start QGS: systemctl start qgsd.service  (or sudo ${SCRIPT_NAME} setup-qgs)"
    fi

    # 3. qemu user must be in the qgsd group to connect to the socket
    if id qgsd >/dev/null 2>&1 && id qemu >/dev/null 2>&1; then
        if id -nG qemu 2>/dev/null | tr ' ' '\n' | grep -qx qgsd; then
            record "PASS" "qemu user is in qgsd group (socket access OK)"
        else
            record "FAIL" "qemu user NOT in qgsd group (cannot reach QGS socket)" \
                "Run: usermod -aG qgsd qemu  (or sudo ${SCRIPT_NAME} setup-qgs)"
        fi
    else
        record "WARN" "qgsd or qemu user missing; skipping group check" ""
    fi

    # 4. QCNL config must exist (QGS reads /etc/sgx_default_qcnl.conf)
    if [[ -f "$QCNL_PKG_CONF" ]]; then
        record "PASS" "QCNL config present: ${QCNL_PKG_CONF}"
    else
        record "FAIL" "QCNL config missing: ${QCNL_PKG_CONF}" \
            "Run: sudo ${SCRIPT_NAME} setup-qgs  (writes QCNL config for QGS)"
    fi

    # 5. Collateral source must be reachable (QGS fetches PCK collateral from here)
    local coll_url
    coll_url=$(collateral_url)
    if probe_collateral_url "$coll_url"; then
        record "PASS" "Collateral source reachable (${COLLATERAL_MODE}): ${coll_url}"
    else
        record "FAIL" "Collateral source unreachable (${COLLATERAL_MODE}): ${coll_url}" \
            "PCS: check host internet access; PCCS: start the local PCCS (--pccs-url)"
    fi

    # 6. VM must have a vsock device (QGS talks to the TD over vsock)
    # Resolve the VM name from the guest IP (match against domifaddr output)
    local GUEST_VM_NAME=""
    if command -v virsh >/dev/null 2>&1; then
        local vm
        while IFS= read -r vm; do
            [[ -z "$vm" ]] && continue
            if virsh domifaddr "$vm" 2>/dev/null | grep -q "$GUEST_IP"; then
                GUEST_VM_NAME="$vm"
                break
            fi
        done < <(virsh list --name 2>/dev/null)
    fi
    local guest_vm_xml
    if [[ -n "$GUEST_VM_NAME" ]]; then
        guest_vm_xml=$(virsh dumpxml "$GUEST_VM_NAME" 2>/dev/null || true)
    else
        guest_vm_xml=""
        GUEST_VM_NAME="<VM>"
    fi
    if [[ -n "$guest_vm_xml" ]] && grep -q "<vsock" <<<"$guest_vm_xml"; then
        record "PASS" "VM '${GUEST_VM_NAME}' has a vsock device"
    else
        record "FAIL" "VM '${GUEST_VM_NAME}' has NO vsock device" \
            "Quote generation over vsock will fail; re-run setup-vm or convert-tdx"
    fi
}

cmd_setup_guest() {
    require_root

    detect_guest_ip

    if [[ -z "$GUEST_IP" ]]; then
        require_cmd "$(distro_pkg_manager)"
    fi

    log "=== Setting up TDX guest (ssh to ${GUEST_IP}) ==="
    step "Inside the TD: install attest libs, write QCNL, generate a Quote" \
        "Confirms a TDX guest device exists, then runs test_tdx_attest to produce quote.dat + report.dat."

    # Verify SSH connectivity before proceeding
    log "Checking SSH connectivity to ${GUEST_IP}..."
    if ! ssh -i "$SSH_KEY" \
        -o StrictHostKeyChecking=accept-new \
        -o ConnectTimeout=10 \
        -o BatchMode=yes \
        "${GUEST_USER}@${GUEST_IP}" "echo ok" >/dev/null 2>&1; then
        die "Cannot connect to ${GUEST_USER}@${GUEST_IP} via SSH.

=== Troubleshooting ===

1. Guest OS not installed yet?
  Open console and install the OS:
    virsh console <VM_NAME>

2. SSH service not running in guest?
  Check inside the guest:
    sudo systemctl status sshd
    sudo systemctl enable --now sshd

3. SSH key not injected?
  The script uses key: ${SSH_KEY}
  If it does not exist, create one:
    ssh-keygen -t ed25519 -f ${SSH_KEY} -N ''
  Then copy the public key to the guest:
    ssh-copy-id -i ${SSH_KEY}.pub ${GUEST_USER}@${GUEST_IP}
  Or manually (if you have console access):
    echo '$(cat ${SSH_KEY}.pub 2>/dev/null || echo "<paste your public key here>")' | ssh ${GUEST_USER}@${GUEST_IP} 'mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys'

4. Wrong IP?
  Check the actual guest IP:
    virsh net-dhcp-leases default

5. Firewall blocking port 22?
  Check inside the guest:
    sudo firewall-cmd --list-ports
    sudo firewall-cmd --add-port=22/tcp --permanent && sudo firewall-cmd --reload"
    fi
    log "SSH connection to ${GUEST_IP} OK"

    # Refuse to run against the TDX host. kvm_intel.tdx=Y exists only on a TDX
    # host, never inside a Trust Domain. Without this guard the target can pass
    # the device probe below (configfs-tsm can be present on the host) and then
    # fail later inside test_tdx_attest with a misleading "Failed to get the
    # report".
    if ssh_guest "grep -qx Y /sys/module/kvm_intel/parameters/tdx 2>/dev/null"; then
        die "Target is the TDX *host* (kvm_intel.tdx=Y), not a Trust Domain.
Boot the TD first, then run:
  sudo tdx-attest.sh setup-guest --guest-ip <TD_IP>
or run this command inside the TD itself."
    fi

    # The guest attestation device node name depends on the kernel:
    #   /dev/tdx_guest   upstream (>= 6.7, SLE 16.1)
    #   /dev/tdx-guest   early upstream backports
    #   /dev/tdx-attest  legacy out-of-tree Intel DCAP driver
    # A real character device is required: configfs-tsm alone is not proof of
    # running inside a TD.
    log "Checking for a TDX guest attestation device (must exist INSIDE a Trust Domain)"
    local tdx_dev=""
    for d in /dev/tdx_guest /dev/tdx-guest /dev/tdx-attest; do
        if ssh_guest "test -c $d"; then
            tdx_dev="$d"
            break
        fi
    done
    if [[ -z "$tdx_dev" ]]; then
        die "No TDX guest attestation device found (looked for /dev/tdx_guest,
/dev/tdx-guest and /dev/tdx-attest).
This command must run INSIDE the Trust Domain, not on the host.
  - If you targeted localhost from the host: use --guest-ip <TD_IP> instead.
  - Inside the TD, check: 'modprobe tdx_guest' and 'dmesg | grep -i tdx'.
    'modprobe: No such device' means the VM is not a Trust Domain.
  - On the host, the VM must be started with -machine q35,confidential-guest-support=tdx
    and a tdx-guest object, with TDX enabled in BIOS.
See doc: tdx-guest-setup troubleshooting."
    fi
    log "Found ${tdx_dev} — running inside a real Trust Domain"

    if ssh_guest "grep -qw tdx /proc/cpuinfo"; then
        log "Guest CPU reports tdx flag"
    else
        warn "Guest CPU does not report tdx flag (may still be OK via host-passthrough)"
    fi

    log "Disabling suspend/hibernate in guest (TDX requirement)"
    if disable_suspend_guest; then
        log "Suspend/hibernate targets masked in guest"
    else
        warn "Failed to mask suspend/hibernate targets in guest. Do it manually:"
        warn "  sudo systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target"
    fi

    log "Creating guest workdir: ${GUEST_WORKDIR}"
    ssh_guest "sudo mkdir -p ${GUEST_WORKDIR} && sudo chown \$(whoami) ${GUEST_WORKDIR}" ||
        ssh_guest "mkdir -p ${GUEST_WORKDIR}"

    log "Checking attestation libraries + KBS client in guest"
    # shellcheck disable=SC2046  # deliberate word-splitting of the package list
    install_pkgs_guest $(guest_distro_pkgs guest_libs)

    log "Verifying libraries"
    ssh_guest "ldconfig -p | grep tdx" || warn "No tdx libraries found in ldconfig"

    # The package kbs-client lacks the TDX attester. Build a TDX-enabled one on
    # the host and ship it to the guest so secret-get can produce a real quote.
    if command -v cargo >/dev/null 2>&1; then
        build_kbs_client_tdx
    else
        warn "cargo not found on host — cannot build TDX-enabled kbs-client."
        warn "secret-get will use the package kbs-client (no TDX attester, falls back to sample)."
        warn "Install Rust (rustup) and re-run setup-guest, or build manually:"
        warn "  git clone ${TRUSTEE_REPO} && cd trustee && cargo build -p kbs-client --release --features tdx-attester"
    fi

    # The guest QCNL uses the same collateral source as the host. In PCCS mode
    # the PCCS root CA is shipped to the guest and trusted there as well.
    setup_collateral_source
    local guest_qcnl_url
    guest_qcnl_url=$(collateral_url)
    local guest_secure="true"
    if [[ "$USE_SECURE_CERT" == "false" || ("$USE_SECURE_CERT" == "auto" && "$guest_qcnl_url" =~ ^http://) ]]; then
        guest_secure="false"
    fi
    log "Writing QCNL config in guest (use_secure_cert=${guest_secure})"
    ssh_guest "sudo bash -s" <<EOF
set -e
mkdir -p /run/dcap
cat > /run/dcap/qcnl.conf <<'QCNL'
{
  "pccs_url": "${guest_qcnl_url}",
  "use_secure_cert": ${guest_secure},
  "retry_times": 6,
  "retry_delay": 10,
  "pck_cache_expire_hours": 168,
  "verify_collateral_cache_expire_hours": 168,
  "local_cache_only": false
}
QCNL
chmod 640 /run/dcap/qcnl.conf
EOF
    if [[ "$COLLATERAL_MODE" == "pccs" && -s "$PCCS_ROOT_CA" ]]; then
        log "Shipping PCCS root CA to guest and trusting it"
        ssh_guest "$(guest_distro_ca_trust_cmd)" \
            <"$PCCS_ROOT_CA" || die "Failed to install PCCS root CA in guest"
    fi
    log "QCNL config written in guest"

    # --- Pre-flight: verify QGS host-side config before generating a quote ---
    # test_tdx_attest fails opaquely if QGS is misconfigured on the host.
    # Check the common failure modes up front and report green/red.
    # shellcheck disable=SC2034  # CHECK_RESULTS used by print_results() and qgs_preflight_checks()
    CHECK_RESULTS=()
    qgs_preflight_checks

    local qgs_fails=0
    print_results
    qgs_fails=$RESULT_FAILS
    if ((qgs_fails > 0)); then
        warn "${qgs_fails} QGS pre-flight check(s) FAILED. Fix the items above, then re-run setup-guest."
        trap - ERR
        return 1
    fi
    log "QGS pre-flight: all checks passed."

    log "Generating TD Report + Quote (test_tdx_attest)"
    if ! guest_generate_quote; then
        # Re-run the QGS pre-flight checks to pinpoint the exact red item(s).
        # shellcheck disable=SC2034  # CHECK_RESULTS used by print_results() in checks.sh
        CHECK_RESULTS=()
        qgs_preflight_checks
        print_results
        if diagnose_quote_failure; then
            die "Quote generation failed: PCS has no PCK certificate for this TDX module (see above). Update the platform TDX module to a PCS-registered version, or re-run with --collateral pccs."
        fi
        die "test_tdx_attest failed. The red items above are the likely cause(s) — fix them, then re-run setup-guest."
    fi

    log "Quote generated. First bytes:"
    ssh_guest "od -A x -t x1z ${GUEST_WORKDIR}/quote.dat | head -10"

    cat <<NEXT

=== Guest setup complete ===
quote.dat and report.dat are in ${GUEST_WORKDIR} on the guest.
Next: sudo tdx-attest.sh attest --guest-ip <GUEST_IP>
NEXT
}
