#!/usr/bin/env python3
"""patch_vm_xml.py — TDX XML patch for libvirt domain XML.

Two modes:

1. virt-install mode (default): post-define XML patch for TDX VM creation
   via virt-install. Injects TDX-specific libvirt domain XML elements that
   virt-install cannot express via CLI flags: launchSecurity, vsock, memtune
   hard_limit, resource partition, and pm suspend-disabled.

   The input XML is produced by virt-install --print-xml, which (on 5.x)
   emits the domain TWICE: first the runtime variant (with the one-shot
   <kernel>/<initrd>/<cmdline> installer boot, cache="unsafe", and an
   <on_reboot>destroy</on_reboot> we do NOT want), then the persistent
   variant (without the kernel, with <boot> order). Two concatenated
   documents are not valid XML, so we keep only the FIRST document (the
   runtime variant — its one-shot installer boot is exactly what the first
   boot needs) and normalize it below.

   This is called from setup-vm.sh (patch_vm_xml_tdx) after virt-install
   generates the XML, so the patch is applied BEFORE the first boot.

2. convert-tdx mode (--rom-loader OVMF_BIN): converts an existing
   (non-TDX) VM's XML (virsh dumpxml) in place: replaces the pflash loader
   with a stateless ROM loader, removes nvram/memoryBacking/ioapic, adds
   launchSecurity + vsock, and disables suspend-to-mem/disk. All other
   elements (disk, network, graphics, video, UUID, MAC, ...) are preserved.

   This is called from setup-vm.sh (edit_vm_xml_tdx, convert-tdx command).

Usage:
    patch_vm_xml.py <input_xml> <output_xml> <qgs_socket> <mem_hard_limit_kib>
    patch_vm_xml.py <input_xml> <output_xml> <qgs_socket> --rom-loader OVMF_BIN

Parsing uses defusedxml.ElementTree.fromstring when available (guards
against entity-expansion attacks) and falls back to the standard library,
which does not expand external entities either. The input is produced
locally (virt-install / virsh), so this is defense-in-depth, not a trust
boundary.
"""

import sys
import xml.etree.ElementTree as ET

try:
    from defusedxml.ElementTree import fromstring
except ImportError:
    fromstring = ET.fromstring


def add_launch_security(root, qgs_socket, before_devices):
    """Ensure <launchSecurity type='tdx'> with policy + QGS socket.

    before_devices=True inserts before <devices> (convert-tdx mode);
    False appends at the end of the document (virt-install mode — the
    canonical position is after <devices>).
    """
    ls = root.find("launchSecurity")
    if ls is None:
        ls = ET.Element("launchSecurity", {"type": "tdx"})
        if before_devices:
            devices = root.find("devices")
            if devices is not None:
                root.insert(list(root).index(devices), ls)
            else:
                root.append(ls)
        else:
            root.append(ls)
    else:
        ls.set("type", "tdx")
    for tag in ("policy", "quoteGenerationService"):
        for el in ls.findall(tag):
            ls.remove(el)
    ET.SubElement(ls, "policy").text = "0x10000000"
    ET.SubElement(ls, "quoteGenerationService", {"path": qgs_socket})


def add_vsock(devices, before_memballoon):
    """Ensure a vsock (virtio, auto cid) in <devices>.

    before_memballoon=True inserts before <memballoon> (convert-tdx mode);
    False appends at the end of <devices> (virt-install mode).
    """
    if devices is None or devices.find("vsock") is not None:
        return
    vsock = ET.Element("vsock", {"model": "virtio"})
    ET.SubElement(vsock, "cid", {"auto": "yes"})
    if before_memballoon:
        memballoon = devices.find("memballoon")
        if memballoon is not None:
            devices.insert(list(devices).index(memballoon), vsock)
            return
    devices.append(vsock)


def disable_suspend(root, devices):
    """TDX cannot hibernate: disable suspend-to-mem/disk in <pm>."""
    pm = root.find("pm")
    if pm is None:
        pm = ET.Element("pm")
        if devices is not None:
            root.insert(list(root).index(devices), pm)
        else:
            root.append(pm)
    for tag in ("suspend-to-mem", "suspend-to-disk"):
        el = pm.find(tag)
        if el is None:
            el = ET.SubElement(pm, tag)
        el.set("enabled", "no")


def patch_convert_tdx(root, rom_loader, qgs_socket):
    """Convert an existing (non-TDX) VM's XML in place to TDX.

    Changes: loader pflash->rom (stateless), removes nvram/memoryBacking/
    ioapic, adds launchSecurity + vsock, disables suspend.
    """
    os_el = root.find("os")
    if os_el is not None:
        # 1. <os>: remove firmware attr and <firmware> element
        os_el.attrib.pop("firmware", None)
        for fw in os_el.findall("firmware"):
            os_el.remove(fw)
        # 2. <loader>: replace pflash with stateless rom (only if present)
        if os_el.find("loader") is not None:
            for child in list(os_el):
                if child.tag == "loader":
                    os_el.remove(child)
            new_loader = ET.Element(
                "loader", {"type": "rom", "format": "raw", "stateless": "yes"}
            )
            new_loader.text = rom_loader
            os_el.insert(1, new_loader)
        # 3. Remove <nvram> from <os> (TDX OVMF is stateless, no NVRAM)
        for nvram in os_el.findall("nvram"):
            os_el.remove(nvram)
    # 4. Remove <memoryBacking>
    for mb in root.findall("memoryBacking"):
        root.remove(mb)
    # 5. Remove <ioapic> from <features>
    features = root.find("features")
    if features is not None:
        for ioapic in features.findall("ioapic"):
            features.remove(ioapic)
    devices = root.find("devices")
    # 6. Add <launchSecurity> before <devices>
    add_launch_security(root, qgs_socket, before_devices=True)
    # 7. Add <vsock> in <devices> (before <memballoon>)
    add_vsock(devices, before_memballoon=True)
    # 8. <pm>: TDX cannot hibernate
    disable_suspend(root, devices)


def patch_virt_install(root, qgs_socket, mem_hard_limit):
    """Normalize a virt-install --print-xml runtime variant for TDX."""
    # Drop <on_reboot>destroy</on_reboot> from the runtime variant: after the
    # install the guest must reboot into the installed OS, not be destroyed.
    for ob in root.findall("on_reboot"):
        root.remove(ob)

    # The runtime variant lacks the <boot> order the persistent one has; a
    # stateless ROM loader needs it explicit. Insert after firmware/loader.
    os_el = root.find("os")
    if os_el is not None and os_el.find("boot") is None:
        boot_devs = ["cdrom", "hd"]
        insert_at = 1  # after <type>
        for child in os_el:
            if child.tag in ("firmware", "loader"):
                insert_at = list(os_el).index(child) + 1
        for i, dev in enumerate(boot_devs):
            os_el.insert(insert_at + i, ET.Element("boot", {"dev": dev}))

    # 1. launchSecurity: ensure TDX policy + QGS socket. libvirt may auto-add a
    #    bare <launchSecurity type='tdx'/> from the machine flag; make it explicit.
    add_launch_security(root, qgs_socket, before_devices=False)

    # 2. vsock (quote generation over vsock)
    devices = root.find("devices")
    add_vsock(devices, before_memballoon=False)

    # 3. memtune hard_limit (firmware + overhead headroom), after currentMemory
    for mb in root.findall("memtune"):
        root.remove(mb)
    mt = ET.Element("memtune")
    ET.SubElement(mt, "hard_limit", {"unit": "KiB"}).text = str(mem_hard_limit)
    children = list(root)
    idx = next((i for i, c in enumerate(children) if c.tag == "currentMemory"), 1)
    root.insert(idx + 1, mt)

    # 4. resource partition /machine, after vcpu
    if root.find("resource") is None:
        res = ET.Element("resource")
        ET.SubElement(res, "partition").text = "/machine"
        children = list(root)
        idx = next((i for i, c in enumerate(children) if c.tag == "vcpu"), 2)
        root.insert(idx + 1, res)

    # 5. pm: TDX cannot hibernate — disable suspend-to-mem/disk, before <devices>
    disable_suspend(root, devices)

    # 6. qemu:commandline: with <launchSecurity type='tdx'> present, libvirt
    #    itself adds the tdx-guest object + confidential-guest-support machine
    #    flag. The explicit -object/-machine args virt-install left in the
    #    qemu-commandline would duplicate them and break TD init (KVM_TDX_INIT_
    #    VCPU EINVAL), so strip that pair (keep any other commandline args).
    NS = "{http://libvirt.org/schemas/domain/qemu/1.0}"
    for cl in root.findall(NS + "commandline"):
        args = cl.findall(NS + "arg")
        for i, arg in enumerate(args):
            v = arg.get("value", "")
            if v in ("-object", "-machine") and i + 1 < len(args):
                nv = args[i + 1].get("value", "")
                if (v == "-object" and nv.startswith("tdx-guest,")) or (
                    v == "-machine" and nv.startswith("confidential-guest-support=")
                ):
                    cl.remove(arg)
                    cl.remove(args[i + 1])
        if not cl.findall(NS + "arg"):
            root.remove(cl)


def main():
    argv = sys.argv[1:]
    rom_loader = None
    if "--rom-loader" in argv:
        i = argv.index("--rom-loader")
        if i + 1 >= len(argv):
            print("Error: --rom-loader requires an OVMF binary path", file=sys.stderr)
            sys.exit(2)
        rom_loader = argv[i + 1]
        del argv[i : i + 2]
    if len(argv) not in (3, 4):
        print(
            f"usage: {sys.argv[0]} <input_xml> <output_xml> <qgs_socket> "
            f"[mem_hard_limit_kib] [--rom-loader OVMF_BIN]",
            file=sys.stderr,
        )
        sys.exit(2)
    input_xml, output_xml, qgs_socket = argv[0:3]
    mem_hard_limit = None
    if len(argv) == 4:
        try:
            mem_hard_limit = int(argv[3])
        except ValueError:
            print(
                f"Error: mem_hard_limit_kib must be an integer, got '{argv[3]}'",
                file=sys.stderr,
            )
            sys.exit(2)
    if rom_loader is None and mem_hard_limit is None:
        print(
            "Error: mem_hard_limit_kib is required unless --rom-loader is given",
            file=sys.stderr,
        )
        sys.exit(2)

    try:
        with open(input_xml, "rb") as fh:
            content = fh.read()
    except OSError as e:
        print(f"Error reading input XML '{input_xml}': {e}", file=sys.stderr)
        sys.exit(1)

    # virt-install 5.x --print-xml emits the domain TWICE (see module
    # docstring). Truncate to the first document BEFORE parsing — two
    # concatenated <domain> documents are not valid XML and the parser
    # would reject them. No-op for single-document input (virsh dumpxml).
    if content.count(b"<domain") > 1:
        end = content.index(b"</domain>") + len(b"</domain>")
        content = content[:end]

    try:
        root = fromstring(content)
    except Exception as e:
        print(f"Error parsing XML from '{input_xml}': {e}", file=sys.stderr)
        sys.exit(1)

    ET.register_namespace("", "")

    if rom_loader is not None:
        patch_convert_tdx(root, rom_loader, qgs_socket)
    else:
        patch_virt_install(root, qgs_socket, mem_hard_limit)

    # Write output XML
    try:
        ET.ElementTree(root).write(output_xml, xml_declaration=True, encoding="unicode")
    except OSError as e:
        print(f"Error writing output XML '{output_xml}': {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
