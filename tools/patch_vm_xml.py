#!/usr/bin/env python3
"""patch_vm_xml.py — Post-define XML patch for virt-install TDX VM creation.

Injects TDX-specific libvirt domain XML elements that virt-install cannot
express via CLI flags: launchSecurity, vsock, memtune hard_limit, resource
partition, and pm suspend-disabled.

Usage:
    patch_vm_xml.py <input_xml> <output_xml> <qgs_socket> <mem_hard_limit_kib>

The input XML is produced by virt-install --print-xml, which (on 5.x) emits
the domain TWICE: first the runtime variant (with the one-shot
<kernel>/<initrd>/<cmdline> installer boot, cache="unsafe", and an
<on_reboot>destroy</on_reboot> we do NOT want), then the persistent variant
(without the kernel, with <boot> order). Two concatenated documents are not
valid XML, so we keep only the FIRST document (the runtime variant — its
one-shot installer boot is exactly what the first boot needs) and normalize
it below.

This is called from setup-vm.sh (patch_vm_xml_tdx) after virt-install
generates the XML, so the patch is applied BEFORE the first boot.

Parsing uses defusedxml.ElementTree.fromstring when available (guards
against entity-expansion attacks) and falls back to the standard library,
which does not expand external entities either. The input is produced
locally by virt-install, so this is defense-in-depth, not a trust boundary.
"""

import sys
import xml.etree.ElementTree as ET

try:
    from defusedxml.ElementTree import fromstring
except ImportError:
    fromstring = ET.fromstring


def main():
    if len(sys.argv) != 5:
        print(
            f"usage: {sys.argv[0]} <input_xml> <output_xml> <qgs_socket> <mem_hard_limit_kib>",
            file=sys.stderr,
        )
        sys.exit(2)

    input_xml, output_xml, qgs_socket, mem_hard_limit = sys.argv[1:5]
    try:
        mem_hard_limit = int(mem_hard_limit)
    except ValueError:
        print(
            f"Error: mem_hard_limit_kib must be an integer, got '{mem_hard_limit}'",
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
    # would reject them.
    if content.count(b"<domain") > 1:
        end = content.index(b"</domain>") + len(b"</domain>")
        content = content[:end]

    try:
        root = fromstring(content)
    except Exception as e:
        print(f"Error parsing XML from '{input_xml}': {e}", file=sys.stderr)
        sys.exit(1)

    ET.register_namespace("", "")

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
    ls = root.find("launchSecurity")
    if ls is None:
        ls = ET.Element("launchSecurity", {"type": "tdx"})
        root.append(ls)  # canonical position: after <devices>
    else:
        ls.set("type", "tdx")
    for tag in ("policy", "quoteGenerationService"):
        for el in ls.findall(tag):
            ls.remove(el)
    ET.SubElement(ls, "policy").text = "0x10000000"
    ET.SubElement(ls, "quoteGenerationService", {"path": qgs_socket})

    # 2. vsock (quote generation over vsock)
    devices = root.find("devices")
    if devices is not None and devices.find("vsock") is None:
        vsock = ET.Element("vsock", {"model": "virtio"})
        ET.SubElement(vsock, "cid", {"auto": "yes"})
        devices.append(vsock)

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

    # Write output XML
    try:
        ET.ElementTree(root).write(output_xml, xml_declaration=True, encoding="unicode")
    except OSError as e:
        print(f"Error writing output XML '{output_xml}': {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
