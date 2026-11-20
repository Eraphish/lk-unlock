import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from liblk.image import LkImage

from . import resource_path
from .cert_bypass import CertBypassMode, apply_cert_bypass
from .keys import get_keys
from .no_wipe import apply_no_wipe_patch
from .protect import apply_fake_lock, apply_lk_protection


def patch_img(
    img_path: str,
    output_path: str = None,
    use_wrap: bool = False,
    no_wipe_block: bool = False,
    lk_protect: str = "fail",
    fake_lock: bool = False,
):
    if output_path is None:
        img = Path(img_path)
        output_path = str(img.with_name(f"{img.stem}_patched{img.suffix}"))

    _, new_pub_key = get_keys()
    new_n_bytes = new_pub_key.public_numbers().n.to_bytes(256, byteorder='big')

    xiaomi_pem = Path("xiaomi.pem")
    if not xiaomi_pem.exists():
        xiaomi_pem = Path(resource_path("xiaomi.pem"))

    try:
        with xiaomi_pem.open("rb") as f:
            old_pub_key = serialization.load_pem_public_key(f.read())
    except FileNotFoundError:
        print("[-] 'xiaomi.pem' file not found.")
        sys.exit(1)

    old_n_bytes = old_pub_key.public_numbers().n.to_bytes(256, byteorder='big')
    try:
        with open(img_path, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        print(f"[-] '{img_path}' file not found.")
        sys.exit(1)

    pos = data.find(old_n_bytes)

    if pos == -1:
        print("[-] Error: Xiaomi's public key modulus not found in LK image. Nothing to patch.")
        sys.exit(1)

    print(f"[+] Original key modulus found at offset 0x{pos:X}")

    patched_data = data[:pos] + new_n_bytes + data[pos + len(new_n_bytes):]

    print(f"[+] Public key patched successfully")

    if no_wipe_block:
        print("[+] Userdata wipe patch disabled by --no-wipe-block")
    else:
        try:
            patched_data, no_wipe_patch, no_wipe_offset = apply_no_wipe_patch(patched_data)
            print(
                f"[+] Userdata wipe patch applied: {no_wipe_patch.name} "
                f"at 0x{no_wipe_offset:X}"
            )
        except ValueError as exc:
            print(f"[!] Userdata wipe patch not applied: {exc}")
            print("[!] Continuing with the public key replacement only")

    try:
        image = LkImage(patched_data)
    except Exception as exc:
        print(f"[-] Failed to parse the patched LK image: {exc}")
        sys.exit(1)

    try:
        if lk_protect != "off" or fake_lock:
            lk = image.partitions["lk"]
            base = lk.lk_address
            lk_data = lk.data
            cave_end = None

            if lk_protect != "off":
                lk_data, info = apply_lk_protection(lk_data, base, lk_protect)
                cave_end = info["cave"] - base + info["size"]
                print(
                    f"[+] LK write protection installed ({lk_protect}): "
                    f"flash handler 0x{info['flash_handler']:X}, "
                    f"erase handler 0x{info['erase_handler']:X}, "
                    f"cave 0x{info['cave']:X}"
                )

            if fake_lock:
                lk_data, info = apply_fake_lock(lk_data, base, cave_off=cave_end)
                print(
                    f"[+] Fake lock state installed: cmdline append at "
                    f"0x{info['cave']:X}"
                )

            lk.data = lk_data
            image._rebuild_contents()
    except Exception as exc:
        print(f"[-] Failed to install LK protection / fake lock: {exc}")
        sys.exit(1)

    try:
        cert_bypass_mode = CertBypassMode.WRAP if use_wrap else CertBypassMode.OVERRIDE
        print(f"[+] Selected cert bypass mode: {cert_bypass_mode.value}")
        signed = apply_cert_bypass(image, cert_bypass_mode)
        if signed:
            patched_data = bytes(image.contents)
            print(f"[+] Cert bypass completed for: {', '.join(signed)}")
        else:
            patched_data = bytes(image.contents)
            print("[+] Cert bypass was not needed")
    except Exception as exc:
        print(f"[-] Failed to apply cert bypass: {exc}")
        sys.exit(1)

    with open(output_path, "wb") as f:
        f.write(patched_data)

    print(f"[+] All done! Lk saved to: {output_path}")


def resign_img(img_path: str, output_path: str = None):
    """Recompute the cert2 hash-override block for an already edited image.

    The image must still carry its original (parseable) cert2 certificates,
    i.e. it must not have been through ``patch`` before.
    """
    if output_path is None:
        img = Path(img_path)
        output_path = str(img.with_name(f"{img.stem}_signed{img.suffix}"))

    with open(img_path, "rb") as f:
        data = f.read()

    try:
        image = LkImage(data)
        signed = apply_cert_bypass(image, CertBypassMode.OVERRIDE)
    except Exception as exc:
        print(f"[-] Failed to re-sign: {exc}")
        sys.exit(1)

    if not signed:
        print("[+] Nothing to sign (all cert2 already match)")
        return

    with open(output_path, "wb") as f:
        f.write(bytes(image.contents))

    print(f"[+] Re-signed partitions: {', '.join(signed)}")
    print(f"[+] Saved to: {output_path}")
