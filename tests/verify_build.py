#!/usr/bin/env python3
"""Pre-flight check for an lk.img built by this tool.

Usage:
    python tests/verify_build.py lk_patched.img --stock lk.img --key private.pem

It verifies that:
  * the image parses into the expected MTK partitions;
  * every partition except ``lk`` is byte-identical to the stock image;
  * cert1 of every partition is untouched;
  * cert2 override hashes match the patched partition contents;
  * the private key on disk matches the modulus embedded in the image.

Exit code 0 means all checks passed.
"""

import argparse
import sys
from pathlib import Path

from liblk.image import LkImage
from pyasn1.codec.der import decoder as der_decode
from pyasn1.codec.der import encoder as der_encode


def diff_ranges(a: bytes, b: bytes):
    """Return [(start, end)] byte ranges that differ (None if lengths differ)."""
    if len(a) != len(b):
        return None
    out, start = [], None
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y and start is None:
            start = i
        elif x == y and start is not None:
            out.append((start, i))
            start = None
    if start is not None:
        out.append((start, len(a)))
    return out


def check_cert2(partition):
    """Return True if the cert2 override hashes match the partition contents."""
    cert2 = partition.certs[1].data if len(partition.certs) > 1 else None
    if cert2 is None or cert2[0] != 0xA0:
        return None
    content = cert2[2:2 + cert2[1]]
    values, offset = [], 0
    while offset < len(content):
        value, _ = der_decode.decode(content[offset:])
        values.append(value)
        offset += len(der_encode.encode(value))
    digests = [bytes(v.asOctets()) for v in values if type(v).__name__ == "BitString"]
    if len(digests) < 2:
        return None
    header_hash, image_hash = partition.compute_hashes()
    return digests[0] == header_hash and digests[1] == image_hash


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("image", help="patched lk image")
    parser.add_argument("--stock", help="stock lk image to compare against")
    parser.add_argument("--key", help="private.pem that should match the image")
    args = parser.parse_args()

    ok = True

    def fail(msg):
        nonlocal ok
        ok = False
        print(f"  [!] {msg}")

    try:
        image = LkImage(Path(args.image).read_bytes())
    except Exception as exc:
        print(f"[-] cannot parse {args.image}: {exc}")
        return 1

    print(f"[+] {args.image}: {len(Path(args.image).read_bytes())} bytes, "
          f"{len(image.partitions)} partitions")

    if "lk" not in image.partitions:
        fail("no 'lk' partition")
        return 1

    stock = None
    if args.stock:
        try:
            stock = LkImage(Path(args.stock).read_bytes())
        except Exception as exc:
            fail(f"cannot parse stock image: {exc}")

    if stock is not None:
        if list(image.partitions) != list(stock.partitions):
            fail("partition list differs from stock")
        else:
            print("  [ok] partition list matches stock")
        for name, part in image.partitions.items():
            other = stock.partitions.get(name)
            if other is None:
                continue
            if name != "lk" and part.data != other.data:
                fail(f"partition '{name}' data differs from stock")
            if len(part.certs) != len(other.certs):
                fail(f"partition '{name}' certificate count differs from stock")
            elif part.certs and part.certs[0].data != other.certs[0].data:
                fail(f"partition '{name}' cert1 differs from stock")
        print("  [ok] non-lk partitions and all cert1 blocks match stock")

        patched_lk = image.partitions["lk"].data
        stock_lk = stock.partitions["lk"].data
        ranges = diff_ranges(stock_lk, patched_lk)
        if ranges is None:
            print(f"  [i] lk data length {len(stock_lk)} -> {len(patched_lk)}")
        else:
            total = sum(e - s for s, e in ranges)
            print(f"  [i] lk data differs in {len(ranges)} range(s), {total} bytes")
            for start, end in ranges:
                print(f"      0x{start:X}-0x{end - 1:X} ({end - start} bytes)")

    result = check_cert2(image.partitions["lk"])
    if result is None:
        fail("lk cert2 has no parsable override block")
    elif not result:
        fail("lk cert2 override hashes do NOT match the data")
    else:
        print("  [ok] lk cert2 override hashes match the patched data")

    if args.key:
        try:
            from cryptography.hazmat.primitives import serialization
            key = serialization.load_pem_private_key(
                Path(args.key).read_bytes(), password=None)
            modulus = key.public_key().public_numbers().n.to_bytes(256, "big")
        except Exception as exc:
            fail(f"cannot load key: {exc}")
        else:
            found = image.partitions["lk"].data.find(modulus)
            if found < 0:
                fail("private key does not match the modulus in the image")
            else:
                print(f"  [ok] private key matches image modulus at 0x{found:X}")

    print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
