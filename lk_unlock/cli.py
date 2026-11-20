import argparse

from .fastboot import unlock_device
from .patch import patch_img, resign_img
from .sign import sign_token


def main():
    parser = argparse.ArgumentParser(description="Unlocking Xiaomi mtk bootloader by patching the public key.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    patch_parser = subparsers.add_parser("patch", help="Patch lk.img")
    patch_parser.add_argument("img", help="lk.img file path")
    patch_parser.add_argument("-o", "--output", help="Output file path", default=None)
    patch_parser.add_argument("--wrap", action="store_true", help="Use wrap mode for cert bypass")
    patch_parser.add_argument(
        "--no-wipe-block",
        action="store_true",
        help="Disable the userdata wipe patch",
    )
    patch_parser.add_argument(
        "--lk-protect",
        choices=("fail", "okay", "off"),
        default="fail",
        help="Block fastboot writes to lk/lk_a/lk_b: fail (default), "
        "okay (pretend success and skip) or off (no protection)",
    )
    patch_parser.add_argument(
        "--fake-lock",
        action="store_true",
        help="Report androidboot.verifiedbootstate=green to Android while unlocked",
    )

    sign_parser = subparsers.add_parser("sign", help="Sign the token")
    sign_parser.add_argument("token", help="Token string")

    unlock_parser = subparsers.add_parser("unlock", help="Unlock patched device automatically")
    unlock_parser.add_argument("--dry-run", action="store_true", help="Read and sign token, but skip stage and unlock")

    resign_parser = subparsers.add_parser(
        "resign", help="Recompute the cert2 hash-override block of an edited image"
    )
    resign_parser.add_argument("img", help="lk.img file path (stock cert2 required)")
    resign_parser.add_argument("-o", "--output", help="Output file path", default=None)

    args = parser.parse_args()

    print("[*] LK-Unlock v2.0 by @georgiynesterov")

    if args.command == "patch":
        patch_img(
            args.img,
            args.output,
            args.wrap,
            args.no_wipe_block,
            args.lk_protect,
            args.fake_lock,
        )
    elif args.command == "sign":
        sign_token(args.token)
    elif args.command == "unlock":
        unlock_device(args.dry_run)
    elif args.command == "resign":
        resign_img(args.img, args.output)
