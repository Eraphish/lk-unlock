
# lk-unlock

This simple tool allows you to unlock the bootloader of Xiaomi devices with mtk socs by patching the little kernel (LK) image. It replaces Xiaomi's public key with your own and generates unlock signature locally . This is made possible by a **cert bypass vulnerability**, originally implemented in [lkpatcher](https://github.com/R0rt1z2/lkpatcher/).

> **⚠️ WARNING:** This method is dangerous and could brick your device. Proceed only if you understand what you are doing and know how to restore the device.

## How it works

Xiaomi bootloader unlocking works using the asymmetric RSA algorithm. The device generates a one-time token, which is then sent to the server. The server signs the token with its private key and sends it back. The device verifies the server signature using the public key embedded in the bootloader (in the case of mtk - LK). The verification will only be successful if the device's one-time token was signed with the server's private key, and not otherwise. No one knows the Xiaomi server's private key, so previously, the unlocking process was impossible to perform offline (without vulnerabilities in the bootloader). A new vulnerability that affects all mtk devices allows to break the secure boot, making possible a modified LK to boot. This allows you to make any patches to it, the simplest of which is the replacement of the Xiaomi public key with your own, for which the private key is known, so that you can generate the unlock signature yourself.

UPD: The tool also patches LK to skip the userdata wipe that normally happens when the bootloader is locked or unlocked. This patch is applied to the original `lk.img` before the certificate bypass, so the resulting image remains verifiable. If you want to keep the stock wipe behavior, disable the patch with `--no-wipe-block` (see below).


## Requirements

- Python 3.7+
- `fastboot` binary in `PATH` or current directory.
- Python dependencies:
  ```bash
  pip install cryptography 
  pip install git+https://github.com/R0rt1z2/liblk
  ```

## Usage

The tool provides three subcommands: `patch`, `sign`, and `unlock`.

### 1. Patch the LK image

First, obtain your device's `lk.img` (e.g., from a firmware or read it from the device directly in brom mode).

```bash
python lk-unlock.py patch lk.img -o lk_patched.img
```

Options:
- `--wrap` – use wrap mode for cert bypass (default is `override`).
- `--no-wipe-block` – disable the userdata wipe patch.

This will:
- Generate `private.pem` and `public.pem` if not present.
- Replace Xiaomi's public key modulus with yours.
- Patch LK to skip the userdata wipe on lock/unlock.
- Apply cert bypass to all signed partitions.
- Save the patched image to `lk_patched.img`.

To keep the stock userdata wipe behavior, disable the patch:

```bash
python lk-unlock.py patch lk.img -o lk_patched.img --no-wipe-block
```

### 2. Flash the patched LK Image

You can use one of these methods:
1.  [MTKClient](https://github.com/bkerler/mtkclient) (if your device is supported):
```bash
python mtk.py r lk_a,lk_b lk_a_backup.img,lk_b_backup.img
python mtk.py w lk_a,lk_b lk_patched.img,lk_patched.img
```
2. The official Xiaomi's brom auth  (provided as a paid service in Telegram and other places online)
3. Temp root exploits (Ghostlock, etc.)
4. UFS programmer / another hardware tool.
5. ???

### 3. Unlock the Device

Once the patched LK is flashed, reboot into fastboot and run the unlock process:

```bash
python lk-unlock.py unlock
```

This will:
- Detect your device in fastboot mode.
- Request an unlock token.
- Sign it using `private.pem`.
- Stage and send the unlock command.

Options:
- `--dry-run` – run unlock command without staging the signature and unlocking the device.

### 4. Manual Token Signing (Optional)

If you want to sign a token manually:

```bash
fastboot oem get_token
python lk-unlock.py sign "TOKEN"
fastboot stage signature.bin
fastboot oem unlock
```

### 5. LK write protection and fake lock state

This fork adds two optional patches, both applied to the stock `lk.img`:

```bash
python lk-unlock.py patch lk.img -o lk_patched.img --lk-protect fail --fake-lock
```

- `--lk-protect {fail,okay,off}` (default `fail`): the fastboot `flash:` and
  `erase:` handlers are wrapped by a small injected routine. Writes/erases of
  `lk`, `lk_a`, `lk_b` and `lk_ab` are refused (`fail` → `FAIL <msg>`) or
  silently skipped (`okay` → `OKAY <msg>`); every other partition is forwarded
  to the original handler untouched.
- `--fake-lock`: appends `androidboot.verifiedbootstate=green` to the kernel
  cmdline, so Android reports a verified/locked boot while the bootloader stays
  unlocked and `flash:`/`erase:` keep working for boot/system/vendor/etc.

Both patches are implemented as code caves in the zero-filled padding before
the `lk` string table and do **not** change the partition size. The cert2
hash-override block is rebuilt automatically afterwards.

Notes:

- The protection only covers fastboot. OTA on the phone writes `lk` through the
  kernel block layer; use a KernelSU loop-redirect module or the
  write will land on the real partition.
- To update the LK later: build with `--lk-protect off`, or write the real
  block device as root (bypassing any `/dev/block/by-name` redirect), or use
  BROM.
- `resign` recomputes the cert2 override for an already edited image whose
  cert2 is still the stock one:

  ```bash
  python lk-unlock.py resign edited.img -o resigned.img
  ```
- The injected code is verified offline with Unicorn:

  ```bash
  pip install unicorn
  python3 tests/emu_check.py lk_patched.img
  ```

  This emulates the caves and checks the partition-name matrix and the cmdline
  appends. It does **not** prove the image boots; always keep a recovery path.

## Cert Bypass Modes

- **Override** (`--override`, default): Inserts a custom hash override block into the certificate (2026 vulnerability, no CVE code). 
- **Wrap** (`--wrap`): Appends a forged certificate after the original one, causing the verifier to use the forged data (CVE-2023-20696).


## Credits

- Cert bypass code adapted from [lkpatcher](https://github.com/R0rt1z2/lkpatcher/) by R0rt1z2.
- [Liblk](https://github.com/R0rt1z2/liblk) by R0rt1z2.
- [MTKClient](https://github.com/bkerler/mtkclient) for flashing the patched image.
-  [Xiaomi bootloader research](https://github.com/lrh2000/Xiaomi-bootloader).

## Disclaimer

This tool is for educational and research purposes only. The authors are not responsible for any damage caused by the use of this tool. Always backup your device data and proceed with caution.

## License

This project is licensed under the AGPL License. LK-Unlock is a free software, which is not intended for sale, commercial use, or illegal purposes.