# OldStock Router

- **Competition:** UCSI CTF x Hackathon
- **Category:** Forensics / Reverse
- **Points:** 500
- **Author:** MaanVad3r
- **Flag:** `UCSI26{0ld5t0ck_fw_b4ckup_l34k}`

## Challenge

> An ISP just decommissioned a batch of ancient OldStock routers. This is the
> firmware dump from one of them — boot header, root filesystem and all. The
> field tech left a backup configuration behind before the box went back for RMA.
> Somewhere in that backup, the old admin wrote the access code for the staging
> network.

Provided file: `OldStock_Router_FW_v1.2.3.bin` (4352 bytes).

## Recon

`file` reports plain `data`, so we go straight to a hexdump:

```
00000000: 4f4c 4453 4657 3031 2e32 2e33 0a4f 6c64  OLDSFW01.2.3.Old
00000010: 5374 6f63 6b20 526f 7574 6572 2066 6972  Stock Router fir
...
00000090: 643a 2073 7175 6173 6866 732d 6c7a 6d61  d: squashfs-lzma
000000a0: 2872 6f6f 7466 7329 0a00 ...              (rootfs)....
00000100: 6873 7173 0e00 0000 dbf5 6d6a 0000 0200  hsqs......mj....
```

Two useful facts:

1. A **custom boot header** (`OLDSFW01.2.3`) describes the image — an Atheros
   AR9331 SoC router with a `squashfs-lzma (rootfs)` payload.
2. At offset **`0x100`** the magic `hsqs` marks the start of a **SquashFS**
   filesystem.

Despite the header saying "lzma", the compressed data blocks inside actually
begin with `78 da` — the standard **zlib/deflate** header. So the blocks are
plain zlib streams and can be decompressed without a SquashFS driver.

## Solution

No `unsquashfs`/`binwalk` was needed. The whole image is small enough to just
scan for every zlib stream and inflate each one:

```python
import zlib

data = open("OldStock_Router_FW_v1.2.3.bin", "rb").read()
out = b""
for i in range(len(data) - 1):
    if data[i] == 0x78 and data[i + 1] in (0x01, 0x9c, 0xda):
        try:
            dec = zlib.decompressobj().decompress(data[i:])
            if dec:
                out += b"\n==== block @%d ====\n" % i + dec
        except zlib.error:
            pass
open("decomp.bin", "wb").write(out)
print(out.decode("latin1"))
```

The first inflated block is the rootfs metadata block, which contains the field
tech's leftover backup config:

```
# Automatic backup taken 2026-07-31 11:47:12 by uhttpd
config backup 'secrets'
	option description 'pre-RMA snapshot'
	option ssid 'OldStock-F9D2'
	option flag 'UCSI26{0ld5t0ck_fw_b4ckup_l34k}'
	option psk 'not-the-flag'
```

The `psk` is a decoy (`'not-the-flag'`); the real value is in `option flag`.

## Flag

```
UCSI26{0ld5t0ck_fw_b4ckup_l34k}
```

## Takeaways

- Trust the bytes over the header string — the image *claimed* LZMA but the
  payload was zlib-compressed SquashFS blocks.
- For tiny firmware dumps you don't need a full SquashFS extraction toolchain;
  brute-scanning for `78 01 / 78 9c / 78 da` zlib headers and inflating each hit
  is fast and dependency-free.
- CTF authors love decoys — always read past the first plausible-looking secret.
