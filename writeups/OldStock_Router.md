# OldStock Router

- Category: forensics
- Model: claude-opus-4-8
- Flag: `UCSI26{0ld5t0ck_fw_b4ckup_l34k}`

## Theme decision

```json
{
  "theme": "forensics",
  "confidence": 0.9,
  "evidence": [
    "custom boot header 'OLDSFW01.2.3' identifies a router firmware image",
    "header declares payload 'squashfs-lzma (rootfs)'",
    "SquashFS magic 'hsqs' present at offset 0x100",
    "compressed blocks begin with zlib header 78 da (deflate, not lzma)"
  ],
  "initial_capabilities": [
    "forensics"
  ],
  "unknowns": [
    "declared lzma payload is actually zlib/deflate compressed"
  ],
  "source": "agent"
}
```

## Sandbox plan

```json
{
  "theme": "forensics",
  "capabilities": [
    "base",
    "forensics"
  ],
  "tools": [
    "python3",
    "file",
    "strings",
    "xxd",
    "unzip",
    "tar",
    "jq",
    "exiftool",
    "binwalk",
    "foremost",
    "tshark"
  ],
  "rationale": [
    "custom boot header 'OLDSFW01.2.3' identifies a router firmware image",
    "header declares payload 'squashfs-lzma (rootfs)'",
    "SquashFS magic 'hsqs' present at offset 0x100",
    "compressed blocks begin with zlib header 78 da (deflate, not lzma)"
  ],
  "network_targets": [],
  "fingerprint": "df5675ee2bbac699310a6cdcba0d777d30e51a82584103ea807d3600455dec5e"
}
```

## Commands used

```sh
file OldStock_Router_FW_v1.2.3.bin
```

```sh
xxd OldStock_Router_FW_v1.2.3.bin | head -80
```

```sh
python3 - <<'PY'
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
PY
```

```sh
grep -aE "flag|UCSI26\{" decomp.bin
```

## Solve narrative

1. **Safe intake.** `file` reports only `data`; the 4352-byte image is inventoried
   without host-side execution.
2. **Classification (forensics).** The hexdump exposes a custom `OLDSFW01.2.3`
   boot header describing an Atheros AR9331 router image whose payload is
   `squashfs-lzma (rootfs)`, and the SquashFS magic `hsqs` at offset `0x100`.
   This selects the `forensics` theme (capabilities `base` + `forensics`).
3. **Key observation.** Although the header claims *lzma*, the compressed blocks
   start with `78 da` — a standard zlib/deflate header — so no SquashFS driver or
   `unsquashfs` is required.
4. **Bounded solve.** A short `python3` (base capability) pass scans for every
   zlib stream and inflates each one. The first inflated block is the rootfs
   metadata, containing the field tech's leftover backup config:

   ```
   config backup 'secrets'
       option description 'pre-RMA snapshot'
       option ssid 'OldStock-F9D2'
       option flag 'UCSI26{0ld5t0ck_fw_b4ckup_l34k}'
       option psk 'not-the-flag'
   ```

5. **Verification.** `option psk 'not-the-flag'` is a decoy; the flag-shaped value
   `UCSI26{0ld5t0ck_fw_b4ckup_l34k}` is extracted from `option flag` and validated
   against the `UCSI26{...}` format.

## Flag

```
UCSI26{0ld5t0ck_fw_b4ckup_l34k}
```
