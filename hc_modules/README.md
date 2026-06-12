# hashcat modules — DPAPI CREDHIST (15920 / 15930)

Hashcat GPU modules for cracking Windows DPAPI CREDHIST entries extracted by DPAPISnoop.

| Mode | Algorithm | Entry type |
|------|-----------|------------|
| 15920 | 3DES + HMAC-SHA1 | Legacy / pre-20H2 3DES entries |
| 15930 | AES-256 + SHA-512 | Win10 20H2+ AES entries |


---

## Hash format

```
$credhist$*<rev>*<SID>*<hash_algo>*<crypt_algo>*<rounds>*<iv>*<sha_len>*<nt_len>*<enc>
```

Example (mode 15920, 3DES):
```
$credhist$*3*S-1-5-21-111111111-222222222-333333333-1001*0x8009*0x6603*1000*000102030405060708090a0b0c0d0e0f*20*16*da04f6b135434d5e15be2b37e9d363d661fc502ffe00f1141d068fd70cb2545e1c5d1812dd85b702
```

Example (mode 15930, AES-256):
```
$credhist$*3*S-1-5-21-111111111-222222222-333333333-1001*0x800e*0x6610*8000*000102030405060708090a0b0c0d0e0f*20*16*9a318c41c7245533ca003993382c3905c7e1759e8165080afc0cc8e549d175870243b8459653f5724ac60d84698f492d
```

---

## Prerequisites

- hashcat source tree (https://github.com/hashcat/hashcat)
- Linux: `gcc`, `make`, OpenCL runtime (NVIDIA/AMD/Intel)
- Windows: Visual Studio 2019+ with MSVC, or MinGW64

---

## Integration

Copy the four files into the hashcat source tree:

```
src/modules/module_15920.c  →  <hashcat>/src/modules/module_15920.c
src/modules/module_15930.c  →  <hashcat>/src/modules/module_15930.c
OpenCL/m15920-pure.cl       →  <hashcat>/OpenCL/m15920-pure.cl
OpenCL/m15930-pure.cl       →  <hashcat>/OpenCL/m15930-pure.cl
```

### Linux

```bash
cd <hashcat>
make
```

Build only the new modules after copying:

```bash
make modules
```

Mode 15920 self-test:
```
Hash:     $credhist$*3*S-1-5-21-111111111-222222222-333333333-1001*0x8009*0x6603*1000*000102030405060708090a0b0c0d0e0f*20*16*4a56f5fd5d71e45ca0dde5a50b1f03f98d6602b760acb5da38f85ccfb6c2efc97d29a26762216eee
Password: SelfTest@2024
```

Mode 15930 self-test:
```
Hash:     $credhist$*3*S-1-5-21-111111111-222222222-333333333-1001*0x800e*0x6610*8000*000102030405060708090a0b0c0d0e0f*20*16*9a318c41c7245533ca003993382c3905c7e1759e8165080afc0cc8e549d175870243b8459653f5724ac60d84698f492d
Password: hashcat
```
