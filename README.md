# DPAPISnoop

A C# tool that extracts crackable DPAPI hashes from user MasterKeys and CREDHIST files.

Targets both the MasterKey (`$DPAPImk$`) and the full CREDHIST chain (`$credhist$`), supporting local paths and remote SMB shares. 

---

## What it extracts

### MasterKey hashes (`$DPAPImk$`)

MasterKey for each user can be found under `\Users\<user>\AppData\Roaming\Microsoft\Protect\<SID>\`. 

Cracking gives the user's domain password and unlocks all DPAPI-protected secrets from that era.

Hash version depends on OS:
- **Version 1** — 3DES + SHA-1 (≤ Vista)
- **Version 2** — AES-256 + SHA-512 (≥ Win7)

Context field encodes account type:
- **1** — Local user
- **2** — Domain user, pre-1607
- **3** — Domain user, post-1607


### CREDHIST hashes (`$credhist$`)

Every entry in each user's CREDHIST file. Each entry is encrypted with a previous password and decrypts to the SHA1 + NTLM of the password before it. 

Cracking the chain reconstructs all historical passwords and their NTLM hashes.

Entries are labelled in the username field so the output is self-describing:
```
alice[current]:$credhist$*...    ← encrypted with the current password; crack this first
alice[prev1]:$credhist$*...      ← encrypted with the previous password
alice[prev2]:$credhist$*...
```

Entry hash version depends on OS:
- **3DES + HMAC-SHA1** (≤ Vista) — crack with hashcat `-m 15920`
- **AES-256 + SHA-512** (≥ Win10 20H2) — crack with hashcat `-m 15930`

---

## Usage

```
DPAPISnoop.exe [rootDir] [options]
```

`rootDir` defaults to `%HOMEDRIVE%` if omitted. UNC paths are fully supported.

| Flag | Description |
|------|-------------|
| *(none)* | Dump `$DPAPImk$` and `$credhist$` for our user|
| `--credhist-only` / `-c` | Skip MasterKey output; emit only `$credhist$` lines |
| `--password <plaintext>` / `-p` | Walk CREDHIST chain from the current plaintext password |
| `--sha1 <40-hex>` | Walk CREDHIST chain from a known SHA1 of the current password |
| `--pre1607` | Emit context 2 (domain pre-1607) instead of context 3 for domain MasterKey hashes |

### Examples

```
# Local machine — dump everything (defaults to %HOMEDRIVE%)
DPAPISnoop.exe

# Local machine — walk CREDHIST chain from a known password
DPAPISnoop.exe C: --password Summer2026!

# Local machine — walk CREDHIST chain from a known SHA1
# (e.g. from sekurlsa::wdigest pwdhash or dpapi cache)
DPAPISnoop.exe C: --sha1 da39a3ee5e6b4b0d3255bfef95601890afd80709

# Remote share — dump everything
DPAPISnoop.exe \\server01\c$

# Remote share — CREDHIST only, redirect hashes to file
DPAPISnoop.exe \\server01\c$ --credhist-only > credhist_hashes.txt

# Remote share — walk CREDHIST chain from a known password
DPAPISnoop.exe \\server01\c$ --password Summer2026!
```

## Cracking

### MasterKey

```
hashcat -a0 -m 15300 hashes.txt wordlist.txt   # v1 local/domain pre-1607
hashcat -a0 -m 15310 hashes.txt wordlist.txt   # v1 domain post-1607
hashcat -a0 -m 15900 hashes.txt wordlist.txt   # v2 local/domain pre-1607
hashcat -a0 -m 15910 hashes.txt wordlist.txt   # v2 domain post-1607
```

### CREDHIST

```
hashcat -a0 -m 15920 credhist_hashes.txt wordlist.txt   # 3DES entries (≤ Vista)
hashcat -a0 -m 15930 credhist_hashes.txt wordlist.txt   # AES-256 entries (≥ Win10 20H2)
```

After cracking, pass the recovered password back to DPAPISnoop to walk the full chain and print every historical SHA1 and NTLM:

```
DPAPISnoop.exe C:\ --password Summer2024! > ntlms.txt
DPAPISnoop.exe C:\ --sha1 <40-hex-sha1> > ntlms.txt
```

## Hashcat Modules
Check [README](./hc_modules/README.md)

---
## AI Usage

This research and development effort was conducted collaboratively between a human and AI-assisted tooling, using the AI models GPT-5.5 and Claude Sonnet 4.6.

The AI models were used to assist with code generation and  reverse engineering support. 

However, all research direction, validation, debugging, testing, security analysis, and final technical decisions were performed by a human ([Imdefinelyhuman](https://www.imdefinitelyhuman.com/)).

All generated content, code, and analysis were reviewed, validated, modified, and integrated manually as part of an iterative human-guided workflow.

The above statement is a fancy way of also saying that the code has bugs and use it at your own risk!

---

## References

1.	[Elie Burzstein and Jean Michel Picod, "Recovering Windows Secrets and EFS Certificates Offline."](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Burzstein.pdf)
2.	[Microsoft, “CryptProtectData function.”](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata)
3.	[Microsoft, “CNG DPAPI.”](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-dpapi)
4.	[Microsoft, “DPAPI Backup Keys on Active Directory Domain Controllers”]( https://learn.microsoft.com/en-us/windows/win32/seccng/cng-dpapi-backup-keys-on-ad-domain-controllers)
5.	[NAI Labs, “Windows Data Protection.”](https://learn.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10))
6.	[SpecterOps, “Offensive Encrypted Data Storage: DPAPI Edition.”]( https://specterops.io/blog/2017/07/31/offensive-encrypted-data-storage-dpapi-edition/)
7.	[SpecterOps, “Operational Guidance for Offensive User DPAPI Abuse.”]( https://specterops.io/blog/2018/08/22/operational-guidance-for-offensive-user-dpapi-abuse/)
8.	[SpecterOps, “DPAPI Backup Key Compromise Pt. 1: Some Forests Must Burn.”](https://specterops.io/blog/2025/07/28/dpapi-backup-key-compromise-pt-1-some-forests-must-burn/)
9.	[Passcape, “DPAPI CREDHIST.” ](https://www.passcape.com/windows_password_recovery_dpapi_credhist)
10.	[Passcape, “DPAPI blob analysis.”](https://www.passcape.com/windows_password_recovery_dpapi_analyse)
11.	[Passcape, “DPAPI Master Key analysis.”]( https://www.passcape.com/windows_password_recovery_dpapi_master_key)
10.	[NirSoft, “CredHistView.”](https://www.nirsoft.net/utils/credhist_view.html)
11.	[Benjamin Delpy, “Mimikatz Wiki: module ~ dpapi.”]( https://github.com/gentilkiwi/mimikatz/wiki/module-~-dpapi)
12.	[Fox-IT, “Dissect CREDHIST parser.”](https://docs.dissect.tools/en/stable/api/dissect/target/plugins/os/windows/credential/credhist/index.html)
13.	[DPAPIck3, PyPI project page](https://pypi.org/project/dpapick3/)
14.	[GhostPack, “SharpDPAPI.”](https://github.com/GhostPack/SharpDPAPI)
15.	[Sygnia, "The Downfall of DPAPI's Top Secret Weapon."](https://www.sygnia.co/blog/the-downfall-of-dpapis-top-secret-weapon/)

---

## Author

Lefteris (lefty) Panos @ LRQA Red Team 2026

