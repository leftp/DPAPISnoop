# DPAPISnoop
A C# tool to output crackable DPAPI hashes from user MasterKeys.

MasterKeys are encrypted with the domain password of the user. Cracking such a key can lead to the compromise of other domain accounts.

Based on DPAPImk2john for hash generation (https://github.com/openwall/john/blob/6ed33a7f10f4fa19a4a995cf0fa099d6169fdcbf/run/DPAPImk2john.py)
Based on SharpDPAPI for masterkey extraction (https://github.com/GhostPack/SharpDPAPI)
# Info
DPAPISnoop once run, it will iterate through every user folder, grab the most recent MasterKey under `C:\Users\User\AppData\Roaming\Microsoft\Protect\{SID}\{GUID}` and output a hashcat/JtR crackable hash.

The tool can be run either in a local or remote context (SMB) after having admin privileges.

The hash can then be attempted to be cracked with Hashcat / JtR. 

Depending on the operating system, we have different type of hashes, where preWin7 DES3 was in use.
  * Version 1 = des3 + sha1 (<=Vista)
  * Version 2 = aes256 + sha512 (>=Win7)

Depending if the user a local account or domain account, the context changes, with:
  * Context 1: Local User
  * Context 2: Domain User domain1607-
  * Context 3: Domain User domain1607+

Generated hash is in the form of:

```
$"{username}:$DPAPImk${version}*{Context}*{sid}*{cipherAlgo}*{hmacAlgo}*{rounds}*{iv}*{cipher.Length}*{cipher}");
```
**CAVEAT**

There is no programatic way to differentiate between domain1607- / domain1607+ although it appears that Context 3 was introduced after Windows 10 version 1607 (build 14393).
The tool currently outputs only Context 3 but feel free to uncomment L#83 

Hashcat supports the following hashes:
* -m 15300 for masterkey file v1 (context 1 / 2)
* -m 15310 for masterkey file v1 (context 3)
* -m 15900 for masterkey file v2 (context 1 / 2)
* -m 15910 for masterkey file v2 (context 3)


# Usage
DPAPISnoop.exe [\\\\server\\C$]



# Useful References
www.synacktiv.ninja/ressources/univershell_2017_dpapi.pdf

https://github.com/hashcat/hashcat/pull/1238

https://github.com/openwall/john/pull/3419

https://github.com/hashcat/hashcat/pull/3208

https://github.com/hashcat/hashcat/pull/1365

https://github.com/hashcat/hashcat/issues/3189

https://github.com/openwall/john/blob/6ed33a7f10f4fa19a4a995cf0fa099d6169fdcbf/run/DPAPImk2john.py

https://github.com/dfirfpi/dpapilab

https://github.com/jordanbtucker/dpapick
https://github.com/GhostPack/SharpDPAPI

# Author
Lefteris (lefty) Panos / @lefterispan / 2023

Shouts to @eks_perience & Nettitude RT
