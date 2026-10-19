# Traffic Analysis and KeePass Decryption Challenge Writeup

## Introduction
This challenge involves analyzing a network packet capture (`traffic.pcapng`) to investigate suspicious traffic originating from a workstation. The investigation reveals a malware infection that dumps the memory of a running KeePass instance, encrypts the memory dump along with the KeePass database, and exfiltrates them over the network. By reversing this process and leveraging a known vulnerability in KeePass (CVE-2023-32784), we can recover the master password and access the flag stored inside the database.

---

## Step 1: Initial PCAP Analysis
We started by examining the protocol hierarchy in the PCAP file to understand what kind of traffic is present.

```bash
tshark -r traffic.pcapng -qz io,phs
```

This revealed a large amount of TCP data and a few HTTP requests. To investigate the HTTP traffic further, we extracted the full URIs and file data:

```bash
tshark -r traffic.pcapng -Y http -T fields -e http.request.full_uri -e http.file_data
```

This output showed a request to `http://10.10.94.106:1339/xxxmmdcclxxxiv.ps1` which downloaded a heavily obfuscated PowerShell script.

## Step 2: Analyzing the PowerShell Script
By reviewing the extracted PowerShell script, we identified several key actions taken by the malware:

1.  **Download ProcDump:** It downloads Sysinternals `procdump.exe` from the official Microsoft URL.
2.  **Memory Dump:** It finds the process ID for `KeePass` and uses `procdump.exe` to create a memory dump named `1337.dmp` on the user's desktop.
3.  **Data Obfuscation (Dump):** It reads the `1337.dmp` file, XORs every byte with the key `0x41`, encodes the result in Base64, and exfiltrates it over a raw TCP socket to `10.10.94.106` on port `1337`.
4.  **Data Obfuscation (Database):** It performs a similar operation on the actual KeePass database file `Database1337.kdbx`. It XORs the file with the key `0x42`, Base64 encodes it, and exfiltrates it to `10.10.94.106` on port `1338`.

## Step 3: Extracting Exfiltrated Data
Knowing that the exfiltrated data was sent to TCP ports 1337 and 1338, we used `tshark` to filter the traffic and extract the raw payloads:

```bash
# Extract data sent to port 1337 (Memory Dump)
tshark -r traffic.pcapng -Y "tcp.dstport==1337" -T fields -e tcp.payload > payload_1337.hex
xxd -r -p payload_1337.hex > 1337_raw.b64

# Extract data sent to port 1338 (KeePass Database)
tshark -r traffic.pcapng -Y "tcp.dstport==1338" -T fields -e tcp.payload > payload_1338.hex
xxd -r -p payload_1338.hex > 1338_raw.b64
```

## Step 4: Decoding and Decrypting the Payloads
We wrote a Python script to reverse the obfuscation applied by the PowerShell malware (Base64 decoding followed by XOR decryption with the respective keys):

```python
import base64

def process_file(in_file, out_file, xor_key):
    with open(in_file, 'r') as f:
        data = f.read().replace('\n', '').replace('\r', '')
    
    print(f"Decoding {in_file}...")
    decoded = bytearray(base64.b64decode(data))
    
    print(f"XORing with {hex(xor_key)}...")
    for i in range(len(decoded)):
        decoded[i] ^= xor_key
        
    with open(out_file, 'wb') as f:
        f.write(decoded)
    print(f"Saved to {out_file}.")

process_file('1338_raw.b64', 'Database1337.kdbx', 0x42)
process_file('1337_raw.b64', '1337.dmp', 0x41)
```

Running this script gave us the original KeePass memory dump (`1337.dmp`) and the database file (`Database1337.kdbx`).

## Step 5: Extracting the Master Password from Memory
KeePass 2.x before version 2.54 is vulnerable to CVE-2023-32784, which allows an attacker to recover the master password from a memory dump. We downloaded a Proof-of-Concept script to exploit this:

```bash
curl -sL "https://raw.githubusercontent.com/matthewhowell/CVE-2023-32784/main/keepass_dumper.py" -o keepass_dump.py
```

We then ran the dumper against our extracted memory dump:

```bash
python3 keepass_dump.py 1337.dmp
```

**Output:**
```
Possible password: ●NoWaYIcanF0rGetThis123
```
This gave us the initial part of the password: `NoWaYIcanF0rGetThis123`, with only the first character missing (`●`).

## Step 6: Cracking the Remaining Password
Since only the first character was missing, we could easily brute-force it. We generated a wordlist containing all possible printable ASCII characters prepended to the known partial password:

```bash
for i in {32..126}; do printf "\\$(printf '%03o' "$i")NoWaYIcanF0rGetThis123\n"; done > passwords.txt
```

Next, we extracted the hash from the KeePass database using `keepass2john` and cracked it using John the Ripper:

```bash
keepass2john Database1337.kdbx > db.hash
john --wordlist=passwords.txt db.hash
```

John successfully cracked the hash, revealing the full master password:
**`?NoWaYIcanF0rGetThis123`**

## Step 7: Retrieving the Flag
With the master password in hand, we wrote a quick Python script using the `pykeepass` library to open the database and print its contents:

```python
from pykeepass import PyKeePass

kp = PyKeePass('Database1337.kdbx', password='?NoWaYIcanF0rGetThis123')
for entry in kp.entries:
    print(f"Title: {entry.title}")
    print(f"Username: {entry.username}")
    print(f"Password: {entry.password}")
    print(f"URL: {entry.url}")
    print(f"Notes: {entry.notes}")
    print("-" * 20)
```

Running the script produced the following output:

```
Title: Sample Entry
Username: User Name
...
--------------------
Title: You win!
Username: None
Password: xWjy8SqH2CDDw76ptmvP
URL: None
Notes: THM{B3tt3r_Upd4t3_Y0ur_K33p455}
--------------------
```

## Conclusion
- **Initial part of the password:** `NoWaYIcanF0rGetThis123`
- **Full Master Password:** `?NoWaYIcanF0rGetThis123`
- **Flag:** `THM{B3tt3r_Upd4t3_Y0ur_K33p455}`
