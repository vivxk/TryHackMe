

## CTF Challenge Solution: UDP AES-GCM Encryption

### Challenge Overview
- **Type**: Cryptography/Network
- **Difficulty**: Hard
- **Objective**: Connect to a UDP server, decrypt AES-GCM encrypted flags using provided credentials, and find the flag matching a specific SHA256 checksum

### Solution Process

#### Step 1: Initial Connection
Send `"hello"` to the UDP server on port 4000 to initiate communication.
- **Server Response**: `"You've connected to the super secret server, send a packet with the payload ready to receive more information"`

#### Step 2: Retrieve Encryption Parameters
Send `"ready"` to receive:
- **Key**: `thisisaverysecretkeyl337` (24 bytes, used as-is)
- **IV/Nonce**: `secureivl337` (12 bytes)
- **SHA256 Checksum**: `5d77f018d2bf777860548655d84d7382dc27d6ce816ede68f65d72621463d9da` (the hash of the correct flag)

The checksum is embedded as binary data in the response after the text `"checksum of "`.

#### Step 3: Collect Encrypted Flags
The server sends **multiple encrypted flags** in a specific format:
- Send `"final"` → Receive **ciphertext** (13 bytes)
- Send `"final"` again → Receive **tag** (16 bytes)
- Repeat to collect multiple (ciphertext, tag) pairs

**Key Insight**: The server sends ciphertext and tag in **separate UDP packets**, requiring two `"final"` requests per flag.

#### Step 4: Decryption
Use **PyCA Cryptography library** with `Cipher` and `modes.GCM` (not `AESGCM`):

```python
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def AES_GCM_decrypt(key, iv, ciphertext, tag):
    decryptor = Cipher(
        algorithms.AES(key), 
        modes.GCM(iv, tag), 
        backend=default_backend()
    ).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()
```

**Important**: The key `thisisaverysecretkeyl337` is used **without padding** to 32 bytes - the library handles variable-length keys.



#### Step 5: Find the Correct Flag
```
#!/usr/bin/env python3
import socket
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

TARGET = "10.48.178.242"
PORT = 4000

def AES_GCM_decrypt(key, iv, ciphertext, tag):
    associated_data = b''
    decryptor = Cipher(
        algorithms.AES(key), 
        modes.GCM(iv, tag), 
        backend=default_backend()
    ).decryptor()
    decryptor.authenticate_additional_data(associated_data)
    return decryptor.update(ciphertext) + decryptor.finalize()

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    
    # Step 1: Send "hello"
    print("[*] Sending 'hello'...")
    sock.sendto(b"hello", (TARGET, PORT))
    data, _ = sock.recvfrom(4096)
    print(f"[+] Response: {data.decode()}")
    
    # Step 2: Send "ready" to get key/IV and checksum
    print("\n[*] Sending 'ready'...")
    sock.sendto(b"ready", (TARGET, PORT))
    ready_data, _ = sock.recvfrom(4096)
    
    # Extract checksum from the binary portion
    checksum_start = ready_data.find(b"checksum of ") + len(b"checksum of ")
    checksum = ready_data[checksum_start:checksum_start+32]
    expected_hash = checksum.hex()
    print(f"[*] Expected SHA256: {expected_hash}")
    
    # Key and IV
    key = b'thisisaverysecretkeyl337'
    iv = b'secureivl337'
    
    # Step 3: Keep collecting flags until we find the match
    print("\n[*] Collecting encrypted flags until match found...")
    
    flag_count = 0
    correct_flag = None
    
    while correct_flag is None:
        # Get ciphertext
        sock.sendto(b"final", (TARGET, PORT))
        ct, _ = sock.recvfrom(4096)
        
        # Get tag
        sock.sendto(b"final", (TARGET, PORT))
        tag, _ = sock.recvfrom(4096)
        
        flag_count += 1
        
        try:
            plaintext = AES_GCM_decrypt(key, iv, ct, tag)
            flag = plaintext.decode('utf-8')
            flag_hash = hashlib.sha256(flag.encode()).hexdigest()
            
            match_status = "✓ MATCH!" if flag_hash == expected_hash else "✗ wrong"
            print(f"[{match_status}] Flag {flag_count}: {flag}")
            
            if flag_hash == expected_hash:
                correct_flag = flag
                break
                
        except Exception as e:
            print(f"[-] Failed to decrypt flag {flag_count}: {e}")
        
        # Safety limit - stop after 50 attempts
        if flag_count >= 50:
            print("[-] Reached 50 attempts, stopping...")
            break
    
    if correct_flag:
        print(f"\n" + "="*60)
        print(f"[***] FOUND! The correct flag is: {correct_flag}")
        print(f"="*60)
    else:
        print(f"\n[-] No matching flag found after {flag_count} attempts")

if __name__ == "__main__":
    main()
```

Decrypt each flag and verify its SHA256 hash against the expected checksum:
- **Flag 8: `THM{eW-sCrIpTiNg-AnD-cRyPtO}`** 

### Key Challenges Overcome

1. **Protocol Understanding**: The server required specific payloads (`"hello"` → `"ready"` → `"final"` × 2 per flag)
2. **Data Format**: Encrypted flags were split across multiple UDP packets (ciphertext separate from tag)
3. **Multiple Flags**: The server sends many decoy flags; only one matches the SHA256 checksum
4. **Cryptographic Implementation**: Required using `Cipher` with `modes.GCM` rather than the simpler `AESGCM` interface

### Tools Used
- Python 3
- `socket` library for UDP communication
- `cryptography` library (PyCA) for AES-GCM decryption
- `hashlib` for SHA256 verification

### Final Flag
```
THM{eW-sCrIpTiNg-AnD-cRyPtO}
```

---

This challenge tested network protocol analysis, cryptographic implementation, and persistence in iterating through multiple encrypted values to find the correct one!