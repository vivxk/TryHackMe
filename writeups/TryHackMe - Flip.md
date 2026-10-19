# Challenge Writeup: Flip (AES-CBC Bit-Flipping Attack)
(*Solved using gemini-cli*)
## Challenge Overview
The "Flip" challenge presents a TCP service (Port 1337) that simulates a login system. The goal is to gain admin access by providing a ciphertext that decrypts to a string containing `admin&password=sUp3rPaSs1`.

*   **Target:** `10.48.156.137:1337`
*   **Flag:** `THM{FliP_DaT_B1t_oR_G3t_Fl1pP3d}`

## Reconnaissance & Code Analysis

The provided source code reveals the following server logic:

1.  **Encryption:** It uses AES-CBC with PKCS7 padding and a fresh 16-byte key and IV for every connection.
2.  **Input Construction:** The server takes `username` and `password` from the user and constructs a message:
    `message = 'access_username=' + username + '&password=' + password`
3.  **Anti-Cheat:** It checks if the string `admin&password=sUp3rPaSs1` is present in the `message` *before* encryption. If found, it terminates the connection.
4.  **Vulnerability:** It then asks the user for a new ciphertext, decrypts it using the *same* key and IV, and checks if `admin&password=sUp3rPaSs1` is present in the decrypted (and unpadded) data.

## Vulnerability: AES-CBC Bit-Flipping

AES in Cipher Block Chaining (CBC) mode is vulnerable to bit-flipping attacks. The plaintext of block $i$ ($P_i$) is calculated as:
$P_i = Dec(C_i, Key) ⊕ C_{i-1}$

By modifying bytes in $C_{i-1}$, we can precisely control the resulting $P_i$. Specifically:
$C_{i-1,new} = C_{i-1,old} ⊕ P_{i,old} ⊕ P_{i,new}$

## Exploit Strategy

The target string is `admin&password=sUp3rPaSs1` (25 bytes).

1.  **Alignment:** 
    *   The prefix `access_username=` is 16 bytes (**Block 0**).
    *   We send 16 'A's as the start of our username (**Block 1**).
    *   We send the rest of the target string `Up3rPaSs1` (**Block 2**).
2.  **Flipping:** We flip bits in **Ciphertext Block 0** so that **Plaintext Block 1** decrypts to `admin&password=s`.
3.  **Result:** The server decrypts the payload, and Block 1 (`admin&password=s`) concatenated with Block 2 (`Up3rPaSs1...`) forms the required admin string.

## Exploit Script

```python
import socket
import binascii
import time

def solve():
    host = '10.48.156.137'
    port = 1337

    # access_username= (16 bytes) -> Block 0
    # username[0:16] (16 bytes) -> Block 1
    # username[16:] (9 bytes) -> Starts Block 2
    username = b"A" * 16 + b"Up3rPaSs1"
    password = b"B"

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((host, port))

    def read_until(s, target):
        data = b""
        while target not in data:
            chunk = s.recv(1)
            if not chunk: break
            data += chunk
        return data

    # 1. Send inputs and get leaked ciphertext
    read_until(s, b"username: ")
    s.sendall(username + b"\n")
    read_until(s, b"password: ")
    s.sendall(password + b"\n")
    resp = read_until(s, b"enter ciphertext: ")
    
    ct_hex = [line.split(b"Leaked ciphertext: ")[1].strip() 
              for line in resp.split(b"\n") if b"Leaked ciphertext: " in line][0]
    ct = binascii.unhexlify(ct_hex)

    # 2. Bit-flip C0 to change P1 from 'A'*16 to 'admin&password=s'
    p1_old = b"A" * 16
    p1_new = b"admin&password=s"
    c0_old = ct[0:16]
    c0_new = bytes([c0_old[i] ^ p1_old[i] ^ p1_new[i] for i in range(16)])
    
    modified_ct = c0_new + ct[16:]
    
    # 3. Send modified ciphertext and get flag
    s.sendall(binascii.hexlify(modified_ct) + b"\n")
    time.sleep(1)
    print(s.recv(4096).decode())
    s.close()

if __name__ == "__main__":
    solve()
```