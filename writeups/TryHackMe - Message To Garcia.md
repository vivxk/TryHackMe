
## Challenge Summary: Encryption and Key Management

### Challenge Overview
A secure file transfer challenge where the goal was to deliver an encrypted message to "Garcia" via a web application with SFTP capabilities. The challenge involved exploiting information disclosure vulnerabilities to recover encryption keys and craft a valid encrypted message.

---

### Step 1: Reconnaissance & Information Gathering

Local File Inclusion (LFI) via Resource Fetcher

The `/fetch` endpoint accepted `file://` URLs without proper validation, allowing arbitrary file reads from the server filesystem.

**Files Extracted**:
- `file:///etc/passwd` - Confirmed LFI worked, revealed system users
- `file:///proc/self/environ` - Revealed application environment variables and working directory (`/home/ubuntu/sftp-msg2g4arc1a/`)
- `file:///proc/self/cmdline` - Revealed the application was running `python3 app.py`

---

### Step 2: Source Code Extraction

**Objective**: Understand application logic and locate cryptographic material

**Files Retrieved via LFI**:
- `file:///home/ubuntu/sftp-msg2g4arc1a/app.py` - Main Flask application
- `file:///home/ubuntu/sftp-msg2g4arc1a/functions.py` - Encryption/validation functions
- `file:///home/ubuntu/sftp-msg2g4arc1a/sftp_server.py` - SFTP server implementation

**Key Findings**:
- Encryption used: **Fernet symmetric encryption** (not PGP as suggested)
- Hardcoded encryption key: `TUVTU0FHRVRPR0FSQ0lBMjAyNF9LRVkhISEhISEhISE=`
- Expected plaintext message: `"Garcia, it seems I've cracked the code!! I need you to meet me at coordinates: 40.4168° N, 3.7038° W. The cipher is: TRACK"`

---

### Step 3: Cryptographic Analysis

**Encryption Scheme**: Fernet (from Python `cryptography` library)
- Symmetric encryption using AES-128 in CBC mode with HMAC authentication
- Key was Base64-encoded and hardcoded in source files

**Validation Logic**:
```python
def validate_encrypted_message(encrypted_data: bytes):
    decrypted = cipher.decrypt(encrypted_data)
    if decrypted.decode('utf-8').strip() == EXPECTED_MESSAGE:
        return True, "Message is valid."
```

---

### Step 4: Exploit Development

**Approach**: Since the encryption key and expected message were exposed through source code disclosure, we craft a properly encrypted payload that passes server-side validation.

**Python Script to Generate Payload**:
```python
from cryptography.fernet import Fernet

# Hardcoded key from source code
ENCRYPTION_KEY = b'TUVTU0FHRVRPR0FSQ0lBMjAyNF9LRVkhISEhISEhISE='
cipher = Fernet(ENCRYPTION_KEY)

# Expected message from source code
message = "Garcia, it seems I've cracked the code!! I need you to meet me at coordinates: 40.4168° N, 3.7038° W. The cipher is: TRACK"

# Encrypt and save
encrypted = cipher.encrypt(message.encode('utf-8'))

with open('message.gpg', 'wb') as f:
    f.write(encrypted)
```

---

### Step 5: Payload Delivery

**Upload Method**: Web interface file upload (`/upload` endpoint)
- File format: `.gpg` or `.enc` (validated by extension)
- Server decrypts using hardcoded key and compares to expected plaintext
- Successful validation sets session token and redirects to success page

---

### Vulnerabilities Exploited

| Vulnerability | Location | Impact |
|--------------|----------|---------|
| **Local File Inclusion (LFI)** | `/fetch` endpoint | Read arbitrary files from server filesystem |
| **Information Disclosure** | Source code in web root | Exposure of encryption keys and expected messages |
| **Hardcoded Credentials** | `functions.py`, `sftp_server.py` | Symmetric encryption key embedded in source |
| **Insecure Direct Object Reference** | File upload path handling | Potential for path traversal (mitigated by `secure_filename`) |

---

### Key Takeaways

1. **Never trust client-side descriptions** - The challenge mentioned "PGP encryption" but actually used Fernet symmetric encryption
2. **Source code exposure is critical** - LFI allowed complete recovery of application logic and secrets
3. **Hardcoded keys are a major risk** - Symmetric keys in source code allow anyone with code access to forge valid messages
4. **Defense in depth** - Even with upload restrictions, information disclosure vulnerabilities can bypass security controls

---

### Tools Used
- Web browser for interacting with the application
- Python with `cryptography` library for payload generation
- Manual HTTP requests for LFI exploitation

