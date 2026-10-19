# CTF Writeup - Target: 10.48.141.218

(*Note: This challenge was solved using gemini-cli*)
## 1. Enumeration

### Nmap Scan
The scan revealed a standard Ubuntu-based web server:
- **Port 22 (SSH):** OpenSSH 8.2p1
- **Port 80 (HTTP):** Apache 2.4.41

### Web Service Analysis
The HTTP service title was "Publisher's Pulse: SPIP Insights & Tips". Investigating the source code and common directories revealed a `/spip/` directory. The `generator` meta tag confirmed the version as **SPIP 4.2.0**.

## 2. Initial Access: SPIP RCE (CVE-2023-27372)

### Vulnerability Background
SPIP versions prior to 4.2.1 are vulnerable to unauthenticated Remote Code Execution. The vulnerability exists in the `oubli` (forgot password) parameter of the `spip_pass` page. It's caused by a mishandling of PHP's `unserialize()` function, allowing an attacker to inject arbitrary PHP code through a serialized object.

### Exploitation Details
The exploit payload targets the `oubli` parameter during a POST request to `spip.php?page=spip_pass`. 

**Payload Structure:**
```php
s:22:"<?php system('id'); ?>";
```
This is a serialized string. When SPIP attempts to process this "email" input, the PHP code is executed.

I utilized a Python PoC script (`51536.py` from Exploit-DB) which automates the retrieval of the `formulaire_action_args` (Anti-CSRF token) and sends the serialized PHP payload. By executing this, I confirmed the target was running as `www-data`.

## 3. User Pivot (think)

### Data Exfiltration
While exploring the filesystem as `www-data`, I noticed that `/home/think/spip` was accessible and owned by `www-data`. However, the root of `/home/think/` contained a `.ssh` directory. 

Crucially, the user's private SSH key (`/home/think/.ssh/id_rsa`) was set to be world-readable. 

### Gaining Shell
I used the RCE to `cat` the private key, saved it locally, and established an SSH session:
```bash
chmod 600 id_rsa_think
ssh -i id_rsa_think think@10.48.141.218
```
- **User Flag:** `fa229046d44eda6a3598c73ad96f4ca5`

## 4. Privilege Escalation to Root

### SUID Binary Investigation
Enumeration revealed an unusual SUID binary: `/usr/sbin/run_container`.
Running `strings` on the binary showed it was a compiled C program that executed a shell script at `/opt/run_container.sh`.

### AppArmor Restriction & Bypass
The script `/opt/run_container.sh` was world-writable (777). However, attempting to overwrite it with `echo`, `sed`, or `tee` resulted in `Permission denied`.

Checking `/etc/apparmor.d/usr.sbin.ash` revealed a profile for the user's login shell (`ash`) that explicitly denied write access to `/opt/`, `/tmp/`, and even `/home/`. Although the profile was in `complain` mode, the explicit `deny` rules remained effective.

**Bypass:** I discovered that the `sftp-server` process was not restricted by this specific AppArmor profile. I used **SFTP** to upload a malicious version of the script:
```bash
echo "put exploit.sh /opt/run_container.sh" | sftp -i id_rsa_think think@10.48.141.218
```

### Docker-to-Host Escalation
The malicious script leveraged the fact that `run_container` runs as root and can execute `docker` commands. Since the Docker daemon runs outside the user's restricted `ash` environment, it can be used to manipulate the host's filesystem.

**Exploit Script:**
```bash
#!/bin/bash
docker run -v /:/host spip-image:latest chmod +s /host/usr/bin/bash
```
This command runs a container, mounts the host's root directory to `/host` inside the container, and then uses the container's root privileges to set the SUID bit on the **host's** `/usr/bin/bash`.

### Final Root Access
After running the SUID binary to trigger the script:
```bash
/usr/sbin/run_container
/usr/bin/bash -p
```
I obtained a root shell.
- **Root Flag:** `3a4225cc9e85709adda6ef55d6a4f2ca`
