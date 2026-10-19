# CTF Write-up: Team (TryHackMe)
(*solved using gemini-cli*)
## **1. Executive Summary**
The objective of this challenge was to gain root access on a target Linux server and retrieve the `user.txt` and `root.txt` flags. The attack path involved exploiting a Local File Inclusion (LFI) vulnerability to discover credentials and an SSH private key, followed by a two-stage privilege escalation leveraging a command injection vulnerability and a writable cronjob script.

---

## **2. Enumeration**

### **Service Scanning**
An initial Nmap scan revealed three open ports:
*   **Port 21 (FTP)**: vsftpd 3.0.3
*   **Port 22 (SSH)**: OpenSSH 7.6p1
*   **Port 80 (HTTP)**: Apache 2.4.29

### **Web Discovery**
Adding the IP to /etc/hosts/  & doing a search for virtual hosts and directories revealed two domains:
*   `team.thm`: The main website.
*   `dev.team.thm`: A development site.

In the `/scripts/` directory of `team.thm`, I found a file named `script.txt`. This bash script was used for FTP backups and contained a critical comment:
> `# Note to self had to change the extension of the old "script" in this folder, as it has creds in`

---

## **3. Initial Access**

### **LFI Exploitation**
The `dev.team.thm` site was found to be vulnerable to **Local File Inclusion (LFI)** via the `page` parameter in `script.php`.

By reading `/etc/passwd`, I identified three relevant users: `dale`, `gyles`, and `ftpuser`. Using the LFI to audit Apache configuration files (`/etc/apache2/sites-available/team.thm.conf`), I confirmed the document root for the main site was `/var/www/team.thm`.

### **Credential Discovery**
Based on the comment in `script.txt`, I used the LFI to search for an older version of the script. I successfully retrieved `/var/www/team.thm/scripts/script.old`, which contained hardcoded credentials:
*   **Username**: `ftpuser`
*   **Password**: `T3@m$h@r3`

### **FTP and SSH Key Retrieval**
Connecting to the FTP server in **active mode** (passive mode failed due to firewall constraints), I found a note in `/home/ftpuser/workshare/New_site.txt`. The note mentioned a "team policy" of placing a copy of `id_rsa` in a "relevant config file."

I audited common configuration files and found `dale`'s **SSH private key** commented out at the bottom of `/etc/ssh/sshd_config`.

### **Gaining a Shell**
I extracted the private key, set the correct permissions (`chmod 600`), and logged in via SSH:
```bash
ssh -i dale_id_rsa dale@team.thm
```
**User Flag**: `THM{6Y0TXHz7c2d}`

---

## **4. Privilege Escalation**

### **Stage 1: Lateral Movement to `gyles`**
Running `sudo -l` as `dale` showed that he could execute a custom script as `gyles` without a password:
```text
(gyles) NOPASSWD: /home/gyles/admin_checks
```
Analysis of the `admin_checks` script revealed a **command injection vulnerability**. A variable named `$error`, populated via user input, was executed directly by the shell without being quoted:
```bash
read -p "Enter 'date' to timestamp the file: " error
$error 2>/dev/null
```
I exploited this by providing a command like `/bin/bash` when prompted for the "date," which granted me a shell as `gyles`. To stabilize my access, I created a setuid bash binary:
```bash
cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash
```

### **Stage 2: Root Access**
I discovered a script at `/opt/admin_stuff/script.sh` that was being executed every minute by a **root cronjob**. This script called another script located at `/usr/local/bin/main_backup.sh`.

Checking the permissions of the called script:
```bash
ls -la /usr/local/bin/main_backup.sh
-rwxrwxr-x 1 root admin 65 Jan 17  2021 /usr/local/bin/main_backup.sh
```
Since `gyles` was a member of the `admin` group, I had write access to this file. I modified the script to copy the root flag to a readable location:
```bash
echo "cp /root/root.txt /tmp/root.txt; chmod 644 /tmp/root.txt" > /usr/local/bin/main_backup.sh
```
After waiting one minute for the cronjob to trigger, the root flag was successfully copied and made readable.

**Root Flag**: `THM{fhqbznavfonq}`

---

## **5. Lessons Learned**
1.  **Passive vs. Active FTP**: Always test active mode (`-P -` in curl) if passive FTP connections time out, as firewall configurations may only permit one or the other.
2.  **Configuration Hygiene**: Never store sensitive data (like SSH keys or credentials) in configuration files, even as comments.
3.  **Secure Scripting**: Always quote variables in shell scripts and avoid executing user input directly to prevent command injection.
4.  **Cronjob Security**: Scripts executed by root cronjobs must have strict permissions to prevent unauthorized modification by members of non-root groups.
