
### Introduction

What if attackers aren't satisfied with just breaching the host but aim to stay, establish control, and use the system as a starting point for future operations? This room completes your Windows threat detection journey and explores how a compromised host can become part of a larger attack, focusing on three tactics: Command and Control, Persistence, and Impact.

##### Learning Objectives
- Remind the concept of Command and Control (C2)
- Learn why and how threat actors maintain control of their victims
- Use Windows event logs to uncover various persistence methods
- See how the learned techniques work in a hands-on environment

##### Prerequisites
- Recall the basics of [MITRE](https://attack.mitre.org/matrices/enterprise/windows/) tactics and [Windows](https://tryhackme.com/room/windowsloggingforsoc) logs
- Complete [Windows Threat Detection 1](https://tryhackme.com/room/windowsthreatdetection1) and [2](https://tryhackme.com/room/windowsthreatdetection2) rooms
- Be ready to dive deeper into the last stages of Windows attacks


### Command And Control

##### Command and Control
You already learned that USB worms and phishing attachments can "infect" the machine. But how do they do it exactly? How do threat actors send the commands and keep control of the victim's host? This task will shed light on this topic and explore the [Command and Control](https://attack.mitre.org/tactics/TA0011/) (C2) MITRE tactic.

##### Attacks Without C2
In some cases, C2 is not needed at all. For example, threat actors can type their commands directly in the RDP session after an RDP breach. Since this method becomes unavailable as soon as RDP is closed or secured, most threat actors choose to still set up a C2 immediately after the breach.

![Pasted image 20250725221618.png](assets/windows-threat-detection-3/Pasted%20image%2020250725221618.png)

##### Simplest C2
For other Initial Access methods, threat actors can't simply use RDP every time they need to run a command, so they need some process that connects back to the attackers and waits for their commands 24/7. In the simplest case, the phishing attachment will be that process and establish the **Command and Control channel**, like on the [CobaltStrike C2](https://www.cobaltstrike.com/) screenshot below.

In more advanced cases, the attachment won't immediately connect back, but rather download an additional C2 malware, hide it in a folder like C:\Temp, and run it as a new stealthy process. This method is beneficial to keep the attack going if the victim decides to delete the original attachment. See how it worked in the [recent ransomware cases](https://umbrella.cisco.com/blog/cybersecurity-threat-spotlight-ransomware-trojans-loaders) and during the [APT29 phishing campaign](https://cloud.google.com/blog/topics/threat-intelligence/tracking-apt29-phishing-campaigns#:~:text=Mandiant%20also%20identified%20APT29%20utilizing).

For this task, access the attached VM and detect the C2 setup using Sysmon logs:  
**C:\Users\Administrator\Desktop\Practice\Task 2\Sysmon.evtx**

**TASK 1**
- Which suspicious archive did the user download?
	- URGENT!.zip
- Where did the attackers hide the C2 malware file?
	- C:\Users\Administrator\AppData\Roaming\update.exe
- What is the domain of the Command and Control server?
	- route.m365officesync.workers.dev



### Persistence Overview

Data stealer infections usually have a very short lifespan: they breach the victim, collect the data, exfiltrate it, and exit - all within minutes. However, for most other attacks, maintaining access to the victim for days or even months after the Initial Access is vital. The tactic of maintaining reliable, long-term access to the target that can survive reboots and password changes is called [Persistence](https://attack.mitre.org/tactics/TA0003/) - a big and interesting topic that you will discover soon.

![Pasted image 20250725224210.png](assets/windows-threat-detection-3/Pasted%20image%2020250725224210.png)

##### Persisting via RDP
Many Windows breaches happen because of the exposed service: RDP with a weak password, a vulnerable mail server, or a misconfigured web app. For such scenarios, the threat actors can access the machine via the same exposed service over and over again until the vulnerability is fixed. Still, threat actors often deploy an additional Persistence method, for example:

- Create an additional hidden vulnerability in the breached service (e.g. a backdoor or a [web shell](https://attack.mitre.org/techniques/T1505/003/)) 
- Create a new user ([T1136](https://attack.mitre.org/techniques/T1136/)), make it an administrator ([T1098](https://attack.mitre.org/techniques/T1098/007/)), and use it for further RDP logins

Let's focus on the second method now and see how you or threat actors can manage users on Windows. The first option is to use the graphical utility by searching for "Computer Management" or by launching `lusrmgr.msc`. The second option is to use a command line, like in the example below:

![Pasted image 20250725230018.png](assets/windows-threat-detection-3/Pasted%20image%2020250725230018.png)

##### Detecting Backdoored Users
It's time to go back to the Security event logs! Every user creation event is logged as Security event ID **4720,** which you explored in the Windows Logging for SOC room. Since threat actors can be very creative with naming the backdoored accounts, you should not rely just on detecting suspicious names like "hacker" but rather investigate:

1. **Who** created the account? Can the person confirm the account creation?
2. **What** is the source IP and time of the creator's login? Is it expected?
3. **Which** other suspicious events can you see in the creator's session?

**Making Users Privileged**

Next, a new user by itself won't give the attacker much, as the default user permissions do not allow remote (RDP) logins or grant administrative privileges on the machine. To overcome this, threat actors will add their backdoored account to one of the privileged groups, which is tracked by Security event ID **4732**. The most commonly exploited groups are **Administrators** and **Remote Desktop Users**.

**Resetting Passwords**

Lastly, in more advanced cases, threat actors may simply reset the password of some old or unused account and use it instead of creating a new one. You can detect it with Security event ID **4724**. In summary, below you can see how the described event IDs look like:

![Pasted image 20250725231149.png](assets/windows-threat-detection-3/Pasted%20image%2020250725231149.png)

**TASK 2**
- How many times did the threat actor fail to log in to the Administrator?
	- 6
- After the successful login, which backdoor user did the attacker create?
	- support
- Which privileged group was the backdoor user added to?
	- Administrators



### Persistence: Tasks And Services

##### Malware Persistence
Persistence via a backdoored user works well if you can remotely log in to it via RDP, but if the attack started through a phishing attack or USB infection, that's not an option. For these scenarios, threat actors need an actively running malware that maintains a connection with their C2 server even after a system reboot. How could they achieve malware persistence?

##### Services And Tasks
Unfortunately for defenders, there are literally a hundred or more methods to persist on a Windows machine. As a SOC L1 or L2 analyst, you don't need to know all of them, but let's start with the two common ones:

| Persistence Method                                    | Attack Example                                                               | Event ID Logging                                                                                 |
| ----------------------------------------------------- | ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| Create a Windows Service  <br>(Runs after OS startup) | `sc create "BadService" binpath= "C:\malware.exe" start= auto`               | **Launch of sc.exe:** Sysmon / **1**  <br>**Service creation:** Security / **4697  <br>**        |
| Create a Scheduled Task  <br>(Run after OS startup)   | `schtasks /create /tn "BadTask" /tr "C:\malware.exe" /sc onstart /ru System` | **Launch of schtasks.exe:** Sysmon / **1**  <br>**Scheduled task creation:** Security / **4698** |
##### Detecting Services
Many critical Windows components like DNS client or Security Center are services. You can view services by launching **services.msc** or searching for "Services", but you need administrative privileges and the **sc.exe** command to create or modify one.

Threat actors can create their own malicious services that will run the specified program on startup, and they do it very often, as you can read in the [MITRE examples](https://attack.mitre.org/techniques/T1543/003/#:~:text=Procedure%20Examples). In logs, you can detect malicious services in three ways:

1. Detect the launch of the `sc.exe create` command via Sysmon event ID **1**
2. Detect service creation via Security event ID **4697** or System event ID [7045](https://www.manageengine.com/products/active-directory-audit/kb/system-events/event-id-7045.html)
3. Detect suspicious processes with a `services.exe` parent process

![Pasted image 20250725232510.png](assets/windows-threat-detection-3/Pasted%20image%2020250725232510.png)

##### Detecting Tasks

Scheduled tasks are another Windows feature heavily used by both the OS and external apps (e.g. to check for updates or make a backup every hour). From GUI, you can manage tasks by launching **taskschd.msc** or searching for "Task Scheduler". From the command line, you can use the **schtasks.exe** command.

Unlike services, scheduled tasks are very easy to configure and hide, which is why they are the most common persistence method by threat actors, like in these [APT28](https://quointelligence.eu/2020/09/apt28-zebrocy-malware-campaign-nato-theme/#:~:text=Next%2C%20the%20malware%20creates%20a%20new%20scheduled%20task) and [APT41](https://cloud.google.com/blog/topics/threat-intelligence/apt41-us-state-governments/#:~:text=APT41%20has%20leveraged%20the%20following%20Windows%20scheduled%20tasks%20for%20persistence) attacks. Similar to services, you can detect scheduled tasks in three ways:

1. Detect the launch of the `schtasks.exe /create` command via Sysmon event ID **1**
2. Detect and analyze scheduled task creation events via Security event ID **4698**
3. Detect suspicious processes with a `svchost.exe [...] -s Schedule` parent

![Pasted image 20250725232618.png](assets/windows-threat-detection-3/Pasted%20image%2020250725232618.png)

**TASK 3**
- Which Windows service was created to persist the Nessie malware?
	- Data Protection Service
- Which scheduled task was created to persist the Troy malware?
	- AmazonSync
- What flag do you get after finding and running the Troy malware?
	- THM{c2_is_on_schedule!}


### Persistence: Run Keys And Startup

##### Run Keys and Startup
Services and scheduled tasks are typically run on system boot and require administrative privileges to configure. However, what if a program has to run only when a specific user logs in? For such cases, Windows provides a few per-user persistence methods that are actively used by both legitimate tools and malware:

| Persistence Method                                        | Attack Example                                                                                           | Event ID Logging                               |
| --------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- | ---------------------------------------------- |
| Add malware to Startup Folder  <br>(Runs upon user login) | `copy C:\malware.exe   "%AppData%\Microsoft\Windows\Start Menu\Programs\Startup\malware.exe"`            | **New startup item:** Sysmon Event ID **11**   |
| Add malware to "Run" keys  <br>(Runs upon user login)     | `reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"   /v BadKey /t REG_SZ /d "C:\malware.exe"` | **New registry value:** Sysmon Event ID **13** |

##### Detecting Startup
The startup folder was meant to be an easy way for inexperienced users to configure programs to run on login. You simply open the startup folder, move your program or program shortcut there, and see how it automatically starts upon your future logins. You can access your startup folder via the path below:
```
C:\Users\<USER>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\
Or for all users: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp
```
The startup folder is not a common choice for legitimate programs, so usually, the folder is empty. Still, threat actors often put their malware there ([Lumma Stealer example](https://www.trendmicro.com/pl_pl/research/25/a/lumma-stealers-github-based-delivery-via-mdr.html#:~:text=We%20also%20observed%20persistence%20being%20established%20through%20the%20Startup%20folder)), and you can detect it by monitoring file creation events (Sysmon Event ID **11**) inside the Startup Folder. Also, note that the programs launched via startup will have an explorer.exe parent, so it may be hard to differentiate them from legitimate user activity or attacks you learned in [Windows Threat Detection 1](https://tryhackme.com/room/windowsthreatdetection1):

![Pasted image 20250725234519.png](assets/windows-threat-detection-3/Pasted%20image%2020250725234519.png)

##### Detecting Run Keys
Run key persistence is very similar to the startup folder; they even share a single MITRE [technique](https://attack.mitre.org/techniques/T1547/001/)! The only major difference is how the entries are added there. Instead of just copying the program to the startup folder, you need to create a new value in the "Run" Windows registry and put the path to your program there:
```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOr for all users: HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
```

To view the "Run" entries, you can launch the `regedit.exe` or search for "Registry Editor" and go to the path shown above. To detect the malicious entry from logs, you can monitor registry change events (Sysmon Event ID **13**) affecting the Run keys:

![Pasted image 20250725234621.png](assets/windows-threat-detection-3/Pasted%20image%2020250725234621.png)

**TASK 4**
- What is the parent process image of the "Odin" malware?
	- C:\Windows\explorer.exe
- What is the last line that the "Odin" malware outputs?
	- done doing bad stuff!
- What flag do you get after finding and running the "Kitten" malware?
	- THM{persisting_in_basket!}


### Impact And Threat Detection Recap

##### Need for Persistence
In the previous tasks, you have learned how threat actors can remain active on the systems. But why would they need it? Why not just steal the data and exit the system before detection? There can be multiple reasons, but the main ones are:

1. **Add the host to a botnet and use it for further attacks**
    - Like how the Kraken Botnet [combines](https://www.avertium.com/resources/threat-reports/in-depth-look-at-the-kraken-botnet) crypto miner, data stealer, and C2 capabilities
2. **Spy on the victim as a part of a state-sponsored campaign**
    - Like how Volt Typhoon [stayed undetected](https://www.itpro.com/security/cyber-attacks/volt-typhoon-threat-group-electric-grid) in the US electric grid for nearly a year
3. **Use the victim as an entry point to the network, breaching which could take months**
    - Like in [the case](https://thedfirreport.com/2024/04/29/from-icedid-to-dagon-locker-ransomware-in-29-days/#timeline) where threat actors spent 29 days breaching a full network


##### Active Directory and Ransomware
Let's take a closer look at the third point. In most cases, a Windows network means a large [Active Directory](https://tryhackme.com/room/winadbasics) that brings its own attacks, detections, and threats - the main one being **ransomware**. Ransomware scares businesses the most. Why? Because it can bring entire companies to a halt, as it did for McLaren hospitals, [affecting 743,000 patients](https://www.bleepingcomputer.com/news/security/mclaren-health-care-says-data-breach-impacts-743-000-patients/). Just imagine seeing your servers encrypted, data stolen, and ransom notes automatically printed on all office printers:

##### Threat Detection Recap
Active Directory and ransomware are complex topics, but all complex attacks start from a simple single breach. In the Windows Threat Detection rooms, you explored how breaches begin, how the attackers steal data, and how they remain undetected for years. You are now ready to use the acquired knowledge to detect and stop the attacks before ransomware causes a disastrous [Impact](https://attack.mitre.org/tactics/TA0040/), preferably right after Initial Access. Here is a quick recap of what you've learned so far (highlighted in yellow):

![Pasted image 20250725235313.png](assets/windows-threat-detection-3/Pasted%20image%2020250725235313.png)

**TASK 5**
- What is the biggest threat to most corporate Windows networks?
	- Ransomware
- At which stage is it best to detect and stop the attack (e.g. Exfiltration)?
	- Initial Access