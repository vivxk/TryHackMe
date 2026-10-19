# TryHackMe — The Finance Trail (Walkthrough & Forensic Investigation Report)

**Platform**: TryHackMe  
**Challenge**: The Finance Trail  
**Category**: Digital Forensics & Incident Response (DFIR) / Splunk / Blue Team  
**Difficulty**: Hard / Intermediate  
**Target Environment**: Splunk Enterprise (Reverse Proxy on Port 80)  
**Investigated Assets**: 
- Compromised Workstation: `VAN-FIN-WS-014` (`10.81.70.254`, user `maya.chen`)
- Internal File & Mail Server: `VAN-FS-02` (`10.81.72.63`)
- Attacker Infrastructure: `lawson-rowe-review.com` (`198.51.100.27`), `cdn-lawsonreview.net` (`203.0.113.45`), `api-lawsoncdn.net` (`192.0.2.77`)

---

## 1. Incident Overview & Scenario

Vantara Financial Group's Security Operations Centre (SOC) escalated an alert involving an acquisition-review workflow that deviated sharply from normal business operations. A finance analyst, Maya Chen, received an acquisition disclosure email containing an external link. Shortly after, the corporate environment recorded unusual web, endpoint, and outbound network activity originating from her workstation.

Vantara contained the workstation and engaged external Incident Responders to reconstruct the attack lifecycle, differentiate routine acquisition noise from confirmed malicious activity, and determine whether proprietary data was staged or exfiltrated.

As the lead responder on this case, I connected to the Splunk instance (`http://10.48.184.190/`) to work through the telemetry collected across 5 distinct data sources:
- `finance_mail`: Postfix mail transfer agent and RFC822 delivery logs.
- `finance_endpoint`: Sysmon, Windows Security, PowerShell, and DNS client event logs.
- `finance_network`: Suricata network intrusion and protocol metadata (HTTP, DNS, SMB).
- `finance_web`: Nginx web server access logs for external review and CDN infrastructure.
- `finance_files`: Samba file share audit logs (`smbd_audit`).

---

---

## 3. Step-by-Step Investigation & Solution Walkthrough

---

### Question 1: Find the delivered email whose sender domain also hosted that ZIP. What is its Message-ID, without angle brackets?

* **Answer:** `20261009022902.06.1a247614eaf9@lawson-rowe-review.com`

#### Analyst Thought Process:
The briefing indicates that an acquisition-review themed email kicked off the incident. I first looked at the mail logs (`index=finance_mail`) to identify external messages arriving for finance employees. 

A search across the mail index for external domains or keywords like "review" or "acquisition" immediately surfaced an email sent to `maya.chen@vantara.local`.

#### Splunk Query:
```spl
index=finance_mail "review"
```

#### Log Evidence:
Looking at the raw RFC822 email headers delivered by the local Postfix queue:
```text
Return-Path: <amelia.hart@lawson-rowe-review.com>
X-Original-To: maya.chen@vantara.local
Delivered-To: maya.chen@vantara.local
Received: from smtp-relay-01.vantara.local (smtp-relay-01.vantara.local [10.81.72.238])
	by mail.vantara.local (Postfix) with ESMTP id D2898CA1EE
	for <maya.chen@vantara.local>; Fri,  9 Oct 2026 02:29:02 +0000 (UTC)
Date: Fri, 09 Oct 2026 02:29:02 +0000
From: Amelia Hart <amelia.hart@lawson-rowe-review.com>
To: maya.chen@vantara.local
Subject: Updated acquisition disclosure schedule for review
Message-ID: <20261009022902.06.1a247614eaf9@lawson-rowe-review.com>

Maya,

The updated acquisition disclosure schedule is ready for review:
http://lawson-rowe-review.com/review/disclosure-schedule

Regards,
Amelia
```

The domain `lawson-rowe-review.com` matches the domain that later hosted the ZIP download. Stripping the surrounding angle brackets leaves the exact Message-ID.

---

### Question 2: After the lure email arrived, which parent executable launched the browser process that opened the external review site? Give the .exe filename.

* **Answer:** `VantaraFinancePortal.exe`

#### Analyst Thought Process:
In the email above, the user was prompted to click `http://lawson-rowe-review.com/review/disclosure-schedule`. When users open links, they usually open them from an email client, a shell, or an enterprise portal. 

I needed to find the process creation event where a browser (such as `chrome.exe`) was spawned with this specific review URL as an argument, and then inspect its `ParentImage`.

#### Splunk Query:
```spl
index=finance_endpoint EventCode=1 "lawson-rowe-review.com"
```
*(Alternatively, using native Windows Security auditing: `index=finance_endpoint EventCode=4688 "lawson-rowe-review.com"`)*

#### Log Evidence:
Sysmon Event ID 1 (`EventRecordID: 1818054`) at `2026-10-09 02:33:13 UTC`:
```xml
<EventData>
  <Data Name='UtcTime'>2026-10-09 02:33:13.734</Data>
  <Data Name='ProcessId'>664</Data>
  <Data Name='Image'>C:\Program Files\Google\Chrome\Application\chrome.exe</Data>
  <Data Name='CommandLine'>"C:\Program Files\Google\Chrome\Application\chrome.exe" http://lawson-rowe-review.com/review/disclosure-schedule</Data>
  <Data Name='ParentProcessId'>1304</Data>
  <Data Name='ParentImage'>C:\Program Files\Vantara\Finance Client\VantaraFinancePortal.exe</Data>
  <Data Name='ParentCommandLine'>"C:\Program Files\Vantara\Finance Client\VantaraFinancePortal.exe"</Data>
  <Data Name='User'>VAN-FIN-WS-014\maya.chen</Data>
</EventData>
```

The browser was not opened from Outlook or Explorer; it was launched directly from Vantara's internal desktop application `VantaraFinancePortal.exe`.

---

### Question 3: On the affected workstation, what SHA-256 did Sysmon's file-stream hash event record when Chrome saved the ZIP that contained the executed loader?

* **Answer:** `98D66005B3F2CFD556EEF503EC1ADA73DE34C24D3800D41D8E30C43AF32DEDEF`

#### Analyst Thought Process:
When a browser downloads a file in Windows, Sysmon captures the Zone.Identifier and Mark-of-the-Web (MotW) creation via **Event ID 15: FileCreateStreamHash**. This event calculates the hash of the stream as it is written to disk by the browser.

I queried `EventCode=15` for any downloaded `.zip` file on Maya's machine.

#### Splunk Query:
```spl
index=finance_endpoint EventCode=15 "chrome.exe" "*.zip"
```

#### Log Evidence:
Sysmon Event ID 15 (`EventRecordID: 1818516`):
```xml
<EventData>
  <Data Name='UtcTime'>2026-10-09 02:33:20.206</Data>
  <Data Name='ProcessId'>5616</Data>
  <Data Name='Image'>C:\Program Files\Google\Chrome\Application\chrome.exe</Data>
  <Data Name='TargetFilename'>C:\Users\maya.chen\Downloads\Disclosure_Schedule_Update.zip</Data>
  <Data Name='CreationUtcTime'>2026-10-09 02:33:16.074</Data>
  <Data Name='Hash'>SHA256=98D66005B3F2CFD556EEF503EC1ADA73DE34C24D3800D41D8E30C43AF32DEDEF</Data>
</EventData>
```

Chrome saved the weaponized ZIP file `Disclosure_Schedule_Update.zip` with file hash `98D66005B3F2CFD556EEF503EC1ADA73DE34C24D3800D41D8E30C43AF32DEDEF`.

---

### Question 4: What SHA-256 do the extracted loader and installed sync client share in their process-creation events?

* **Answer:** `AAD4B231C4AFC7D02A09344545A957086FE36CD6A9CCA8F1F92E1AC3DDFFAC5C`

#### Analyst Thought Process:
The question notes that the extracted loader and the installed sync client share the exact same hash. Following the user's download of `Disclosure_Schedule_Update.zip`, I looked at process creation logs (`EventCode=1`) in Maya's Temp folder and Local AppData.

At `02:33:23`, Windows Explorer extracted and spawned `ledgerdrop.exe` from Temp. Seconds later, a new executable named `VantaraSync.exe` appeared in `AppData\Local\VantaraSync\`.

#### Splunk Query:
```spl
index=finance_endpoint EventCode=1 ("ledgerdrop.exe" OR "VantaraSync.exe")
```

#### Log Evidence:
1. **Extracted Loader (`ledgerdrop.exe`)** — `EventRecordID: 1818625`:
   - `Image`: `C:\Users\maya.chen\AppData\Local\Temp\1\Temp1_Disclosure_Schedule_Update.zip\ledgerdrop.exe`
   - `Hashes`: `SHA256=AAD4B231C4AFC7D02A09344545A957086FE36CD6A9CCA8F1F92E1AC3DDFFAC5C`

2. **Installed Sync Client (`VantaraSync.exe`)** — `EventRecordID: 1818992`:
   - `Image`: `C:\Users\maya.chen\AppData\Local\VantaraSync\VantaraSync.exe`
   - `OriginalFileName`: `ledgerdrop.exe`
   - `Hashes`: `SHA256=AAD4B231C4AFC7D02A09344545A957086FE36CD6A9CCA8F1F92E1AC3DDFFAC5C`

The loader simply copied itself to `%LocalAppData%\VantaraSync\VantaraSync.exe` to disguise itself as an internal sync utility. Both binaries share the identical SHA-256 hash.

---

### Question 5: Which scheduled task belongs to the loader's process lineage, not routine document syncing? Omit the leading backslash.

* **Answer:** `VantaraUpdateCheck`

#### Analyst Thought Process:
Attackers frequently establish persistence using scheduled tasks. Legitimate corporate environments also run scheduled tasks for template syncing (e.g. `FinanceTemplateRefresh`). 

To find the task associated specifically with the malware's lineage, I examined processes spawned directly by `ledgerdrop.exe` (PID 1656), or searched for `schtasks.exe` invocations.

#### Splunk Query:
```spl
index=finance_endpoint EventCode=1 "schtasks.exe"
```

#### Log Evidence:
Sysmon Event ID 1 (`EventRecordID: 1818912`):
```xml
<EventData>
  <Data Name='UtcTime'>2026-10-09 02:33:25.624</Data>
  <Data Name='ProcessId'>2620</Data>
  <Data Name='Image'>C:\Windows\System32\schtasks.exe</Data>
  <Data Name='CommandLine'>"schtasks.exe" /Create /TN VantaraUpdateCheck /SC DAILY /ST 03:15 /TR "C:\Users\maya.chen\AppData\Local\VantaraSync\VantaraSync.exe --sync" /F</Data>
  <Data Name='ParentProcessId'>1656</Data>
  <Data Name='ParentImage'>C:\Users\maya.chen\AppData\Local\Temp\1\Temp1_Disclosure_Schedule_Update.zip\ledgerdrop.exe</Data>
</EventData>
```

`ledgerdrop.exe` executed `schtasks.exe` to create a daily task named `VantaraUpdateCheck` pointing to `VantaraSync.exe --sync`.

---

### Question 6: The sync client did not call out the moment it started. How many seconds passed between its Sysmon process-creation UtcTime and its first command-and-control (C2) callback in the Nginx web log, rounded to the nearest second?

* **Answer:** `47`

#### Analyst Thought Process:
Malware often introduces a sleep or initial delay before reaching out to its C2 infrastructure to evade automated sandbox analysis. To measure this delay, I needed:
1. The exact process start time from Sysmon Event 1 (`UtcTime`).
2. The earliest request timestamp in the Nginx logs (`finance_web`) from Maya's IP (`10.81.70.254`).

#### Correlation & Timestamps:
1. **Sysmon Process Creation (`VantaraSync.exe`)**:
   - Query: `index=finance_endpoint EventCode=1 "VantaraSync.exe"`
   - `UtcTime`: `2026-10-09 02:33:25.981`

2. **Nginx Web Log Callback**:
   - Query: `index=finance_web client_ip="10.81.70.254" "cdn-lawsonreview.net" | sort _time | head 1`
   - Log Entry:
     ```json
     {
       "time": "2026-10-09T02:34:13+00:00",
       "server_name": "cdn-lawsonreview.net",
       "client_ip": "10.81.70.254",
       "destination_ip": "203.0.113.45",
       "uri": "/sync/v4/check?tenant=lawson-rowe&channel=stable",
       "status": 204
     }
     ```
   - Callback Time: `2026-10-09 02:34:13.000`

#### Mathematical Difference:
$$\Delta t = \text{02:34:13.000} - \text{02:33:25.981} = 47.019 \text{ seconds}$$
Rounding to the nearest whole second yields **`47`**.

---

### Question 7: For the loader-installed sync client's first successful callback from the affected workstation, which local TCP source port appears in both Suricata HTTP and the Windows Filtering Platform (WFP) allowed-connection event?

* **Answer:** `50611`

#### Analyst Thought Process:
Network sensors and endpoint firewalls provide complementary views of outbound connections. Suricata captures network traffic on the wire, while Windows Filtering Platform (WFP Event 5156) captures the kernel-level socket binding and permission.

I cross-referenced the first callback at `02:34:13` across both log sources to determine the client ephemeral port.

#### Splunk Queries:
1. **Suricata Network Log**:
   ```spl
   index=finance_network event_type=http dest_ip="203.0.113.45" | sort _time | head 1
   ```
   - Output:
     ```json
     {
       "timestamp": "2026-10-09T02:34:13.481312+0000",
       "src_ip": "10.81.70.254",
       "src_port": 50611,
       "dest_ip": "203.0.113.45",
       "dest_port": 80,
       "http": { "hostname": "cdn-lawsonreview.net", "status": 204 }
     }
     ```

2. **Endpoint WFP Event Log**:
   ```spl
   index=finance_endpoint EventCode=5156 "203.0.113.45" | sort _time | head 1
   ```
   - Output (`EventRecordID: 276887`):
     ```xml
     <EventData>
       <Data Name='Application'>\device\harddiskvolume1\users\maya.chen\appdata\local\vantarasync\vantarasync.exe</Data>
       <Data Name='SourceAddress'>10.81.70.254</Data>
       <Data Name='SourcePort'>50611</Data>
       <Data Name='DestAddress'>203.0.113.45</Data>
       <Data Name='DestPort'>80</Data>
     </EventData>
     ```

Both records corroborate that ephemeral TCP source port **`50611`** handled the initial callback.

---

### Question 8: The main C2 server returned HTTP 503, and after that the sync client used a backup domain. In Suricata, the Domain Name System (DNS) answer of type A for the backup domain was recorded before that 503. How many milliseconds before the 503 was it recorded, to three decimal places?

* **Answer:** `8.307`

#### Analyst Thought Process:
The question describes a high-precision race condition: while communicating with its primary C2 (`cdn-lawsonreview.net`), the server responded with an HTTP 503 error. Antagonistic actors often program fallback logic to query a secondary backup domain (`api-lawsoncdn.net`) when an anomaly or degradation is detected.

Suricata logs preserve timestamps down to microsecond precision (`YYYY-MM-DDTHH:MM:SS.ffffff+0000`). I located the 503 HTTP event and the DNS response for `api-lawsoncdn.net`.

#### Splunk Queries:
1. **Find HTTP 503 Event**:
   ```spl
   index=finance_network event_type=http http.status=503
   ```
   - Timestamp: `2026-10-09T02:53:21.531963+0000`

2. **Find DNS A Answer for Backup Domain**:
   ```spl
   index=finance_network event_type=dns "api-lawsoncdn.net"
   ```
   - Suricata DNS Response (`"type": "response"`):
     ```json
     {
       "timestamp": "2026-10-09T02:53:21.523656+0000",
       "dns": {
         "type": "response",
         "answers": [{ "rrname": "api-lawsoncdn.net", "rrtype": "A", "rdata": "192.0.2.77" }]
       }
     }
     ```
   - Timestamp: `2026-10-09T02:53:21.523656+0000`

#### Microsecond Calculation:
$$\begin{aligned}
t_{\text{HTTP 503}} &= 21.531963 \text{ s} \\
t_{\text{DNS Answer}} &= 21.523656 \text{ s} \\
\hline
\Delta t &= 21.531963 - 21.523656 = 0.008307 \text{ seconds}
\end{aligned}$$

Converting to milliseconds:
$$0.008307 \times 1000 = \mathbf{8.307 \text{ ms}}$$

---

### Question 9: Find the PowerShell process that created the archive later written to the share. In that workstation's captured Sysmon process-creation history, which executable last used its process ID before PowerShell started? Give the .exe filename.

* **Answer:** `elevation_service.exe`

#### Analyst Thought Process:
Windows dynamically recycles Process IDs (PIDs). Over time, a newly spawned process can be assigned a PID previously used by a terminated process.

First, I searched for the PowerShell execution responsible for creating an archive on the workstation. Next, I took note of its PID and searched backwards in the Sysmon process history (`EventCode=1`) on `VAN-FIN-WS-014` to find which executable previously held that same PID.

#### Splunk Query:
```spl
index=finance_endpoint EventCode=1 "powershell.exe" "Compress-Archive"
```

#### Log Evidence:
1. **PowerShell Staging Command** (`EventRecordID: 1819730`):
   - `UtcTime`: `2026-10-09 02:53:28.528`
   - `ProcessId`: **`692`**
   - `CommandLine`: `"powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "Compress-Archive -Path 'C:\Users\maya.chen\Documents\BoardReview\*' -DestinationPath 'C:\Users\maya.chen\Documents\review_notes_2026.zip' -Force"`
   - `ParentProcessId`: `4736` (`VantaraSync.exe`)

2. **Prior Process Reusing PID 692**:
   Searching for `ProcessId: 692` prior to `02:53:28`:
   ```spl
   index=finance_endpoint EventCode=1 "692"
   ```
   Sysmon Event ID 1 (`EventRecordID: 1818183`) at `02:33:14 UTC`:
   - `UtcTime`: `2026-10-09 02:33:14.256`
   - `ProcessId`: **`692`**
   - `Image`: `C:\Program Files\Google\Chrome\Application\155.0.8059.40\elevation_service.exe`
   - `OriginalFileName`: `elevation_service.exe`

Before PowerShell was invoked to compress the board review files, PID `692` belonged to Chrome's **`elevation_service.exe`**.

---

### Question 10: The attacker staged an archive on the workstation and then moved it to the file server. How many whole seconds passed between the archive’s Sysmon file-creation UtcTime and its successful SMB2 WRITE in Suricata?

* **Answer:** `11`

#### Analyst Thought Process:
The attacker collected sensitive acquisition files from `C:\Users\maya.chen\Documents\BoardReview\*`, compressed them into `review_notes_2026.zip`, and subsequently uploaded the archive to the network file share (`VAN-FS-02`).

I correlated:
1. **Sysmon File Creation (`EventCode=11`)** for `review_notes_2026.zip` on the workstation.
2. **Suricata Network Sensor Event** recording the successful SMB2 WRITE (`command: SMB2_COMMAND_WRITE`, `status: STATUS_SUCCESS`) destined for file server `10.81.72.63`.

#### Log Evidence:
1. **Sysmon Event 11 (File Creation)** — `EventRecordID: 1820492`:
   ```xml
   <EventData>
     <Data Name='UtcTime'>2026-10-09 02:53:29.688</Data>
     <Data Name='Image'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
     <Data Name='TargetFilename'>C:\Users\maya.chen\Documents\review_notes_2026.zip</Data>
   </EventData>
   ```
   - UtcTime: `2026-10-09 02:53:29.688`

2. **Suricata SMB2 WRITE Event**:
   ```spl
   index=finance_network event_type=smb smb.command="SMB2_COMMAND_WRITE" smb.filename="review_notes_2026.zip"
   ```
   - Suricata Output:
     ```json
     {
       "timestamp": "2026-10-09T02:53:40.986626+0000",
       "event_type": "smb",
       "src_ip": "10.81.70.254",
       "dest_ip": "10.81.72.63",
       "smb": {
         "command": "SMB2_COMMAND_WRITE",
         "status": "STATUS_SUCCESS",
         "filename": "review_notes_2026.zip"
       }
     }
     ```
   - Timestamp: `2026-10-09 02:53:40.986626`

#### Whole Seconds Calculation:
$$\Delta t = 40.986626 - 29.688000 = 11.298626 \text{ seconds}$$
Truncating / taking whole seconds yields **`11`**.

---

## 4. Response Scope & Containment Recommendations

1. **Host Containment**:
   - Isolate `VAN-FIN-WS-014` (`10.81.70.254`) immediately from the production VLAN.
   - Kill running process `VantaraSync.exe` (PID 4736) and remove the binary from `C:\Users\maya.chen\AppData\Local\VantaraSync\`.
   - Delete the malicious scheduled task `VantaraUpdateCheck`.

2. **Network Defenses**:
   - Block malicious external domains and IPs at the boundary perimeter and DNS resolvers:
     - `lawson-rowe-review.com` (`198.51.100.27`)
     - `cdn-lawsonreview.net` (`203.0.113.45`)
     - `api-lawsoncdn.net` (`192.0.2.77`)
   - Add Suricata / Snort signature for User-Agent: `VantaraSync/*`.

3. **Data Loss Assessment**:
   - Inspect file server `VAN-FS-02` (`/srv/finance-review/review_notes_2026.zip`).
   - Audit all documents under `C:\Users\maya.chen\Documents\BoardReview\*` to determine potential exposure of non-public financial / M&A disclosures.
