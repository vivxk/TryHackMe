
### Data Exfil: Overview, techniques, and Indicators

Data exfiltration is the unauthorized transfer of data from an organization to an external destination controlled by an adversary. It can be deliberate (insider) or via malware / compromised credentials.

##### Why Adversaries Perform Data Exfiltration
Data exfiltration is the act of stealing sensitive information from a network. Adversaries do this for several reasons:
- **Financial Gain**: Stolen data (e.g., credit card info, personal records) can be sold on the dark web or used for fraud.
- **Espionage**: Nation-state actors target intellectual property, trade secrets, or classified data for strategic advantage.
- **Ransomware & Extortion**: Attackers steal data and threaten to leak it unless a ransom is paid.
- **Disruption & Sabotage**: Some adversaries aim to damage reputations or operations by leaking internal data.
- **Persistence & Reconnaissance**: Exfiltrated data helps attackers understand the environment for future attacks.

##### Threat Actors & Their Exfiltration Techniques
The following table covers some of the real-world threat actors and their data exfiltration methods.

|Threat Actor / Campaign|Exfiltration Technique|Description|
|---|---|---|
|[**APT29 (Cozy Bear)**](https://www.picussecurity.com/resource/blog/apt29-cozy-bear-evolution-techniques)|HTTPS over legitimate domains|Encrypted HTTPS channels were used to exfiltrate data from government networks.|
|[**FIN7**](https://www.fbi.gov/contact-us/field-offices/seattle/news/stories/how-cyber-crime-group-fin7-attacked-and-stole-data-from-hundreds-of-us-companies)|HTTP POST to C2 servers|Embedded stolen data in HTTP POST requests to evade detection.|
|[**Lunar Spider (Zloader)**](https://thedfirreport.com/2025/09/29/from-a-single-click-how-lunar-spider-enabled-a-near-two-month-intrusion/)|Encrypted C2 channels|Maintained a two-month intrusion using encrypted channels and staged exfiltration.|
|[**DarkSide Ransomware**](https://www.varonis.com/blog/darkside-ransomware)|Dual extortion: encryption + exfil|Stole data before encrypting systems, then threatened public leaks.|
|[**APT10 (Cloud Hopper)**](https://www.sei.cmu.edu/blog/operation-cloud-hopper-case-study/)|Cloud-to-cloud transfer|Exfiltrated data from managed service providers using cloud APIs.|

##### Common phases related to exfiltration
- **Discovery / Collection**: attacker locates sensitive files. 
- **Staging / Compression**: attacker aggregates, compresses, encrypts, or encodes files (ZIP, RAR, 7z, tar, base64, steganography).
- **Exfiltration transport**: transfer over network, removable media, cloud, or covert channels.
- **Command & Control (C2) coordination**: orchestrates transfer and confirms receipt.

##### Techniques and Indicators
Detecting exfiltration requires correlating host and network-level indicators such as unusually large or frequent outbound uploads (proxy/firewall), long or high-entropy DNS queries, suspicious process command-lines and network connections (Sysmon/EDR), cloud storage API activity, removable-media events, and effective SOC L1 triage focuses on source host/user, destination, transferred volume, process identity/command-line, and supporting evidence across proxy, DNS, flow, host, and cloud logs.

| Techniques                        | Examples                                                                                                                                                                                                    | Indicator of Attack & where to look                                                                                                                                                           |
| --------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Network-based**                 | HTTP/HTTPS uploads to S3/Azure Blob/webmail, FTP/SFTP/SCP, DNS tunnelling, ICMP/covert protocols, custom TCP/UDP.                                                                                           | Proxy/web gateway logs (large POSTs, uploads to cloud endpoints), firewall/NGFW flows (high bytes to single IP/ASN), netflow (spikes/outbound flows), DNS logs (long hostnames, TXT queries). |
| **Host-based**                    | Powershell/Invoke-WebRequest, rclone, awscli, curl/wget, archive creation (zip/rar), use of removable USBs, ADS/hidden streams.                                                                             | Sysmon/EDR (Process Create, Network Connect, File Create events), Windows Security (4663/4656 object access), auditd/shell history on Linux, and removable-media events.                      |
| **Cloud exfiltration**            | S3 PutObject / multipart upload, Azure Blob uploads, Google Cloud Storage objects. Insert, Drive/SharePoint external sharing.                                                                               | CloudTrail / Azure Activity / GCP Audit, cloud storage access logs, unusual service-account or IP activity.                                                                                   |
| **Covert & encoding**             | DNS tunnelling, base64 or chunked encoding, steganography into images/audio, splitting files into many small requests (low-and-slow).                                                                       | DNS logs, proxy logs with many small POSTs, correlation of intermittent uploads + suspicious process activity.                                                                                |
| **Insider & collaboration tools** | Slack/Teams/Dropbox/Google Drive/Box uploads or sharing to external users; compromised employee accounts.                                                                                                   | Audit logs (share events, file downloads), and mail logs.                                                                                                                                     |
| **General IoAs & triage signals** | A large outbound volume to external IPs/domains, unknown destination domains, suspicious processes/command lines, many file read events followed by an outbound connection, and multipart/streamed uploads. | Correlate: Proxy/Firewall/Netflow, DNS, Sysmon/EDR (EventID 1/3/11), mail server logs.                                                                                                        |

Data exfiltration is a high-impact threat that combines opportunistic methods, legitimate tools, and creative covert channels to move sensitive assets outside an organisation. An effective detection depends less on single-point alerts and more on rapid correlation across host, network, and cloud telemetry, identifying who accessed data, what was transferred, how it was staged, and where it was sent.


### Detection: Data Exfil through DNS Tunneling

DNS exfiltration abuses the Domain Name System, a protocol normally allowed through networks, to smuggle bytes encoded inside DNS queries/responses so firewalls and web proxies don't notice. Because DNS is typically allowed and often unfiltered or forwarded to public resolvers, it's attractive for covert channels.

##### DNS Tunneling
DNS (Domain Name System) translates human-friendly domain names (e.g., `example.com`) into IP addresses and provides other record types (A, AAAA, TXT, MX, CNAME, etc.). Key points:

- DNS queries are ubiquitous: almost every host performs DNS lookups.
- DNS is normally allowed through firewalls and gateways, making it an attractive covert channel.
- DNS uses UDP (mostly) on port 53 for queries and responses; TCP is used for zone transfers or large responses.

Why attackers use DNS for exfiltration:
- Always-on service: DNS lookups are routine and often allowed outbound.
- High cover: queries look like normal requests unless inspected closely.
- Flexible payload: data can be encoded into the subdomain labels or TXT responses.

##### **Indicators of attack** 
**When analysing DNS traffic for possible indicators of data exfiltration, we should look for:**
- **Many DNS queries are sent to a single external domain, especially with very high counts compared to the baseline.**
- **Long subdomain labels or unusually long full query names (> 60–100 characters).**
- **High entropy or Base32/Base64-like patterns in the query name (lots of mixed case letters, digits, `-`, `=` signs for base64).**
- **Rare record types (TXT, NULL) or many large TXT responses.**
- **Unusual response behavior: frequent NXDOMAIN (if attacker uses exfil-by-query without answering), or TCP/large UDP fragments for DNS.**
- **Queries at regular intervals (beaconing behaviour).**

Let's use this knowledge and examine the network traffic `dns_exfil.pcap` placed at `/data_exfil/dns_exfil/` on the desktop:

##### Detecting through Wireshark
Below are Wireshark display filters, tshark commands, and what to look for when analyzing `dns_exfil.pcap`.

Let's start by applying filter on dns traffic, using the following filter, as shown below:

**Filter:** `dns`

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/5e8dd9a4a45e18443162feab-1759117822714.png)

Let's filter on the DNS queries with no response using the following filter:

**Filter:** `DNS.flags.response == 0`

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/5e8dd9a4a45e18443162feab-1759117884964.png)

We can see some DNS entries with a large query length.

##### Find long queries (suspicious subdomain lengths)
Let's apply filter on the query length and see if we can narrow down our results.

**Filter:** `DNS && frame.len > 70`

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/5e8dd9a4a45e18443162feab-1759118255747.png)

The above result identifies one particular suspicious domain, which is receiving these suspicious-looking DNS requests. Let's filter on the suspicious domain using the following filter:

**Filter:** `DNS && DNS.qry.name contains <REDACTED>`

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/5e8dd9a4a45e18443162feab-1759118367397.png)

Looks like we have successfully identified the DNS tunneling attempt. From the network traffic, we can observe:
- Multiple internal hosts are compromised.
- All these hosts are sending the data in chunks using DNS tunneling techniques.
- There is only one external domain identified as the one receiving the DNS queries.

Let's correlate this using Splunk.

##### Investigating with Splunk
Open the splunk instance. In the search bar, enter the following search query.

**Search Query:** `index=data_exfil sourcetype=DNS_logs`

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/5e8dd9a4a45e18443162feab-1759204545663.png)

This search query will filter show the results matching `sourcetype=DNS_logs`.

**What to look for**

In the DNS logs, we need to look at the suspicious looking domains with a huge query count from multiple hosts or from one host (suspicious if the domain is untrusted). 

Let's run the following search query to display the stats of DNS queries generated per source IP, as shown below:

**Search Query**: `index="data_exfil" sourcetype="DNS_logs" | stats count by src_ip`

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/5e8dd9a4a45e18443162feab-1759118814896.png)Let's now apply filter on the stats of the queries to identidy the suspicious ones, as shown below:

**Search Query:** `index="data_exfil" sourcetype="dns_logs" | stats count by query | sort -count` 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/5e8dd9a4a45e18443162feab-1759119347715.png)

The above results, clearly display some odd looking DNS queries with the a large size of the query.

**What to look for:**

We can look at single hosts generating far more DNS requests than normal.

##### Long query names (subdomain encoding)
Let's now apply the following filter on the queries with length over 30 and see if we can filter the odd-looking ones out, as shown below:

**Search Query:** `index="data_exfil" sourcetype="DNS_logs" | where len(query) > 30`

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/5e8dd9a4a45e18443162feab-1759204803154.png)

Perfect. With the following indicators, we were able to identify the data exfiltration attempts through DNS tunneling:

- A Large number of DNS requests with no response.
- Large length of the DNS query.

**Task 1**
- What is the suspicious domain receiving the DNS traffic?
	- tunnelcorp.net
- How many suspicious traffic/logs related to dns tunneling were observed?
	- 315
- Which local IP sent the maximum number of suspicious requests?
	- 192.168.1.103



### Detection: Data Exfil through FTP

FTP (File Transfer Protocol) is one of the oldest protocols for transferring files between a client and server over a TCP/IP network. Attackers use it to move large amounts of data off a network, sometimes via compromised credentials, misconfigured servers, or ephemeral accounts. Detection relies on a mix of packet inspection (FTP only), server logs, SSH session metadata, and network flow/size/pattern analysis.

##### How adversaries use FTP for exfiltration
- Use **legitimate FTP servers** (public or misconfigured internal servers) to stage/transfer data.
- Use **compromised credentials** (service accounts, user creds).
- Use **non-standard ports** or tunneling to blend with other traffic.

##### **Indicators of attack**
**What to look for:**
- **`USER` and `PASS` commands (cleartext credentials).**
- **`STOR` (upload) and `RETR` (download) commands: repeated or large transfers.**
- **Large data connections to unusual external IPs, especially outside business hours.**
- **Data channel openings on ephemeral ports (PASV) paired with large payloads.**

Let's examine the `ftp-lab.pcap` file placed in the `/data_exfil/ftp_exfil/` on the Desktop. Open the file in Wireshark, and follow the steps mentioned below:

**Isolate FTP control & data**

First, we will look for FTP Sessions using the `ftp || ftp-data` filter, as shown below:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/5e8dd9a4a45e18443162feab-1759206448445.png)

This filter will isolate the ftp control traffic.

**Look for Credentials**

Let's filter to show only login attempts with USER/PASS:`ftp.request.command == "USER" || ftp.request.command == "PASS"`

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/5e8dd9a4a45e18443162feab-1759207083723.png)

From the output, we can look for suspicious usernames or weak passwords.

**Look for Anomalies in Filenames or Credentials**

**Filter**: `ftp contains "STOR"`

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/5e8dd9a4a45e18443162feab-1759206696132.png)

Right-click a `packet → Follow → TCP Stream`, as shown below:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/5e8dd9a4a45e18443162feab-1759206931317.png)

We can look at suspicious files by filtering on the file extensions like PDF, csv, TXT etc. Let's apply a filter on ftp packets containing the term `csv` in it, as shown below:

**Filter:** `ftp contains "csv"`

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/5e8dd9a4a45e18443162feab-1759207402100.png)

The above results show a suspicious IP connected as Guest account has transferred some sensitive csv files to a supicious external IP.

##### Identifying the traffic with a large payload size

Look at the traffic with a large length, using the filter `ftp && frame.len > 90` and check out the content in TCP Stream, as shown below:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/5e8dd9a4a45e18443162feab-1759405309863.png)

Looks like a document with sensitive information was being transferred to the external IP address. Explore other streams to find more indicators of sensitive documents being exfiltrated through the HTTP protocol.

**Task 2**
- How many connections were observed from the guest account?
	- 5
- Apply the filter; what is the name of the customer-related file exfiltrated from the root account?
	- customer_data.xlsx
- Which internal IP was found to be sending the largest payload to an external IP?
	- 192.168.1.105
- What is the flag hidden inside the ftp stream transferring the CSV file to the suspicious IP?
	- THM{ftp_exfil_hidden_flag}




### Detection: Data Exfil through HTTP

**Data exfiltration via HTTP** is when an attacker moves sensitive data out of a target network using HTTP as the transport. HTTP is commonly abused because it blends with normal web traffic, can traverse firewalls and proxies, and can be obfuscated (encoding, encryption, tunneling). This detection task aims to teach SOC analysts how to identify signs of HTTP-based exfiltration in packet captures (Wireshark) and logs (Splunk), and to provide practical search queries and investigation steps.

##### Why it matters
- HTTP is very common; attackers hide exfiltration in the noise of legitimate web usage.
- Successful detection stops data breaches and helps trace attacker activity post-compromise.
- Organizations must detect and respond to protect sensitive data and meet compliance requirements.

##### **How adversaries use HTTP for data exfiltration**
- **POST uploads to external servers: Bulk data is sent to attacker-controlled hosts or cloud storage in POST request bodies.**
- **GET requests with encoded data: Attacker squeezes small chunks into query strings or path segments (useful for low-and-slow exfiltration).**
- **Use of common services / CDN: Exfiltration disguised as uploads to popular services or attacker-controlled subdomains under reputable domains.**
- **Custom headers: Data placed in headers (e.g., `X-Data: <base64>`) may bypass some string-based DLP.**
- **Chunked transfer / multipart: Large payloads split into multiple requests to avoid size thresholds.**
- **HTTPS/TLS tunneling: The encrypted channel hides the payload; detection requires TLS inspection, SNI analysis, or metadata-based detection.**
- **Staging via cloud services: The attacker uploads to Dropbox/GitHub/Gist and then fetches externally.**

**Adversaries adapt: low-and-slow approaches, encryption/encoding, and use of legitimate services to evade detection.**

##### **Indicators of Attack (IoAs)** 
###### **Common network indicators**
- **Unusually large HTTP POST requests to external/unexpected hosts.**
- **HTTP requests to domains with low reputation / rarely seen in baseline traffic.**
- **Frequent small requests (beaconing) to the same host, followed by large uploads.**
- **Chunked or multipart transfers where multiple requests compose a larger file.**

Let's examine the http logs in Splunk and see if we can find the indicators of the data exfiltration attempt in the logs.

##### Analyzing Logs in Splunk
To start, use the following search query to get the `http_logs` and make sure to select Time range as `All Time`, as shown below:

**Search Query:** `index="data_exfil" sourcetype="http_logs"`

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/5e8dd9a4a45e18443162feab-1759405928050.png)

As we understand, the exfiltration attempts can be done via POST requests. We will apply a filter on the POST method to further narrow down our results, as shown below:

**Search Query:** `index="data_exfil" sourcetype="http_logs" method=POST`

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/5e8dd9a4a45e18443162feab-1759406320576.png)

Let's now look at the average amount of bytes sent out to various domains, as shown below:

**Search Query:** `index="data_exfil" sourcetype="http_logs" method=POST | stats count avg(bytes_sent) max(bytes_sent) min(bytes_sent) by domain | sort - count`

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/5e8dd9a4a45e18443162feab-1759406401319.png)

Let's filter out benign traffic and isolate POSTs with large payloads.

**Search Query:** `index="data_exfil" sourcetype="http_logs" method=POST bytes_sent > 600 | table _time src_ip uri domain dst_ip bytes_sent | sort - bytes_sent`

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/5e8dd9a4a45e18443162feab-1759407051358.png)Our analysis so far points to one suspicious entry, with a large chunk of data uploaded to an external source. Let's correlate this with the pcap to extend our analysis further.

##### Network Traffic Analysis
Open the `http_lab.pcap` placed in the `/data_exfil/http_exfil/` folder.

##### Filter on HTTP traffic
Apply a filter on the HTTP traffic, as shown below:

**Filter**: `http`

![wireshark showing http traffic](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/5e8dd9a4a45e18443162feab-1759121711213.png)

We can see HTTP traffic with both GET and POST requests. Filter on POST requests, as shown below:

**Filter**: `http.request.method == "POST"`

![wireshark showing http traffic PODT requests](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/5e8dd9a4a45e18443162feab-1759121787546.png)

Filter on the traffic with the frame length of more than 500, as shown below:

**Filter**: `http.request.method == "POST" and frame.len > 500`

![wireshark showing http traffic with frame length over 500.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/5e8dd9a4a45e18443162feab-1759121887682.png)

We still have a lot of noise. Let's increase the size to 750 and see if we can further filter down the result.

Filter: `http.request.method == "POST" and frame.len > 750`

![wireshark showing http traffic](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/5e8dd9a4a45e18443162feab-1759123551573.png)

This request shows only one entry, which looks the same as the one we found in Splunk. Let's go to the HTTP stream to see the file's content, as shown below:

![wireshark showing http traffic](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/5e8dd9a4a45e18443162feab-1759127408547.png)

Great. We have looked at the indicators of data exfiltration attempts in the logs and network traffic and were able to correlate and identify the secret document being exfiltrated to the external IP.

**Task 3**
- Which internal compromised host was used to exfiltrate this sensitive data?
	- 192.168.1.103
- What's the flag hidden inside the exfiltrated data?
	- THM{http_raw_3xf1ltr4t10n_succ3ss}




### Detection: Data Exfiltration via ICMP

ICMP is a network-layer protocol used for diagnostics and control (e.g., ping, TTL exceeded). Because it is commonly allowed through firewalls and typically inspected less strictly than TCP/UDP, attackers sometimes abuse ICMP to tunnel and exfiltrate data. Malicious actors encode data into ICMP payloads (echo request/reply, timestamp, info) and send it to a remote listener under their control.

##### **How adversaries use ICMP for exfiltration**
**Common techniques:**
- **ICMP echo (type 8) / reply (type 0) tunneling: attackers place encoded (base64, hex) chunks of files inside ICMP payloads. The remote server collects and decodes them.**
- **Custom ICMP types/codes: using uncommon ICMP types or non-zero codes to avoid signature-based detections.**
- **Fragmentation and reassembly: large payloads are split across multiple packets.**
- **Encryption/obfuscation: Encrypting or encrypting payloads (base64 is common) to look like random data.**

**Indicators that something may be malicious:**
- **Persistent ICMP sessions to an external host not used for legitimate monitoring.**
- **Unusually large ICMP payloads or frequent ICMP with payload > typical ping size.**
- **ICMP payloads that contain high-entropy data or patterns consistent with base64/hex.**
- **Bursts of ICMP are immediately followed by no other legitimate application traffic from the same host.**

##### **Indicators of attack in Wireshark**
**Look for the following in a pcap when inspecting in Wireshark:**
- **ICMP packet volumes: a single host sending many ICMP echo requests to an external IP.**
- **Large `frame.len` or `icmp.payload`: pings with payloads much larger than typical (e.g., > 64 bytes).** 
- **ICMP type/code unusual values: e.g., unusual use of timestamp(13/14) or custom codes.**
- **Regular timing (periodicity): evenly spaced ICMP packets carrying similar-sized payloads.**
- **Fragments with reassembly: multiple ICMP fragments from the same src/dst pair.**

**Traffic Analysis**

For this task, open the `icmp_lab.pcap` placed in `/data_exfil/icmp/exfil` folder on the Desktop.

 **Filter All ICMP Traffic**

The filter below isolates all ICMP packets. Look for unusually frequent or large ICMP Echo Requests/Replies.

**Filter**: `icmp`

![Wirehark showing icmp filtered traffic](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/5e8dd9a4a45e18443162feab-1759127754119.png)

**Isolate Echo Requests**

Let's apply the filter to isolate ICMP Echo Request packets, as shown below:

**Filter**: `icmp.type == 8`

![Wirehark showing icmp filtered traffic](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/5e8dd9a4a45e18443162feab-1759127920030.png)

**Examine Large ICMP Packets**

Let's now apply the filter on the ICMP requests and focus on the frame length over 100, as shown below:

**Filter**: `icmp.type == 8 and frame.len > 100`

![Wirehark showing icmp filtered traffic](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/5e8dd9a4a45e18443162feab-1759127920071.png)  
Flags packets with unusually large payloads. Normal pings are ~74 bytes total. Anything over 100 is suspicious.

![Wirehark showing icmp filtered traffic](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/5e8dd9a4a45e18443162feab-1759128128688.png)

That's it.

ICMP is simple, and any anomaly can be detected easily by examining the frame size and investigating the larger payload size than usual.

**Task 4**
- What is the flag found in the exfiltrated data through ICMP?
	- THM{1cmp_3ch0_3xf1ltr4t10n_succ3ss}


