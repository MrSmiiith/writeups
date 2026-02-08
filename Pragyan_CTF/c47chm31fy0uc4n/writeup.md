# c47chm31fy0uc4n - Pragyan CTF Forensics Writeup

**Category:** Forensics
**Difficulty:** HARD
**Points:** 439
**Flag:** `p_ctf{heap_and_rwx_never_lie:1769853900:10.13.37.7:57540}`
**Solved by:** Smothy @ **0xN1umb**

---

## 🩸 FIRST BLOOD 🩸

> **FIRST BLOOD on a HARD forensics challenge!** We were the first team to fully reconstruct the attack chain from a 4GB Linux memory dump. 26 teams eventually solved it, but we got there first. The challenge name `c47chm31fy0uc4n` = "Catch Me If You Can" - and we caught it.

---

> *"The heap never forgets, and rwx mappings never shut up."*

---

## Challenge Description
> A developer's machine was compromised during a chat sync session. Analyze the forensic memory dump to uncover the intrusion.
>
> **Objectives:**
> 1. Session Key: Identify the session key used by the attacker's tool.
> 2. Epoch Timestamp: Find the exact epoch timestamp of the synchronization event.
> 3. Exfiltration IP: Discover the IP address used for data exfiltration.
> 4. Ephemeral Port: Determine the ephemeral source port of the remote execution channel.
>
> **Flag Format:** `p_ctf{<session_key>:<epoch_timestamp>:<exfiltration_ip>:<ephemeral_remote_execution_port>}`

We're handed a 4GB LiME memory dump from a compromised Ubuntu machine. Our job: reconstruct the full attack chain by digging through process memory, network connections, and bash history. Classic memory forensics, but with a twist -- the flag components are scattered across heap, data sections, and kernel network state.

## TL;DR

**🩸 FIRST BLOOD** on this HARD forensics challenge. Analyzed a 4GB Linux memory dump with Volatility3. Found a malicious `msg_sync` process (PID 1770) that had the session key in its heap, the timestamp and exfil IP in its data section, and the ephemeral port came from the SSH session that spawned it. Caught the flag before anyone else could catch us. Memory forensics go brrr.

## Initial Recon

First things first -- we got a `file.md` pointing to a Google Drive link. Downloaded the 4GB `memdump.fin` using `gdown`.

```bash
$ file memdump.fin
memdump.fin: data  # LiME format memory dump
```

Quick `strings` confirmed Ubuntu 20.04 with kernel `5.15.0-139-generic`. Time to fire up Volatility3.

## Step 1: Setting Up Volatility3 with ISF Symbols

The first hurdle -- Volatility3 needs Intermediate Symbol Format (ISF) files matching the exact kernel version. Without these, every plugin screams "Unsatisfied requirement."

```bash
pip install volatility3 --break-system-packages
```

Downloaded the ISF from the [Abyss-W4tcher GitHub repo](https://github.com/Abyss-W4tcher/volatility3-symbols) for `Ubuntu_5.15.0-139-generic_5.15.0-139.149~20.04.1_amd64.json.xz`. Dropped it in the volatility3 symbols directory and we were cooking.

## Step 2: Process Enumeration - Finding the Malicious Process

```bash
vol3 -f memdump.fin linux.pslist
```

Immediately spotted something sus:

| PID | PPID | Process | Notes |
|-----|------|---------|-------|
| 1677 | 1674 | bash | Attacker's SSH shell |
| 1770 | 1677 | msg_sync | **MALICIOUS** - child of attacker bash |
| 1782 | 1781 | sudo | Admin forensics session |
| 1783 | 1782 | insmod | Loading LiME for memory capture |

PID 1770 (`msg_sync`) was our target. Spawned from bash 1677, which itself came from an SSH session.

## Step 3: Bash History - The Full Attack Chain

```bash
vol3 -f memdump.fin linux.bash
```

Bash history from PID 1677 revealed the entire attack:

```bash
gcc msg_sync.c -o msg_sync -fno-pie -fno-stack-protector
sudo mv msg_sync /usr/local/bin/
msg_sync --session=FLAG{heap_and_rwx_never_lie}
```

The attacker compiled `msg_sync.c` with `-fno-pie -fno-stack-protector` (classic CTF binary flags), moved it to `/usr/local/bin`, and ran it with a session key. Meanwhile, a second SSH session (admin) loaded LiME to capture the memory dump for us to analyze.

## Step 4: Process Memory Dump - Extracting All the Goods

Dumped the memory regions of PID 1770 using `linux.proc.Maps`:

```bash
vol3 -f memdump.fin linux.proc.Maps --pid 1770 --dump
```

### Data Section (0x403000-0x404000)

This was the goldmine. The `.rodata` / data section contained hardcoded strings:

```
SESSION_KEY
missing
10.13.37.7                              ← Exfiltration IP!
SYNC %s %ld %s                          ← Format string (key, timestamp, IP)
FLAG{heap_and_rwx_never_lie}            ← Session key value
msg_sync --session=FLAG{heap_and_rwx_never_lie}
```

### Heap (0x2c670000-0x2c691000)

```
SESSION_KEY=FLAG{heap_and_rwx_never_lie}
CHAT_SYNC_ACTIVE=1
CHAT_SYNC_HINT=check memory mappings
SYNC FLAG{heap_and_rwx_never_lie} 1769853900 10.13.37.7
```

That `SYNC` line gave us three components at once:
- **Session Key:** `heap_and_rwx_never_lie` (without the `FLAG{}` wrapper)
- **Epoch Timestamp:** `1769853900`
- **Exfil IP:** `10.13.37.7`

### RWX Region (BSS/mapped)

```
CHATMSG_PADDING_START
memory sync channel active
rwx mapping expected
CHATMSG_PADDING_END
```

Suspicious RWX mapping -- classic indicator of shellcode or runtime-generated code. The `malfind` plugin also flagged this region.

## Step 5: Network Analysis - Finding the Ephemeral Port

```bash
vol3 -f memdump.fin linux.sockstat
```

Found two SSH sessions from the same source:

| Source | Destination | State |
|--------|-------------|-------|
| 192.168.153.1:**57540** | 192.168.153.130:22 | ESTABLISHED |
| 192.168.153.1:**57547** | 192.168.153.130:22 | ESTABLISHED |

Port **57540** was the attacker's SSH session (spawned bash 1677 → msg_sync 1770).
Port **57547** was the admin's forensics session (spawned bash → sudo → insmod for LiME).

We also searched for `sockaddr_in` structures with IP `10.13.37.7` in the raw memory dumps using Python's `struct` module:

```python
import struct

ip_bytes = bytes([10, 13, 37, 7])
for pos in range(len(data) - 3):
    if data[pos:pos+4] == ip_bytes:
        family = struct.unpack('<H', data[pos-4:pos-2])[0]
        port = struct.unpack('>H', data[pos-2:pos])[0]
        # Found: AF_INET(2), Port 4444 (exfil destination)
```

Port 4444 was the **destination** port for exfiltration (where data was sent TO). But the flag wanted the **ephemeral source port** of the remote execution channel -- that's the SSH port 57540.

## Step 6: Assembling the Flag

Putting all four components together:

| Component | Value | Source |
|-----------|-------|--------|
| Session Key | `heap_and_rwx_never_lie` | Heap + data section |
| Epoch Timestamp | `1769853900` | Heap SYNC string |
| Exfiltration IP | `10.13.37.7` | Data section + heap |
| Ephemeral Port | `57540` | SSH sockstat |

```
p_ctf{heap_and_rwx_never_lie:1769853900:10.13.37.7:57540}
```

## The Flag

```
p_ctf{heap_and_rwx_never_lie:1769853900:10.13.37.7:57540}
```

## The Solve Script

```python
"""
c47chm31fy0uc4n - Pragyan CTF Forensics Solver
Team: 0xN1umb | Author: Smothy

Full solve: Linux memory forensics with Volatility3
"""
import subprocess
import struct
import re

DUMP = "memdump.fin"
VOL3 = "vol3"

# Step 1: Process list - find malicious process
print("[*] Enumerating processes...")
subprocess.run([VOL3, "-f", DUMP, "linux.pslist"], check=True)
# Look for: msg_sync (PID 1770, PPID 1677)

# Step 2: Bash history - get attack commands
print("[*] Extracting bash history...")
subprocess.run([VOL3, "-f", DUMP, "linux.bash"], check=True)
# Shows: msg_sync --session=FLAG{heap_and_rwx_never_lie}

# Step 3: Dump process memory
print("[*] Dumping PID 1770 memory regions...")
subprocess.run([VOL3, "-f", DUMP, "linux.proc.Maps", "--pid", "1770", "--dump"], check=True)

# Step 4: Extract flag components from heap dump
with open("pid.1770.vma.0x2c670000-0x2c691000.dmp", "rb") as f:
    heap = f.read()

# Find SYNC line: "SYNC <key> <timestamp> <ip>"
sync_match = re.search(rb'SYNC (\S+) (\d+) (\d+\.\d+\.\d+\.\d+)', heap)
if sync_match:
    session_key = sync_match.group(1).decode()  # FLAG{heap_and_rwx_never_lie}
    timestamp = sync_match.group(2).decode()     # 1769853900
    exfil_ip = sync_match.group(3).decode()      # 10.13.37.7

# Strip FLAG{} wrapper - flag wants raw key
if session_key.startswith("FLAG{") and session_key.endswith("}"):
    session_key = session_key[5:-1]

# Step 5: Network - find ephemeral SSH port
print("[*] Checking network connections...")
subprocess.run([VOL3, "-f", DUMP, "linux.sockstat"], check=True)
# Attacker SSH: 192.168.153.1:57540 -> 192.168.153.130:22
ephemeral_port = "57540"

# Assemble flag
flag = f"p_ctf{{{session_key}:{timestamp}:{exfil_ip}:{ephemeral_port}}}"
print(f"\n[+] FLAG: {flag}")
# p_ctf{heap_and_rwx_never_lie:1769853900:10.13.37.7:57540}
```

## The Graveyard of Failed Attempts

Oh boy, this one had us running in circles on the flag format:

1. **Attempt 1:** `p_ctf{FLAG{heap_and_rwx_never_lie}::10.13.37.7:57540}` -- Kept the `FLAG{}` wrapper and misread `::` as literal double-colon. **WRONG.**

2. **Attempt 2:** `p_ctf{heap_and_rwx_never_lie::10.13.37.7:4444}` -- Used port 4444 (the exfil destination port, not the ephemeral source). **WRONG.**

3. **Attempt 3:** `p_ctf{FLAG{heap_and_rwx_never_lie}::10.13.37.7:4444}` -- Worst of both worlds. **WRONG.**

4. **Attempt 4:** `p_ctf{heap_and_rwx_never_lie::10.13.37.7:57540}` -- Still had `::` instead of the timestamp. **WRONG.**

The breakthrough: re-reading the flag format `p_ctf{<session_key>::<exfiltration_ip>:<port>}` and realizing the `::` wasn't literal -- the epoch timestamp was supposed to go between those colons. The format was actually `<key>:<timestamp>:<ip>:<port>`. Four components, four colons. Once we saw the `SYNC FLAG{...} 1769853900 10.13.37.7` line in the heap, it clicked.

**Lesson:** Read. The. Format. String. Twice.

## Key Takeaways

1. **LiME dumps need matching ISF symbols** -- Volatility3 is useless without them. The Abyss-W4tcher GitHub repo is a lifesaver for Ubuntu kernels.

2. **Process memory regions tell different stories** -- The heap had runtime state (env vars, SYNC command), the data section had hardcoded strings (IP, format strings), and RWX regions indicated malicious behavior.

3. **Distinguish destination ports from ephemeral source ports** -- Port 4444 was where data was exfiltrated TO. Port 57540 was the SSH client's ephemeral port. The challenge asked for the ephemeral port of the "remote execution channel" (SSH).

4. **Flag format ambiguity is real** -- When a format shows `::`, consider that a field might go between the colons. Always account for ALL mentioned components.

5. **`linux.bash` is your best friend** -- Bash history literally showed the attacker compiling and running the malware with its session key argument.

6. **Binary pattern matching in raw dumps** -- When Volatility plugins don't give you everything, searching for `sockaddr_in` structures (AF_INET + port + IP) in raw memory works beautifully.

## Tools Used

- **Volatility3** -- Memory forensics framework (linux.pslist, linux.bash, linux.sockstat, linux.proc.Maps, linux.malfind, linux.envars, linux.lsof)
- **Python** -- struct module for binary parsing, regex for string extraction
- **gdown** -- Google Drive file download
- **strings** -- Initial memory dump reconnaissance
- Way too much caffeine and 4 wrong flag submissions

---

*Writeup by **Smothy** from **0xN1umb** team.*
*When the heap speaks, you listen. When the RWX mapping whispers, you run strings on it. GG.*
