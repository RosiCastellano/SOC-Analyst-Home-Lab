# 06 - Incident Response Case Study: LSASS Credential Dumping (T1003.001)

> **About this document.** This is a worked incident response case study for the
> SOC Analyst Home Lab. It walks a single detection — LSASS process memory
> access — through the full analyst workflow: alert, triage, investigation,
> scoping, containment, eradication, recovery, and lessons learned.
>
> Sections marked **`[LAB EVIDENCE]`** are placeholders for screenshots or log
> excerpts you capture when you run the attack in your own lab (see
> [05 - Attack Simulation](05-Attack-Simulation.md)). The narrative, queries,
> and analyst reasoning are real and reusable; the specific timestamps,
> hostnames, and account names shown in examples are illustrative and should be
> replaced with your lab's actual values.

---

## 1. Executive Summary

| Field | Value |
|-------|-------|
| Case ID | IR-2026-001 |
| Detection | LSASS Memory Access — Credential Dumping |
| MITRE ATT&CK | [T1003.001 — OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/) |
| Severity | Critical |
| Status | Closed — Contained & Eradicated |
| Affected host | `WIN10-PC` (10.0.1.10) |
| Detection source | Sysmon Event ID 10 (ProcessAccess), via Splunk |
| Analyst | RosiCastellano |

**One-paragraph summary.** A Sysmon ProcessAccess alert fired indicating a
non-system process opened a handle to `lsass.exe` with access rights consistent
with memory reads. Investigation showed the source process was a renamed
credential-dumping tool launched from a user-writable directory by an account
that had recently authenticated from an unusual source. The activity was scoped
to a single workstation, no lateral movement was observed, the host was isolated,
the malicious binary and its persistence removed, and affected credentials were
rotated. Root cause was an initial-access foothold via a successful brute force
(see related case IR-2026-000, T1110).

---

## 2. Detection

### 2.1 The alert that fired

The detection comes from the repository's credential-dumping rule
(`detection-rules/splunk-queries/credential-dumping.spl` and the Sigma rule
`detection-rules/sigma-rules/windows-credential-access.yml`). The triggering
Splunk search:

```spl
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
| where NOT match(SourceImage, "(?i)(MsMpEng|csrss|wininit|services|svchost)")
| eval alert_severity="critical"
| eval attack_technique="T1003.001 - LSASS Memory"
| table _time, Computer, SourceImage, SourceUser, GrantedAccess, CallTrace
```

The field that makes this high-fidelity is `GrantedAccess`. Credential dumping
tools typically request `0x1010` or `0x1410` (PROCESS_VM_READ |
PROCESS_QUERY_LIMITED_INFORMATION). Legitimate access by AV/EDR usually looks
different and originates from known signed binaries — which is why the rule
filters known system source images rather than relying on the access mask alone.

**`[LAB EVIDENCE]`** *Screenshot: the Splunk alert in the Activity → Triggered
Alerts view, showing the event count and the populated `SourceImage` /
`GrantedAccess` fields. Replace this line with your screenshot.*

### 2.2 Why this is not a false positive

Before escalating, the analyst rules out the common benign causes. This is the
triage decision that separates a real incident from noise:

| Benign cause | Ruled out because |
|--------------|-------------------|
| Antivirus / Defender scanning LSASS | `SourceImage` is not `MsMpEng.exe` / `MpCmdRun.exe`; the rule's AV filter did not match |
| Backup or EDR agent | `SourceImage` path is a user directory, not `Program Files`; binary is unsigned |
| Legitimate admin tooling (e.g. Process Explorer run as admin) | No corresponding change ticket; `SourceUser` is a standard user, not an admin performing planned work |
| Windows internal process | Source is not `wininit`, `csrss`, `services`, or `svchost` |

When none of the benign explanations hold, the alert is promoted to an incident.

---

## 3. Triage

### 3.1 Initial questions

The analyst answers four questions before going deeper:

1. **What process touched LSASS?** — the `SourceImage` value.
2. **Who ran it?** — the `SourceUser` value.
3. **When did it happen, and is it ongoing?** — `_time`, and whether new events
   are still arriving.
4. **Is this host the only one affected?** — pivot the same search across all
   hosts.

### 3.2 Pivot: is it isolated to one host?

```spl
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
| where NOT match(SourceImage, "(?i)(MsMpEng|csrss|wininit|services|svchost)")
| stats count, values(SourceImage) as tools, min(_time) as first_seen,
        max(_time) as last_seen by Computer, SourceUser
| sort - count
```

**`[LAB EVIDENCE]`** *Screenshot or table: output of this pivot. In the lab
walkthrough this should show a single `Computer` row, establishing the blast
radius as one workstation. Replace with your result.*

### 3.3 Triage decision

At the end of triage the analyst records a clear, defensible call:

> **Decision:** Confirmed true positive. Single host (`WIN10-PC`). A non-system
> process accessed LSASS memory with read rights. Escalating to full
> investigation and beginning containment in parallel because credential theft
> is time-sensitive — any delay increases the chance harvested credentials are
> used for lateral movement.

Containment running *in parallel* with investigation (not after it) is the
correct posture for credential-access incidents. You do not finish a leisurely
investigation while an attacker uses stolen hashes.

---

## 4. Investigation

### 4.1 What was the source process?

Pull the full process-creation record for the `SourceImage` using Sysmon Event
ID 1, joined on the image path:

```spl
index=sysmon EventCode=1 Image="C:\\Users\\*\\AppData\\*"
| table _time, Computer, User, Image, OriginalFileName, CommandLine,
        ParentImage, ParentCommandLine, Hashes, Signed
```

Key things the analyst looks for, and what each tells you:

- **`OriginalFileName` vs `Image`** — if the file on disk is `svchost.exe` but
  the PE's `OriginalFileName` is `procdump` or `mimikatz`, that is a renamed
  tool. This single mismatch is often the strongest indicator.
- **`CommandLine`** — arguments like `sekurlsa::logonpasswords`, `-ma lsass.exe`,
  or `comsvcs.dll MiniDump` are unambiguous.
- **`ParentImage`** — what launched it? `powershell.exe`, `cmd.exe`, or an
  Office app as parent tells you the delivery path.
- **`Signed` / `Hashes`** — unsigned binary in a user directory is suspicious on
  its own; the hash is your pivot into threat intel and the IOC list.

**`[LAB EVIDENCE]`** *Log excerpt: the Event ID 1 record for the malicious
process. Redact nothing — this is a lab. Replace this line.*

### 4.2 How did it get there? (Working backward)

Walk the parent chain and file-creation events to reconstruct delivery:

```spl
index=sysmon (EventCode=1 OR EventCode=11) Computer="WIN10-PC"
| transaction ProcessGuid maxspan=10m
| table _time, EventCode, Image, ParentImage, CommandLine, TargetFilename
```

A typical reconstructed chain for this technique:

```
4624 logon (Type 3, unusual source IP)
   └─ explorer.exe
        └─ powershell.exe  -enc <base64>           (Sysmon EID 1)
             └─ <dropped>.exe written to \AppData\  (Sysmon EID 11)
                  └─ <dropped>.exe  → opens handle to lsass.exe (Sysmon EID 10)  ← ALERT
```

### 4.3 Correlate with authentication

Credential dumping rarely starts the kill chain — something granted the
attacker code execution first. Pivot to the authentication logs around the
event window:

```spl
index=windows sourcetype="WinEventLog:Security" (EventCode=4624 OR EventCode=4625)
  Computer="WIN10-PC"
| eval src_ip=coalesce(src_ip, IpAddress, Source_Network_Address)
| where isnotnull(src_ip) AND src_ip!="-" AND src_ip!="127.0.0.1"
| stats count by EventCode, user, src_ip, Logon_Type
| sort - count
```

**`[LAB EVIDENCE]`** *Result: in the lab scenario this links the compromise to a
burst of 4625 failures followed by a 4624 success from an attacker-controlled IP
— i.e. the initial access was a brute force (T1110). Replace with your output.*

This is the moment the case stops being "a tool touched LSASS" and becomes a
coherent story: **brute force → execution → credential access**, all on one host.

### 4.4 Timeline

| Time (lab-relative) | Event | Source | ATT&CK |
|---------------------|-------|--------|--------|
| T-0:00 | Burst of failed logons (4625) from external IP | Security 4625 | T1110 |
| T+0:02 | Successful logon (4624, Type 3) same IP | Security 4624 | T1078 |
| T+0:05 | Encoded PowerShell spawned | Sysmon 1 | T1059.001 |
| T+0:06 | Payload written to `\AppData\` | Sysmon 11 | T1105 |
| T+0:07 | Payload opens handle to `lsass.exe` | Sysmon 10 | **T1003.001** |
| T+0:07 | **Detection fires** | Splunk alert | — |

**`[LAB EVIDENCE]`** *Replace the relative times with the real timestamps from
your lab run so the timeline is concrete.*

---

## 5. Scoping

The goal of scoping is a defensible answer to "how bad is this?" The analyst
checks each direction an attacker could have gone:

- **Other hosts running the same tool?** — re-run the §3.2 pivot fleet-wide.
  *Lab result: none. Blast radius = 1 host.*
- **Lateral movement from this host?** — look for outbound RDP/SMB/WMI:
  ```spl
  index=sysmon EventCode=3 Computer="WIN10-PC"
  | where dest_port IN (445, 3389, 5985, 135)
  | stats count by dest_ip, dest_port
  ```
  *Lab result: no anomalous outbound admin-protocol connections.*
- **What credentials were exposed?** — any account with a session on
  `WIN10-PC` at T+0:07 must be considered compromised. At minimum: the logged-on
  user and any cached domain credentials. If a domain admin had ever logged in
  interactively, escalate scope to the domain.
- **Persistence established?** — check Run keys, scheduled tasks, services
  (the repo's `windows-persistence.yml` rules):
  ```spl
  index=sysmon (EventCode=13 OR EventCode=1) Computer="WIN10-PC"
  | regex TargetObject="(?i)CurrentVersion\\\\Run" OR CommandLine="(?i)schtasks.*/create"
  ```

**Scoping conclusion (lab scenario):** One workstation, one user account
compromised, local credentials exposed, one persistence mechanism (Run key), no
lateral movement, no domain-admin exposure.

---

## 6. Containment, Eradication, Recovery

### 6.1 Containment (immediate)

1. **Network isolate `WIN10-PC`** — host-based firewall block or switch port
   disable. Preserve the machine powered-on; do not pull power (loses volatile
   memory that may be needed for forensics).
2. **Disable the compromised user account** in AD and kill active sessions.
3. **Block the attacker source IP** at the firewall (pfSense) — this also helps
   confirm no second channel exists.

### 6.2 Eradication

1. Remove the persistence mechanism (the Run key identified in §5).
2. Remove the dropped payload from `\AppData\`.
3. Confirm no additional payloads via a full Sysmon EID 1/11 review for the host.
4. Given credential theft occurred, the defensible action is to **reimage** the
   host rather than clean-in-place — you cannot fully trust a box where LSASS
   was read.

### 6.3 Recovery

1. **Rotate every credential exposed on that host**: the user's password, any
   local admin password, and — because LSASS may have held cached domain
   creds — force-reset and monitor those accounts.
2. Rebuild `WIN10-PC` from a known-good image; re-enroll Sysmon and the
   forwarder.
3. Restore the user account with a new password and (ideally) require MFA.
4. Monitor the rotated accounts and the attacker IOC hash/IP for 30 days for
   re-use.

---

## 7. Root Cause & Lessons Learned

**Root cause.** Initial access was a successful brute force against an
internet-reachable RDP/SMB service on `WIN10-PC` (T1110), enabled by a weak
password and no account-lockout/MFA. Credential dumping was a follow-on action,
not the entry point.

**What the detection did well.** The Sysmon EID 10 rule with the system-image
filter caught the credential-access step with high fidelity and low noise — the
`GrantedAccess` + non-system `SourceImage` combination is a strong signal.

**Gaps this incident exposed:**

| Gap | Recommended improvement |
|-----|-------------------------|
| Brute force was detected only retroactively, during IR | Promote the T1110 rule to a real-time alert with account-lockout enrichment |
| LSASS was readable by a non-protected process | Enable **LSA Protection (RunAsPPL)** and Credential Guard on workstations |
| Renamed-binary detection was manual | Add a detection on `OriginalFileName` ≠ `Image` for known tool names |
| No MFA on the exposed service | Require MFA; remove internet exposure of RDP/SMB |

**Detection engineering follow-up.** Add a correlation rule that links a
T1110 success to any T1003 event on the same host within N minutes and raises a
single high-severity, kill-chain-aware alert rather than two disconnected ones.
This is the difference between "two alerts an analyst must mentally join" and
"one alert that tells the story."

---

## 8. IOCs

| Type | Value | Notes |
|------|-------|-------|
| Host | `WIN10-PC` / 10.0.1.10 | Affected workstation |
| Account | *(lab user)* | Compromised, rotated |
| File hash | **`[LAB EVIDENCE]`** SHA256 of dropped payload | Pivot for fleet sweep |
| IP | *(attacker IP)* | Blocked at perimeter |
| Registry | `HKCU\...\CurrentVersion\Run\<value>` | Persistence, removed |

---

## 9. Appendix: Mapping to Repository Detections

This case exercises detections already in the repo, which is the point of the
lab — the IR narrative and the detection content reinforce each other:

| Phase | Repo detection |
|-------|----------------|
| Initial access (T1110) | `splunk-queries/authentication-attacks.spl` |
| Execution (T1059.001) | `splunk-queries/powershell-suspicious.spl` |
| Credential access (T1003.001) | `splunk-queries/credential-dumping.spl`, `sigma-rules/windows-credential-access.yml` |
| Persistence (T1547.001) | `sigma-rules/windows-persistence.yml` |

---

*Prepared for the SOC Analyst Home Lab. Replace all `[LAB EVIDENCE]` placeholders
with artifacts from your own lab run before presenting this as completed work.*
