# Incident Case Study — Nancy / Amatera Stealer Infection (2026-08-25)

> **Real incident. Real evidence. Actually happened to me.**
>
> This is not a lab simulation — it is a genuine infostealer compromise with full evidence preserved: Defender DetectionHistory records, scheduled task persistence export, SHA256 payload manifest, chain-of-custody log, and blockchain time-travel proof of C2 rotation.
>
> This case study demonstrates the full IR lifecycle on a real system: delivery chain reconstruction, persistence identification, evidence collection with provenance, eradication, and the investigative techniques used to recover a C2 that never wrote its plaintext to disk — including EtherHiding over Binance Smart Chain.

---

## Incident at a glance

| Attribute | Detail |
|-----------|--------|
| Date of infection | 2026-08-23 ~23:00 SAST |
| Date of eradication | 2026-08-25 ~22:05 SAST |
| Incident type | Infostealer (Amatera / ACR) + loader chain (RenPy/PavinLoader → Wacatac → MSBuild LOLBIN) |
| Delivery vector | Fake "SamFw FRP Tool v5.5.1 Setup" from `frptoolsdownload.com` via `*.kaqwmm.cyou` redirect gate |
| Persistence | Scheduled task `\\UpdateService` (logon trigger) — deleted |
| C2 mechanism | EtherHiding — JSON-RPC `eth_call` to BSC contract `0x328a1fadff154290f0ce1389a4e633698cdfdaa7` selector `0x06fdde03` |
| C2 rotation | Proven via blockchain archive — 4 distinct 54-byte encrypted blobs across 4 blocks |
| Exposed data | Edge browser vault (36 credentials across 32 sites), Firefox vaults (23 logins), all browser cookies/sessions, Discord token, Google OAuth client_secret, autofill data |
| Defender detections | SuspRenpiExecProc.A x2, Wacatac.H!ml MSI, SuspEtherRpcConn.C |
| Status | Chain killed, task removed, payload shredded. Credentials rotated. |

**Why this matters for the portfolio:**
- Real incident response on a live system — not a CTF or lab simulation.
- Full evidence chain with provenance (EVIDENCE_LOG.md documents who collected what, when, and how).
- Advanced C2 recovery technique — EtherHiding via BSC, reconstructed using blockchain archive nodes at specific block heights.
- Complete delivery chain recovered down to the terminal payload URL — decoded from the gate's own base64 JSON response.
- Campaign correlation — this incident's tooling links to Malwarebytes' published July 2026 RenPy/PavinLoader campaign.

---

## Section contents

| File | Purpose |
|------|---------|
| `VICTIM_REPORT.md` | Main narrative — infection timeline, delivery chain, impact, evidence index, investigative value, requested actions |
| `IOCs.md` | Full indicator dossier — delivery chain, persistence, payload hashes, C2 infrastructure, blockchain block numbers, third-party analysis links |
| `EVIDENCE_LOG.md` | Provenance and chain of custody for each artifact — how, when, and by whom each piece of evidence was collected |
| `sha256_manifest.txt` | SHA256 hashes of all 8 payload files recovered from `%LOCALAPPDATA%\Microsoft\Windows\Caches\Nancy\` |
| `UpdateService_task.xml` | Full XML export of the scheduled task `\\UpdateService` — persistence mechanism |
| `detection_history/*.bin` | 5 raw Microsoft Defender DetectionHistory records (3 from Aug 25 re-detections, 1 from Aug 10, 1 unrelated) |
| `nancy_amatera_detection_rules.yml` | 5 Sigma rules for Nancy/Amatera detection (EtherHiding C2, MSBuild LOLBIN, scheduled task persistence, BAT stager, WPA.exe payload) |
| `nancy_amatera_ioc_scanner.py` | Python IOC scanner — checks scheduled tasks, files, registry, event logs, known hashes, C2 indicators |

---

## Delivery chain — fully recovered

The infection began with a fake "SamFw FRP Tool v5.5.1 Setup" downloaded from a malicious distribution chain. The full URL chain was recovered from Firefox `places.sqlite`:

```
frptoolsdownload.com/samfw-tool/
  → redirect gate on link-file-nu623.kaqwmm.cyou
  → checking-id-8scp.kaqwmm.cyou
  → access-id-8scp.kaqwmm.cyou
  → cloud-file-4xzl.kaqwmm.cyou ("NextShare" landing page)
  → final payload server:
    https://d8baab0c37a0454d6f22ad4c.192169482.com/
      675ab055f00e5d1087ae481e21d24a
```

**Campaign identifiers decoded from the gate's base64 JSON response:**
- `"id":"nu623"`
- `"tag":"6bnS3H2T:C1"`

**Terminal payload URL decoded from the gate's `"redirect"` field** — this is the actual executable that was executed. Neither this host nor the `.kaqwmm.cyou` infrastructure appears in any published IOC set as of 2026-08-25.

**Infrastructure status at time of report (2026-08-25 ~23:00 SAST):**
- Final payload host `d8baab0c37a0454d6f22ad4c.192169482.com` — LIVE behind Cloudflare (proxies: 172.67.208.123, 104.21.93.90)
- `frptoolsdownload.com` — LIVE behind Cloudflare (proxies: 104.21.76.40, 172.67.186.155)

---

## Execution chain — RenPy/PavinLoader → MSBuild LOLBIN

The installer (`Setup.exe`) delivered Trojan:Script/Wacatac.H!ml (MSI in `%TEMP%`) which deployed a multi-stage loader:

1. **Hidden BAT** (`sync_afc1.cmd`) — initial stager
2. **Headless conhost relaunch** — stealthy execution
3. **MSBuild LOLBIN execution** — `MSBUILDENABLEALLPROPERTYFUNCTIONS=1` enabled, executing trojanized `Nancy.csproj` project files

This is a documented technique — abusing MSBuild as a LOLBIN (Living Off the Land Binary) to execute malicious code while appearing as a legitimate build process. Defender's `SuspRenpiExecProc.A` detection captures exactly this: suspicious MSBuild execution of RenPy-related project files.

**MSBuild process details from Defender DetectionHistory:**
- PID 16332 — `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe` — Behavior: Win32/SuspEtherRpcConn.C (EtherHiding beacon)
- PID 10764 — same MSBuild path — Behavior: Win32/SuspRenpiExecProc.A (RenPy execution)
- PID 23796 — same MSBuild path — Behavior: Win32/SuspRenpiExecProc.A (re-detection)

All running as `NT AUTHORITY\SYSTEM`.

---

## Persistence — scheduled task `\\UpdateService`

The malware persisted via a scheduled task that re-executed the chain at every logon:

```xml
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <URI>\UpdateService</URI>
  <Triggers>
    <LogonTrigger>
      <UserId>SALVADOR\chees</UserId>
    </LogonTrigger>
  </Triggers>
  <Actions Context="Author">
    <Exec>
      <Command>C:\WINDOWS\system32\cmd.exe</Command>
      <Arguments>/c "C:\Users\chees.SALVADOR\AppData\Local\Microsoft\Windows\Caches\Nancy\sync_afc1.cmd"</Arguments>
    </Exec>
  </Actions>
  <Settings>
    <Hidden>true</Hidden>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    ...
  </Settings>
</Task>
```

**Persistence characteristics:**
- Hidden task — not visible in standard Task Scheduler view without configuration change
- Logon trigger — re-executes every time the user logs in
- No execution time limit (`PT0S`) — runs to completion regardless of duration
- Executes the hidden BAT stager from the Nancy cache directory

**Evidence of active persistence (Aug 25):**
- 2026-08-25 11:32-11:34 — UpdateService fired; MSBuild PID 18084 resident for 10 hours
- 11:33:26 — `csc.exe` compile confirms active stage rebuild (the malware recompiles its stage on each trigger)

---

## C2 — EtherHiding over Binance Smart Chain

This is the most technically interesting aspect of the incident. The malware's C2 does not use a static domain or IP — it uses **EtherHiding**: storing the C2 data on-chain via a Binance Smart Chain smart contract, retrieved by the malware through JSON-RPC `eth_call`.

**C2 retrieval:**
```
JSON-RPC eth_call → bsc-dataseed.binance.org
  Contract: 0x328a1fadff154290f0ce1389a4e633698cdfdaa7
  Selector: 0x06fdde03
  Returns: 54-byte encrypted blob (per-session C2 data)
```

**The key investigative breakthrough — blockchain time-travel:**
The C2 blob is freshly encrypted per session and never persists in plaintext. To prove C2 rotation and reconstruct what the malware retrieved at specific times, I used a BSC archive node to read the contract's state at historical block heights:

| Block | Timestamp (approx) | Event | Blob |
|-------|-------------------|-------|------|
| 117684888 | Aug 23 23:05 SAST | Infection beacon (first C2 retrieval) | 54B cipher blob #1 |
| ~117784311 | Aug 24 (logon) | Second C2 retrieval | 54B DIFFERENT blob |
| ~117976228 | Aug 25 (logon) | Third C2 retrieval | 54B DIFFERENT blob |
| Latest (Aug 25 night) | Aug 25 night | Most recent retrieval | 54B yet another blob |

**Conclusion from blockchain evidence:**
The contract serves a **different 54-byte encrypted value at each block height** queried. This proves:
1. The C2 is genuinely rotating per session (not a static value).
2. The plaintext C2 domain is never written to disk — it exists only in memory during the session.
3. The encryption is at minimum RC4/AES-class, resistant to single-byte XOR and known-family XOR key crib-sliding (tested against `https://`, `http://`, TLD cribs).

**To recover the exact per-session C2 hostname**, one would need to:
1. Reverse a sample (VT MD5: `810F257542018BE0FC62AF542D13D012` or `29203ca123d51b1b33505a0813d360df`)
2. Extract the in-memory-only decryption key from the GollopDevest stage
3. Replay `eth_call` at the saved block numbers with the recovered key

This makes the incident evidence valuable for researchers who reverse the family — the block numbers and contract address are preserved to allow future decoding.

---

## C2 infrastructure — published campaign

The Amatera stealer family uses a distributed C2 and distribution infrastructure. Published by Malwarebytes (Jul-Aug 2026):

**Stealer C2:**
- `login.orbitalframework.cc` (Amatera C2, July wave)

**PavinLoader pool (August wave):**
- `catalyst-pro.lat`, `twigoamwu.cfd`, `trusaifi.cfd`, `stellar-minds.cfd`, `pinnacle-labs.lat`, `nexahub.lat`, `fimwoglea.shop`, `velodium.lat`, `rpcsecnoweb.pro`, `more-arpc.icu`, `echo-systems.cfd`, `kelemet.shop`

**Payload delivery IPs:**
- `144.124.251.171`, `195.63.140.33`, `78.40.196.252`
- `93.152.224.75`, `65.21.80.170`, `195.63.142.49`

**Distribution (fake download sites):**
- `downpro.net`, `macisofile.sbs`, `visitmama.blog`, `visitmama.guru`, `getgamerfree.com`, `fullgames.digital`, `flingbase.net`, `citronemu.com`

**Additional infrastructure:**
- `filemodo.xyz`, `storage06x.cfd`, `p03sil.cyou`, `wimsedas.xyz`, `againstmor.store`, `host03q.cfd`, `cloud01y.cfd`, `storage11x.cfd`, `storage04x.cfd`, `host82p.cfd`, `cloud05y.cfd`, `analyticstrack-pzh.click`

**This incident's own source:**
- `frptoolsdownload.com` + `*.kaqwmm.cyou` — not published in any IOC set as of 2026-08-25

---

## Impact — what was exfiltrated

The Amatera stealer harvests browser data, session tokens, and autofill secrets. Based on the stealer family's known behavior and the verified presence of all targeted data stores on this machine, exfiltration is assessed as **COMPLETED** for each successful execution window.

| Data category | Status | Detail |
|---------------|--------|--------|
| Edge browser vault | Exposed | 36 saved credentials across 32 sites, including financial institutions and trading platforms |
| Firefox vaults (2 profiles) | Exposed | 23 saved logins total |
| Browser cookies/sessions | Exposed | Edge, Firefox, Chrome profiles present — session hijacking possible |
| Discord local token | Exposed | Discord token storage accessible to stealer |
| Autofill data | Exposed | Edge Web Data autofill |
| Google OAuth client_secret | Exposed | Present in Downloads — could be used for OAuth token theft |
| Service token file | Exposed | `f13_token.txt` in Downloads |
| auth.json keys | Exposed | API keys in `auth.json` |
| Cryptocurrency wallets | Not installed | No wallet software present — no direct wallet loss |

**All affected credentials have been rotated post-remediation.**

---

## Evidence — collection and provenance

All evidence was collected on 2026-08-25 between 21:45 and 22:30 SAST by the reporter with live system access. See `EVIDENCE_LOG.md` for full provenance.

### 1. SHA256 manifest (`sha256_manifest.txt`)

SHA256 hashes of all 8 files found in `%LOCALAPPDATA%\Microsoft\Windows\Caches\Nancy\` — a hidden, read-only directory with timestomped files (uniform timestamp 2021-11-23 23:04:53).

| SHA256 | Filename | Size |
|--------|----------|------|
| 905ECF0E9F...37CF | cache_21ebfd.dat | 66 bytes |
| 6E955E70F7...90707D | Nancy.Compile.targets | 1,058,695 bytes |
| 2213EA8392...D701B | Nancy.csproj | 9,762,294 bytes |
| 8195BE8C73...7CDE | Nancy.csproj.user | 407,398 bytes |
| BA5D127EDE...C6E83 | Nancy.Internal.props | 383,944 bytes |
| 5DAB708323...2B1CF | runtime_4133.dat | 188 bytes |
| F025A3E26C...46023 | runtime_bda1.tmp | 247 bytes |
| F6C2597371...5224DC | sync_afc1.cmd | 1,520 bytes |

The payload files were **shredded** (3-pass random overwrite) after hashing. The originals are not retained — the hashes are sufficient for family/sample correlation, and identical-family samples are obtainable via published MD5s from Malwarebytes' 2026-07-20 report.

### 2. Scheduled task export (`UpdateService_task.xml`)

Full XML export of `\\UpdateService` captured **before** eradication via `Export-ScheduledTask`. The task was then removed with `Unregister-ScheduledTask`.

### 3. Defender DetectionHistory records (`detection_history/*.bin`)

5 raw DetectionHistory records copied byte-for-byte from `C:\ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory\`.

**Aug 25 re-detections (4 records, 21:28):**
| File ID | Behavior | Process | Detail |
|---------|----------|---------|--------|
| `6413895B...` | Win32/SuspEtherRpcConn.C | `MSBuild.exe` PID 16332 | EtherHiding beacon — 64-bit MSBuild |
| `7C9D1FDB...` | Win32/SuspRenpiExecProc.A | `MSBuild.exe` PID 10764 | RenPy execution — 32-bit MSBuild |
| `C73B7AE2...` | Backdoor:PHP/P_hatetshell.A!dh | File: `D:\workspace\My skills\Bug orchestra\Phase` | PHP backdoor (unrelated — pentest content) |
| `E46DA0BC...` | Win32/SuspRenpiExecProc.A | `MSBuild.exe` PID 23796 | RenPy execution — re-detection |

**Aug 10 (1 record):**
| File ID | Behavior | Detail |
|---------|----------|--------|
| `D6484B7B...` | Trojan:Script/Wacatac.H!ml | File: `C:\Users\chees.SALVADOR\AppData\Local\Temp\3te9lj...` — Wacatac MSI path from initial infection |

The Aug 10 record is from the initial infection event — the Wacatac MSI that deployed the loader chain. It confirms the initial dropper.

### 4. Gate JSON decode (Firefox `places.sqlite`)

The full redirect chain was recovered by reading the Firefox `places.sqlite` database from the active profile and decoding the base64 `data=` parameters in the visited URLs. This is a read-only copy — the original evidence database remains intact on the system.

---

## Investigative value — why this incident matters beyond personal impact

1. **Complete delivery chain recovered, including terminal payload URL** — `d8baab0c37a0454d6f22ad4c.192169482.com/675ab055f00e5d1087ae481e21d24a`. Neither this host nor the `.kaqwmm.cyou` infrastructure appears in any published IOC set. The campaign identifiers (`nu623`, `6bnS3H2T:C1`) allow correlation of every other victim funneled through this same operation.

2. **Live infrastructure at report time** — both the final payload host and `frptoolsdownload.com` were still resolving via Cloudflare on 2026-08-25. Registrar/host abuse action within days may preserve evidence before rotation.

3. **Blockchain time-travel evidence** — archive-node reads of contract `0x328a1fadff154290f0ce1389a4e633698cdfdaa7` at blocks 117684888, ~117784311, ~117976228 show **four distinct 54-byte encrypted values**, proving per-session C2 rotation. Block numbers are preserved to allow key-holders (researchers who reverse the GollopDevest stage) to decode exact hostnames used by this victim's sessions.

4. **Payload file hashes link to published campaign** — the tooling patterns match Malwarebytes' July 2026 RenPy/PavinLoader campaign set (family MD5s published in their report match this incident's tooling).

5. **System logs intact** — no event log clearing observed (Security oldest record 2026-08-20; System 2026-06-02; zero Event ID 1102/104 occurrences). Attacker anti-forensics limited to payload-file timestomping and temp cleanup. The System log is unbroken since 2026-06-02.

---

## ATT&CK mapping — this incident

| Phase | Technique | Sub-technique | Evidence in this incident |
|-------|-----------|---------------|--------------------------|
| Initial Access | T1566 | T1566.001 — Phishing: Spearphishing Link | Fake FRP tool download via malicious gate — user clicked link to fake download site |
| Execution | T1204 | T1204.002 — User Execution: Malicious File | User executed `Setup.exe` (D:\ and C:\) |
| Defense Evasion | T1562 | T1562.001 — Disable or Modify Tools | Firewall packet logging configured but never written; DNS Client operational logging disabled |
| Defense Evasion | T1027 | T1027 — Obfuscated Files or Information | Encoded C2 blobs on BSC; timestomped payload files |
| Execution | T1059 | T1059.003 — Windows Command Shell | `cmd.exe /c` executing `sync_afc1.cmd` from scheduled task |
| Execution | T1559 | T1559.003 — MSBuild | MSBuild LOLBIN executing trojanized `.csproj` files with `MSBUILDENABLEALLPROPERTYFUNCTIONS=1` |
| Persistence | T1053 | T1053.005 — Scheduled Task/Job | `\\UpdateService` scheduled task — logon trigger, hidden |
| Persistence | T1547 | T1547.001 — Registry Run Keys / Startup Folder | Payload cache directory at `%LOCALAPPDATA%\Microsoft\Windows\Caches\Nancy` |
| Credential Access | T1555 | T1555.003 — Credentials from Password Stores | Browser password vaults (Edge, Firefox) exfiltrated |
| Credential Access | T1555 | T1555.004 — Keylogging (potential) | Infostealer family behavior — keylogging capability in some builds |
| Collection | T1555 | T1555.003 — Credentials from Password Stores | 36 Edge credentials, 23 Firefox logins, cookies, autofill, Discord token |
| Exfiltration | T1567 | T1567 — Exfiltration Over Web Service | POST to C2 over HTTPS with custom headers (X-Timestamp, X-Nonce, X-Signature HMAC) |
| Command and Control | T1071 | T1071.001 — Web Protocols | HTTPS C2 communication |
| Command and Control | T1102 | T1102.002 — Web Service (Blockchain) | EtherHiding — C2 data stored on BSC smart contract, retrieved via JSON-RPC |
| Command and Control | T1573 | T1573.002 — Asymmetric Cryptography (potential) | Encrypted blobs resistant to XOR crib-sliding — suggests AES/RC4 with embedded key |

---

## Remediation — what was done

| Step | Action | Time |
|------|--------|------|
| 1 | Identified infection via Defender alerts and suspicious scheduled task | Aug 25 ~21:45 |
| 2 | Collected all evidence (SHA256 manifest, task XML, DetectionHistory, gate JSON decode) | Aug 25 21:45-22:30 |
| 3 | Killed active processes (MSBuild, conhost, csc) | Aug 25 ~22:05 |
| 4 | Deleted scheduled task `\\UpdateService` | Aug 25 ~22:05 |
| 5 | Shredded payload directory (`%LOCALAPPDATA%\Microsoft\Windows\Caches\Nancy`) — 3-pass random overwrite | Aug 25 ~22:05 |
| 6 | Ran full Defender scan to confirm no remaining detections | Aug 25 ~22:15 |
| 7 | Rotated all exposed credentials (browser passwords, Discord, Google OAuth, service tokens, auth.json keys) | Aug 25-26 |
| 8 | Compiled incident report and IOC package | Aug 25-26 |

---

## Screenshots / evidence images

The detection_history `*.bin` files are raw Defender records in a binary format. To include visual evidence in the portfolio, I should generate readable representations:

- **Defender alert screenshot** — capture from Windows Security / Defender showing the detections (SuspRenpiExecProc.A, Wacatac.H!ml, SuspEtherRpcConn.C) with timestamps.
- **Scheduled task screenshot** — Task Scheduler showing the `\\UpdateService` task (hidden task, logon trigger).
- **EtherHiding C2 proof** — a diagram or screenshot showing the blockchain block query and the 4 distinct blobs retrieved at different block heights.
- **BSC archive node query** — terminal output showing the `eth_call` to the archive node returning different blobs at different blocks.

Currently these are represented by:
- The raw `*.bin` files (with decoded content in the case study README)
- The `VICTIM_REPORT.md` and `IOCs.md` narrative
- Placeholder generated images would need to be replaced with real captures

---

## Submission and abuse actions taken / recommended

**Where this incident was / should be reported:**

1. **IC3 (FBI)** — `ic3.gov` — file a complaint with the victim report narrative
2. **Microsoft Digital Crimes Unit** — `microsoft.com/en-us/security/report-a-issue` — emphasize the EtherHiding C2 contract address and block numbers; DCU has reverse-engineering capacity for the rotation keys
3. **Malwarebytes** — contact from their 2026-07-20 RenPy blog / submissions email — lead with the unpublished `.kaqwmm.cyou` chain + LIVE final payload URL + gate campaign tags (`nu623`, `6bnS3H2T:C1`)
4. **South Africa — Hawks (SAPS Serious Commercial Crime) + bank fraud line** — crime victim with financial-credential exposure; open a case reference number

**Infrastructure abuse (fast-impact, 10 minutes):**
- Cloudflare abuse: `abuse.cloudflare.com` — phishing/malware for `frptoolsdownload.com`, `*.kaqwmm.cyou`, `d8baab0c37a0454d6f22ad4c.192169482.com`
- Registrar WHOIS abuse contact for `192169482.com` and `kaqwmm.cyou`
- Google Safe Browsing report: `safebrowsing.google.com/safebrowsing/report_badware/`

**Preservation reminders:**
- Do not clear Firefox history/profiles (original evidence DB lives there)
- Do not reinstall Windows or wipe `%TEMP%` remnants beyond what eradication already did
- Keep Defender history intact
- Store one zip copy off-machine (cloud drive OK)

---

## Why this strengthens the portfolio

| What most portfolios have | What this case study adds |
|--------------------------|--------------------------|
| CTF write-ups and lab simulations | **Real incident** — actually happened, actually impacted a real person |
| Simulated malware in a sandbox | **Real malware** on a real system — Defender caught it, real persistence, real C2 |
| IOC lists from threat intel feeds | **Personally collected IOCs** — delivery chain reconstructed from browser history, C2 recovered via blockchain time-travel, payload hashed and shredded |
| Generic IR playbook | **Actual IR performed** — evidence collected with provenance, eradication executed, credentials rotated |
| Standard C2 (domain/IP) | **Advanced C2 (EtherHiding over BSC)** — blockchain-based, per-session rotation, recovered via archive nodes at specific block heights |
| Attacker perspective (red team) | **Defender + investigator perspective** — how to investigate when you're the victim, what logs exist, what doesn't, how to recover what the attacker tried to hide |

This is not a simulation. It is a real compromise with real evidence. Including it demonstrates that I can investigate an actual incident end-to-end — from delivery chain reconstruction through C2 recovery to eradication and credential rotation — and that I understand both the attacker techniques (EtherHiding, LOLBIN MSBuild, scheduled task persistence, DoH + raw sockets for C2 hiding) and the defensive/investigative response.

---

## Next steps

- [ ] Capture real screenshots: Defender alert history, Task Scheduler hidden task, BSC archive node query output
- [ ] Generate a diagram of the delivery chain and C2 architecture (payload → loader → MSBuild → EtherHiding → BSC)
- [ ] Generate a timeline visualization from the evidence log (Aug 20 browsing → Aug 23 infection → Aug 25 eradication)
- [ ] Add the detection_history `*.bin` files as evidence artifacts with decoded content summaries
- [ ] Replace placeholder images with real captures
- [ ] Consider publishing the IOC package to Malwarebytes (extend their published IOC set with unpublished `.kaqwmm.cyou` chain and LIVE payload URL)
