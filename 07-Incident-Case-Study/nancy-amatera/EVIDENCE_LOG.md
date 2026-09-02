# EVIDENCE LOG — Provenance & Chain of Custody

Machine: Windows 11 workstation (single user-admin). Timezone: South Africa Standard Time (UTC+2).
All timestamps below are machine-local unless noted. Evidence collected 2026-08-25 between
21:45 and 22:30 SAST by the reporter with live system access, using read-only queries except
where noted (malware eradication actions flagged).

## Artifacts

### 5. Gate JSON decode (added 2026-08-25 ~23:00 SAST)
- Content: full redirect-chain URLs from Firefox `places.sqlite` (active profile), with
  base64 `data=` parameters decoded:
  - gate campaign fields: `"id":"nu623"`, `"tag":"6bnS3H2T:C1"`
  - terminal `"redirect"` value:
    `https://d8baab0c37a0454d6f22ad4c.192169482.com/675ab055f00e5d1087ae481e21d24a`
    serving "SamFw FRP Tool v5.5.1 Setup"
- Capture: read-only sqlite copy of places.sqlite; base64 decode of URL parameters.
- Liveness check 2026-08-25 ~23:00 SAST: final host resolving via Cloudflare
  (172.67.208.123, 104.21.93.90); frptoolsdownload.com also live
  (104.21.76.40, 172.67.186.155). No active content fetch performed against either.

### 1. sha256_manifest.txt
- Content: SHA256, filename, byte size for all 8 files found in
  `%LOCALAPPDATA%\Microsoft\Windows\Caches\Nancy\` (hidden, readonly, timestomped
  to uniform 2021-11-23 23:04:53).
- Capture: PowerShell Get-FileHash over directory listing, before any modification.
- Notes: payload files were then shredded (3-pass random overwrite) AFTER hashing;
  originals intentionally not retained pending guidance (hashes sufficient for family/
  sample correlation; identical-family samples obtainable via published MD5s from
  Malwarebytes 2026-07-20 report).

### 2. UpdateService_task.xml
- Content: full XML export of scheduled task `\UpdateService` (logon trigger,
  executes cmd.exe -> sync_afc1.cmd).
- Capture: Export-ScheduledTask prior to Unregister-ScheduledTask (eradication).

### 3. detection_history/*.bin (5 files)
- Content: raw copies of Microsoft Defender DetectionHistory records.
  - 4 records dated 2026-08-25 21:28 (re-detections during background quick scan):
    MSBuild.exe behavior detections (SuspendedRenpiExecProc.A x2 process paths,
    SuspEtherRpcConn.C) and Wacatac MSI path
    `%TEMP%\3te9ljtcq7VdCbqS\3te9ljNOvj0O1v4U.msi`.
  - 1 record dated 2026-08-10 (unrelated false positive on reporter's own pentest
    content, included only for completeness).
- Capture: byte-level ReadAllBytes copy from
  `C:\ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory\`.

### 4. IOCs.md
- Content: consolidated dossier — delivery chain, persistence, payload hashes,
  published-family cross-references, C2 retrieval endpoint + smart contract address,
  historical block numbers and rotation proof, third-party analysis links
  (Joe Sandbox 1628040, Gridinsoft reports, MetaMask eth-phishing-detect #272509),
  credential exposure inventory summary.

## Key timeline anchors (machine-local, UTC+2)

- 2026-08-20 23:35-23:39 : user browsing download-manager addons (benign context)
- 2026-08-23 17:33       : ChimeraInstaller.exe downloaded from LEGITIMATE
                           chimeratool.com CDN (ruled out as vector)
- 2026-08-23 20:52-20:55 : Google "samfw tool download"; visit sequence incl.
                           samfwtool.updatestar.com -> frptoolsdownload.com ->
                           *.kaqwmm.cyou gate (recorded in Firefox places.sqlite,
                           profile w0a5t39h.attacker VM-1783601917324)
- 2026-08-23 23:00       : D:\Setup.exe executed (UserAssist record)
- 2026-08-23 23:01       : Defender SuspRenpiExecProc.A x2 (32-bit MSBuild)
- 2026-08-23 23:02       : C:\Setup.exe executed (UserAssist record)
- 2026-08-23 23:03       : Defender flags Wacatac MSI; SecHealthUI opened by user
- 2026-08-23 23:05       : Defender SuspEtherRpcConn.C (64-bit MSBuild) — EtherHiding beacon
- 2026-08-24 19:07+      : unrelated user software changes (360 Total Security install etc.)
- 2026-08-25 11:32-11:34 : UpdateService fired; MSBuild PID 18084 resident 10h;
                           csc.exe compile 11:33:26 confirms active stage rebuild
- 2026-08-25 ~22:05      : eradication (process kill, task deletion, payload shred)

## Integrity notes

- No event-log clearing observed (Security oldest record 2026-08-20; System 2026-06-02;
  zero Event 1102/104 occurrences) — attacker anti-forensics limited to payload-file
  timestomping and temp cleanup.
- Firewall packet logging was configured but never written (pfirewall.log absent);
  DNS Client operational logging disabled — network-level destination capture
  unavailable by design of attacker (DoH + raw sockets documented for this family).
- Blockchain archive reads performed via public RPC (bsc-mainnet.public.blastapi.io)
  on 2026-08-25; queried values reproducible by any party at the recorded block heights.
