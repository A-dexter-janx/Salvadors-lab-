# VICTIM INCIDENT REPORT — Infostealer Infection & Data Exfiltration

**Classification:** Victim report / threat intelligence contribution
**Date of report:** 2026-08-25
**Reporter:** [NAME], [COUNTRY: South Africa] — [EMAIL], [PHONE]
**Status of reporter:** Victim (credentials and session data exfiltrated); system remediated 2026-08-25

---

## 1. Summary

On 2026-08-23 at approx. 23:00 SAST, the reporter executed two installer executables
(`D:\Setup.exe`, `C:\Setup.exe`) obtained from a fake "SamFw FRP Tool v5.5.1" download.
The download was acquired at ~20:55 via `frptoolsdownload[.]com` following redirects through
a malicious gate on `*.kaqwmm[.]cyou` ("NextShare" landing pages).

The installer delivered Trojan:Script/Wacatac.H!ml (MSI in %TEMP%) which deployed a
multi-stage loader consistent with publicly tracked **RenPy/PavinLoader** campaigns:
hidden BAT (`sync_afc1.cmd`) -> headless conhost relaunch -> MSBuild LOLBIN execution of
trojanized `Nancy.csproj` project files with `MSBUILDENABLEALLPROPERTYFUNCTIONS=1`.

**Source URL chain (fully recovered):**
`frptoolsdownload[.]com/samfw-tool/` -> redirect gate on `link-file-nu623[.]kaqwmm[.]cyou`
-> `checking-id-8scp[.]kaqwmm[.]cyou` -> `access-id-8scp[.]kaqwmm[.]cyou` ->
`cloud-file-4xzl[.]kaqwmm[.]cyou` ("NextShare") -> **final payload server**
`https://d8baab0c37a0454d6f22ad4c[.]192169482[.]com/675ab055f00e5d1087ae481e21d24a`
(decoded from the gate's base64 JSON response; campaign identifiers `"id":"nu623"`,
`"tag":"6bnS3H2T:C1"`; gate timestamp matches download moment). Both the final host and
`frptoolsdownload[.]com` remained LIVE behind Cloudflare as of 2026-08-25 ~23:00 SAST
(proxy IPs 172.67.208.123 / 104.21.93.90 / 104.21.76.40 / 172.67.186.155).

The chain resolved its command-and-control via EtherHiding: JSON-RPC `eth_call` to
Binance Smart Chain contract `0x328a1fadff154290f0ce1389a4e633698cdfdaa7`
(selector `0x06fdde03`). Microsoft Defender captured this behavior
(Behavior:Win32/SuspEtherRpcConn.C) at 2026-08-23 23:05:11 SAST.

Persistence: scheduled task `\UpdateService` (logon trigger) re-executed the chain at
every logon until removal on 2026-08-25 (~22:05 SAST). Compiler activity (csc.exe)
corroborates re-compilation during task runs.

Final payload per vendor tracking of this campaign family: **Amatera Stealer**
(aka ACR/AcridRain; obfuscated build disguised as WPA.exe), executed fully in memory.

## 2. Impact

Exfiltration is assessed as COMPLETED for each successful execution window. Exposed data:

- Edge browser vault: 36 saved credentials across 32 sites, including financial
  institutions and trading platforms (inventory available on request; sites listed in
  analyst notes)
- Firefox vaults (two profiles): 23 saved logins total
- All browser cookies/session tokens (Edge/Firefox/Chrome profiles present)
- Discord local token storage
- Autofill data (Edge Web Data)
- Secrets resident in Downloads: Google OAuth client_secret JSON; service token file

No cryptocurrency wallet software was installed (no direct wallet loss).
All affected credentials have been rotated post-remediation.

## 3. Evidence index (see EVIDENCE_LOG.md for provenance)

| Artifact | Path in this package |
|---|---|
| SHA256 manifest of all recovered payload files | sha256_manifest.txt |
| Persistence mechanism (exported task XML) | UpdateService_task.xml |
| Defender DetectionHistory records (Aug 23-25 detections) | detection_history/ (5 files) |
| Full IOC dossier incl. blockchain block numbers for historical C2 state | IOCs.md |

## 4. Notable investigative value

1. **Complete delivery chain recovered, including the terminal payload URL** —
   `d8baab0c37a0454d6f22ad4c[.]192169482[.]com/675ab055f00e5d1087ae481e21d24a` — decoded
   from the gate's own base64 JSON (`"redirect"` field). Neither this host nor the
   `.kaqwmm[.]cyou` infrastructure appears in any published IOC set as of 2026-08-25.
   Gate campaign identifiers (`nu623`, `6bnS3H2T:C1`) allow correlation of every other
   victim funneled through this same operation.
2. **Live infrastructure at report time** — final payload host and `frptoolsdownload[.]com`
   both still resolving via Cloudflare on 2026-08-25 (~23:00 SAST). Registrar/host abuse
   action within days may preserve evidence before rotation.
3. **Blockchain time-travel evidence**: archive-node reads of contract
   `0x328a1fadff154290f0ce1389a4e633698cdfdaa7` at blocks 117684888 (infection beacon),
   ~117784311, ~117976228 show four DISTINCT 54-byte encrypted values, proving
   per-session C2 rotation. Block numbers preserved to allow key-holders (e.g.,
   researchers who reverse GollopDevest MD5 810F257542018BE0FC62AF542D13D012) to decode
   exact hostnames used by THIS victim's sessions.
4. Payload file hashes link this incident to Malwarebytes' July 2026 RenPy/PavinLoader
   campaign set (family MD5s published there match tooling patterns).

## 5. Requested actions

- Correlate `.kaqwmm[.]cyou` / `frptoolsdownload[.]com` infrastructure with existing
  PavinLoader/RenPy investigations
- Consider registrar/host abuse action against the redirect-gate domains
- Preserve this report as victim statement supporting any future seizure or prosecution
  related to Amatera/ACR infrastructure

## 6. Reporter declarations

- Reporter is available for follow-up questions and can produce original artifacts.
- System remains in post-remediation state; no anti-forensic cleanup performed beyond
  malware eradication. Original infection-era logs intact (System log unbroken since
  2026-06-02; no Event ID 1102/104 clearing events).

---
*Attachments: sha256_manifest.txt, UpdateService_task.xml, detection_history/*.bin, IOCs.md*
