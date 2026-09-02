# Incident 2026-08-25 — RenPy Loader / Nancy / Amatera Stealer

## Confirmed on THIS machine
- Infection: Aug 23 ~23:00 via fake "SamFw FRP Tool v5.5.1 Setup" from frptoolsdownload.com
  - Redirect gate: *.kaqwmm.cyou ("NextShare" landing pages)
  - Executed: D:\Setup.exe (23:00), C:\Setup.exe (23:02)
- Persistence: scheduled task \UpdateService (logon trigger) — DELETED
- Payload dir: %LOCALAPPDATA%\Microsoft\Windows\Caches\Nancy — SHREDDED
  - SHA256 manifest: sha256_manifest.txt (this folder)
- Defender detections: SuspRenpiExecProc.A x2, Wacatac.H!ml MSI, SuspEtherRpcConn.C
- C2 retrieval (proven fired here): JSON-RPC eth_call -> bsc-dataseed.binance.org
  - contract 0x328a1fadff154290f0ce1389a4e633698cdfdaa7 selector 0x06fdde03
  - contract still live 2026-08-25; currently serves encrypted blob (54 bytes)

## Published campaign C2 / infra (Malwarebytes Jul-Aug 2026)
### Stealer C2
- login.orbitalframework.cc  (Amatera C2, July wave)
- Aug PavinLoader pool: catalyst-pro.lat, twigoamwu.cfd, trusaifi.cfd,
  stellar-minds.cfd, pinnacle-labs.lat, nexahub.lat, fimwoglea.shop,
  velodium.lat, rpcsecnoweb.pro, more-arpc.icu, echo-systems.cfd, kelemet.shop
### Payload delivery IPs
- 144.124.251.171 / 195.63.140.33 / 78.40.196.252
- 93.152.224.75 / 65.21.80.170 / 195.63.142.49
### Distribution (fake download sites)
- downpro.net, macisofile.sbs, visitmama.blog, visitmama.guru,
  getgamerfree.com, fullgames.digital, flingbase.net, citronemu.com
- Infra: filemodo.xyz, storage06x.cfd, p03sil.cyou, wimsedas.xyz,
  againstmor.store, host03q.cfd, cloud01y.cfd, storage11x.cfd,
  storage04x.cfd, host82p.cfd, cloud05y.cfd, analyticstrack-pzh.click
### This machine's own source
- Gate redirect chain (Firefox places.sqlite, 2026-08-23 20:55 SAST):
  - link-file-nu623.kaqwmm.cyou -> checking-id-8scp.kaqwmm.cyou ->
    access-id-8scp.kaqwmm.cyou -> cloud-file-4xzl.kaqwmm.cyou
  - Gate campaign identifiers (base64 JSON params): "id":"nu623", "tag":"6bnS3H2T:C1"
- FINAL PAYLOAD URL (decoded from gate JSON "redirect" field):
  - https://d8baab0c37a0454d6f22ad4c.192169482.com/675ab055f00e5d1087ae481e21d24a
  - Served trojanized "SamFw FRP Tool v5.5.1 Setup"
  - Status 2026-08-25: LIVE behind Cloudflare (172.67.208.123 / 104.21.93.90 proxy)
  - Apex 192169482.com: Cloudflare-hosted zone, no direct A record
- frptoolsdownload.com still live via Cloudflare (104.21.76.40 / 172.67.186.155)

## Exfil behavior (Amatera 4.2.3-alpha1 as WPA.exe)
- POST harvested archive to live C2 over HTTPS
- Custom headers: X-Timestamp, X-Nonce, X-Signature (HMAC)
- Stage fetches: /assets/{TwoWords}.json XOR-encoded under cache.content
- Uses DNS-over-HTTPS via Google DNS + raw sockets (\Device\Afd\Endpoint) to hide resolution

## Local logging gaps (why exact POST target unprovable)
- Firewall packet logging configured but pfirewall.log never written
- Microsoft-Windows-DNS-Client/Operational disabled
- DNS cache TTLs expired; no Sysmon; no packet capture

## C2 rotation proof (recovered 2026-08-25 via blockchain time travel)
- Archive node (bsc-mainnet.public.blastapi.io) served contract state at historical blocks:
  - Block 117684888 (= Aug 23 23:05 SAST, infection beacon): 54B cipher blob #1
  - Block ~117784311 (Aug 24 logon): 54B DIFFERENT blob
  - Block ~117976228 (Aug 25 logon): 54B DIFFERENT blob
  - Latest (Aug 25 night): 54B yet another blob
- Conclusion: C2 domain is freshly encrypted per session; plaintext never persists.
- Blobs resistant to single-byte XOR, known-family XOR keys, repeating-key crib-slide
  (https://, http://, TLD cribs) => RC4/AES-class with key embedded in in-memory-only
  GollopDevest stage. Exact per-session hostname recoverable ONLY by reversing a sample
  (VT MD5s: 810F257542018BE0FC62AF542D13D012 / 29203ca123d51b1b33505a0813d360df)
  and replaying eth_call at these saved block numbers.

## Vector confirmation (third-party)
- Joe Sandbox analysis 1628040: samfw.com SamFwToolSetup = Wacatac dropper (score 84/100)
- Gridinsoft reports a3a38db6/a1eaa5bf: SamFwToolSetup.exe = Trojan Wacatac/Packed, unsigned Inno Setup
- MetaMask eth-phishing-detect issue #272509: SamFw Tool = stealer dropper, wallet-drain victim report

## Status
- Chain killed, task removed, payload shredded 2026-08-25 ~22:05
- Credential rotation REQUIRED (browser passwords all profiles, Discord,
  Google OAuth client_secret in Downloads, f13_token.txt, auth.json keys)
