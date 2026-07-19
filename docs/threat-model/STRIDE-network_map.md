# STRIDE Threat Model - Module A: Network Map

| Threat Category | Description | Specific Impact on NetSentinel | Mitigation |
|---|---|---|---|
| **Spoofing** | Rogue node spoofing MAC/IP address. | NetSentinel displays incorrect network map topology. | Display warning if MAC address conflicts or matches known spoofing signatures. |
| **Tampering** | Malicious hostname returned by DNS containing formatting tags. | Pango markup injection in GTK4 UI (*stored XSS-like* desktop vulnerability). | Strict HTML/Pango escaping of hostnames/IPs before rendering in GTK UI. |
| **Repudiation** | User denies running scan against sensitive asset. | Legal/operational disputes. | Log all scan initializations (timestamps, scopes) in the cryptographically chained audit ledger. |
| **Information Disclosure** | Leak of network topology cache to unauthorized local users. | Attacker learns layout of target network. | Store discovery data in SQLCipher database; set restrictive permissions (`0600`) on SQLite files. |
| **Denial of Service** | Flooding the scanner with thousands of virtual hosts (ARP flooding). | GTK rendering freezes or runs out of memory. | Implement paging/filtering in the network view and limit UI node updates to a sensible maximum. |
| **Elevation of Privilege** | Vulnerability in helper tool used for discovery (`arp-scan` / `nmap`). | Execution of arbitrary commands with `cap_net_raw` permissions. | Never pass inputs via shell compilation. Call binaries using safe `argv[]` format in `subprocess.run()`. |
