# STRIDE Threat Model - Module E: Active Enumeration

| Threat Category | Description | Specific Impact on NetSentinel | Mitigation |
|---|---|---|---|
| **Spoofing** | Masquerading scanning traffic or spoofing User-Agent. | Blaming other tools or evasion of detection. | Enforce standard, transparent `User-Agent` headers that identify NetSentinel and include contact/consent info. |
| **Tampering** | Wordlist path injection or target manipulation. | Reading system files (Local File Inclusion / Path Traversal) via arbitrary wordlist selection. | Restrict wordlists to specific directories. Validate that target URLs conform strictly to session scope (RE-02). |
| **Repudiation** | Denying initiating brute force or directory busting. | High-frequency attack traced back to local IP. | Log all active enumeration targets, wordlists, and timing profiles to the immutable audit ledger. |
| **Information Disclosure** | Leak of discovered subdomains/directories. | Disclosing hidden administration panels or staging assets. | Encrypt all discovery databases. Require user authorization before copying discovery data. |
| **Denial of Service** | Flooding the target web server with high-frequency HTTP requests. | Target web server crashes (Accidental DoS). | Hardcode rate limits (e.g. minimum 50ms delay between requests) unless overridden and validated by PDDL rules. |
| **Elevation of Privilege** | Code injection through custom DNS/Directory Buster wrappers. | Execution of malicious command strings. | Run enumeration tooling in unprivileged userspace. Never compile commands as strings. |
