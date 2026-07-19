# STRIDE Threat Model - Module B: Fingerprint, CTEM & PQC Audit

| Threat Category | Description | Specific Impact on NetSentinel | Mitigation |
|---|---|---|---|
| **Spoofing** | Rogue service mimicking target banner/TLS configuration. | False confidence in Post-Quantum Cryptography (PQC) readiness. | Validate certificate chains using trusted root stores; cross-reference TLS signatures. |
| **Tampering** | Parameter injection into the Nmap wrapper command. | Attacker runs arbitrary Nmap flags (e.g. `--script` or script payload). | Pydantic schema validation for all parameters. No direct string injection. Strict whitelist of arguments. |
| **Repudiation** | Denying active scan or BAS (Breach and Attack Simulation) action. | Liability for target downtime. | Cryptographic audit logging (RE-01/RE-02) matching every Nmap scan execution with its scope and consent. |
| **Information Disclosure** | Leak of vulnerability assessment data. | Attackers gain an actionable list of open ports and weak ciphers. | Restrict SQLite DB access, encrypt via SQLCipher, and mask findings in standard UI views. |
| **Denial of Service** | Aggressive port-scanning causing CPU exhaustion on target or host. | Target crashing or network switch saturation. | Restrict default scan rates (`--max-rate ≤ T3` default). Warn user before launching "deep" scans. |
| **Elevation of Privilege** | Abuse of `netsentinel-helperd` capabilities. | Helper command allows loading custom NSE scripts with root-like access. | Hardcode allowed Nmap scripts on the helper side. Do not permit arbitrary script execution paths. |
