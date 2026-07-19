# STRIDE Threat Model - Module G: Reports

| Threat Category | Description | Specific Impact on NetSentinel | Mitigation |
|---|---|---|---|
| **Spoofing** | Forging report author or modifying "AI Generated" labels. | False compliance reports generated to satisfy auditors. | Automatically sign reports using GPG/detached signatures. Label all LLM outputs as "Généré par IA". |
| **Tampering** | Path traversal or script injection in HTML-to-PDF template parsing. | Reading system files or local code execution. | Use a secure, sandboxed PDF generator. Escape all dynamic strings (e.g. hostnames, CVE text) in templates. |
| **Repudiation** | Claiming a vulnerability report was edited post-facto. | Dispute on the original security findings. | Store the cryptographic hash of the PDF report in the immutable audit log ledger at creation time. |
| **Information Disclosure** | Secrets/passwords leaked in clear inside the PDF. | Sensitive client credentials exposed to unauthorized readers. | Apply credential masking (`••••••••`) to all exported reports. Require user confirmation before exporting clear secrets. |
| **Denial of Service** | Generating report for a massive session, causing Out Of Memory (OOM) crash. | Application hangs or host system freezes. | Paginate report generation. Use streaming writes instead of keeping the whole PDF structure in memory. |
| **Elevation of Privilege** | Path traversal in report export file dialog. | Overwriting critical system files (e.g. `.bashrc` or `.ssh/authorized_keys`). | Restrict export paths to user directories (e.g. `~/Documents/Reports`). Validate target path before writing. |
