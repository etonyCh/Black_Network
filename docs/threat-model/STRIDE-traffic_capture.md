# STRIDE Threat Model - Module C: Traffic Capture

| Threat Category | Description | Specific Impact on NetSentinel | Mitigation |
|---|---|---|---|
| **Spoofing** | Interface spoofing or passing arbitrary capture sources. | Capturing traffic from unauthorized networks. | Whitelist network interface names fetched from the kernel/NetworkManager; do not accept arbitrary text interfaces. |
| **Tampering** | User-controlled BPF (Berkeley Packet Filter) syntax injection. | Invalid filters or malicious parameters passed to helper execution. | Compile and validate the BPF filter locally on the UI side before spawning `dumpcap`. |
| **Repudiation** | Denying active packet capture execution on host. | Unauthorized local traffic logging. | Every capture session start/stop must log to the cryptographically chained audit log. |
| **Information Disclosure** | Leak of raw PCAP files containing sensitive credentials/secrets. | Unencrypted credentials or PII (Personally Identifiable Info) exposed on disk. | Decouple: `dumpcap` runs as helper, stdout is piped to unprivileged `tshark` parser. Encrypt all extracted secrets in SQLCipher DB. |
| **Denial of Service** | Disk space exhaustion due to large PCAP capture. | Host system crash or failure to log critical system data. | Buffer capture files in `/run/netsentinel/` (tmpfs), limit capture size/time, and enforce auto-rotation/cleanup. |
| **Elevation of Privilege** | Exploit in rich tshark dissection engine. | Attacker gets system execution via malformed packet dissection. | Never run `tshark` or `pyshark` with elevated privileges. Only `dumpcap` receives `cap_net_raw`, passing data down. |
