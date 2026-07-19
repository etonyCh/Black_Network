# STRIDE Threat Model - Module D: Web Interceptor Proxy

| Threat Category | Description | Specific Impact on NetSentinel | Mitigation |
|---|---|---|---|
| **Spoofing** | MitM CA certificate spoofed or stolen. | Attacker intercepts other TLS traffic on user's machine. | Restrict MitM CA certificate permissions to `0600`. Bind `mitmdump` to `127.0.0.1` by default. Purge certs on session end. |
| **Tampering** | Modification of intercepted request/response parameters. | SSRF or payload injection into internal services. | Force requests to stay within the session's **Authorized Scope (RE-02)**. Human validation of replayed URLs. |
| **Repudiation** | Denying modifying a web request. | Unauthorized web scanning/attacks traced back to the user. | Cryptographically sign and chain all web modification and replay events in the audit log. |
| **Information Disclosure** | Intercepted session tokens or cookies stored in plain text. | Account hijack of audited users. | Redact sensitive headers (e.g. `Authorization`, `Cookie`) from default UI displays unless explicitly "revealed" and logged. |
| **Denial of Service** | Mitmproxy processes crashing or hogging HTTP sockets. | Local user loses internet access. | Run `mitmdump` with tight memory/CPU constraints. Ensure graceful cleanup of proxy settings on app crash. |
| **Elevation of Privilege** | Replay engine executing requests against localhost admin endpoints. | SSRF to access system D-Bus/helper or cloud metadata services. | Block SSRF cibles (such as local link-local addresses, loopback endpoints) unless explicitly whitelisted in the session scope. |
