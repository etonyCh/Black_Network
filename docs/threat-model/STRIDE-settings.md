# STRIDE Threat Model - Module H: Settings

| Threat Category | Description | Specific Impact on NetSentinel | Mitigation |
|---|---|---|---|
| **Spoofing** | Spoofing D-Bus settings requests. | Unauthorized alteration of app configurations. | Authenticate configuration updates via system D-Bus and validate caller identities. |
| **Tampering** | Writing malicious parameters directly into the configuration. | Command injection through network interface selection. | Only allow selection of interfaces that exist physically (validated via kernel APIs). Reject arbitrary text input. |
| **Repudiation** | Disabling audit logs or changing retention policies without record. | Compliance failures. | Log all setting changes (especially retention policies and logging levels) to the immutable audit ledger. |
| **Information Disclosure** | Storing Gemini API Keys or credentials in clear text in `config.ini`. | Theft of credentials leading to financial loss or API abuse. | **Never store API keys in plaintext.** Store them exclusively in GNOME Keyring via `libsecret`. |
| **Denial of Service** | Corrupting the settings file. | App crashes or fails to start. | Validate configuration structure on startup. Reset to safe defaults if corruption is detected. |
| **Elevation of Privilege** | Bypassing Polkit checks for privileged settings (e.g. changing helper paths). | Running rogue helper binaries. | Helper daemon binaries and paths are hardcoded or read from root-owned configurations, never from user settings. |
