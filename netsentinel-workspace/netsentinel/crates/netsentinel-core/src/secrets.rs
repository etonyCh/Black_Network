use anyhow::{anyhow, Context, Result};
use std::collections::HashMap;
use std::sync::Mutex;
use zeroize::{Zeroize, Zeroizing};

const SERVICE_NAME: &str = "netsentinel";

pub struct KeyringStore {
    service: String,
}

impl KeyringStore {
    pub fn new() -> Self {
        Self {
            service: SERVICE_NAME.to_string(),
        }
    }

    pub fn set_secret(&self, key: &str, value: &str) -> Result<()> {
        let entry = keyring::Entry::new(&self.service, key)
            .with_context(|| format!("Échec création entrée keyring pour `{}`", key))?;
        entry
            .set_password(value)
            .with_context(|| format!("Échec sauvegarde secret keyring `{}`", key))?;
        Ok(())
    }

    pub fn get_secret(&self, key: &str) -> Result<Option<String>> {
        let entry = keyring::Entry::new(&self.service, key)
            .with_context(|| format!("Échec accès keyring pour `{}`", key))?;
        match entry.get_password() {
            Ok(pass) => Ok(Some(pass)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(anyhow!("Erreur lecture secret keyring `{}` : {}", key, e)),
        }
    }

    pub fn delete_secret(&self, key: &str) -> Result<()> {
        let entry = keyring::Entry::new(&self.service, key)
            .with_context(|| format!("Échec accès keyring pour `{}`", key))?;
        match entry.delete_credential() {
            Ok(_) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(anyhow!("Erreur suppression secret keyring `{}` : {}", key, e)),
        }
    }
}

impl Default for KeyringStore {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct SecretBuffer(pub Zeroizing<String>);

impl SecretBuffer {
    pub fn new(val: impl Into<String>) -> Self {
        Self(Zeroizing::new(val.into()))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

pub struct RamStore {
    store: Mutex<HashMap<String, SecretBuffer>>,
}

impl RamStore {
    pub fn new() -> Self {
        Self {
            store: Mutex::new(HashMap::new()),
        }
    }

    pub fn set_secret(&self, key: &str, value: &str) {
        if let Ok(mut guard) = self.store.lock() {
            guard.insert(key.to_string(), SecretBuffer::new(value));
        }
    }

    pub fn get_secret(&self, key: &str) -> Option<String> {
        if let Ok(guard) = self.store.lock() {
            guard.get(key).map(|buf| buf.as_str().to_string())
        } else {
            None
        }
    }

    pub fn delete_secret(&self, key: &str) {
        if let Ok(mut guard) = self.store.lock() {
            if let Some(mut old) = guard.remove(key) {
                old.0.zeroize();
            }
        }
    }

    pub fn clear(&self) {
        if let Ok(mut guard) = self.store.lock() {
            for (_, mut buf) in guard.drain() {
                buf.0.zeroize();
            }
        }
    }
}

impl Default for RamStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ram_store_zeroization() {
        let store = RamStore::new();
        store.set_secret("API_KEY", "super_secret_token_123");
        assert_eq!(store.get_secret("API_KEY"), Some("super_secret_token_123".to_string()));

        store.delete_secret("API_KEY");
        assert_eq!(store.get_secret("API_KEY"), None);

        store.set_secret("K1", "V1");
        store.set_secret("K2", "V2");
        store.clear();
        assert_eq!(store.get_secret("K1"), None);
        assert_eq!(store.get_secret("K2"), None);
    }
}
