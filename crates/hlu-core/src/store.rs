//! Hybrid persistence: a SQLite working store plus human-readable JSON import/export.
//!
//! Each [`Device`] is stored as a JSON blob keyed by its stable id, with `ip`/`mac`/`last_seen`
//! mirrored into columns for cheap querying. This keeps the schema forward-compatible with the
//! evolving [`Device`] type while still allowing SQL filtering.

use crate::error::{CoreError, Result};
use crate::model::{AuthMethod, CredentialMeta, Device, StoredCredential};
use rusqlite::{Connection, params};
use std::path::Path;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS devices (
    id        TEXT PRIMARY KEY,
    ip        TEXT NOT NULL,
    mac       TEXT,
    data      TEXT NOT NULL,
    last_seen INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen);

CREATE TABLE IF NOT EXISTS ssh_credentials (
    mac         TEXT PRIMARY KEY,
    auth_method TEXT NOT NULL,
    pw_cipher   BLOB,
    pw_nonce    BLOB,
    key_path    TEXT,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS app_settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
";

/// The device inventory backed by SQLite.
pub struct Store {
    conn: Connection,
}

impl Store {
    /// Open (creating if needed) the store at `path`, ensuring the parent directory and schema.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }

    /// Open an ephemeral in-memory store (used by tests and `--no-persist` runs).
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }

    /// Insert or update a device by its stable id.
    pub fn upsert(&self, device: &Device) -> Result<()> {
        let data = serde_json::to_string(device)?;
        self.conn.execute(
            "INSERT INTO devices (id, ip, mac, data, last_seen) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(id) DO UPDATE SET ip = ?2, mac = ?3, data = ?4, last_seen = ?5",
            params![
                device.id,
                device.ip.to_string(),
                device.mac,
                data,
                device.last_seen
            ],
        )?;
        Ok(())
    }

    /// Upsert many devices in a single transaction.
    pub fn upsert_many(&mut self, devices: &[Device]) -> Result<()> {
        let tx = self.conn.transaction()?;
        for device in devices {
            let data = serde_json::to_string(device)?;
            tx.execute(
                "INSERT INTO devices (id, ip, mac, data, last_seen) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(id) DO UPDATE SET ip = ?2, mac = ?3, data = ?4, last_seen = ?5",
                params![
                    device.id,
                    device.ip.to_string(),
                    device.mac,
                    data,
                    device.last_seen
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// All devices, most-recently-seen first. Malformed rows are skipped (and logged).
    pub fn all(&self) -> Result<Vec<Device>> {
        let mut stmt = self
            .conn
            .prepare("SELECT data FROM devices ORDER BY last_seen DESC")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            let json = row?;
            match serde_json::from_str::<Device>(&json) {
                Ok(device) => out.push(device),
                Err(err) => tracing::warn!("skipping malformed device row: {err}"),
            }
        }
        Ok(out)
    }

    /// Fetch a single device by id.
    pub fn get(&self, id: &str) -> Result<Option<Device>> {
        let mut stmt = self
            .conn
            .prepare("SELECT data FROM devices WHERE id = ?1")?;
        let mut rows = stmt.query_map(params![id], |row| row.get::<_, String>(0))?;
        match rows.next() {
            Some(row) => Ok(Some(serde_json::from_str(&row?)?)),
            None => Ok(None),
        }
    }

    /// Set (or clear, with `None`) a device's user-supplied name.
    pub fn set_custom_name(&self, id: &str, name: Option<&str>) -> Result<bool> {
        let Some(mut device) = self.get(id)? else {
            return Ok(false);
        };
        device.custom_name = name.map(|n| n.to_string());
        self.upsert(&device)?;
        Ok(true)
    }

    /// Set (or clear, with `None`) a device's chosen SSH login.
    pub fn set_username(&self, id: &str, user: Option<&str>) -> Result<bool> {
        let Some(mut device) = self.get(id)? else {
            return Ok(false);
        };
        device.ssh_user = user.map(|u| u.to_string());
        self.upsert(&device)?;
        Ok(true)
    }

    /// Delete a device row by id. Returns whether a row was removed.
    pub fn delete_device(&self, id: &str) -> Result<bool> {
        let n = self
            .conn
            .execute("DELETE FROM devices WHERE id = ?1", params![id])?;
        Ok(n > 0)
    }

    // --- SSH credentials (keyed by MAC) -------------------------------------------------------
    //
    // The store is crypto-agnostic: `pw_cipher`/`pw_nonce` are opaque bytes produced and consumed
    // by the desktop app's crypto layer. `get_credential` (with ciphertext) is for that layer only;
    // the UI must go through `get_credential_meta`, which never carries the ciphertext.

    /// Insert or replace a device's SSH credential (keyed by MAC), preserving `created_at`.
    pub fn upsert_credential(&self, cred: &StoredCredential) -> Result<()> {
        self.conn.execute(
            "INSERT INTO ssh_credentials
                 (mac, auth_method, pw_cipher, pw_nonce, key_path, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(mac) DO UPDATE SET
                 auth_method = ?2, pw_cipher = ?3, pw_nonce = ?4, key_path = ?5, updated_at = ?7",
            params![
                cred.mac,
                cred.auth_method.as_db_str(),
                cred.pw_cipher,
                cred.pw_nonce,
                cred.key_path,
                cred.created_at,
                cred.updated_at,
            ],
        )?;
        Ok(())
    }

    /// Fetch a device's full credential **including ciphertext** — for the crypto layer only.
    pub fn get_credential(&self, mac: &str) -> Result<Option<StoredCredential>> {
        let mut stmt = self.conn.prepare(
            "SELECT mac, auth_method, pw_cipher, pw_nonce, key_path, created_at, updated_at
             FROM ssh_credentials WHERE mac = ?1",
        )?;
        let mut rows = stmt.query_map(params![mac], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<Vec<u8>>>(2)?,
                row.get::<_, Option<Vec<u8>>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })?;
        match rows.next() {
            Some(row) => {
                let (mac, method, pw_cipher, pw_nonce, key_path, created_at, updated_at) = row?;
                let auth_method = AuthMethod::from_db_str(&method).ok_or_else(|| {
                    CoreError::Integrity(format!("unknown auth_method '{method}' for {mac}"))
                })?;
                Ok(Some(StoredCredential {
                    mac,
                    auth_method,
                    pw_cipher,
                    pw_nonce,
                    key_path,
                    created_at,
                    updated_at,
                }))
            }
            None => Ok(None),
        }
    }

    /// Fetch the **non-secret** metadata for a device's credential — safe for the UI.
    pub fn get_credential_meta(&self, mac: &str) -> Result<Option<CredentialMeta>> {
        Ok(self.get_credential(mac)?.map(|c| CredentialMeta {
            mac: c.mac,
            auth_method: c.auth_method,
            has_password: c.pw_cipher.is_some(),
            key_path: c.key_path,
        }))
    }

    /// Delete a device's stored credential. Returns whether a row was removed.
    pub fn delete_credential(&self, mac: &str) -> Result<bool> {
        let n = self
            .conn
            .execute("DELETE FROM ssh_credentials WHERE mac = ?1", params![mac])?;
        Ok(n > 0)
    }

    // --- App settings (simple key/value) ------------------------------------------------------

    /// Read a persisted app setting.
    pub fn get_setting(&self, key: &str) -> Result<Option<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT value FROM app_settings WHERE key = ?1")?;
        let mut rows = stmt.query_map(params![key], |row| row.get::<_, String>(0))?;
        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    /// Write (insert or replace) a persisted app setting.
    pub fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO app_settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = ?2",
            params![key, value],
        )?;
        Ok(())
    }

    /// Write the full inventory to a pretty-printed JSON file.
    pub fn export_json(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let devices = self.all()?;
        std::fs::write(path, serde_json::to_string_pretty(&devices)?)?;
        Ok(())
    }

    /// Import devices from a JSON export, upserting each; returns the count imported.
    pub fn import_json(&mut self, path: &Path) -> Result<usize> {
        let json = std::fs::read_to_string(path)?;
        let devices: Vec<Device> = serde_json::from_str(&json)?;
        self.upsert_many(&devices)?;
        Ok(devices.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Device;

    #[test]
    fn upsert_and_read_roundtrip() {
        let store = Store::open_in_memory().unwrap();
        let mut d = Device::seen("192.168.1.50".parse().unwrap());
        d.set_mac("aa:bb:cc:dd:ee:ff".into());
        d.vendor = Some("Raspberry Pi Foundation".into());
        store.upsert(&d).unwrap();

        let all = store.all().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].id, "aa:bb:cc:dd:ee:ff");
        assert_eq!(all[0].vendor.as_deref(), Some("Raspberry Pi Foundation"));
    }

    #[test]
    fn custom_name_update_persists() {
        let store = Store::open_in_memory().unwrap();
        let d = Device::seen("10.0.0.2".parse().unwrap());
        let id = d.id.clone();
        store.upsert(&d).unwrap();
        assert!(store.set_custom_name(&id, Some("Router")).unwrap());
        assert_eq!(store.get(&id).unwrap().unwrap().display_name(), "Router");
    }

    #[test]
    fn credential_roundtrip_meta_and_delete() {
        use crate::model::{AuthMethod, StoredCredential};
        let store = Store::open_in_memory().unwrap();
        let mac = "aa:bb:cc:dd:ee:ff";

        let pw_cred = StoredCredential {
            mac: mac.into(),
            auth_method: AuthMethod::Password,
            pw_cipher: Some(vec![1, 2, 3, 4]),
            pw_nonce: Some(vec![9; 24]),
            key_path: None,
            created_at: 100,
            updated_at: 100,
        };
        store.upsert_credential(&pw_cred).unwrap();

        let got = store.get_credential(mac).unwrap().unwrap();
        assert_eq!(got.auth_method, AuthMethod::Password);
        assert_eq!(got.pw_cipher.as_deref(), Some(&[1u8, 2, 3, 4][..]));

        let meta = store.get_credential_meta(mac).unwrap().unwrap();
        assert!(meta.has_password);
        assert_eq!(meta.key_path, None);

        // Switching to key auth clears the password material; created_at is preserved.
        let key_cred = StoredCredential {
            auth_method: AuthMethod::Key,
            pw_cipher: None,
            pw_nonce: None,
            key_path: Some("/home/me/.ssh/id_ed25519".into()),
            updated_at: 200,
            ..pw_cred.clone()
        };
        store.upsert_credential(&key_cred).unwrap();
        let got = store.get_credential(mac).unwrap().unwrap();
        assert_eq!(got.created_at, 100);
        let meta = store.get_credential_meta(mac).unwrap().unwrap();
        assert!(!meta.has_password);
        assert_eq!(meta.auth_method, AuthMethod::Key);
        assert_eq!(meta.key_path.as_deref(), Some("/home/me/.ssh/id_ed25519"));

        assert!(store.delete_credential(mac).unwrap());
        assert!(store.get_credential_meta(mac).unwrap().is_none());
        assert!(!store.delete_credential(mac).unwrap());
    }

    #[test]
    fn settings_roundtrip() {
        let store = Store::open_in_memory().unwrap();
        assert_eq!(store.get_setting("default_terminal").unwrap(), None);
        store.set_setting("default_terminal", "wt").unwrap();
        assert_eq!(
            store.get_setting("default_terminal").unwrap().as_deref(),
            Some("wt")
        );
        store.set_setting("default_terminal", "kitty").unwrap();
        assert_eq!(
            store.get_setting("default_terminal").unwrap().as_deref(),
            Some("kitty")
        );
    }
}
