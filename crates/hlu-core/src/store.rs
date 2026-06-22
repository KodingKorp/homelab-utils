//! Hybrid persistence: a SQLite working store plus human-readable JSON import/export.
//!
//! Each [`Device`] is stored as a JSON blob keyed by its stable id, with `ip`/`mac`/`last_seen`
//! mirrored into columns for cheap querying. This keeps the schema forward-compatible with the
//! evolving [`Device`] type while still allowing SQL filtering.

use crate::error::Result;
use crate::model::Device;
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
}
