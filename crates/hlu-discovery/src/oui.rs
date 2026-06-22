//! MAC vendor (OUI) lookup using the IEEE database embedded by `mac_oui`'s `with-db` feature.

use mac_oui::Oui;

/// A loaded OUI database. Construction parses the embedded dataset once; reuse a single instance
/// across a scan.
pub struct VendorDb {
    db: Oui,
}

impl VendorDb {
    /// Load the embedded OUI database. Returns `None` if it cannot be parsed.
    pub fn load() -> Option<Self> {
        Oui::default().ok().map(|db| Self { db })
    }

    /// Resolve a canonical-lowercase MAC to its vendor/company name, if known.
    pub fn lookup(&self, mac: &str) -> Option<String> {
        match self.db.lookup_by_mac(mac) {
            Ok(Some(entry)) => Some(entry.company_name.clone()),
            _ => None,
        }
    }
}
