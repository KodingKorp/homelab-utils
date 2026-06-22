//! Encryption of stored SSH passwords.
//!
//! A single random 256-bit master key lives in the OS keychain (Windows Credential Manager, macOS
//! Keychain, Linux Secret Service). Passwords are sealed with XChaCha20-Poly1305 and the device
//! MAC is bound in as associated data (AAD), so a ciphertext cannot be moved between device rows.
//! Only the ciphertext + nonce are persisted in SQLite — the key never touches the database.

use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
};
use keyring::{Entry, Error as KeyringError};
use zeroize::Zeroizing;

/// Keychain service/account under which the master key is stored.
const KR_SERVICE: &str = "dev.KodingKorp.homelab-utils";
const KR_USER: &str = "ssh-credential-master-key";
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;

/// Failures from the credential crypto layer.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// The OS keychain is missing/unusable (e.g. no platform backend) — we refuse to pretend a
    /// secret was protected when it would not be.
    #[error("secure key store unavailable: {0}")]
    KeyStoreUnavailable(String),
    /// A keychain operation failed.
    #[error("keychain error: {0}")]
    Keyring(#[from] KeyringError),
    /// AEAD seal/open failed (wrong key, tampered ciphertext, or AAD mismatch).
    #[error("encryption/decryption failed")]
    Aead,
    /// A persisted nonce had the wrong length.
    #[error("stored nonce is malformed")]
    BadNonce,
    /// A decrypted password was not valid UTF-8.
    #[error("decrypted password is not valid UTF-8")]
    BadUtf8,
}

/// Load the master key from the OS keychain, generating + storing it on first use.
///
/// After generating a fresh key we read it straight back: if the keychain silently fell back to a
/// no-op store (e.g. a missing platform backend), the readback won't match and we fail loudly
/// rather than pretend a secret was protected.
fn master_key() -> Result<Zeroizing<[u8; KEY_LEN]>, CryptoError> {
    let entry = Entry::new(KR_SERVICE, KR_USER)?;
    match entry.get_secret() {
        Ok(bytes) if bytes.len() == KEY_LEN => {
            let mut key = Zeroizing::new([0u8; KEY_LEN]);
            key.copy_from_slice(&bytes);
            Ok(key)
        }
        // No entry yet, or a corrupt/wrong-length one: generate, store, and verify persistence.
        Ok(_) | Err(KeyringError::NoEntry) => {
            let fresh = XChaCha20Poly1305::generate_key(&mut OsRng);
            entry.set_secret(fresh.as_slice())?;
            match entry.get_secret() {
                Ok(rb) if rb == fresh.as_slice() => {
                    let mut key = Zeroizing::new([0u8; KEY_LEN]);
                    key.copy_from_slice(fresh.as_slice());
                    Ok(key)
                }
                _ => Err(CryptoError::KeyStoreUnavailable(
                    "key did not persist (no usable OS keychain backend)".into(),
                )),
            }
        }
        Err(e) => Err(CryptoError::Keyring(e)),
    }
}

/// Encrypt `plaintext` under `key`, binding `aad`. Returns `(ciphertext, nonce)`.
///
/// Pure (key + aad injected) so it is unit-testable without the keychain.
pub fn encrypt(
    key: &[u8; KEY_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Aead)?;
    Ok((ciphertext, nonce.to_vec()))
}

/// Decrypt `ciphertext` under `key`, verifying `aad`.
pub fn decrypt(
    key: &[u8; KEY_LEN],
    aad: &[u8],
    ciphertext: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if nonce.len() != NONCE_LEN {
        return Err(CryptoError::BadNonce);
    }
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = XNonce::from_slice(nonce);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Aead)
}

/// Encrypt a password for the device identified by `mac` (bound as AAD). Returns `(cipher, nonce)`.
pub fn encrypt_password(mac: &str, plaintext: &str) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let key = master_key()?;
    encrypt(&key, mac.as_bytes(), plaintext.as_bytes())
}

/// Decrypt a stored password for `mac`, returning a zeroize-on-drop string.
pub fn decrypt_password(
    mac: &str,
    ciphertext: &[u8],
    nonce: &[u8],
) -> Result<Zeroizing<String>, CryptoError> {
    let key = master_key()?;
    let plaintext = Zeroizing::new(decrypt(&key, mac.as_bytes(), ciphertext, nonce)?);
    let text = String::from_utf8(plaintext.to_vec()).map_err(|_| CryptoError::BadUtf8)?;
    Ok(Zeroizing::new(text))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; KEY_LEN] = [0x42; KEY_LEN];

    #[test]
    fn roundtrip_with_aad() {
        let (ct, nonce) = encrypt(&KEY, b"aa:bb:cc:dd:ee:ff", b"hunter2").unwrap();
        assert_eq!(nonce.len(), NONCE_LEN);
        let pt = decrypt(&KEY, b"aa:bb:cc:dd:ee:ff", &ct, &nonce).unwrap();
        assert_eq!(pt, b"hunter2");
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let (mut ct, nonce) = encrypt(&KEY, b"mac", b"secret").unwrap();
        ct[0] ^= 0xff;
        assert!(decrypt(&KEY, b"mac", &ct, &nonce).is_err());
    }

    #[test]
    fn wrong_aad_fails() {
        // A ciphertext sealed for one MAC must not open under another.
        let (ct, nonce) = encrypt(&KEY, b"mac-A", b"secret").unwrap();
        assert!(decrypt(&KEY, b"mac-B", &ct, &nonce).is_err());
    }

    #[test]
    fn bad_nonce_length_is_rejected() {
        let (ct, _) = encrypt(&KEY, b"mac", b"secret").unwrap();
        assert!(matches!(
            decrypt(&KEY, b"mac", &ct, &[0u8; 12]),
            Err(CryptoError::BadNonce)
        ));
    }
}
