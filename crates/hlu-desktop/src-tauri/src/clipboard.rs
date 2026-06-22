//! Clipboard helpers for copying secrets.
//!
//! A copied password is written as *sensitive* data — on Windows it is excluded from Clipboard
//! History and cloud sync — and is best-effort cleared after a short delay if it hasn't already
//! been replaced by the user.

use std::time::Duration;

use tauri::AppHandle;
use tauri_plugin_clipboard_manager::ClipboardExt;
use zeroize::Zeroizing;

/// How long a copied secret lingers before the best-effort auto-clear fires. Generous enough to
/// open a terminal, connect, and reach the password prompt before pasting.
const CLEAR_AFTER: Duration = Duration::from_secs(120);

/// Copy a secret to the clipboard as "sensitive" and schedule a best-effort clear.
///
/// The clear only fires if the clipboard still holds exactly this secret, so it never clobbers
/// something the user copied in the meantime.
pub fn copy_secret(app: &AppHandle, secret: &str) -> Result<(), String> {
    write_sensitive(app, secret)?;
    schedule_clear(app.clone(), secret.to_string());
    Ok(())
}

#[cfg(windows)]
fn write_sensitive(_app: &AppHandle, secret: &str) -> Result<(), String> {
    // Hold one clipboard session so the text and the marker formats land together.
    let _clip = clipboard_win::Clipboard::new_attempts(10)
        .map_err(|e| format!("clipboard open failed: {e}"))?;
    write_sensitive_open(secret)
}

/// Write the text + sensitivity markers into an already-open clipboard session.
///
/// CRITICAL: `raw::set` and `raw::set_string` EMPTY the clipboard on every call, so the text must
/// be set first and the marker formats appended with `set_without_clear` — otherwise each marker
/// would wipe the text we just wrote and paste would yield nothing.
#[cfg(windows)]
fn write_sensitive_open(secret: &str) -> Result<(), String> {
    use clipboard_win::raw;

    raw::set_string(secret).map_err(|e| format!("clipboard write failed: {e}"))?;

    // Best-effort: exclude from Clipboard History and cloud sync (older Windows ignores these).
    for name in [
        "ExcludeClipboardContentFromMonitorProcessing",
        "CanIncludeInClipboardHistory",
        "CanUploadToCloudClipboard",
    ] {
        if let Some(fmt) = raw::register_format(name) {
            let _ = raw::set_without_clear(fmt.get(), &0u32.to_ne_bytes());
        }
    }
    Ok(())
}

#[cfg(not(windows))]
fn write_sensitive(app: &AppHandle, secret: &str) -> Result<(), String> {
    app.clipboard()
        .write_text(secret.to_string())
        .map_err(|e| e.to_string())
}

/// Spawn a detached timer that clears the clipboard once, only if it still holds our secret.
fn schedule_clear(app: AppHandle, secret: String) {
    let secret = Zeroizing::new(secret);
    std::thread::spawn(move || {
        std::thread::sleep(CLEAR_AFTER);
        if let Ok(current) = app.clipboard().read_text() {
            if current == *secret {
                let _ = app.clipboard().write_text(String::new());
            }
        }
    });
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    /// Regression for the clipboard-win auto-empty bug: the sensitivity markers must NOT wipe the
    /// pasteable text. Ignored by default because it touches the real system clipboard — run with
    /// `cargo test -p hlu-desktop -- --ignored`.
    #[test]
    #[ignore]
    fn sensitive_write_preserves_pasteable_text() {
        let secret = "p@ss w0rd! ✓ multi word";
        {
            let _clip = clipboard_win::Clipboard::new_attempts(10).unwrap();
            write_sensitive_open(secret).unwrap();
        }
        let got = clipboard_win::get_clipboard_string().unwrap();
        assert_eq!(
            got, secret,
            "clipboard text was wiped by the marker formats"
        );
    }
}
