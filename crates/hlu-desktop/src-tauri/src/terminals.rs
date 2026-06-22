//! Modular terminal-launcher registry.
//!
//! Each [`Launcher`] knows how to (a) detect whether its emulator is installed and (b) build a
//! detached [`Command`] that opens a new window running a given `ssh` argv. The set is assembled
//! per-OS via `cfg`, so only launchers valid for the current platform are compiled and offered.
//!
//! Injection safety: argv-based launchers (the majority) pass the `ssh` arguments as separate
//! process arguments — no shell ever parses them. The few that require a single command *string*
//! (macOS `osascript`, Windows PowerShell `-Command`) build it through dedicated quoting helpers.

use std::process::{Command, Stdio};

use serde::Serialize;

/// A terminal emulator offered to the UI.
#[derive(Debug, Clone, Serialize)]
pub struct TerminalInfo {
    /// Stable id used to select the launcher (e.g. `"wt"`, `"kitty"`).
    pub id: String,
    /// Human-readable name shown in the picker.
    pub display: String,
}

/// One entry in the launcher registry.
struct Launcher {
    id: &'static str,
    display: &'static str,
    /// Whether this emulator appears installed on this machine.
    detect: fn() -> bool,
    /// Build a detached command that opens a window running `ssh_argv`.
    build: fn(&[String]) -> Command,
}

/// Whether `exe` is resolvable on `PATH`.
fn on_path(exe: &str) -> bool {
    which::which(exe).is_ok()
}

/// Whether a macOS `.app` bundle named `name` exists in a standard location.
#[cfg(target_os = "macos")]
fn app_bundle(name: &str) -> bool {
    use std::path::Path;
    if Path::new(&format!("/Applications/{name}.app")).exists() {
        return true;
    }
    if let Ok(home) = std::env::var("HOME") {
        if Path::new(&format!("{home}/Applications/{name}.app")).exists() {
            return true;
        }
    }
    false
}

/// Join an argv into a POSIX shell command string (single-quoting as needed). macOS-only.
#[cfg(target_os = "macos")]
fn posix_join(argv: &[String]) -> String {
    shell_words::join(argv)
}

/// Escape a string for embedding inside an AppleScript double-quoted literal. macOS-only.
#[cfg(target_os = "macos")]
fn applescript_quote(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Build a PowerShell command string that runs `argv` via the call operator with every token
/// single-quoted, so shell metacharacters in user-supplied values are inert. Windows-only.
#[cfg(windows)]
fn powershell_join(argv: &[String]) -> String {
    let mut out = String::from("& ");
    for (i, token) in argv.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push('\'');
        out.push_str(&token.replace('\'', "''"));
        out.push('\'');
    }
    out
}

#[cfg(windows)]
mod win {
    use super::Command;
    use std::os::windows::process::CommandExt;

    /// Open a console app in its own new window.
    const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;

    pub fn detect_wt() -> bool {
        super::on_path("wt") || super::on_path("wt.exe")
    }
    pub fn detect_powershell() -> bool {
        super::on_path("powershell") || super::on_path("pwsh")
    }
    pub fn detect_cmd() -> bool {
        super::on_path("cmd")
    }

    pub fn wt(argv: &[String]) -> Command {
        // Windows Terminal is a GUI app and opens its own window — no console flag needed.
        let mut c = Command::new("wt.exe");
        c.arg("new-tab");
        c.args(argv);
        c
    }

    pub fn powershell(argv: &[String]) -> Command {
        let exe = if super::on_path("pwsh") {
            "pwsh"
        } else {
            "powershell.exe"
        };
        let mut c = Command::new(exe);
        c.arg("-NoExit")
            .arg("-Command")
            .arg(super::powershell_join(argv));
        c.creation_flags(CREATE_NEW_CONSOLE);
        c
    }

    pub fn cmd(argv: &[String]) -> Command {
        // `/K` keeps the window open after ssh exits; argv is passed as separate args (cmd
        // re-joins it) so we never hand-build a fragile cmd command string.
        let mut c = Command::new("cmd.exe");
        c.arg("/K");
        c.args(argv);
        c.creation_flags(CREATE_NEW_CONSOLE);
        c
    }
}

#[cfg(target_os = "macos")]
mod mac {
    use super::{Command, applescript_quote, posix_join};

    pub fn terminal(argv: &[String]) -> Command {
        let inner = applescript_quote(&posix_join(argv));
        let script = format!(
            "tell application \"Terminal\"\n\
                 activate\n\
                 do script \"{inner}\"\n\
             end tell"
        );
        let mut c = Command::new("osascript");
        c.arg("-e").arg(script);
        c
    }

    pub fn iterm(argv: &[String]) -> Command {
        let inner = applescript_quote(&posix_join(argv));
        let script = format!(
            "tell application \"iTerm\"\n\
                 activate\n\
                 set w to (create window with default profile)\n\
                 tell current session of w to write text \"{inner}\"\n\
             end tell"
        );
        let mut c = Command::new("osascript");
        c.arg("-e").arg(script);
        c
    }

    pub fn ghostty(argv: &[String]) -> Command {
        // Launch the .app bundle and hand it the command to execute.
        let mut c = Command::new("open");
        c.arg("-na").arg("Ghostty").arg("--args").arg("-e");
        c.args(argv);
        c
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::Command;

    pub fn gnome(argv: &[String]) -> Command {
        let mut c = Command::new("gnome-terminal");
        c.arg("--");
        c.args(argv);
        c
    }
    pub fn konsole(argv: &[String]) -> Command {
        let mut c = Command::new("konsole");
        c.arg("--hold").arg("-e");
        c.args(argv);
        c
    }
    pub fn xterm(argv: &[String]) -> Command {
        let mut c = Command::new("xterm");
        c.arg("-hold").arg("-e");
        c.args(argv);
        c
    }
    pub fn ghostty(argv: &[String]) -> Command {
        let mut c = Command::new("ghostty");
        c.arg("-e");
        c.args(argv);
        c
    }
}

#[cfg(unix)]
mod unixterm {
    use super::Command;

    pub fn alacritty(argv: &[String]) -> Command {
        let mut c = Command::new("alacritty");
        c.arg("-e");
        c.args(argv);
        c
    }
    pub fn kitty(argv: &[String]) -> Command {
        // kitty takes the command directly (no `-e`); `--hold` keeps the window after exit.
        let mut c = Command::new("kitty");
        c.arg("--hold");
        c.args(argv);
        c
    }
    pub fn wezterm(argv: &[String]) -> Command {
        let mut c = Command::new("wezterm");
        c.arg("start").arg("--");
        c.args(argv);
        c
    }
}

/// Assemble the launchers valid for the current OS.
fn all_launchers() -> Vec<Launcher> {
    let mut v: Vec<Launcher> = Vec::new();

    #[cfg(windows)]
    {
        v.push(Launcher {
            id: "wt",
            display: "Windows Terminal",
            detect: win::detect_wt,
            build: win::wt,
        });
        v.push(Launcher {
            id: "powershell",
            display: "PowerShell",
            detect: win::detect_powershell,
            build: win::powershell,
        });
        v.push(Launcher {
            id: "cmd",
            display: "Command Prompt",
            detect: win::detect_cmd,
            build: win::cmd,
        });
    }

    #[cfg(target_os = "macos")]
    {
        v.push(Launcher {
            id: "macos-terminal",
            display: "Terminal",
            detect: || true,
            build: mac::terminal,
        });
        v.push(Launcher {
            id: "iterm2",
            display: "iTerm2",
            detect: || app_bundle("iTerm"),
            build: mac::iterm,
        });
        v.push(Launcher {
            id: "ghostty",
            display: "Ghostty",
            detect: || app_bundle("Ghostty") || on_path("ghostty"),
            build: mac::ghostty,
        });
    }

    #[cfg(target_os = "linux")]
    {
        v.push(Launcher {
            id: "gnome-terminal",
            display: "GNOME Terminal",
            detect: || on_path("gnome-terminal"),
            build: linux::gnome,
        });
        v.push(Launcher {
            id: "konsole",
            display: "Konsole",
            detect: || on_path("konsole"),
            build: linux::konsole,
        });
        v.push(Launcher {
            id: "xterm",
            display: "xterm",
            detect: || on_path("xterm"),
            build: linux::xterm,
        });
        v.push(Launcher {
            id: "ghostty",
            display: "Ghostty",
            detect: || on_path("ghostty"),
            build: linux::ghostty,
        });
    }

    // Cross-platform emulators (macOS + Linux), detected on PATH.
    #[cfg(unix)]
    {
        v.push(Launcher {
            id: "alacritty",
            display: "Alacritty",
            detect: || on_path("alacritty"),
            build: unixterm::alacritty,
        });
        v.push(Launcher {
            id: "kitty",
            display: "kitty",
            detect: || on_path("kitty"),
            build: unixterm::kitty,
        });
        v.push(Launcher {
            id: "wezterm",
            display: "WezTerm",
            detect: || on_path("wezterm"),
            build: unixterm::wezterm,
        });
    }

    v
}

/// Terminals detected as installed on this machine, in registry order.
pub fn available() -> Vec<TerminalInfo> {
    all_launchers()
        .into_iter()
        .filter(|l| (l.detect)())
        .map(|l| TerminalInfo {
            id: l.id.to_string(),
            display: l.display.to_string(),
        })
        .collect()
}

/// Launch `ssh_argv` in the terminal with the given id. Errors if unknown or not installed.
pub fn launch(id: &str, ssh_argv: &[String]) -> Result<(), String> {
    let launcher = all_launchers()
        .into_iter()
        .find(|l| l.id == id)
        .ok_or_else(|| format!("unknown terminal '{id}'"))?;
    if !(launcher.detect)() {
        return Err(format!("terminal '{id}' is not available"));
    }
    spawn_detached((launcher.build)(ssh_argv))
}

/// Spawn a command fully detached: no inherited stdio, and we don't wait on it.
fn spawn_detached(mut cmd: Command) -> Result<(), String> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    cmd.spawn()
        .map(|_child| ())
        .map_err(|e| format!("failed to launch terminal: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arg_strings(cmd: &Command) -> Vec<String> {
        cmd.get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn available_never_panics() {
        // Detection probes the filesystem/PATH; it must be safe to call on any machine.
        let _ = available();
    }

    #[test]
    fn unknown_terminal_is_an_error() {
        assert!(launch("does-not-exist", &["ssh".into(), "u@h".into()]).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn wt_builds_new_tab_argv() {
        let cmd = win::wt(&["ssh".to_string(), "u@h".to_string()]);
        assert_eq!(cmd.get_program().to_string_lossy(), "wt.exe");
        assert_eq!(arg_strings(&cmd), vec!["new-tab", "ssh", "u@h"]);
    }

    #[cfg(windows)]
    #[test]
    fn powershell_join_neutralizes_injection() {
        let s = powershell_join(&[
            "ssh".to_string(),
            "-i".to_string(),
            "C:\\k ey".to_string(),
            "u@h; rm -rf /".to_string(),
        ]);
        assert!(s.starts_with("& 'ssh'"));
        assert!(s.contains("'C:\\k ey'"));
        // The whole malicious token is single-quoted, so ';' cannot start a new statement.
        assert!(s.contains("'u@h; rm -rf /'"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn applescript_quote_escapes_quotes_and_backslashes() {
        assert_eq!(applescript_quote(r#"a"b\c"#), r#"a\"b\\c"#);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn posix_join_quotes_dangerous_tokens() {
        let s = posix_join(&["ssh".to_string(), "u@h; rm -rf /".to_string()]);
        // shell-words single-quotes the token containing the ';'.
        assert!(s.contains("'u@h; rm -rf /'"));
    }
}
