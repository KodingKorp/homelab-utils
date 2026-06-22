import { useCallback, useEffect, useMemo, useState } from "react";
import { open as openFileDialog } from "@tauri-apps/plugin-dialog";
import * as api from "../api";
import type { AuthMethod, CredentialMeta, Device, TerminalInfo } from "../types";
import { SSH_LABEL, chosenUser, displayName, sshActionable } from "../format";

// Refresh automatically once per app launch so persisted status (SSH, liveness) is never stale.
let autoScanned = false;

export function DevicesView() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [toast, setToast] = useState<string | null>(null);

  const showToast = useCallback((message: string) => {
    setToast(message);
    window.setTimeout(() => setToast(null), 2600);
  }, []);

  const patchDevice = useCallback((id: string, patch: Partial<Device>) => {
    setDevices((prev) =>
      prev.map((d) => (d.id === id ? { ...d, ...patch } : d)),
    );
  }, []);

  const removeDevice = useCallback(
    async (id: string) => {
      try {
        await api.removeDevice(id);
        setDevices((prev) => prev.filter((d) => d.id !== id));
        showToast("Device forgotten");
      } catch (e) {
        showToast(`Could not remove: ${e}`);
      }
    },
    [showToast],
  );

  const runScan = useCallback(async () => {
    setScanning(true);
    setError(null);
    try {
      setDevices(await api.scan());
    } catch (e) {
      setError(String(e));
    } finally {
      setScanning(false);
    }
  }, []);

  // Show persisted devices instantly, then auto-refresh once per launch so SSH/liveness is current.
  useEffect(() => {
    api
      .listDevices()
      .then(setDevices)
      .catch((e) => setError(String(e)));
    if (!autoScanned) {
      autoScanned = true;
      void runScan();
    }
  }, [runScan]);

  const stats = useMemo(() => {
    const online = devices.filter((d) => d.status === "online").length;
    const ssh = devices.filter((d) => d.ssh.status === "confirmed_ssh").length;
    return { total: devices.length, online, ssh };
  }, [devices]);

  return (
    <div className="tool">
      <header className="tool-header">
        <div>
          <h2>Devices</h2>
          <p className="tool-sub">Discover and connect to machines on your network</p>
        </div>
        <button className="scan-btn" onClick={runScan} disabled={scanning}>
          {scanning ? "Scanning…" : "Scan network"}
        </button>
      </header>

      <section className="stats">
        <Stat label="Devices" value={stats.total} />
        <Stat label="Online" value={stats.online} />
        <Stat label="SSH ready" value={stats.ssh} />
      </section>

      {error && <div className="error-banner">{error}</div>}

      <div className="device-list">
        {devices.length === 0 ? (
          <EmptyState scanning={scanning} onScan={runScan} />
        ) : (
          devices.map((d) => (
            <DeviceRow
              key={d.id}
              device={d}
              onPatch={patchDevice}
              onToast={showToast}
              onRemove={removeDevice}
            />
          ))
        )}
      </div>

      {toast && <div className="toast">{toast}</div>}
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="stat">
      <span className="stat-value">{value}</span>
      <span className="stat-label">{label}</span>
    </div>
  );
}

function EmptyState({
  scanning,
  onScan,
}: {
  scanning: boolean;
  onScan: () => void;
}) {
  return (
    <div className="empty">
      <p>No devices yet.</p>
      <button className="scan-btn" onClick={onScan} disabled={scanning}>
        {scanning ? "Scanning…" : "Run your first scan"}
      </button>
    </div>
  );
}

function DeviceRow({
  device,
  onPatch,
  onToast,
  onRemove,
}: {
  device: Device;
  onPatch: (id: string, patch: Partial<Device>) => void;
  onToast: (msg: string) => void;
  onRemove: (id: string) => void | Promise<void>;
}) {
  const [editingName, setEditingName] = useState(false);
  const [nameDraft, setNameDraft] = useState("");
  const [userDraft, setUserDraft] = useState(chosenUser(device));
  const [showCred, setShowCred] = useState(false);
  const offline = device.status === "offline";

  const forget = () => {
    const ok = window.confirm(
      `Forget "${displayName(device)}"? This removes it from the list and deletes any saved credential.`,
    );
    if (ok) void onRemove(device.id);
  };

  const saveName = async () => {
    const value = nameDraft.trim();
    try {
      await api.setCustomName(device.id, value || null);
      onPatch(device.id, { custom_name: value || null });
    } catch (e) {
      onToast(`Could not rename: ${e}`);
    }
    setEditingName(false);
  };

  const saveUser = async () => {
    const value = userDraft.trim();
    try {
      await api.setUsername(device.id, value || null);
      onPatch(device.id, { ssh_user: value || null });
    } catch (e) {
      onToast(`Could not save user: ${e}`);
    }
  };

  const copy = async () => {
    try {
      const cmd = await api.copySshCommand(device.id, userDraft.trim() || null);
      onToast(`Copied: ${cmd}`);
    } catch (e) {
      onToast(`Copy failed: ${e}`);
    }
  };

  const expanded = showCred && !!device.mac;

  return (
    <div className="device-wrap">
      <article
        className={`device${offline ? " offline" : ""}${expanded ? " expanded" : ""}`}
      >
        <span
          className={`status-dot status-${device.status}`}
          title={device.status}
        />

        <div className="device-main">
          {editingName ? (
            <input
              className="name-input"
              autoFocus
              value={nameDraft}
              onChange={(e) => setNameDraft(e.target.value)}
              onBlur={saveName}
              onKeyDown={(e) => {
                if (e.key === "Enter") saveName();
                if (e.key === "Escape") setEditingName(false);
              }}
            />
          ) : (
            <button
              className="device-name"
              title="Click to rename"
              onClick={() => {
                setNameDraft(device.custom_name ?? displayName(device));
                setEditingName(true);
              }}
            >
              {displayName(device)}
            </button>
          )}

          <div className="meta">
            <span className="chip">{device.ip}</span>
            {device.mac && <span className="chip mono">{device.mac}</span>}
            {device.vendor && <span className="chip">{device.vendor}</span>}
            {offline && <span className="chip dim">offline</span>}
            {device.open_ports.length > 0 && (
              <span className="chip mono">:{device.open_ports.join(" :")}</span>
            )}
          </div>
        </div>

        <div className="device-ssh">
          <span
            className={`badge ssh-${device.ssh.status}`}
            title={device.ssh.banner ?? ""}
          >
            {SSH_LABEL[device.ssh.status]}
          </span>

          {sshActionable(device) && (
            <div className="ssh-actions">
              <span className="at">ssh</span>
              <input
                className="user-input"
                value={userDraft}
                spellCheck={false}
                onChange={(e) => setUserDraft(e.target.value)}
                onBlur={saveUser}
                aria-label="SSH username"
              />
              <span className="at">@{device.ip}</span>
              <button className="copy-btn" onClick={copy}>
                Copy
              </button>
            </div>
          )}

          <div className="device-actions">
            {device.mac && (
              <button
                className={`chip-btn ${showCred ? "active" : ""}`}
                onClick={() => setShowCred((v) => !v)}
                aria-expanded={showCred}
                title="Saved SSH credentials"
              >
                <KeyIcon />
                <span>Credentials</span>
              </button>
            )}
            <button
              className="chip-btn danger"
              onClick={forget}
              title="Forget this device"
            >
              <TrashIcon />
              <span>Forget</span>
            </button>
          </div>
        </div>
      </article>

      {showCred && device.mac && (
        <CredentialPanel device={device} onPatch={onPatch} onToast={onToast} />
      )}
    </div>
  );
}

function KeyIcon() {
  return (
    <svg
      width="13"
      height="13"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      <circle cx="7.5" cy="15.5" r="4.5" />
      <path d="M10.7 12.3 21 2" />
      <path d="M16.5 6.5 19 9" />
    </svg>
  );
}

function TrashIcon() {
  return (
    <svg
      width="13"
      height="13"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      <path d="M3 6h18" />
      <path d="M8 6V4h8v2" />
      <path d="M6 6l1 14h10l1-14" />
    </svg>
  );
}

function CredentialPanel({
  device,
  onPatch,
  onToast,
}: {
  device: Device;
  onPatch: (id: string, patch: Partial<Device>) => void;
  onToast: (msg: string) => void;
}) {
  const mac = device.mac;

  const [meta, setMeta] = useState<CredentialMeta | null>(null);
  const [account, setAccount] = useState(chosenUser(device));
  const [method, setMethod] = useState<AuthMethod>("password");
  const [password, setPassword] = useState("");
  const [keyPath, setKeyPath] = useState("");
  const [terminals, setTerminals] = useState<TerminalInfo[]>([]);
  const [terminal, setTerminal] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!mac) return;
    api
      .getCredentialMeta(mac)
      .then((m) => {
        setMeta(m);
        if (m) {
          setMethod(m.auth_method);
          setKeyPath(m.key_path ?? "");
        }
      })
      .catch((e) => onToast(String(e)));
    api.listTerminals().then(setTerminals).catch(() => {});
    api
      .getDefaultTerminal()
      .then((d) => d && setTerminal(d))
      .catch(() => {});
  }, [mac, onToast]);

  if (!mac) return null;

  const reloadMeta = () => api.getCredentialMeta(mac).then(setMeta).catch(() => {});

  const saveAccount = async () => {
    const value = account.trim();
    try {
      await api.setUsername(device.id, value || null);
      onPatch(device.id, { ssh_user: value || null });
    } catch (e) {
      onToast(`Could not save account: ${e}`);
    }
  };

  const savePassword = async () => {
    if (!password) {
      onToast("Enter a password first");
      return;
    }
    setBusy(true);
    try {
      await saveAccount();
      await api.setSshPassword(mac, password);
      setPassword("");
      await reloadMeta();
      onToast("Password saved (encrypted)");
    } catch (e) {
      onToast(`Could not save password: ${e}`);
    } finally {
      setBusy(false);
    }
  };

  const browseKey = async () => {
    try {
      const picked = await openFileDialog({
        multiple: false,
        directory: false,
        title: "Select SSH private key",
      });
      if (typeof picked === "string") setKeyPath(picked);
    } catch (e) {
      onToast(`Could not open file picker: ${e}`);
    }
  };

  const saveKey = async () => {
    const value = keyPath.trim();
    if (!value) {
      onToast("Choose a key file first");
      return;
    }
    setBusy(true);
    try {
      await saveAccount();
      await api.setSshKey(mac, value);
      await reloadMeta();
      onToast("SSH key saved");
    } catch (e) {
      onToast(`Could not save key: ${e}`);
    } finally {
      setBusy(false);
    }
  };

  const copyPassword = async () => {
    try {
      await api.copySshPassword(mac);
      onToast("Password copied — paste at the prompt");
    } catch (e) {
      onToast(`Copy failed: ${e}`);
    }
  };

  const openTerminal = async () => {
    setBusy(true);
    try {
      await saveAccount();
      await api.openSshTerminal(mac, terminal || null);
      onToast("Launching terminal…");
    } catch (e) {
      onToast(`Could not open terminal: ${e}`);
    } finally {
      setBusy(false);
    }
  };

  const clearCred = async () => {
    try {
      await api.clearCredential(mac);
      setMeta(null);
      setPassword("");
      onToast("Credential removed");
    } catch (e) {
      onToast(`Could not remove: ${e}`);
    }
  };

  const chooseTerminal = async (id: string) => {
    setTerminal(id);
    try {
      await api.setDefaultTerminal(id);
    } catch {
      /* preference save is non-fatal */
    }
  };

  const status =
    meta?.auth_method === "password" && meta.has_password
      ? "Password saved"
      : meta?.auth_method === "key"
        ? "Key saved"
        : "No credential saved";

  return (
    <section className="cred-panel">
      <div className="cred-grid">
        <span className="cred-label">Account</span>
        <input
          className="cred-input"
          value={account}
          spellCheck={false}
          placeholder="username"
          onChange={(e) => setAccount(e.target.value)}
          onBlur={saveAccount}
          aria-label="SSH account"
        />
        <span className="cred-status">{status}</span>

        <span className="cred-label">Auth</span>
        <div className="auth-toggle">
          <button
            className={method === "password" ? "active" : ""}
            onClick={() => setMethod("password")}
          >
            Password
          </button>
          <button
            className={method === "key" ? "active" : ""}
            onClick={() => setMethod("key")}
          >
            SSH key
          </button>
        </div>
        <span />

        {method === "password" ? (
          <>
            <span className="cred-label">Password</span>
            <input
              className="cred-input"
              type="password"
              value={password}
              placeholder={meta?.has_password ? "•••••••• saved" : "password"}
              onChange={(e) => setPassword(e.target.value)}
              aria-label="SSH password"
            />
            <div className="cred-actions">
              <button
                className="btn-primary"
                onClick={savePassword}
                disabled={busy}
              >
                Save
              </button>
              {meta?.has_password && (
                <button className="btn-ghost" onClick={copyPassword}>
                  Copy
                </button>
              )}
            </div>
          </>
        ) : (
          <>
            <span className="cred-label">Key file</span>
            <div className="cred-input-group">
              <input
                className="cred-input"
                value={keyPath}
                spellCheck={false}
                placeholder="~/.ssh/id_ed25519"
                onChange={(e) => setKeyPath(e.target.value)}
                aria-label="SSH key path"
              />
              <button className="btn-ghost" onClick={browseKey}>
                Browse…
              </button>
            </div>
            <div className="cred-actions">
              <button className="btn-primary" onClick={saveKey} disabled={busy}>
                Save
              </button>
            </div>
          </>
        )}

        <span className="cred-label">Terminal</span>
        {terminals.length > 0 ? (
          <select
            className="cred-input"
            value={terminal}
            onChange={(e) => chooseTerminal(e.target.value)}
          >
            {!terminal && <option value="">Default…</option>}
            {terminals.map((t) => (
              <option key={t.id} value={t.id}>
                {t.display}
              </option>
            ))}
          </select>
        ) : (
          <span className="cred-status">No terminal detected</span>
        )}
        <div className="cred-actions">
          <button
            className="btn-primary"
            onClick={openTerminal}
            disabled={busy || terminals.length === 0}
          >
            Open terminal
          </button>
        </div>
      </div>

      <div className="cred-footer">
        <span className="cred-note">
          {method === "password"
            ? "Password is encrypted on this machine. Copy puts it on the clipboard briefly, then auto-clears."
            : "Only the key path is stored; the key file stays on disk. Open terminal runs ssh -i directly."}
        </span>
        {meta && (
          <button className="btn-ghost danger" onClick={clearCred}>
            Remove credential
          </button>
        )}
      </div>
    </section>
  );
}
