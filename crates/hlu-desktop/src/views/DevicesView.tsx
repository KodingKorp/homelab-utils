import { useCallback, useEffect, useMemo, useState } from "react";
import * as api from "../api";
import type { Device } from "../types";
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
}: {
  device: Device;
  onPatch: (id: string, patch: Partial<Device>) => void;
  onToast: (msg: string) => void;
}) {
  const [editingName, setEditingName] = useState(false);
  const [nameDraft, setNameDraft] = useState("");
  const [userDraft, setUserDraft] = useState(chosenUser(device));

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

  return (
    <article className="device">
      <span className={`status-dot status-${device.status}`} title={device.status} />

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
      </div>
    </article>
  );
}
