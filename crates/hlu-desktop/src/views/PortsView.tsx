import { useCallback, useEffect, useState } from "react";
import * as api from "../api";
import type { Device } from "../types";
import { displayName } from "../format";

export function PortsView() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [full, setFull] = useState(false);
  const [scanning, setScanning] = useState<Record<string, boolean>>({});
  const [scanningAll, setScanningAll] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .listDevices()
      .then(setDevices)
      .catch((e) => setError(String(e)));
  }, []);

  const scanOne = useCallback(
    async (device: Device) => {
      setScanning((s) => ({ ...s, [device.id]: true }));
      setError(null);
      try {
        const services = await api.scanPorts(device.ip, full);
        setDevices((prev) =>
          prev.map((d) =>
            d.id === device.id
              ? { ...d, services, ports_scanned_at: Math.floor(Date.now() / 1000) }
              : d,
          ),
        );
      } catch (e) {
        setError(String(e));
      } finally {
        setScanning((s) => ({ ...s, [device.id]: false }));
      }
    },
    [full],
  );

  const scanAll = useCallback(async () => {
    setScanningAll(true);
    setError(null);
    for (const device of devices) {
      await scanOne(device);
    }
    setScanningAll(false);
  }, [devices, scanOne]);

  return (
    <div className="tool">
      <header className="tool-header">
        <div>
          <h2>Ports &amp; Services</h2>
          <p className="tool-sub">
            Find open ports and identify running applications
            {full ? " — full range (1–65535), slower" : " — common ports (fast)"}
          </p>
        </div>
        <div className="header-actions">
          <label
            className="toggle"
            title="Off: ~70 common service ports (fast). On: all 65535 ports — much slower, especially for firewalled hosts."
          >
            <input
              type="checkbox"
              checked={full}
              onChange={(e) => setFull(e.target.checked)}
            />
            <span>Full range</span>
          </label>
          <button
            className="scan-btn"
            onClick={scanAll}
            disabled={scanningAll || devices.length === 0}
          >
            {scanningAll ? "Scanning…" : "Scan all"}
          </button>
        </div>
      </header>

      {error && <div className="error-banner">{error}</div>}

      <div className="device-list">
        {devices.length === 0 ? (
          <div className="empty">
            <p>No devices yet — run a scan in the Devices tool first.</p>
          </div>
        ) : (
          devices.map((device) => (
            <PortCard
              key={device.id}
              device={device}
              scanning={!!scanning[device.id]}
              onScan={() => scanOne(device)}
            />
          ))
        )}
      </div>
    </div>
  );
}

function PortCard({
  device,
  scanning,
  onScan,
}: {
  device: Device;
  scanning: boolean;
  onScan: () => void;
}) {
  const scanned = device.ports_scanned_at != null;
  return (
    <article className="port-card">
      <div className="port-card-head">
        <div className="device-main">
          <span className="device-name-static">{displayName(device)}</span>
          <div className="meta">
            <span className="chip">{device.ip}</span>
            {device.vendor && <span className="chip">{device.vendor}</span>}
            {scanned && (
              <span className="chip">{device.services.length} open</span>
            )}
          </div>
        </div>
        <button className="copy-btn" onClick={onScan} disabled={scanning}>
          {scanning
            ? "Scanning…"
            : device.services.length
              ? "Rescan"
              : "Scan ports"}
        </button>
      </div>

      {device.services.length > 0 && (
        <div className="services">
          {device.services.map((s) => (
            <div className="service-row" key={s.port}>
              <span className="port-num mono">{s.port}</span>
              <span className="port-service">
                {s.product ?? s.service ?? "unknown"}
                {s.version && <span className="port-version"> {s.version}</span>}
                {s.product && s.service && (
                  <span className="port-proto"> · {s.service}</span>
                )}
              </span>
              <span className="port-detail">
                {s.title && <span className="port-title">{s.title}</span>}
                {s.banner && <span className="port-banner mono">{s.banner}</span>}
              </span>
            </div>
          ))}
        </div>
      )}

      {!scanning && scanned && device.services.length === 0 && (
        <div className="services-empty">No open ports found.</div>
      )}
    </article>
  );
}
