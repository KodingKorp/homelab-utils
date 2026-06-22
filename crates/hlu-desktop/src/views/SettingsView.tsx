import { useEffect, useState } from "react";
import { getVersion } from "@tauri-apps/api/app";
import { checkForUpdate, type Update } from "../updater";
import * as api from "../api";
import type { TerminalInfo } from "../types";

export function SettingsView({
  onUpdateFound,
}: {
  onUpdateFound: (update: Update) => void;
}) {
  const [version, setVersion] = useState("");
  const [status, setStatus] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);
  const [terminals, setTerminals] = useState<TerminalInfo[]>([]);
  const [terminal, setTerminal] = useState("");

  useEffect(() => {
    getVersion()
      .then(setVersion)
      .catch(() => setVersion("?"));
    api.listTerminals().then(setTerminals).catch(() => {});
    api
      .getDefaultTerminal()
      .then((d) => d && setTerminal(d))
      .catch(() => {});
  }, []);

  const chooseTerminal = async (id: string) => {
    setTerminal(id);
    try {
      await api.setDefaultTerminal(id);
    } catch {
      /* preference save is non-fatal */
    }
  };

  const check = async () => {
    setChecking(true);
    setStatus(null);
    try {
      const update = await checkForUpdate();
      if (update) {
        setStatus(`Update available: v${update.version}`);
        onUpdateFound(update);
      } else {
        setStatus("You're on the latest version.");
      }
    } catch (e) {
      setStatus(`Couldn't check for updates: ${e}`);
    } finally {
      setChecking(false);
    }
  };

  return (
    <div className="tool">
      <header className="tool-header">
        <div>
          <h2>Settings</h2>
          <p className="tool-sub">App info and updates</p>
        </div>
      </header>

      <div className="settings">
        <div className="setting-row">
          <span>Version</span>
          <span className="mono">v{version}</span>
        </div>
        <div className="setting-row">
          <span>Default terminal</span>
          {terminals.length > 0 ? (
            <select
              className="terminal-select"
              value={terminal}
              onChange={(e) => chooseTerminal(e.target.value)}
            >
              {!terminal && <option value="">Choose…</option>}
              {terminals.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.display}
                </option>
              ))}
            </select>
          ) : (
            <span className="mono">none detected</span>
          )}
        </div>
        <div className="setting-row">
          <span>Updates</span>
          <button className="copy-btn" onClick={check} disabled={checking}>
            {checking ? "Checking…" : "Check for updates"}
          </button>
        </div>
        {status && <p className="setting-status">{status}</p>}
      </div>
    </div>
  );
}
