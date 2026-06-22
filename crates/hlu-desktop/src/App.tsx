import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import { getVersion } from "@tauri-apps/api/app";
import { DevicesView } from "./views/DevicesView";
import { PortsView } from "./views/PortsView";
import { SettingsView } from "./views/SettingsView";
import { UpdateBanner } from "./components/UpdateBanner";
import { checkForUpdate, type Update } from "./updater";
import { GearIcon, PortsIcon, RadarIcon } from "./icons";

// Context passed to each tool's render so it can surface an available update to the app shell.
type ToolContext = { onUpdateFound: (update: Update) => void };

type Tool = {
  id: string;
  label: string;
  icon: ReactNode;
  render: (ctx: ToolContext) => ReactNode;
};

// The tool registry. Add a new homelab tool by appending one entry here — the left nav and
// content area are driven entirely off this list.
const TOOLS: Tool[] = [
  {
    id: "devices",
    label: "Devices",
    icon: <RadarIcon />,
    render: () => <DevicesView />,
  },
  {
    id: "ports",
    label: "Ports",
    icon: <PortsIcon />,
    render: () => <PortsView />,
  },
  {
    id: "settings",
    label: "Settings",
    icon: <GearIcon />,
    render: (ctx) => <SettingsView onUpdateFound={ctx.onUpdateFound} />,
  },
];

// Check for an update at most once per app launch.
let autoChecked = false;

export function App() {
  const [activeId, setActiveId] = useState(TOOLS[0].id);
  const [update, setUpdate] = useState<Update | null>(null);
  const [version, setVersion] = useState("");
  const active = TOOLS.find((t) => t.id === activeId) ?? TOOLS[0];

  useEffect(() => {
    getVersion()
      .then((v) => setVersion(`v${v}`))
      .catch(() => setVersion(""));
    if (autoChecked) return;
    autoChecked = true;
    // Silent on failure (e.g. no published release yet / offline) — Settings has a manual check.
    checkForUpdate()
      .then((u) => u && setUpdate(u))
      .catch(() => {});
  }, []);

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="sidebar-brand">
          <span className="brand-mark" aria-hidden />
          <span className="sidebar-title">Homelab Utils</span>
        </div>

        <nav className="nav">
          {TOOLS.map((tool) => (
            <button
              key={tool.id}
              className={`nav-item ${tool.id === activeId ? "active" : ""}`}
              onClick={() => setActiveId(tool.id)}
            >
              <span className="nav-icon">{tool.icon}</span>
              <span className="nav-label">{tool.label}</span>
            </button>
          ))}
        </nav>

        <div className="sidebar-footer">{version}</div>
      </aside>

      <main className="content">
        {update && (
          <UpdateBanner update={update} onDismiss={() => setUpdate(null)} />
        )}
        {active.render({ onUpdateFound: setUpdate })}
      </main>
    </div>
  );
}
