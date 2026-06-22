import { useState } from "react";
import type { ReactNode } from "react";
import { DevicesView } from "./views/DevicesView";
import { PortsView } from "./views/PortsView";
import { ToolPlaceholder } from "./views/ToolPlaceholder";
import { GearIcon, PortsIcon, RadarIcon } from "./icons";

type Tool = {
  id: string;
  label: string;
  icon: ReactNode;
  render: () => ReactNode;
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
    render: () => (
      <ToolPlaceholder
        title="Settings"
        hint="Scan options, elevated 'deep scan' mode, and auto-update preferences will live here."
      />
    ),
  },
];

export function App() {
  const [activeId, setActiveId] = useState(TOOLS[0].id);
  const active = TOOLS.find((t) => t.id === activeId) ?? TOOLS[0];

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

        <div className="sidebar-footer">v0.1.0</div>
      </aside>

      <main className="content">{active.render()}</main>
    </div>
  );
}
