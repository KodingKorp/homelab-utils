// TypeScript mirror of the `hlu_core` serde model. Keep field names in sync with the Rust
// `Device` (serialized snake_case).

export type SshStatus =
  | "unknown"
  | "unreachable"
  | "port_reachable"
  | "confirmed_ssh";

export type DeviceStatus = "online" | "offline" | "unknown";

export interface DeviceNames {
  mdns_hostname: string | null;
  mdns_services: string[];
  upnp_friendly_name: string | null;
  reverse_dns: string | null;
  netbios: string | null;
}

export interface SshInfo {
  status: SshStatus;
  port: number | null;
  banner: string | null;
  os_hint: string | null;
  suggested_users: string[];
}

export interface Device {
  id: string;
  ip: string;
  mac: string | null;
  vendor: string | null;
  custom_name: string | null;
  ssh_user: string | null;
  names: DeviceNames;
  status: DeviceStatus;
  ssh: SshInfo;
  open_ports: number[];
  first_seen: number;
  last_seen: number;
}
