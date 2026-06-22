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

export interface ServicePort {
  port: number;
  service: string | null;
  product: string | null;
  version: string | null;
  title: string | null;
  banner: string | null;
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
  services: ServicePort[];
  ports_scanned_at: number | null;
  first_seen: number;
  last_seen: number;
}

export type AuthMethod = "password" | "key";

/** Non-secret view of a saved credential — never carries the password itself. */
export interface CredentialMeta {
  mac: string;
  auth_method: AuthMethod;
  has_password: boolean;
  key_path: string | null;
}

/** A terminal emulator detected on this machine. */
export interface TerminalInfo {
  id: string;
  display: string;
}
