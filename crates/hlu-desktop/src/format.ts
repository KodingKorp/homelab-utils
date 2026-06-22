import type { Device, SshStatus } from "./types";

/// Derive the best display name (mirrors `Device::display_name` in Rust).
export function displayName(d: Device): string {
  if (d.custom_name && d.custom_name.trim()) return d.custom_name.trim();
  const clean = (s: string) => s.replace(/\.local\.?$/i, "").replace(/\.$/, "");
  if (d.names.mdns_hostname) return clean(d.names.mdns_hostname);
  if (d.names.upnp_friendly_name) return d.names.upnp_friendly_name;
  if (d.names.reverse_dns) return clean(d.names.reverse_dns);
  if (d.names.netbios) return d.names.netbios;
  if (d.vendor) return `${d.vendor} @ ${d.ip}`;
  return d.ip;
}

/// The login that will be used for the ssh command.
export function chosenUser(d: Device): string {
  if (d.ssh_user && d.ssh_user.trim()) return d.ssh_user.trim();
  return d.ssh.suggested_users[0] ?? "root";
}

export const SSH_LABEL: Record<SshStatus, string> = {
  confirmed_ssh: "SSH",
  port_reachable: "Port open",
  unreachable: "No SSH",
  unknown: "Unknown",
};

/// Whether the SSH action row is meaningful for this device.
export function sshActionable(d: Device): boolean {
  return (
    d.ssh.status === "confirmed_ssh" ||
    d.ssh.status === "port_reachable" ||
    d.open_ports.includes(22)
  );
}
