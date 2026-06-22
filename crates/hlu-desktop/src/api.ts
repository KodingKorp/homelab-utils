// Thin wrappers around the Tauri command bridge. Keys match the Rust command parameter names.

import { invoke } from "@tauri-apps/api/core";
import type { Device, ServicePort } from "./types";

export function scan(opts?: {
  enableMdns?: boolean;
  enableSsh?: boolean;
}): Promise<Device[]> {
  return invoke<Device[]>("scan", {
    enable_mdns: opts?.enableMdns ?? true,
    enable_ssh: opts?.enableSsh ?? true,
  });
}

export function listDevices(): Promise<Device[]> {
  return invoke<Device[]>("list_devices");
}

export function scanPorts(ip: string, full = true): Promise<ServicePort[]> {
  return invoke<ServicePort[]>("scan_ports", { ip, full });
}

export function setCustomName(id: string, name: string | null): Promise<void> {
  return invoke<void>("set_custom_name", { id, name });
}

export function setUsername(id: string, user: string | null): Promise<void> {
  return invoke<void>("set_username", { id, user });
}

export function copySshCommand(
  id: string,
  user?: string | null,
): Promise<string> {
  return invoke<string>("copy_ssh_command", { id, user: user ?? null });
}
