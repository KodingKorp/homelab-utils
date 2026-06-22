// Thin wrappers around the Tauri command bridge. Keys match the Rust command parameter names.

import { invoke } from "@tauri-apps/api/core";
import type { CredentialMeta, Device, ServicePort, TerminalInfo } from "./types";

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

/** Forget a device: remove it from the inventory and delete any saved credential. */
export function removeDevice(id: string): Promise<void> {
  return invoke<void>("remove_device", { id });
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

// ---- SSH credentials (per device, keyed by MAC) ----

export function getCredentialMeta(mac: string): Promise<CredentialMeta | null> {
  return invoke<CredentialMeta | null>("get_credential_meta", { mac });
}

export function setSshPassword(mac: string, password: string): Promise<void> {
  return invoke<void>("set_ssh_password", { mac, password });
}

export function setSshKey(mac: string, keyPath: string): Promise<void> {
  return invoke<void>("set_ssh_key", { mac, key_path: keyPath });
}

export function clearCredential(mac: string): Promise<void> {
  return invoke<void>("clear_credential", { mac });
}

/** Decrypt the saved password and copy it to the clipboard (server-side; plaintext never returned). */
export function copySshPassword(mac: string): Promise<void> {
  return invoke<void>("copy_ssh_password", { mac });
}

// ---- Terminal launching ----

export function listTerminals(): Promise<TerminalInfo[]> {
  return invoke<TerminalInfo[]>("list_terminals");
}

export function getDefaultTerminal(): Promise<string | null> {
  return invoke<string | null>("get_default_terminal");
}

export function setDefaultTerminal(id: string): Promise<void> {
  return invoke<void>("set_default_terminal", { id });
}

export function openSshTerminal(
  mac: string,
  terminalId?: string | null,
): Promise<void> {
  return invoke<void>("open_ssh_terminal", {
    mac,
    terminal_id: terminalId ?? null,
  });
}
