// Thin wrapper around the Tauri updater + process plugins.

import { check, type Update } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";

export type { Update };

/// Check GitHub Releases for a newer signed version. Returns the Update, or null if up to date.
export function checkForUpdate(): Promise<Update | null> {
  return check();
}

/// Download + install an update (verifying its signature), reporting progress, then relaunch.
export async function applyUpdate(
  update: Update,
  onProgress?: (percent: number | null) => void,
): Promise<void> {
  let downloaded = 0;
  let total: number | null = null;

  await update.downloadAndInstall((event) => {
    switch (event.event) {
      case "Started":
        total = event.data.contentLength ?? null;
        break;
      case "Progress":
        downloaded += event.data.chunkLength;
        onProgress?.(total ? Math.round((downloaded / total) * 100) : null);
        break;
      case "Finished":
        onProgress?.(100);
        break;
    }
  });

  await relaunch();
}
