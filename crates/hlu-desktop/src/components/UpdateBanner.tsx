import { useState } from "react";
import { applyUpdate, type Update } from "../updater";

export function UpdateBanner({
  update,
  onDismiss,
}: {
  update: Update;
  onDismiss: () => void;
}) {
  const [installing, setInstalling] = useState(false);
  const [percent, setPercent] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  const install = async () => {
    setInstalling(true);
    setError(null);
    try {
      // On success the app relaunches into the new version, so nothing runs after this.
      await applyUpdate(update, setPercent);
    } catch (e) {
      setError(String(e));
      setInstalling(false);
    }
  };

  return (
    <div className="update-banner">
      <div className="update-info">
        <strong>Update available — v{update.version}</strong>
        {update.body && <span className="update-notes">{update.body}</span>}
        {error && <span className="update-error">{error}</span>}
      </div>
      <div className="update-actions">
        {installing ? (
          <span className="update-progress">
            {percent != null ? `Installing… ${percent}%` : "Installing…"}
          </span>
        ) : (
          <>
            <button className="scan-btn" onClick={install}>
              Update now
            </button>
            <button className="copy-btn" onClick={onDismiss}>
              Later
            </button>
          </>
        )}
      </div>
    </div>
  );
}
