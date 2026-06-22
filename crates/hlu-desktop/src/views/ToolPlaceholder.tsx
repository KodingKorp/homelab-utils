// A stub view for tools that are not built yet — shows the pattern for adding new tools.

export function ToolPlaceholder({ title, hint }: { title: string; hint: string }) {
  return (
    <div className="tool">
      <header className="tool-header">
        <div>
          <h2>{title}</h2>
          <p className="tool-sub">Coming soon</p>
        </div>
      </header>
      <div className="placeholder">
        <p>{hint}</p>
      </div>
    </div>
  );
}
