import { Zap, RefreshCw } from "lucide-react";

function timeAgo(dateStr) {
  if (!dateStr) return "";
  try {
    const diff = Date.now() - new Date(dateStr).getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return "just now";
    if (mins < 60) return `${mins}m ago`;
    const hours = Math.floor(mins / 60);
    if (hours < 24) return `${hours}h ago`;
    const days = Math.floor(hours / 24);
    return `${days}d ago`;
  } catch {
    return "";
  }
}

export default function CacheBanner({ cacheInfo, onReanalyze, isLoading }) {
  if (!cacheInfo) return null;

  return (
    <div
      className="animate-slide-down flex items-center justify-between gap-4 py-2.5 px-4 rounded-xl text-xs"
      style={{
        background: "rgba(34,211,238,0.07)",
        border: "1px solid rgba(34,211,238,0.18)",
      }}
    >
      <div className="flex items-center gap-2">
        <Zap size={14} style={{ color: "#22d3ee" }} />
        <span style={{ color: "#22d3ee", fontWeight: 600 }}>Cached result</span>
        {cacheInfo.created_at && (
          <span style={{ color: "var(--text-muted)" }}>
            from {timeAgo(cacheInfo.created_at)}
          </span>
        )}
      </div>
      <button
        onClick={onReanalyze}
        disabled={isLoading}
        className="flex items-center gap-1.5 py-1 px-3 rounded-lg text-xs font-semibold transition-all hover:scale-105"
        style={{
          background: "rgba(34,211,238,0.12)",
          border: "1px solid rgba(34,211,238,0.25)",
          color: "#22d3ee",
          opacity: isLoading ? 0.5 : 1,
          cursor: isLoading ? "not-allowed" : "pointer",
        }}
      >
        <RefreshCw size={12} className={isLoading ? "animate-spin-slow" : ""} />
        Re-analyze
      </button>
    </div>
  );
}
