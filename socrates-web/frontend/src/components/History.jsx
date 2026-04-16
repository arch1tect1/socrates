import { Clock, Globe, Hash, Link, Shield, Zap } from "lucide-react";

const TYPE_ICON = {
  ip: Globe,
  domain: Globe,
  url: Link,
  hash: Hash,
};

const VERDICT_PILL = {
  MALICIOUS: "pill-red",
  SUSPICIOUS: "pill-orange",
  "LIKELY BENIGN": "pill-green",
  INCONCLUSIVE: "pill-purple",
};

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
    if (days === 1) return "yesterday";
    return `${days}d ago`;
  } catch {
    return "";
  }
}

export default function History({ items, onSelect }) {
  if (!items || items.length === 0) return null;

  return (
    <div className="card w-full max-w-3xl mx-auto">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Clock size={14} style={{ color: "var(--text-muted)" }} />
          <h3 className="section-label">Recent Queries</h3>
        </div>
      </div>

      <div className="space-y-1 max-h-60 overflow-y-auto">
        {items.map((item, i) => {
          const Icon = TYPE_ICON[item.type] || Shield;
          return (
            <button
              key={item.id || i}
              onClick={() => onSelect(item.ioc)}
              className="w-full flex items-center gap-3 py-2.5 px-3 rounded-lg text-left transition-all duration-150 hover:scale-[1.01]"
              style={{ background: "transparent" }}
              onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-card-hover)")}
              onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
            >
              <Icon size={14} style={{ color: "var(--accent-cyan)", flexShrink: 0 }} />
              <span
                className="text-sm font-mono truncate flex-1 min-w-0"
                style={{ color: "var(--text-primary)" }}
              >
                {item.ioc}
              </span>
              {item.verdict && (
                <span className={`pill ${VERDICT_PILL[item.verdict] || "pill-purple"} text-[9px] flex-shrink-0`}>
                  {item.verdict}
                </span>
              )}
              {item.cached && (
                <Zap size={12} style={{ color: "#22d3ee", flexShrink: 0 }} title="Cached" />
              )}
              <span
                className="text-[10px] tabular-nums flex-shrink-0 min-w-[52px] text-right"
                style={{ color: "var(--text-muted)" }}
              >
                {item.created_at ? timeAgo(item.created_at) : item.timestamp || ""}
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
}
