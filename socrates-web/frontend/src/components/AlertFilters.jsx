import { useMemo } from "react";

const STATUSES = ["open", "investigating", "resolved", "false_positive", "escalated"];
const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const RANGES = [
  { id: "1h", label: "Last 1h" },
  { id: "24h", label: "24h" },
  { id: "7d", label: "7d" },
  { id: "30d", label: "30d" },
  { id: "all", label: "All" },
];

function toggleCsv(current, value) {
  const set = new Set((current || "").split(",").filter(Boolean));
  if (set.has(value)) set.delete(value);
  else set.add(value);
  return [...set].join(",");
}

export default function AlertFilters({ filters, setFilters, sources }) {
  const statusSet = useMemo(
    () => new Set((filters.status || []).filter(Boolean)),
    [filters.status]
  );
  const severitySet = useMemo(
    () => new Set((filters.severity || []).filter(Boolean)),
    [filters.severity]
  );

  return (
    <div
      className="rounded-xl border p-4 space-y-4"
      style={{ borderColor: "var(--border)", background: "var(--bg-card)" }}
    >
      <h2 className="text-xs font-semibold uppercase tracking-widest" style={{ color: "var(--text-muted)" }}>
        Filters
      </h2>

      <div>
        <label className="block text-[10px] uppercase mb-1.5" style={{ color: "var(--text-muted)" }}>
          Status
        </label>
        <div className="flex flex-wrap gap-1.5">
          {STATUSES.map((s) => (
            <button
              key={s}
              type="button"
              onClick={() => {
                const csv = toggleCsv(filters.status?.join(","), s);
                setFilters({
                  status: csv || undefined,
                });
              }}
              className={`px-2 py-0.5 rounded text-[10px] border transition-colors ${
                statusSet.has(s)
                  ? "bg-cyan-500/20 border-cyan-500/50 text-cyan-200"
                  : "border-transparent bg-black/20 opacity-70 hover:opacity-100"
              }`}
              style={
                !statusSet.has(s)
                  ? { color: "var(--text-secondary)", borderColor: "var(--border)" }
                  : undefined
              }
            >
              {s.replace("_", " ")}
            </button>
          ))}
        </div>
      </div>

      <div>
        <label className="block text-[10px] uppercase mb-1.5" style={{ color: "var(--text-muted)" }}>
          Severity
        </label>
        <div className="flex flex-wrap gap-1.5">
          {SEVERITIES.map((s) => (
            <button
              key={s}
              type="button"
              onClick={() => {
                const csv = toggleCsv(filters.severity?.join(","), s);
                setFilters({
                  severity: csv || undefined,
                });
              }}
              className={`px-2 py-0.5 rounded text-[10px] border transition-colors ${
                severitySet.has(s)
                  ? "bg-amber-500/20 border-amber-500/50 text-amber-200"
                  : "border-transparent bg-black/20 opacity-70 hover:opacity-100"
              }`}
              style={
                !severitySet.has(s)
                  ? { color: "var(--text-secondary)", borderColor: "var(--border)" }
                  : undefined
              }
            >
              {s}
            </button>
          ))}
        </div>
      </div>

      <div>
        <label className="block text-[10px] uppercase mb-1.5" style={{ color: "var(--text-muted)" }}>
          Time range
        </label>
        <div className="flex flex-wrap gap-1">
          {RANGES.map((r) => (
            <button
              key={r.id}
              type="button"
              onClick={() => setFilters({ range: r.id === "24h" ? undefined : r.id })}
              className={`px-2 py-0.5 rounded text-[10px] border ${
                (filters.range || "24h") === r.id
                  ? "bg-violet-500/20 border-violet-500/50 text-violet-200"
                  : ""
              }`}
              style={
                (filters.range || "24h") !== r.id
                  ? { color: "var(--text-secondary)", borderColor: "var(--border)" }
                  : undefined
              }
            >
              {r.label}
            </button>
          ))}
        </div>
      </div>

      <div>
        <label className="block text-[10px] uppercase mb-1.5" style={{ color: "var(--text-muted)" }}>
          Source
        </label>
        <select
          value={filters.source || ""}
          onChange={(e) => setFilters({ source: e.target.value || undefined })}
          className="w-full text-xs rounded-lg border px-2 py-1.5 font-mono"
          style={{
            borderColor: "var(--border)",
            background: "var(--bg-primary)",
            color: "var(--text-primary)",
          }}
        >
          <option value="">All sources</option>
          {sources.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </div>

      <div>
        <label className="block text-[10px] uppercase mb-1.5" style={{ color: "var(--text-muted)" }}>
          Search
        </label>
        <input
          type="search"
          placeholder="Rule, title, IOC…"
          value={filters.q || ""}
          onChange={(e) => setFilters({ q: e.target.value || undefined })}
          className="w-full text-xs rounded-lg border px-2 py-1.5"
          style={{
            borderColor: "var(--border)",
            background: "var(--bg-primary)",
            color: "var(--text-primary)",
          }}
        />
      </div>
    </div>
  );
}
