const MAP = {
  critical: {
    bg: "bg-red-500/25",
    border: "border-red-500/50",
    text: "text-red-200",
    label: "critical",
  },
  high: {
    bg: "bg-orange-500/25",
    border: "border-orange-500/50",
    text: "text-orange-200",
    label: "high",
  },
  medium: {
    bg: "bg-yellow-500/25",
    border: "border-yellow-500/50",
    text: "text-yellow-200",
    label: "medium",
  },
  low: {
    bg: "bg-blue-500/25",
    border: "border-blue-500/50",
    text: "text-blue-200",
    label: "low",
  },
  info: {
    bg: "bg-slate-500/25",
    border: "border-slate-500/50",
    text: "text-slate-200",
    label: "info",
  },
};

export default function SeverityBadge({ severity }) {
  const s = MAP[severity] || MAP.info;
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wide border ${s.bg} ${s.border} ${s.text}`}
    >
      {s.label}
    </span>
  );
}
