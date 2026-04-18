import { Loader2 } from "lucide-react";

export default function VerdictBadge({ verdict, pending }) {
  if (pending) {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs" style={{ color: "var(--text-muted)" }}>
        <Loader2 className="w-3.5 h-3.5 animate-spin-slow shrink-0" />
        <span className="italic">analyzing…</span>
      </span>
    );
  }

  if (!verdict) {
    return (
      <span className="text-[10px] uppercase tracking-wide px-2 py-0.5 rounded border border-dashed border-slate-500/50 text-slate-400">
        pending
      </span>
    );
  }

  const v = (verdict.verdict || "").toLowerCase();
  const styles = {
    malicious: "bg-red-500/20 border-red-500/40 text-red-200",
    suspicious: "bg-amber-500/20 border-amber-500/40 text-amber-200",
    benign: "bg-emerald-500/20 border-emerald-500/40 text-emerald-200",
    inconclusive:
      "bg-slate-600/30 border-slate-500/50 text-slate-300",
  };
  const cls = styles[v] || styles.inconclusive;

  return (
    <span
      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase tracking-wide border ${cls}`}
    >
      {v || "—"}
      {v === "inconclusive" && (
        <span className="text-[9px] font-normal opacity-80 normal-case">needs review</span>
      )}
    </span>
  );
}
