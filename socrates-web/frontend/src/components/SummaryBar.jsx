import { Activity, Clock, Tag, Zap } from "lucide-react";

const VERDICT_COLORS = {
  MALICIOUS: { bg: "rgba(239,68,68,0.13)", border: "rgba(239,68,68,0.27)", color: "#ef4444" },
  SUSPICIOUS: { bg: "rgba(245,158,11,0.13)", border: "rgba(245,158,11,0.27)", color: "#f59e0b" },
  "LIKELY BENIGN": { bg: "rgba(34,197,94,0.13)", border: "rgba(34,197,94,0.27)", color: "#22c55e" },
  INCONCLUSIVE: { bg: "rgba(167,139,250,0.13)", border: "rgba(167,139,250,0.27)", color: "#a78bfa" },
};

const TYPE_LABELS = {
  ip: "IP Address",
  domain: "Domain",
  url: "URL",
  hash: "File Hash",
};

export default function SummaryBar({ sources, verdict, totalElapsed, iocType }) {
  if (!sources || sources.length === 0) return null;

  const complete = sources.filter((s) => s.status === "complete").length;
  const errored = sources.filter((s) => s.status === "error").length;
  const skipped = sources.filter((s) => s.status === "skipped").length;
  const total = sources.length;

  const vc = verdict ? VERDICT_COLORS[verdict.verdict] || VERDICT_COLORS.INCONCLUSIVE : null;

  return (
    <div className="animate-slide-down card !py-3 !px-5">
      <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-xs">
        <div className="flex items-center gap-2">
          <Activity size={13} style={{ color: "var(--accent-cyan)" }} />
          <span style={{ color: "var(--text-muted)" }}>SOURCES</span>
          <span style={{ color: "var(--text-primary)" }}>
            {complete} complete
            {errored > 0 && <span style={{ color: "#ef4444" }}>, {errored} error</span>}
            {skipped > 0 && <span style={{ color: "var(--text-muted)" }}>, {skipped} skipped</span>}
            <span style={{ color: "var(--text-muted)" }}> / {total}</span>
          </span>
        </div>

        {vc && (
          <div className="flex items-center gap-2">
            <Zap size={13} style={{ color: vc.color }} />
            <span style={{ color: "var(--text-muted)" }}>VERDICT</span>
            <span
              className="pill text-[10px]"
              style={{ background: vc.bg, border: `1px solid ${vc.border}`, color: vc.color }}
            >
              {verdict.verdict}
            </span>
            <span className="pill text-[10px] pill-cyan">{verdict.confidence}</span>
          </div>
        )}

        {totalElapsed != null && (
          <div className="flex items-center gap-2">
            <Clock size={13} style={{ color: "var(--text-muted)" }} />
            <span style={{ color: "var(--text-muted)" }}>TIME</span>
            <span className="tabular-nums" style={{ color: "var(--text-primary)" }}>{totalElapsed}s</span>
          </div>
        )}

        {iocType && (
          <div className="flex items-center gap-2">
            <Tag size={13} style={{ color: "var(--text-muted)" }} />
            <span style={{ color: "var(--text-muted)" }}>TYPE</span>
            <span style={{ color: "var(--text-primary)" }}>{TYPE_LABELS[iocType] || iocType}</span>
          </div>
        )}
      </div>
    </div>
  );
}
