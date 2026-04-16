import { CheckCircle2, XCircle, Circle, Loader2, Brain, SkipForward, Info } from "lucide-react";
import { skipReasonForSource } from "../lib/skipReasons";

const STATUS_CONFIG = {
  pending: {
    icon: Circle,
    color: "var(--text-muted)",
    label: "Pending",
  },
  querying: {
    icon: Loader2,
    color: "#fbbf24",
    label: "Querying...",
    spin: true,
  },
  complete: {
    icon: CheckCircle2,
    color: "#22c55e",
    label: "Complete",
  },
  error: {
    icon: XCircle,
    color: "#ef4444",
    label: "Error",
  },
  skipped: {
    icon: SkipForward,
    color: "var(--text-muted)",
    label: "Skipped",
  },
};

function SourceRow({ source, status, elapsed, error, skip_reason: skipReason, iocType }) {
  const config = STATUS_CONFIG[status] || STATUS_CONFIG.pending;
  const Icon = config.icon;
  const resolvedSkip =
    status === "skipped" ? skipReason || skipReasonForSource(source, iocType) : null;

  const statusLabel =
    status === "skipped" && resolvedSkip ? (
      <span style={{ color: "#475569" }}>
        Skipped —{" "}
        <span className="italic inline-flex items-center gap-0.5" style={{ color: "#64748b" }}>
          <Info size={12} className="flex-shrink-0 opacity-80" aria-hidden />
          {resolvedSkip}
        </span>
      </span>
    ) : (
      <span style={{ color: config.color }}>{config.label}</span>
    );

  return (
    <div
      className="py-3 px-4 rounded-lg transition-all duration-300"
      style={{
        background:
          status === "querying" ? "rgba(251,191,36,0.05)" :
          status === "complete" ? "rgba(34,197,94,0.03)" :
          status === "error" ? "rgba(239,68,68,0.03)" :
          "transparent",
      }}
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Icon
            size={16}
            style={{ color: config.color, flexShrink: 0 }}
            className={config.spin ? "animate-spin-slow" : ""}
          />
          <span
            className="text-sm font-medium"
            style={{ color: "var(--text-primary)" }}
          >
            {source}
          </span>
        </div>

        <div className="flex items-center gap-4 flex-shrink-0 ml-4 max-w-[55%] sm:max-w-none">
          <span className="text-xs font-medium text-right sm:text-left break-words">
            {statusLabel}
          </span>
          <span
            className="text-xs tabular-nums w-14 text-right"
            style={{ color: "var(--text-muted)" }}
          >
            {status === "skipped" ? "—" : elapsed != null ? `${elapsed}s` : "—"}
          </span>
        </div>
      </div>

      {error && (
        <p
          className="mt-1.5 ml-7 text-xs leading-relaxed break-words"
          style={{ color: "rgba(239,68,68,0.8)" }}
        >
          {error}
        </p>
      )}
    </div>
  );
}

export default function ProgressPanel({ sources, aiStatus, totalElapsed, iocType }) {
  if (!sources || sources.length === 0) return null;

  return (
    <div className="card animate-fade-in-up w-full max-w-3xl mx-auto">
      <div className="flex items-center justify-between mb-4">
        <h3 className="section-label">Enrichment Sources</h3>
        {totalElapsed != null && (
          <span className="text-xs tabular-nums" style={{ color: "var(--text-muted)" }}>
            Total: {totalElapsed}s
          </span>
        )}
      </div>

      <div className="space-y-1">
        {sources.map((s) => (
          <SourceRow key={s.source} {...s} iocType={iocType} />
        ))}
      </div>

      {aiStatus && (
        <div
          className="mt-4 pt-4 flex items-center gap-3"
          style={{ borderTop: "1px solid var(--border)" }}
        >
          {aiStatus === "generating" ? (
            <>
              <Brain size={16} className="text-accent-purple animate-pulse-glow" />
              <span className="text-sm font-medium" style={{ color: "#a78bfa" }}>
                AI Analysis — Generating verdict...
              </span>
              <Loader2 size={14} className="animate-spin text-accent-purple ml-auto" />
            </>
          ) : (
            <>
              <CheckCircle2 size={16} className="text-accent-green" />
              <span className="text-sm font-medium" style={{ color: "#22c55e" }}>
                AI Analysis — Complete
              </span>
            </>
          )}
        </div>
      )}
    </div>
  );
}
