import { Link, useParams } from "react-router-dom";
import { ArrowLeft } from "lucide-react";
import { useAlertDetail } from "../hooks/useAlertDetail";
import SeverityBadge from "../components/SeverityBadge";
import IOCList from "../components/IOCList";
import AgentTraceViewer from "../components/AgentTraceViewer";

function latestVerdict(verdicts) {
  if (!verdicts?.length) return null;
  return [...verdicts].sort(
    (a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0)
  )[0];
}

export default function AlertDetailPage() {
  const { id } = useParams();
  const { alert, loading, error } = useAlertDetail(id);

  if (loading && !alert) {
    return (
      <main className="flex-1 max-w-4xl mx-auto px-4 py-12">
        <p className="text-sm" style={{ color: "var(--text-muted)" }}>
          Loading…
        </p>
      </main>
    );
  }

  if (error && !alert) {
    return (
      <main className="flex-1 max-w-4xl mx-auto px-4 py-12">
        <p className="text-sm text-red-400">{error.message || String(error)}</p>
        <Link to="/alerts" className="text-cyan-400 text-sm mt-4 inline-block">
          ← Back to alerts
        </Link>
      </main>
    );
  }

  if (!alert) {
    return (
      <main className="flex-1 max-w-4xl mx-auto px-4 py-12">
        <p className="text-sm" style={{ color: "var(--text-muted)" }}>
          Alert not found.
        </p>
        <Link to="/alerts" className="text-cyan-400 text-sm mt-4 inline-block">
          ← Back to alerts
        </Link>
      </main>
    );
  }

  const v = latestVerdict(alert.verdicts);
  const pending = alert.status === "investigating" && !v;

  return (
    <main className="flex-1 w-full max-w-4xl mx-auto px-4 sm:px-6 py-8 space-y-6">
      <Link
        to="/alerts"
        className="inline-flex items-center gap-2 text-sm font-mono opacity-80 hover:opacity-100"
        style={{ color: "var(--accent-cyan)" }}
      >
        <ArrowLeft className="w-4 h-4" />
        All alerts
      </Link>

      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex flex-wrap items-center gap-2 mb-2">
            <SeverityBadge severity={alert.severity} />
            <span className="text-xs font-mono px-2 py-0.5 rounded border" style={{ borderColor: "var(--border)", color: "var(--text-muted)" }}>
              {alert.status?.replace("_", " ")}
            </span>
          </div>
          <h1 className="font-display text-xl sm:text-2xl font-bold" style={{ color: "var(--text-primary)" }}>
            {alert.title}
          </h1>
          {alert.rule_name && (
            <p className="text-sm font-mono mt-1" style={{ color: "var(--text-secondary)" }}>
              Rule: {alert.rule_name}
            </p>
          )}
          <p className="text-xs mt-2 font-mono" style={{ color: "var(--text-muted)" }}>
            {alert.source} · {alert.id}
          </p>
        </div>
      </div>

      {alert.description && (
        <div className="card">
          <h2 className="section-label mb-2">Description</h2>
          <pre
            className="text-xs whitespace-pre-wrap font-mono leading-relaxed"
            style={{ color: "var(--text-secondary)" }}
          >
            {alert.description}
          </pre>
        </div>
      )}

      <div className="card">
        <h2 className="section-label mb-3">Extracted IOCs</h2>
        <IOCList iocs={alert.alert_iocs} />
      </div>

      <div className="card">
        <h2 className="section-label mb-3">Verdict</h2>
        {pending && (
          <p className="text-sm italic animate-pulse" style={{ color: "var(--text-muted)" }}>
            Triage agent running… this page updates automatically.
          </p>
        )}
        {!pending && v && (
          <>
            <div className="flex flex-wrap items-baseline gap-3 mb-3">
              <span className="text-lg font-mono font-semibold text-red-200/90">{v.verdict}</span>
              {v.confidence != null && (
                <span className="text-sm" style={{ color: "var(--text-muted)" }}>
                  confidence {Number(v.confidence).toFixed(2)}
                </span>
              )}
              {v.recommended_action && (
                <code className="text-xs px-2 py-0.5 rounded bg-black/30 border border-white/10">
                  {v.recommended_action}
                </code>
              )}
            </div>
            <p className="text-sm leading-relaxed whitespace-pre-wrap" style={{ color: "var(--text-secondary)" }}>
              {v.reasoning}
            </p>
          </>
        )}
        {!pending && !v && (
          <p className="text-sm" style={{ color: "var(--text-muted)" }}>
            No verdict yet.
          </p>
        )}
      </div>

      {v?.agent_trace?.length > 0 && (
        <div className="card">
          <h2 className="section-label mb-4">Agent trace</h2>
          <AgentTraceViewer verdict={v} />
        </div>
      )}
    </main>
  );
}
