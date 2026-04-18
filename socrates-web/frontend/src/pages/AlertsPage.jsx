import { Link } from "react-router-dom";
import { useAlerts } from "../hooks/useAlerts";
import AlertFilters from "../components/AlertFilters";
import AlertsTable from "../components/AlertsTable";

export default function AlertsPage() {
  const { alerts, loading, error, filters, setFilters, sources, latestVerdict } = useAlerts();

  return (
    <main className="flex-1 w-full max-w-7xl mx-auto px-4 sm:px-6 py-8">
      <div className="flex flex-col sm:flex-row sm:items-end sm:justify-between gap-4 mb-6">
        <div>
          <h1
            className="font-display text-2xl sm:text-3xl font-bold glow-text"
            style={{ color: "var(--text-primary)" }}
          >
            Alerts
          </h1>
          <p className="text-sm mt-1" style={{ color: "var(--text-secondary)" }}>
            Live feed via Supabase Realtime — verdicts update as triage completes.
          </p>
        </div>
        <Link
          to="/"
          className="text-xs font-mono underline underline-offset-2 opacity-80 hover:opacity-100"
          style={{ color: "var(--accent-cyan)" }}
        >
          ← IOC analyzer
        </Link>
      </div>

      {error && (
        <div className="card mb-6 border-red-500/40 bg-red-500/10">
          <p className="text-sm text-red-300">{error.message || String(error)}</p>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-[260px_1fr] gap-6 items-start">
        <AlertFilters filters={filters} setFilters={setFilters} sources={sources} />
        <div className="space-y-3">
          {loading && (
            <p className="text-sm animate-pulse" style={{ color: "var(--text-muted)" }}>
              Loading alerts…
            </p>
          )}
          <AlertsTable alerts={alerts} latestVerdict={latestVerdict} />
        </div>
      </div>
    </main>
  );
}
