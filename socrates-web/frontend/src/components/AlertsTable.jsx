import { useNavigate } from "react-router-dom";
import { ChevronRight } from "lucide-react";
import SeverityBadge from "./SeverityBadge";
import VerdictBadge from "./VerdictBadge";
import { formatAge } from "../lib/time";

function latestVerdict(verdicts) {
  if (!verdicts?.length) return null;
  return [...verdicts].sort(
    (a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0)
  )[0];
}

export default function AlertsTable({ alerts, latestVerdict: lv }) {
  const navigate = useNavigate();
  const getV = lv || latestVerdict;

  if (!alerts?.length) {
    return (
      <div className="card text-center py-12 text-sm" style={{ color: "var(--text-muted)" }}>
        No alerts match the current filters.
      </div>
    );
  }

  return (
    <div className="overflow-x-auto rounded-xl border" style={{ borderColor: "var(--border)" }}>
      <table className="w-full text-left text-sm border-collapse">
        <thead>
          <tr
            className="text-[10px] uppercase tracking-wider"
            style={{ color: "var(--text-muted)", borderBottom: "1px solid var(--border)" }}
          >
            <th className="px-3 py-2 font-semibold">Severity</th>
            <th className="px-3 py-2 font-semibold">Rule</th>
            <th className="px-3 py-2 font-semibold">Source</th>
            <th className="px-3 py-2 font-semibold">IOCs</th>
            <th className="px-3 py-2 font-semibold">Verdict</th>
            <th className="px-3 py-2 font-semibold">Status</th>
            <th className="px-3 py-2 font-semibold">Age</th>
            <th className="px-3 py-2 w-8" />
          </tr>
        </thead>
        <tbody>
          {alerts.map((a) => {
            const v = getV(a.verdicts);
            const pending = a.status === "investigating" && !v;
            return (
              <tr
                key={a.id}
                role="button"
                tabIndex={0}
                onClick={() => navigate(`/alerts/${a.id}`)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    navigate(`/alerts/${a.id}`);
                  }
                }}
                className="cursor-pointer transition-colors hover:bg-white/5 border-t"
                style={{ borderColor: "var(--border)" }}
              >
                <td className="px-3 py-2 align-middle">
                  <SeverityBadge severity={a.severity} />
                </td>
                <td
                  className="px-3 py-2 align-middle max-w-[180px] truncate font-mono text-xs"
                  title={a.rule_name || a.title}
                  style={{ color: "var(--text-primary)" }}
                >
                  {a.rule_name || "—"}
                </td>
                <td
                  className="px-3 py-2 align-middle text-xs font-mono truncate max-w-[120px]"
                  style={{ color: "var(--text-secondary)" }}
                >
                  {a.source}
                </td>
                <td className="px-3 py-2 align-middle text-xs" style={{ color: "var(--text-secondary)" }}>
                  {(a.alert_iocs || []).length}
                </td>
                <td className="px-3 py-2 align-middle">
                  <VerdictBadge verdict={v} pending={pending} />
                </td>
                <td className="px-3 py-2 align-middle text-xs" style={{ color: "var(--text-muted)" }}>
                  {a.status?.replace("_", " ")}
                </td>
                <td className="px-3 py-2 align-middle text-xs whitespace-nowrap" style={{ color: "var(--text-muted)" }}>
                  {formatAge(a.created_at)}
                </td>
                <td className="px-2 py-2 align-middle text-slate-500">
                  <ChevronRight className="w-4 h-4" />
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
