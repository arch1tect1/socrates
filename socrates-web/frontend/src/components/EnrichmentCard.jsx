import { ChevronDown, ChevronRight, ExternalLink, Globe, Shield, AlertTriangle, Radio, Scan } from "lucide-react";
import { useState, useRef, useEffect } from "react";
import { linkifyCVEs } from "./CVELink";

const SOURCE_ICONS = {
  VirusTotal: Shield,
  Shodan: Globe,
  AbuseIPDB: AlertTriangle,
  "OTX AlienVault": Radio,
  "URLScan.io": Scan,
};

/* ── Helpers ── */

function DataRow({ label, value, color }) {
  if (value == null || value === "N/A" || value === "") return null;
  const display = Array.isArray(value) ? value.join(", ") : String(value);
  if (!display) return null;

  return (
    <div className="flex gap-3 py-1.5">
      <span className="stat-label min-w-[130px] pt-0.5">{label}</span>
      <span className="text-sm break-all" style={{ color: color || "var(--text-primary)" }}>
        {linkifyCVEs(display)}
      </span>
    </div>
  );
}

function Stat({ value, label, color }) {
  return (
    <div className="text-center min-w-0">
      <div className="stat-number" style={{ color: color || "var(--text-primary)" }}>
        {value}
      </div>
      <div className="stat-label mt-1">{label}</div>
    </div>
  );
}

function detectionColor(mal, total) {
  if (!total) return "var(--text-muted)";
  const pct = mal / total;
  if (pct > 0.5) return "#ef4444";
  if (pct > 0.1) return "#f59e0b";
  return "#22c55e";
}

function abuseColor(score) {
  if (score > 70) return "#ef4444";
  if (score > 30) return "#f59e0b";
  return "#22c55e";
}

function ExpandPanel({ open, children }) {
  const ref = useRef(null);
  const [height, setHeight] = useState(0);
  const [settled, setSettled] = useState(false);

  useEffect(() => {
    if (open) {
      const measure = () => {
        if (ref.current) setHeight(ref.current.scrollHeight);
      };
      measure();
      const t1 = setTimeout(measure, 50);
      const t2 = setTimeout(measure, 200);
      const t3 = setTimeout(() => setSettled(true), 350);
      return () => { clearTimeout(t1); clearTimeout(t2); clearTimeout(t3); };
    } else {
      setSettled(false);
      setHeight(0);
    }
  }, [open, children]);

  return (
    <div
      className="expand-content"
      style={{
        maxHeight: settled ? "none" : open ? height + "px" : "0px",
        opacity: open ? 1 : 0,
        overflow: settled ? "visible" : "hidden",
      }}
    >
      <div ref={ref}>{children}</div>
    </div>
  );
}

/* ── Compact stat summaries (collapsed view) ── */

function VTStats({ data }) {
  const [mal, total] = (data.detection_ratio || "0/0").split("/").map(Number);
  return (
    <div className="flex items-center justify-around gap-4 py-2">
      <Stat value={`${mal}/${total}`} label="Detections" color={detectionColor(mal, total)} />
      <Stat value={data.community_score ?? "—"} label="Score" />
      <div className="text-center min-w-0">
        <div className="text-sm font-semibold truncate" style={{ color: "var(--text-primary)" }}>
          {data.threat_label !== "N/A" ? data.threat_label : "—"}
        </div>
        <div className="stat-label mt-1">Label</div>
      </div>
    </div>
  );
}

function ShodanStats({ data }) {
  return (
    <div className="flex items-center justify-around gap-4 py-2">
      <Stat value={data.open_ports?.length ?? 0} label="Open Ports" color="var(--accent-cyan)" />
      <div className="text-center min-w-0">
        <div className="text-sm font-semibold truncate" style={{ color: "var(--text-primary)" }}>
          {data.org !== "N/A" ? data.org : data.isp !== "N/A" ? data.isp : "—"}
        </div>
        <div className="stat-label mt-1">ISP / Org</div>
      </div>
      <div className="text-center min-w-0">
        <div className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>
          {data.country !== "N/A" ? data.country : "—"}
        </div>
        <div className="stat-label mt-1">Country</div>
      </div>
    </div>
  );
}

function AbuseStats({ data }) {
  const score = data.abuse_confidence_score || 0;
  return (
    <div className="flex items-center justify-around gap-4 py-2">
      <Stat value={`${score}%`} label="Abuse Score" color={abuseColor(score)} />
      <Stat value={data.total_reports ?? 0} label="Reports" />
      <div className="text-center min-w-0">
        <div className="text-sm font-semibold truncate" style={{ color: "var(--text-secondary)" }}>
          {data.last_reported_at ? relativeTime(data.last_reported_at) : "—"}
        </div>
        <div className="stat-label mt-1">Last Reported</div>
      </div>
    </div>
  );
}

function OTXStats({ data }) {
  const topTag = data.tags?.length > 0 ? data.tags[0] : "—";
  return (
    <div className="flex items-center justify-around gap-4 py-2">
      <Stat value={data.pulse_count ?? 0} label="Pulses" color={data.pulse_count > 0 ? "#f59e0b" : "#22c55e"} />
      <Stat value={data.reputation ?? 0} label="Reputation" />
      <div className="text-center min-w-0">
        <div className="text-sm font-semibold truncate max-w-[120px]" style={{ color: "var(--text-secondary)" }}>
          {topTag}
        </div>
        <div className="stat-label mt-1">Top Tag</div>
      </div>
    </div>
  );
}

function URLScanStats({ data }) {
  const isMal = data.is_malicious;
  return (
    <div className="flex items-center justify-around gap-4 py-2">
      <div className="text-center">
        <span
          className="pill text-[10px]"
          style={{
            background: isMal ? "rgba(239,68,68,0.13)" : "rgba(34,197,94,0.13)",
            border: `1px solid ${isMal ? "rgba(239,68,68,0.27)" : "rgba(34,197,94,0.27)"}`,
            color: isMal ? "#ef4444" : "#22c55e",
          }}
        >
          {isMal ? "Malicious" : "Clean"}
        </span>
        <div className="stat-label mt-2">Verdict</div>
      </div>
      <div className="text-center min-w-0">
        <div className="text-sm font-semibold truncate max-w-[140px]" style={{ color: "var(--text-primary)" }}>
          {data.domain !== "N/A" ? data.domain : data.final_url || "—"}
        </div>
        <div className="stat-label mt-1">Domain</div>
      </div>
      <div className="text-center min-w-0">
        <div className="text-sm font-semibold truncate" style={{ color: "var(--text-secondary)" }}>
          {data.server !== "N/A" ? data.server : "—"}
        </div>
        <div className="stat-label mt-1">Server</div>
      </div>
    </div>
  );
}

const STATS_MAP = {
  VirusTotal: VTStats,
  Shodan: ShodanStats,
  AbuseIPDB: AbuseStats,
  "OTX AlienVault": OTXStats,
  "URLScan.io": URLScanStats,
};

/* ── Full detail content (expanded view) ── */

function VTDetails({ data }) {
  return (
    <div className="space-y-1 pt-1">
      <DataRow label="Threat Categories" value={data.threat_categories} />
      <DataRow label="Tags" value={data.tags} />
      <DataRow label="Last Analysis" value={data.last_analysis_date ? new Date(data.last_analysis_date * 1000).toLocaleDateString() : null} />
    </div>
  );
}

function ShodanDetails({ data }) {
  return (
    <div className="space-y-1 pt-1">
      {data.note && (
        <p className="text-xs mb-2 py-1.5 px-3 rounded" style={{ background: "rgba(34,211,238,0.06)", color: "var(--accent-cyan)" }}>
          {data.note}
        </p>
      )}
      <DataRow label="IP" value={data.ip} />
      {data.resolved_from && <DataRow label="Resolved From" value={data.resolved_from} />}
      <DataRow label="Hostnames" value={data.hostnames} />
      <DataRow label="ASN" value={data.asn} />
      <DataRow label="City" value={data.city} />
      <DataRow label="OS" value={data.os} />
      <DataRow label="Tags" value={data.tags} />
      <DataRow label="CPEs" value={data.cpes} />
      {data.services?.length > 0 && (
        <div className="mt-2">
          <span className="stat-label">Services</span>
          <div className="mt-1 grid gap-1">
            {data.services.map((s, i) => (
              <div key={i} className="text-xs py-1 px-2 rounded" style={{ background: "var(--bg-primary)" }}>
                <span className="font-bold" style={{ color: "var(--accent-cyan)" }}>:{s.port}</span>
                <span style={{ color: "var(--text-secondary)" }}> {s.product} {s.version}</span>
              </div>
            ))}
          </div>
        </div>
      )}
      {data.vulnerabilities?.length > 0 && (
        <DataRow label="Vulnerabilities" value={data.vulnerabilities} color="#ef4444" />
      )}
    </div>
  );
}

function AbuseDetails({ data }) {
  const score = data.abuse_confidence_score || 0;
  const color = abuseColor(score);
  return (
    <div className="space-y-1 pt-1">
      <div className="flex items-center gap-3 mb-2">
        <div className="relative flex-1 h-2 rounded-full overflow-hidden" style={{ background: "var(--border)" }}>
          <div className="absolute left-0 top-0 h-full rounded-full transition-all duration-700" style={{ width: `${score}%`, background: color }} />
        </div>
      </div>
      <DataRow label="ISP" value={data.isp} />
      <DataRow label="Usage Type" value={data.usage_type} />
      <DataRow label="Domain" value={data.domain} />
      <DataRow label="Country" value={data.country_code} />
      <DataRow label="Whitelisted" value={data.is_whitelisted ? "Yes" : "No"} color={data.is_whitelisted ? "#22c55e" : "var(--text-secondary)"} />
    </div>
  );
}

function OTXDetails({ data }) {
  return (
    <div className="space-y-1 pt-1">
      <DataRow label="All Tags" value={data.tags} />
      <DataRow label="Malware Families" value={data.malware_families} color="#ef4444" />
      {data.geo && (
        <>
          <DataRow label="Country" value={data.geo.country} />
          <DataRow label="City" value={data.geo.city} />
          <DataRow label="ASN" value={data.geo.asn} />
        </>
      )}
    </div>
  );
}

function URLScanDetails({ data }) {
  return (
    <div className="space-y-1 pt-1">
      {data.source_note && (
        <p className="text-xs mb-2 py-1.5 px-3 rounded" style={{ background: "rgba(34,211,238,0.06)", color: "var(--accent-cyan)" }}>
          {data.source_note}
        </p>
      )}
      <DataRow label="Final URL" value={data.final_url} />
      <DataRow label="IP" value={data.ip} />
      <DataRow label="Country" value={data.country} />
      <DataRow label="Status Code" value={data.status_code} />
      <DataRow label="Verdict Score" value={data.verdict_score} />
      {data.screenshot_url && (
        <div className="mt-3">
          <span className="stat-label">Screenshot</span>
          <img src={data.screenshot_url} alt="Page screenshot" className="mt-2 rounded-lg border max-w-full" style={{ borderColor: "var(--border)", maxHeight: "200px" }} />
        </div>
      )}
      {data.result_url && (
        <a href={data.result_url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 mt-2 text-xs hover:underline" style={{ color: "var(--accent-cyan)" }}>
          View full scan <ExternalLink size={12} />
        </a>
      )}
    </div>
  );
}

const DETAILS_MAP = {
  VirusTotal: VTDetails,
  Shodan: ShodanDetails,
  AbuseIPDB: AbuseDetails,
  "OTX AlienVault": OTXDetails,
  "URLScan.io": URLScanDetails,
};

/* ── Utilities ── */

function relativeTime(dateStr) {
  if (!dateStr || dateStr === "N/A") return "—";
  try {
    const diff = Date.now() - new Date(dateStr).getTime();
    const days = Math.floor(diff / 86400000);
    if (days < 1) return "Today";
    if (days === 1) return "Yesterday";
    if (days < 30) return `${days}d ago`;
    if (days < 365) return `${Math.floor(days / 30)}mo ago`;
    return `${Math.floor(days / 365)}y ago`;
  } catch {
    return dateStr;
  }
}

/* ── Main card component ── */

export default function EnrichmentCard({ source, data, status, error, delay = 0 }) {
  const [expanded, setExpanded] = useState(false);
  const Icon = SOURCE_ICONS[source] || Globe;
  const StatsComponent = STATS_MAP[source];
  const DetailsComponent = DETAILS_MAP[source];

  if (status === "skipped") return null;
  if (status !== "complete" && status !== "error") return null;

  return (
    <div
      className={`compact-card ${expanded ? "expanded" : ""}`}
      style={{ animationDelay: `${delay}ms`, animation: `stagger-fade-in 0.35s ease-out ${delay}ms both` }}
      onClick={() => setExpanded((e) => !e)}
    >
      {/* Header */}
      <div className="flex items-center justify-between mb-1">
        <div className="flex items-center gap-2.5">
          <Icon size={16} style={{ color: "var(--accent-cyan)" }} />
          <span className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>{source}</span>
          {status === "complete" && (
            <span className="pill pill-green text-[9px] !py-0.5 !px-2">OK</span>
          )}
          {status === "error" && (
            <span className="pill pill-red text-[9px] !py-0.5 !px-2">Error</span>
          )}
        </div>
        {expanded ? (
          <ChevronDown size={14} style={{ color: "var(--text-muted)" }} />
        ) : (
          <ChevronRight size={14} style={{ color: "var(--text-muted)" }} />
        )}
      </div>

      {/* Compact stats or error */}
      {error ? (
        <p className="text-xs mt-2" style={{ color: "rgba(239,68,68,0.8)" }}>{error}</p>
      ) : data && StatsComponent ? (
        <StatsComponent data={data} />
      ) : null}

      {/* Expanded detail section */}
      <ExpandPanel open={expanded}>
        {data && DetailsComponent && (
          <div className="mt-3 pt-3" style={{ borderTop: "1px solid var(--border)" }}>
            <DetailsComponent data={data} />
          </div>
        )}
      </ExpandPanel>
    </div>
  );
}
