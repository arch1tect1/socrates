import { useState, useRef, useEffect } from "react";
import { ShieldAlert, ShieldCheck, ShieldQuestion, AlertTriangle, Target, ListChecks, Crosshair, Brain, ChevronDown } from "lucide-react";
import { linkifyCVEs } from "./CVELink";

const VERDICT_CONFIG = {
  MALICIOUS: { color: "#ef4444", icon: ShieldAlert },
  SUSPICIOUS: { color: "#f59e0b", icon: AlertTriangle },
  "LIKELY BENIGN": { color: "#22c55e", icon: ShieldCheck },
  INCONCLUSIVE: { color: "#a78bfa", icon: ShieldQuestion },
};

const CONFIDENCE_PILL = { HIGH: "pill-green", MEDIUM: "pill-orange", LOW: "pill-red" };

const SEVERITY_COLOR = {
  critical: "#ef4444",
  high: "#f59e0b",
  medium: "#fbbf24",
  low: "#22c55e",
  info: "#a78bfa",
};

function AccordionSection({ icon: Icon, title, count, defaultOpen, children }) {
  const [open, setOpen] = useState(defaultOpen || false);
  const ref = useRef(null);
  const [height, setHeight] = useState(0);
  const [settled, setSettled] = useState(defaultOpen || false);

  useEffect(() => {
    if (open) {
      const measure = () => { if (ref.current) setHeight(ref.current.scrollHeight); };
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
    <div>
      <button
        className="section-toggle w-full"
        onClick={(e) => { e.stopPropagation(); setOpen((o) => !o); }}
      >
        <div className="flex items-center gap-2">
          <Icon size={13} />
          <span>{title}</span>
          {count != null && (
            <span className="pill pill-cyan text-[9px] !py-0 !px-1.5">{count}</span>
          )}
        </div>
        <ChevronDown
          size={14}
          className="transition-transform duration-200"
          style={{ transform: open ? "rotate(0deg)" : "rotate(-90deg)" }}
        />
      </button>
      <div
        className="expand-content"
        style={{
          maxHeight: settled ? "none" : open ? height + "px" : "0px",
          opacity: open ? 1 : 0,
          overflow: settled ? "visible" : "hidden",
        }}
      >
        <div ref={ref} className="pb-2">
          {children}
        </div>
      </div>
    </div>
  );
}

export default function VerdictPanel({ verdict }) {
  if (!verdict) return null;

  const config = VERDICT_CONFIG[verdict.verdict] || VERDICT_CONFIG.INCONCLUSIVE;
  const VerdictIcon = config.icon;
  const findingsCount = verdict.key_findings?.length || 0;
  const mitreCount = verdict.mitre_attack?.length || 0;
  const actionsCount = verdict.recommended_actions?.length || 0;

  return (
    <div
      className="card animate-fade-in-up overflow-hidden"
      style={{ borderLeft: `4px solid ${config.color}`, animationDelay: "200ms" }}
    >
      {/* Compact header — always visible */}
      <div className="flex flex-wrap items-center gap-3">
        <VerdictIcon size={24} style={{ color: config.color }} />
        <span
          className="pill font-bold tracking-wider"
          style={{
            background: `${config.color}1a`,
            border: `1px solid ${config.color}44`,
            color: config.color,
            fontSize: "14px",
            padding: "5px 16px",
          }}
        >
          {verdict.verdict}
        </span>
        <span className={`pill ${CONFIDENCE_PILL[verdict.confidence] || "pill-purple"}`}>
          {verdict.confidence} CONFIDENCE
        </span>
      </div>

      {/* Accordion sections */}
      <div className="mt-4">
        {/* Key Findings — expanded by default */}
        {findingsCount > 0 && (
          <AccordionSection icon={Crosshair} title="Key Findings" count={findingsCount} defaultOpen>
            <div className="grid gap-1.5">
              {verdict.key_findings.map((f, i) => (
                <div
                  key={i}
                  className="flex items-start gap-2.5 py-1.5 px-2.5 rounded-lg"
                  style={{ background: "var(--bg-primary)" }}
                >
                  <span
                    className="pill text-[8px] mt-0.5 !py-0 !px-1.5"
                    style={{
                      background: `${SEVERITY_COLOR[f.severity] || "#a78bfa"}1a`,
                      border: `1px solid ${SEVERITY_COLOR[f.severity] || "#a78bfa"}44`,
                      color: SEVERITY_COLOR[f.severity] || "#a78bfa",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {f.severity}
                  </span>
                  <div className="min-w-0">
                    <p className="text-xs leading-relaxed" style={{ color: "var(--text-primary)" }}>
                      {linkifyCVEs(f.finding)}
                    </p>
                    <p className="text-[10px]" style={{ color: "var(--text-muted)" }}>
                      {f.source}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </AccordionSection>
        )}

        {/* AI Reasoning — collapsed */}
        <AccordionSection icon={Brain} title="AI Reasoning">
          <div
            className="text-sm leading-relaxed whitespace-pre-line px-1"
            style={{ color: "var(--text-secondary)" }}
          >
            {linkifyCVEs(verdict.reasoning)}
          </div>
        </AccordionSection>

        {/* MITRE ATT&CK — collapsed */}
        {mitreCount > 0 && (
          <AccordionSection icon={Target} title="MITRE ATT&CK" count={mitreCount}>
            <div className="grid gap-1.5">
              {verdict.mitre_attack.map((m, i) => (
                <div
                  key={i}
                  className="flex items-start gap-2.5 py-1.5 px-2.5 rounded-lg"
                  style={{ background: "var(--bg-primary)" }}
                >
                  <span className="pill pill-red text-[9px] font-bold whitespace-nowrap !py-0 !px-1.5 mt-0.5">
                    {m.technique_id}
                  </span>
                  <div className="min-w-0">
                    <p className="text-xs font-medium" style={{ color: "var(--text-primary)" }}>
                      {linkifyCVEs(m.technique_name)}
                    </p>
                    <p className="text-[10px]" style={{ color: "var(--text-muted)" }}>
                      {linkifyCVEs(m.relevance)}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </AccordionSection>
        )}

        {/* Recommended Actions — collapsed */}
        {actionsCount > 0 && (
          <AccordionSection icon={ListChecks} title="Recommended Actions" count={actionsCount}>
            <ul className="space-y-1.5">
              {verdict.recommended_actions.map((a, i) => (
                <li key={i} className="flex items-start gap-2.5 text-xs" style={{ color: "var(--text-secondary)" }}>
                  <span
                    className="flex-shrink-0 w-4 h-4 rounded-full flex items-center justify-center text-[9px] font-bold mt-0.5"
                    style={{ background: "rgba(34,211,238,0.1)", color: "#22d3ee", border: "1px solid rgba(34,211,238,0.2)" }}
                  >
                    {i + 1}
                  </span>
                  {linkifyCVEs(a)}
                </li>
              ))}
            </ul>
          </AccordionSection>
        )}
      </div>
    </div>
  );
}
