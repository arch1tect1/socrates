import { Shield, Search } from "lucide-react";
import ThemeToggle from "./ThemeToggle";

const CVE_ANALYZER_URL = "https://cve-analyzer.lovable.app/";

export default function Header({ onReset }) {
  const goHome = (e) => {
    e?.preventDefault?.();
    e?.stopPropagation?.();
    if (typeof onReset === "function") {
      onReset();
    }
  };

  return (
    <header
      className="sticky top-0 z-50 backdrop-blur-md border-b"
      style={{
        background: "color-mix(in srgb, var(--bg-primary) 80%, transparent)",
        borderColor: "var(--border)",
      }}
    >
      <div className="max-w-7xl mx-auto px-4 sm:px-6 h-14 grid items-center gap-3 sm:gap-4 w-full"
        style={{
          gridTemplateColumns: "auto minmax(0, 1fr) auto",
        }}
      >
        {/* Home — grid column 1, always receives clicks first */}
        <button
          type="button"
          onClick={goHome}
          aria-label="SOCrates home - clear and start over"
          className="flex items-center gap-2.5 sm:gap-3 justify-self-start text-left relative z-[2] transition-opacity duration-200 hover:opacity-80"
          style={{ cursor: "pointer", background: "none", border: "none", padding: 0 }}
        >
          <span className="flex items-center justify-center w-8 h-8 sm:w-9 sm:h-9 rounded-lg bg-accent-cyan/10 border border-accent-cyan/20">
            <Shield size={20} className="text-accent-cyan" />
          </span>
          <span className="flex flex-col">
            <span className="font-display text-base sm:text-lg font-bold tracking-wide" style={{ color: "var(--text-primary)" }}>
              SOCrates
            </span>
            <span className="text-[9px] sm:text-[10px] tracking-[2px] uppercase leading-tight" style={{ color: "var(--text-muted)" }}>
              AI IOC Triage
            </span>
          </span>
        </button>

        {/* CVE promo — full strip is one link */}
        <a
          href={CVE_ANALYZER_URL}
          target="_blank"
          rel="noopener noreferrer"
          className="justify-self-center flex items-center gap-1.5 w-full max-w-md min-w-0 px-2.5 py-1 rounded-md no-underline relative z-[1] transition-opacity hover:opacity-90"
          style={{
            background: "rgba(34,211,238,0.06)",
            borderLeft: "2px solid #22d3ee",
            maxHeight: 34,
          }}
          title="CVE Patch Analyzer — open in new tab"
        >
          <Search size={11} className="flex-shrink-0" style={{ color: "#22d3ee" }} />
          <span
            className="min-w-0 truncate font-medium"
            style={{
              fontSize: 11,
              lineHeight: 1.2,
              color: "var(--text-secondary)",
              whiteSpace: "nowrap",
              overflow: "hidden",
              textOverflow: "ellipsis",
            }}
          >
            <strong style={{ color: "#22d3ee" }}>NEW:</strong> CVE Patch Analyzer - Install Chrome Extension
          </span>
        </a>

        <div className="justify-self-end flex-shrink-0 relative z-[2]">
          <ThemeToggle />
        </div>
      </div>
    </header>
  );
}
