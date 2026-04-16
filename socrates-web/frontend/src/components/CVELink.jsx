const CVE_REGEX = /(CVE-\d{4}-\d{4,})/g;
const CVE_URL = "https://cve-analyzer.lovable.app/";

export function CVETag({ cve }) {
  return (
    <a
      href={CVE_URL}
      target="_blank"
      rel="noopener noreferrer"
      title={`Analyze ${cve} with CVE Patch Analyzer`}
      className="inline-flex items-center gap-1 font-mono transition-all duration-150"
      style={{
        color: "#22d3ee",
        background: "rgba(34,211,238,0.1)",
        border: "1px solid rgba(34,211,238,0.3)",
        borderRadius: "4px",
        padding: "1px 6px",
        fontSize: "inherit",
        textDecoration: "none",
      }}
      onMouseEnter={(e) => { e.currentTarget.style.background = "rgba(34,211,238,0.18)"; }}
      onMouseLeave={(e) => { e.currentTarget.style.background = "rgba(34,211,238,0.1)"; }}
    >
      <span style={{ fontSize: "0.85em" }}>&#128269;</span>
      {cve}
    </a>
  );
}

export function linkifyCVEs(text) {
  if (!text || typeof text !== "string") return text;
  if (!CVE_REGEX.test(text)) return text;

  CVE_REGEX.lastIndex = 0;
  const parts = [];
  let lastIndex = 0;
  let match;

  while ((match = CVE_REGEX.exec(text)) !== null) {
    if (match.index > lastIndex) {
      parts.push(text.slice(lastIndex, match.index));
    }
    parts.push(<CVETag key={match.index} cve={match[1]} />);
    lastIndex = CVE_REGEX.lastIndex;
  }

  if (lastIndex < text.length) {
    parts.push(text.slice(lastIndex));
  }

  return parts;
}
