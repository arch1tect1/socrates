export default function IOCList({ iocs, compact }) {
  if (!iocs?.length) {
    return (
      <span className="text-xs" style={{ color: "var(--text-muted)" }}>
        —
      </span>
    );
  }

  if (compact) {
    return (
      <span className="text-xs font-mono" style={{ color: "var(--text-secondary)" }}>
        {iocs.length} IOC{iocs.length !== 1 ? "s" : ""}
      </span>
    );
  }

  return (
    <ul className="space-y-1">
      {iocs.map((ioc) => (
        <li
          key={ioc.id || `${ioc.ioc_type}-${ioc.ioc_value}`}
          className="font-mono text-xs flex flex-wrap gap-2"
          style={{ color: "var(--text-secondary)" }}
        >
          <span className="opacity-70">{ioc.ioc_type}</span>
          <span style={{ color: "var(--text-primary)" }}>{ioc.ioc_value}</span>
        </li>
      ))}
    </ul>
  );
}
