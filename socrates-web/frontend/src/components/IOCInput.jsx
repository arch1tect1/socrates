import { Search, Loader2 } from "lucide-react";
import { useState, useEffect } from "react";

const IOC_PATTERNS = [
  { type: "ip", label: "IPv4 Address", regex: /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/ },
  { type: "ip", label: "IPv6 Address", regex: /^(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}$/ },
  { type: "hash", label: "SHA-256 Hash", regex: /^[0-9a-fA-F]{64}$/ },
  { type: "hash", label: "SHA-1 Hash", regex: /^[0-9a-fA-F]{40}$/ },
  { type: "hash", label: "MD5 Hash", regex: /^[0-9a-fA-F]{32}$/ },
  { type: "url", label: "URL", regex: /^https?:\/\//i },
  { type: "domain", label: "Domain", regex: /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/ },
];

function refang(value) {
  let v = value.trim();
  v = v.replace(/\[.\]/g, ".").replace(/\(dot\)/gi, ".").replace(/\[dot\]/gi, ".");
  v = v.replace(/^hxxps?:\/\//i, (m) => m.replace(/hxxp/i, "http"));
  v = v.replace(/\[:\/\/\]/g, "://").replace(/\[:\]/g, ":").replace(/\[at\]/gi, "@").replace(/\[@\]/g, "@");
  return v;
}

function detectIOC(value) {
  const cleaned = refang(value);
  if (!cleaned) return null;
  const isDefanged = cleaned !== value.trim();
  for (const { type, label, regex } of IOC_PATTERNS) {
    if (regex.test(cleaned)) {
      return { type, label: isDefanged ? `${label} (defanged)` : label };
    }
  }
  return null;
}

export default function IOCInput({ onSubmit, isLoading }) {
  const [value, setValue] = useState("");
  const [detected, setDetected] = useState(null);

  useEffect(() => {
    setDetected(detectIOC(value));
  }, [value]);

  const handleSubmit = (e) => {
    e.preventDefault();
    const trimmed = value.trim();
    if (!trimmed || isLoading) return;
    onSubmit(trimmed);
  };

  return (
    <form onSubmit={handleSubmit} className="w-full max-w-3xl mx-auto">
      <div
        className="relative flex items-center rounded-xl border-2 transition-all duration-200 focus-within:shadow-lg"
        style={{
          background: "var(--bg-card)",
          borderColor: detected ? "var(--accent-cyan)" : "var(--border)",
          boxShadow: detected
            ? "0 0 30px rgba(34,211,238,0.08)"
            : "none",
        }}
      >
        <Search
          size={20}
          className="absolute left-5 pointer-events-none"
          style={{ color: "var(--text-muted)" }}
        />
        <input
          type="text"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder="Paste an IOC — IP, domain, URL, or file hash"
          disabled={isLoading}
          className="w-full bg-transparent pl-14 pr-36 py-5 text-base font-mono outline-none placeholder:opacity-40"
          style={{ color: "var(--text-primary)" }}
        />
        <button
          type="submit"
          disabled={!value.trim() || isLoading}
          className="absolute right-3 flex items-center gap-2 px-5 py-2.5 rounded-lg text-sm font-semibold tracking-wide transition-all duration-200 disabled:opacity-30"
          style={{
            background: "var(--accent-cyan)",
            color: "#0a0a0f",
          }}
        >
          {isLoading ? (
            <Loader2 size={16} className="animate-spin" />
          ) : (
            <>
              Analyze
              <kbd className="hidden sm:inline-block text-[10px] opacity-60 ml-1 px-1.5 py-0.5 rounded border border-current/20">
                ↵
              </kbd>
            </>
          )}
        </button>
      </div>

      <div className="h-6 mt-2 px-2">
        {detected && (
          <p className="text-xs animate-fade-in-up" style={{ color: "var(--accent-cyan)" }}>
            Detected: {detected.label}
          </p>
        )}
      </div>
    </form>
  );
}
