import { useState } from "react";
import { Settings2 } from "lucide-react";

const STORAGE_KEY = "socrates_setup_intro_dismissed";

export default function SetupIntroCard({ onChooseStart }) {
  const [dismissed, setDismissed] = useState(
    () => typeof window !== "undefined" && localStorage.getItem(STORAGE_KEY) === "1"
  );

  if (dismissed) return null;

  const dismissSkip = () => {
    localStorage.setItem(STORAGE_KEY, "1");
    setDismissed(true);
  };

  const dismissStart = () => {
    localStorage.setItem(STORAGE_KEY, "1");
    onChooseStart?.();
    setDismissed(true);
  };

  return (
    <div
      className="card w-full max-w-3xl mx-auto animate-fade-in-up"
      style={{ borderLeft: "3px solid rgba(34,211,238,0.4)" }}
    >
      <div className="flex items-start gap-3">
        <Settings2 size={20} className="flex-shrink-0 mt-0.5" style={{ color: "#22d3ee" }} />
        <div className="min-w-0 flex-1 space-y-3">
          <div>
            <h3 className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>
              Quick setup (optional, ~30 seconds)
            </h3>
            <p className="text-xs mt-1 leading-relaxed" style={{ color: "var(--text-secondary)" }}>
              Answer a few questions about your environment so SOCrates can tailor triage recommendations
              to your context. For example: a bank seeing traffic to a crypto mining pool may rate it
              CRITICAL, while a crypto company might treat the same IOC as normal. Your answers help the
              AI make smarter, context-aware decisions.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={dismissStart}
              className="text-xs font-semibold px-3 py-1.5 rounded-lg transition-opacity hover:opacity-90"
              style={{
                background: "rgba(34,211,238,0.15)",
                color: "#22d3ee",
                border: "1px solid rgba(34,211,238,0.35)",
              }}
            >
              Start setup
            </button>
            <button
              type="button"
              onClick={dismissSkip}
              className="text-xs px-3 py-1.5 rounded-lg transition-opacity hover:opacity-80"
              style={{ color: "var(--text-muted)", border: "1px solid var(--border)" }}
            >
              Skip — use defaults
            </button>
          </div>
          <p className="text-[10px]" style={{ color: "var(--text-muted)" }}>
            Full org profile setup is available in the Telegram bot via{" "}
            <code className="text-[10px]">/setup</code>. On the web, analysis uses generic context until you configure that flow.
          </p>
        </div>
      </div>
    </div>
  );
}
