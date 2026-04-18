import { ChevronDown } from "lucide-react";

/** One-line preview for collapsed <details> headers */
function iterationPreview(step) {
  const sr = (step.stop_reason || "").toLowerCase();
  const blocks = step.content || [];

  if (sr === "end_turn") {
    const textBlock = blocks.find((b) => b.type === "text");
    if (textBlock?.text) {
      const t = String(textBlock.text).trim();
      return t.length > 100 ? `${t.slice(0, 100)}…` : t || "Final verdict";
    }
    return "Final verdict";
  }

  const toolBlock = blocks.find((b) => b.type === "tool_use");
  const textBlock = blocks.find((b) => b.type === "text");
  const inp = toolBlock?.input && typeof toolBlock.input === "object" ? toolBlock.input : {};
  const toolName = toolBlock?.name;
  const iocValue =
    inp.ioc_value ?? inp.ip ?? inp.domain ?? inp.url ?? (Object.keys(inp).length ? "…" : null);

  let reasoningPreview = null;
  if (textBlock?.text) {
    const t = String(textBlock.text).trim();
    reasoningPreview = t.length > 80 ? `${t.slice(0, 80)}…` : t;
  }

  if (reasoningPreview && toolName) {
    return `${reasoningPreview}  →  ${toolName}(${iocValue ?? "…"})`;
  }
  if (toolName) {
    return `${toolName}(${iocValue ?? "…"})`;
  }
  if (reasoningPreview) {
    return reasoningPreview;
  }
  return "";
}

function BlockContent({ block }) {
  if (!block || typeof block !== "object") return null;
  if (block.type === "text") {
    return (
      <p className="text-sm whitespace-pre-wrap leading-relaxed" style={{ color: "var(--text-secondary)" }}>
        {block.text}
      </p>
    );
  }
  if (block.type === "tool_use") {
    return (
      <div className="rounded-lg border p-3 space-y-2" style={{ borderColor: "var(--border)", background: "var(--bg-card-hover)" }}>
        <div className="text-xs font-semibold text-cyan-400/90">Tool: {block.name}</div>
        <pre
          className="text-[11px] overflow-x-auto p-2 rounded border font-mono"
          style={{
            borderColor: "var(--border)",
            background: "var(--bg-primary)",
            color: "var(--text-muted)",
          }}
        >
          {JSON.stringify(block.input ?? {}, null, 2)}
        </pre>
      </div>
    );
  }
  return (
    <pre className="text-[10px] font-mono opacity-70 overflow-x-auto">
      {JSON.stringify(block, null, 2)}
    </pre>
  );
}

export default function AgentTraceViewer({ verdict }) {
  const trace = verdict?.agent_trace;
  if (!trace || !Array.isArray(trace) || trace.length === 0) {
    return (
      <p className="text-sm" style={{ color: "var(--text-muted)" }}>
        No agent trace stored for this verdict.
      </p>
    );
  }

  return (
    <div className="space-y-4">
      {trace.map((step, idx) => {
        const preview = iterationPreview(step);
        return (
        <details
          key={idx}
          className="group card open:border-cyan-500/30"
          open={idx < 3}
        >
          <summary className="cursor-pointer list-none flex items-center gap-2 gap-y-1 font-medium text-sm select-none flex-wrap">
            <ChevronDown className="w-4 h-4 shrink-0 transition-transform group-open:rotate-180 text-cyan-400/80" />
            <span style={{ color: "var(--text-primary)" }} className="shrink-0">
              Iteration {(step.iteration ?? idx) + 1}
              {step.stop_reason && (
                <span className="ml-2 text-xs font-normal opacity-70">
                  ({step.stop_reason})
                </span>
              )}
            </span>
            {preview ? (
              <span
                className="text-xs font-mono truncate flex-1 min-w-[12rem] max-w-full pl-1"
                style={{ color: "var(--text-muted)" }}
                title={preview}
              >
                {preview}
              </span>
            ) : null}
          </summary>
          <div className="mt-3 pl-6 space-y-3 border-l-2 border-cyan-500/20 ml-1.5">
            {(step.content || []).map((block, j) => (
              <div key={j}>
                <BlockContent block={block} />
              </div>
            ))}
          </div>
        </details>
        );
      })}

      <div
        className="rounded-xl border p-4 mt-6"
        style={{
          borderColor: "rgba(239, 68, 68, 0.35)",
          background: "rgba(239, 68, 68, 0.06)",
        }}
      >
        <div className="text-xs font-semibold uppercase tracking-wide text-red-300/90 mb-1">
          Final verdict
        </div>
        <p className="text-sm font-mono">
          <span className="text-red-200">{verdict.verdict}</span>
          {verdict.confidence != null && (
            <span className="text-slate-400 ml-2">(confidence {Number(verdict.confidence).toFixed(2)})</span>
          )}
        </p>
        {verdict.recommended_action && (
          <p className="text-xs mt-2" style={{ color: "var(--text-secondary)" }}>
            Recommended:{" "}
            <code className="text-cyan-300/90">{verdict.recommended_action}</code>
          </p>
        )}
      </div>
    </div>
  );
}
