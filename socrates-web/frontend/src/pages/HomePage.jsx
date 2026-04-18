import { useState, useEffect, useCallback, useRef } from "react";
import IOCInput from "../components/IOCInput";
import ProgressPanel from "../components/ProgressPanel";
import SummaryBar from "../components/SummaryBar";
import CacheBanner from "../components/CacheBanner";
import EnrichmentCard from "../components/EnrichmentCard";
import VerdictPanel from "../components/VerdictPanel";
import History from "../components/History";
import useAnalysis from "../hooks/useAnalysis";
import { getSessionId } from "../lib/session";

export default function HomePage({ resetKey }) {
  const {
    isLoading,
    sources,
    enrichments,
    aiStatus,
    verdict,
    totalElapsed,
    error,
    currentIOC,
    cacheInfo,
    analyze,
    reset: resetAnalysis,
  } = useAnalysis();

  const [history, setHistory] = useState([]);
  const resetAnalysisRef = useRef(resetAnalysis);
  resetAnalysisRef.current = resetAnalysis;

  useEffect(() => {
    resetAnalysisRef.current();
  }, [resetKey]);

  const loadHistory = useCallback(async () => {
    try {
      const sid = encodeURIComponent(getSessionId());
      const resp = await fetch(`/api/history?limit=20&session_id=${sid}`);
      if (resp.ok) {
        const data = await resp.json();
        if (data.items?.length > 0) {
          setHistory(data.items);
          return;
        }
      }
    } catch {
      // API history unavailable
    }
    try {
      const local = JSON.parse(localStorage.getItem("socrates-history") || "[]");
      setHistory(local);
    } catch {
      setHistory([]);
    }
  }, []);

  useEffect(() => {
    loadHistory();
  }, [loadHistory]);

  useEffect(() => {
    if (verdict && currentIOC) {
      loadHistory();
    }
  }, [verdict, currentIOC, loadHistory]);

  const handleSubmit = (ioc) => {
    analyze(ioc);
  };

  const handleReanalyze = () => {
    if (currentIOC) {
      analyze(currentIOC, { force: true });
    }
  };

  const completedSources = sources.filter(
    (s) => s.status === "complete" || s.status === "error"
  );
  const showResults = completedSources.length > 0;
  const iocType = currentIOC ? detectTypeClient(currentIOC) : null;

  return (
    <main className="flex-1 w-full max-w-6xl mx-auto px-6 py-12 space-y-6">
      {!isLoading && !showResults && (
        <div className="text-center mb-8 animate-fade-in-up">
          <h2
            className="font-display text-4xl sm:text-5xl font-bold mb-3 glow-text"
            style={{ color: "var(--text-primary)" }}
          >
            Threat Intelligence Triage
          </h2>
          <p className="text-base" style={{ color: "var(--text-secondary)" }}>
            Paste an IOC below. SOCrates will enrich it across multiple sources
            and deliver an AI-powered verdict.
          </p>
        </div>
      )}

      <IOCInput key={resetKey} onSubmit={handleSubmit} isLoading={isLoading} />

      {error && (
        <div className="card animate-fade-in-up text-center max-w-3xl mx-auto" style={{ borderColor: "#ef4444" }}>
          <p className="text-sm" style={{ color: "#ef4444" }}>{error}</p>
        </div>
      )}

      <CacheBanner cacheInfo={cacheInfo} onReanalyze={handleReanalyze} isLoading={isLoading} />

      {sources.length > 0 && !cacheInfo && (
        <div className="max-w-3xl mx-auto">
          <ProgressPanel
            sources={sources}
            aiStatus={aiStatus}
            totalElapsed={totalElapsed}
            iocType={iocType}
          />
        </div>
      )}

      {showResults && (
        <SummaryBar
          sources={sources}
          verdict={verdict}
          totalElapsed={totalElapsed}
          iocType={iocType}
        />
      )}

      {showResults && (
        <div>
          <h3 className="section-label px-1 mb-3">Enrichment Results</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {sources.map((s, i) => (
              <EnrichmentCard
                key={s.source}
                source={s.source}
                status={s.status}
                data={enrichments[s.source]}
                error={s.error}
                skip_reason={s.skip_reason}
                iocType={iocType}
                delay={i * 50}
              />
            ))}
          </div>
        </div>
      )}

      {verdict && (
        <div>
          <h3 className="section-label px-1 mb-3">Triage Verdict</h3>
          <VerdictPanel verdict={verdict} />
        </div>
      )}

      <History items={history} onSelect={handleSubmit} />
    </main>
  );
}

function detectTypeClient(value) {
  if (/^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/.test(value)) return "ip";
  if (/^[0-9a-fA-F]{32,64}$/.test(value)) return "hash";
  if (/^https?:\/\//i.test(value)) return "url";
  if (/^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(value)) return "domain";
  return "unknown";
}
