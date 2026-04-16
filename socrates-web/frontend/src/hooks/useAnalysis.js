import { useState, useCallback, useRef } from "react";
import { getSessionId } from "../lib/session";

const SOURCES = [
  "VirusTotal",
  "Shodan",
  "AbuseIPDB",
  "OTX AlienVault",
  "URLScan.io",
];

export default function useAnalysis() {
  const [isLoading, setIsLoading] = useState(false);
  const [sources, setSources] = useState([]);
  const [enrichments, setEnrichments] = useState({});
  const [aiStatus, setAiStatus] = useState(null);
  const [verdict, setVerdict] = useState(null);
  const [totalElapsed, setTotalElapsed] = useState(null);
  const [error, setError] = useState(null);
  const [currentIOC, setCurrentIOC] = useState(null);
  const [cacheInfo, setCacheInfo] = useState(null);
  const abortRef = useRef(null);
  /** Incremented on every reset / new session so in-flight async work can bail out. */
  const analysisEpochRef = useRef(0);

  const reset = useCallback(() => {
    analysisEpochRef.current += 1;
    if (abortRef.current) {
      try {
        abortRef.current.abort();
      } catch {
        /* ignore */
      }
      abortRef.current = null;
    }
    setIsLoading(false);
    setCurrentIOC(null);
    setSources([]);
    setEnrichments({});
    setAiStatus(null);
    setVerdict(null);
    setTotalElapsed(null);
    setError(null);
    setCacheInfo(null);
  }, []);

  function applyCachedResult(data) {
    if (data.sources) {
      setSources(
        data.sources.map((s) => ({
          source: s.source,
          status: s.status,
          elapsed: s.elapsed,
          error: s.error || null,
          skip_reason: s.skip_reason || null,
        }))
      );
    }

    if (data.enrichments) {
      setEnrichments(data.enrichments);
    }

    if (data.verdict) {
      setAiStatus("complete");
      setVerdict(data.verdict);
    }

    setTotalElapsed(data.total_elapsed);
    setCacheInfo({ created_at: data.created_at, query_id: data.query_id });
  }

  async function checkCache(ioc) {
    try {
      const resp = await fetch(`/api/cache/check?ioc=${encodeURIComponent(ioc)}`);
      if (!resp.ok) return null;
      const data = await resp.json();
      if (data.cached) return data;
    } catch {
      // cache check failure is non-fatal
    }
    return null;
  }

  async function analyzeSSE(ioc, signal) {
    const urls = ["/api/analyze", "http://localhost:8000/api/analyze"];
    let lastErr = null;

    for (const url of urls) {
      try {
        const resp = await fetch(url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ ioc, session_id: getSessionId() }),
          signal,
        });

        if (!resp.ok) {
          const errData = await resp.json().catch(() => ({}));
          throw new Error(errData.detail || `HTTP ${resp.status}`);
        }

        const ct = resp.headers.get("content-type") || "";
        if (!ct.includes("text/event-stream")) {
          throw new Error("SSE not supported by server");
        }

        const reader = resp.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";
        let eventType = null;
        let receivedEvents = false;

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split("\n");
          buffer = lines.pop() || "";

          for (const line of lines) {
            if (line.startsWith("event: ")) {
              eventType = line.slice(7).trim();
            } else if (line.startsWith("data: ") && eventType) {
              try {
                const data = JSON.parse(line.slice(6));
                handleEvent(eventType, data);
                receivedEvents = true;
              } catch {
                // skip malformed JSON
              }
              eventType = null;
            } else if (line === "") {
              eventType = null;
            }
          }
        }

        if (receivedEvents) return true;
        throw new Error("No SSE events received");
      } catch (err) {
        if (err.name === "AbortError") throw err;
        lastErr = err;
      }
    }
    throw lastErr || new Error("SSE failed");
  }

  async function analyzeBatch(ioc, signal, force = false) {
    const resp = await fetch("/api/analyze/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ioc, force, session_id: getSessionId() }),
      signal,
    });

    if (!resp.ok) {
      const errData = await resp.json().catch(() => ({}));
      throw new Error(errData.detail || `HTTP ${resp.status}`);
    }

    const data = await resp.json();

    if (data.cached) {
      applyCachedResult(data);
      return;
    }

    setSources(
      data.sources.map((s) => ({
        source: s.source,
        status: s.status,
        elapsed: s.elapsed,
        error: s.error || null,
        skip_reason: s.skip_reason || null,
      }))
    );

    const enrichMap = {};
    for (const s of data.sources) {
      if (s.status === "complete" && s.data) {
        enrichMap[s.source] = s.data;
      }
    }
    setEnrichments(enrichMap);

    setAiStatus("complete");
    setVerdict(data.verdict);
    setTotalElapsed(data.total_elapsed);
  }

  const analyze = useCallback(async (ioc, { force = false } = {}) => {
    if (abortRef.current) {
      try {
        abortRef.current.abort();
      } catch {
        /* ignore */
      }
      abortRef.current = null;
    }

    reset();
    const controller = new AbortController();
    abortRef.current = controller;
    const epoch = analysisEpochRef.current;

    setIsLoading(true);
    setCurrentIOC(ioc);

    // Check cache first (unless force re-analyse)
    if (!force) {
      const cached = await checkCache(ioc);
      if (epoch !== analysisEpochRef.current) {
        return;
      }
      if (cached) {
        applyCachedResult(cached);
        setIsLoading(false);
        abortRef.current = null;
        return;
      }
    }

    if (epoch !== analysisEpochRef.current) {
      return;
    }

    setSources(
      SOURCES.map((s) => ({
        source: s,
        status: "pending",
        elapsed: null,
        error: null,
        skip_reason: null,
      }))
    );

    try {
      await analyzeSSE(ioc, controller.signal);
    } catch (sseErr) {
      if (sseErr.name === "AbortError") {
        setIsLoading(false);
        abortRef.current = null;
        return;
      }

      if (epoch !== analysisEpochRef.current) {
        return;
      }

      try {
        setAiStatus("generating");
        await analyzeBatch(ioc, controller.signal, force);
      } catch (batchErr) {
        if (batchErr.name !== "AbortError") {
          setError(batchErr.message);
        }
      }
    } finally {
      if (epoch === analysisEpochRef.current) {
        setIsLoading(false);
        abortRef.current = null;
      }
    }
  }, [reset]);

  function handleEvent(event, data) {
    switch (event) {
      case "sources":
        setSources(
          data.map((s) => ({
            ...s,
            elapsed: null,
            error: null,
            skip_reason: null,
            data: null,
          }))
        );
        break;

      case "source_status":
        setSources((prev) =>
          prev.map((s) =>
            s.source === data.source ? { ...s, status: data.status } : s
          )
        );
        break;

      case "source_complete":
        setSources((prev) =>
          prev.map((s) =>
            s.source === data.source
              ? {
                  ...s,
                  status: data.status,
                  elapsed: data.elapsed,
                  error: data.error || null,
                  skip_reason: data.skip_reason || null,
                }
              : s
          )
        );
        if (data.status === "complete" && data.data) {
          setEnrichments((prev) => ({ ...prev, [data.source]: data.data }));
        }
        break;

      case "ai_start":
        setAiStatus("generating");
        break;

      case "ai_complete":
        setAiStatus("complete");
        setVerdict(data.verdict);
        setTotalElapsed(data.total_elapsed);
        break;

      case "done":
        setTotalElapsed(data.total_elapsed);
        break;

      default:
        break;
    }
  }

  return {
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
    reset,
  };
}
