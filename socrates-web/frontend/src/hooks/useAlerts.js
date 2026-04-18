import { useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { supabase, isSupabaseConfigured } from "../lib/supabase";
import { withinTimeRange } from "../lib/time";

function parseList(param) {
  if (!param || !String(param).trim()) return [];
  return String(param)
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function latestVerdict(verdicts) {
  if (!verdicts?.length) return null;
  return [...verdicts].sort(
    (a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0)
  )[0];
}

async function fetchAlertFull(id) {
  if (!supabase) return null;
  const { data, error } = await supabase
    .from("alerts")
    .select("*, alert_iocs(*), verdicts(*)")
    .eq("id", id)
    .maybeSingle();
  if (error) {
    console.warn("fetchAlertFull", error);
    return null;
  }
  return data;
}

export function useAlerts() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const filters = useMemo(
    () => ({
      status: parseList(searchParams.get("status")),
      severity: parseList(searchParams.get("severity")),
      range: searchParams.get("range") || "24h",
      q: (searchParams.get("q") || "").trim().toLowerCase(),
      source: (searchParams.get("source") || "").trim(),
    }),
    [searchParams]
  );

  const setFilters = useCallback(
    (patch) => {
      const next = new URLSearchParams(searchParams);
      Object.entries(patch).forEach(([k, v]) => {
        if (v === undefined || v === null || v === "" || v === "all") {
          next.delete(k);
        } else {
          next.set(k, String(v));
        }
      });
      setSearchParams(next, { replace: true });
    },
    [searchParams, setSearchParams]
  );

  const applyClientFilters = useCallback(
    (list) => {
      let out = list || [];
      const { status, severity, range, q, source } = filters;

      if (status.length) {
        out = out.filter((a) => status.includes(a.status));
      }
      if (severity.length) {
        out = out.filter((a) => severity.includes(a.severity));
      }
      out = out.filter((a) => withinTimeRange(a.created_at, range));
      if (source) {
        out = out.filter((a) => (a.source || "") === source);
      }
      if (q) {
        out = out.filter((a) => {
          const rule = (a.rule_name || "").toLowerCase();
          const title = (a.title || "").toLowerCase();
          const desc = (a.description || "").toLowerCase();
          const iocs = (a.alert_iocs || []).some((ioc) =>
            (ioc.ioc_value || "").toLowerCase().includes(q)
          );
          return (
            rule.includes(q) ||
            title.includes(q) ||
            desc.includes(q) ||
            iocs
          );
        });
      }
      return out;
    },
    [filters]
  );

  const alerts = useMemo(
    () => applyClientFilters(rows),
    [rows, applyClientFilters]
  );

  const sources = useMemo(() => {
    const s = new Set();
    rows.forEach((a) => {
      if (a.source) s.add(a.source);
    });
    return [...s].sort();
  }, [rows]);

  useEffect(() => {
    if (!isSupabaseConfigured() || !supabase) {
      setLoading(false);
      setError(
        new Error(
          "Set VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY for the alerts dashboard."
        )
      );
      return;
    }

    let cancelled = false;

    const loadInitial = async () => {
      setLoading(true);
      setError(null);
      const { data, error: err } = await supabase
        .from("alerts")
        .select("*, alert_iocs(*), verdicts(*)")
        .order("created_at", { ascending: false })
        .limit(100);

      if (cancelled) return;
      if (err) {
        setError(err);
        setRows([]);
      } else {
        setRows(data ?? []);
      }
      setLoading(false);
    };

    loadInitial();

    const channel = supabase
      .channel("alerts-dashboard")
      .on(
        "postgres_changes",
        { event: "INSERT", schema: "public", table: "alerts" },
        async (payload) => {
          const full = await fetchAlertFull(payload.new?.id);
          if (!full) return;
          setRows((prev) => {
            const rest = prev.filter((a) => a.id !== full.id);
            return [full, ...rest].slice(0, 100);
          });
        }
      )
      .on(
        "postgres_changes",
        { event: "UPDATE", schema: "public", table: "alerts" },
        async (payload) => {
          const id = payload.new?.id;
          if (!id) return;
          const full = await fetchAlertFull(id);
          if (!full) return;
          setRows((prev) =>
            prev.map((a) => (a.id === full.id ? full : a))
          );
        }
      )
      .on(
        "postgres_changes",
        { event: "INSERT", schema: "public", table: "verdicts" },
        async (payload) => {
          const row = payload.new;
          if (!row?.alert_id) return;
          setRows((prev) => {
            const i = prev.findIndex((a) => a.id === row.alert_id);
            if (i < 0) return prev;
            const copy = [...prev];
            const a = { ...copy[i] };
            const v = (a.verdicts || []).filter((x) => x.id !== row.id);
            a.verdicts = [...v, row];
            copy[i] = a;
            return copy;
          });
        }
      )
      .subscribe();

    return () => {
      cancelled = true;
      supabase.removeChannel(channel);
    };
  }, []);

  return {
    alerts,
    loading,
    error,
    filters,
    setFilters,
    sources,
    latestVerdict,
  };
}
