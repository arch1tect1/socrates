import { useEffect, useState } from "react";
import { supabase, isSupabaseConfigured } from "../lib/supabase";

export function useAlertDetail(id) {
  const [alert, setAlert] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!id) {
      setAlert(null);
      setLoading(false);
      return;
    }

    if (!isSupabaseConfigured() || !supabase) {
      setError(new Error("Supabase not configured"));
      setLoading(false);
      return;
    }

    let cancelled = false;

    const load = async () => {
      setLoading(true);
      setError(null);
      const { data, error: err } = await supabase
        .from("alerts")
        .select("*, alert_iocs(*), verdicts(*)")
        .eq("id", id)
        .maybeSingle();

      if (cancelled) return;
      if (err) {
        setError(err);
        setAlert(null);
      } else {
        setAlert(data);
      }
      setLoading(false);
    };

    load();

    const channel = supabase
      .channel(`alert-detail-${id}`)
      .on(
        "postgres_changes",
        {
          event: "*",
          schema: "public",
          table: "alerts",
          filter: `id=eq.${id}`,
        },
        () => load()
      )
      .on(
        "postgres_changes",
        {
          event: "INSERT",
          schema: "public",
          table: "verdicts",
          filter: `alert_id=eq.${id}`,
        },
        () => load()
      )
      .subscribe();

    return () => {
      cancelled = true;
      supabase.removeChannel(channel);
    };
  }, [id]);

  return { alert, loading, error };
}
