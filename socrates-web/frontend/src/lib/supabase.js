import { createClient } from "@supabase/supabase-js";

const url = import.meta.env.VITE_SUPABASE_URL;
const anon = import.meta.env.VITE_SUPABASE_ANON_KEY;

/** Browser client — requires anon key + RLS policies allowing read (and insert if needed). */
export const supabase =
  url && anon
    ? createClient(url, anon, {
        auth: { persistSession: false },
      })
    : null;

export function isSupabaseConfigured() {
  return Boolean(url && anon);
}
