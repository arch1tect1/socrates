import { createClient } from "@supabase/supabase-js";

// Build: injected in vite.config from SUPABASE_URL / NEXT_PUBLIC_SUPABASE_ANON_KEY (or VITE_*).
// Dev: same + import.meta.env fallbacks when using .env.local with VITE_ or NEXT_PUBLIC_.
// eslint-disable-next-line no-undef -- Vite `define`
const _defUrl = typeof __SOC_SUPABASE_URL__ !== "undefined" ? __SOC_SUPABASE_URL__ : "";
// eslint-disable-next-line no-undef
const _defAnon = typeof __SOC_SUPABASE_ANON__ !== "undefined" ? __SOC_SUPABASE_ANON__ : "";

const url =
  _defUrl ||
  import.meta.env.VITE_SUPABASE_URL ||
  import.meta.env.NEXT_PUBLIC_SUPABASE_URL ||
  "";
const anon =
  _defAnon ||
  import.meta.env.VITE_SUPABASE_ANON_KEY ||
  import.meta.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ||
  "";

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
