/** Relative time like "3m ago" / "2h ago" */
export function formatAge(iso) {
  if (!iso) return "—";
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return "—";
  let sec = Math.floor((Date.now() - t) / 1000);
  if (sec < 0) sec = 0;
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const h = Math.floor(min / 60);
  if (h < 48) return `${h}h ago`;
  const d = Math.floor(h / 24);
  return `${d}d ago`;
}

/** True if created_at is within range from now */
export function withinTimeRange(iso, range) {
  if (!iso || range === "all") return true;
  const t = new Date(iso).getTime();
  const now = Date.now();
  const ms = {
    "1h": 3600_000,
    "24h": 86400_000,
    "7d": 7 * 86400_000,
    "30d": 30 * 86400_000,
  }[range];
  if (!ms) return true;
  return now - t <= ms;
}
