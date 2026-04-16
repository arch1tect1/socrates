/** Fallback labels when API omits skip_reason (kept in sync with backend skip_reasons.py). */

const SOURCE_IOC_SUPPORT = {
  VirusTotal: new Set(["ip", "domain", "url", "hash"]),
  Shodan: new Set(["ip", "domain"]),
  AbuseIPDB: new Set(["ip", "domain"]),
  "OTX AlienVault": new Set(["ip", "domain", "hash"]),
  "URLScan.io": new Set(["domain", "url"]),
};

const SKIP_FALLBACK = {
  Shodan: "IP and domain lookups only",
  AbuseIPDB: "IP and domain lookups only",
  "OTX AlienVault": "Not supported for this IOC type",
  "URLScan.io": "Domains and URLs only",
};

export function skipReasonForSource(source, iocType) {
  const t = (iocType || "").toLowerCase();
  const supported = SOURCE_IOC_SUPPORT[source];
  if (!supported) return "Not supported for this IOC type";
  const effective = t && t !== "unknown" ? t : null;
  if (!effective || !supported.has(effective)) {
    return SKIP_FALLBACK[source] || "Not supported for this IOC type";
  }
  return "Unavailable for this query";
}
