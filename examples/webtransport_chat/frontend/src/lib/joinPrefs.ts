// Persists the join form (server URL, certificate hash, display name, mic
// preference) across visits. localStorage only ever holds this one key;
// corrupted or missing data reads back as null so the form falls back to its
// defaults.

const KEY = "webtransport-chat.join";

export type JoinPrefs = {
  url: string;
  certHash: string;
  name: string;
  micOff: boolean;
};

function isJoinPrefs(v: unknown): v is JoinPrefs {
  if (typeof v !== "object" || v === null) return false;
  const p = v as Record<string, unknown>;
  return (
    typeof p.url === "string" &&
    typeof p.certHash === "string" &&
    typeof p.name === "string" &&
    typeof p.micOff === "boolean"
  );
}

export function saveJoinPrefs(prefs: JoinPrefs): void {
  try {
    localStorage.setItem(KEY, JSON.stringify(prefs));
  } catch {
    /* storage unavailable (private mode, quota): joining still works */
  }
}

export function loadJoinPrefs(): JoinPrefs | null {
  try {
    const raw = localStorage.getItem(KEY);
    if (raw === null) return null;
    const parsed: unknown = JSON.parse(raw);
    return isJoinPrefs(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

export function clearJoinPrefs(): void {
  try {
    localStorage.removeItem(KEY);
  } catch {
    /* nothing to clear if storage is unavailable */
  }
}
