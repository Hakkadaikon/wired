// Persists the join form (server URL, certificate hash, participant id)
// across visits. localStorage only ever holds this one key; corrupted or
// missing data reads back as null so the form falls back to its defaults.
//
// Unlike webtransport_chat's joinPrefs, there is no room field (moqt_chat is
// a single fixed room, moqt-plan.md decision 3) and no mic-off field until
// voice ships (M5).

const KEY = "moqt-chat.join";

export type JoinPrefs = {
  url: string;
  certHash: string;
  name: string;
  // Free-text display name (moqt-plan.md's participant id stays the wire
  // identity/track-alias key; this is presentation-only, see moqtClient.ts's
  // nickname self-announce). Older saved prefs lack it -- isJoinPrefs below
  // accepts a missing field and loadJoinPrefs backfills "".
  nickname?: string;
};

function isJoinPrefs(v: unknown): v is JoinPrefs {
  if (typeof v !== "object" || v === null) return false;
  const p = v as Record<string, unknown>;
  return (
    typeof p.url === "string" &&
    typeof p.certHash === "string" &&
    typeof p.name === "string" &&
    (p.nickname === undefined || typeof p.nickname === "string")
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

// RNNoise defaults on in production; the e2e harness appends `?ns=0` to
// isolate transport gates (loss/jitter/plc) from the worklet's own CPU cost
// (see noiseSuppressor.ts) rather than measuring the network path.
export function noiseSuppressionDefault(search: string): boolean {
  return new URLSearchParams(search).get("ns") !== "0";
}
