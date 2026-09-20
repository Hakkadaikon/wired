// Pass/fail gates over summarizeVoiceTrace's output (voiceMetrics.mjs).
// Pure functions so the thresholds are unit-testable; scenarios override
// knobs per network profile (a 5% loss profile tolerates more than clean).
// send->recv latency and buffer dwell stay report-only until a baseline is
// established -- gating them now would encode today's numbers, not a spec.

export const DEFAULT_VOICE_GATES = {
  maxFrameLossRate: 0.005, // seq-gap loss per pub->sub pair
  maxInterArrivalP99Ms: 100, // received-frame spacing p99
  maxPlayheadLagGrowthMs: 100, // last-quarter mean - first-quarter mean
  maxMeanSendBytes: 90, // mean encoded Opus frame size (VOIP config, 20ms/24kbps)
  maxPlayheadLagP95Ms: 220, // absolute p95 scheduling lag (Q-A jitter buffer)
  maxSkippedRate: 0.01, // fraction of play() calls dropped by the lag cap
  maxPlcCount: 0, // Q-B concealed losses per pub->sub pair (0 = clean network)
  minPlcCount: 0, // report-only unless a scenario overrides it (e.g. loss profile)
};

/**
 * @param {object} voiceTrace summarizeVoiceTrace() result
 * @param {object} [overrides] partial DEFAULT_VOICE_GATES
 * @returns {string[]} failures (empty = all gates green)
 */
export function evaluateVoiceGates(voiceTrace, overrides = {}) {
  const g = { ...DEFAULT_VOICE_GATES, ...overrides };
  const failures = [];
  for (const [page, data] of Object.entries(voiceTrace ?? {})) {
    for (const [src, s] of Object.entries(data.perSender ?? {})) {
      const loss = s.loss?.lossRate ?? 0;
      if (loss > g.maxFrameLossRate) {
        failures.push(
          `${src}->${page}: frame loss ${(loss * 100).toFixed(2)}% > ` +
            `${(g.maxFrameLossRate * 100).toFixed(2)}% ` +
            `(${s.loss.lost}/${s.loss.received + s.loss.lost})`,
        );
      }
      const p99 = s.interArrivalMs?.p99;
      if (p99 != null && p99 > g.maxInterArrivalP99Ms) {
        failures.push(
          `${src}->${page}: inter-arrival p99 ${p99.toFixed(1)}ms > ${g.maxInterArrivalP99Ms}ms`,
        );
      }
      const meanBytes = s.sendBytesMean;
      if (meanBytes != null && meanBytes > g.maxMeanSendBytes) {
        failures.push(
          `${src}->${page}: mean send bytes ${meanBytes.toFixed(1)} > ${g.maxMeanSendBytes}`,
        );
      }
      const plcCount = s.plcCount ?? 0;
      if (plcCount > g.maxPlcCount) {
        failures.push(`${src}->${page}: plc count ${plcCount} > ${g.maxPlcCount}`);
      }
      if (plcCount < g.minPlcCount) {
        failures.push(`${src}->${page}: plc count ${plcCount} < ${g.minPlcCount}`);
      }
    }
    const lag = data.playheadLag;
    if (lag) {
      const growth = lag.lastQuarterMeanMs - lag.firstQuarterMeanMs;
      if (growth > g.maxPlayheadLagGrowthMs) {
        failures.push(
          `${page}: playhead lag grew ${growth.toFixed(1)}ms > ${g.maxPlayheadLagGrowthMs}ms ` +
            `(first-quarter ${lag.firstQuarterMeanMs.toFixed(1)} -> last-quarter ${lag.lastQuarterMeanMs.toFixed(1)})`,
        );
      }
      if (lag.p95 != null && lag.p95 > g.maxPlayheadLagP95Ms) {
        failures.push(`${page}: playhead lag p95 ${lag.p95.toFixed(1)}ms > ${g.maxPlayheadLagP95Ms}ms`);
      }
    }
    const playCount = data.playCount ?? 0;
    if (playCount > 0) {
      const skippedRate = (data.skippedCount ?? 0) / playCount;
      if (skippedRate > g.maxSkippedRate) {
        failures.push(
          `${page}: skipped rate ${(skippedRate * 100).toFixed(2)}% > ` +
            `${(g.maxSkippedRate * 100).toFixed(2)}% (${data.skippedCount}/${playCount})`,
        );
      }
    }
  }
  return failures;
}
