// Renders decoded voice AudioData through Web Audio, one running playhead
// PER SENDER: a single shared playhead would serialize every speaker onto
// one timeline, so a room of 3 people talking at once would play their
// voices one after another instead of together, and each additional
// speaker would push everyone else's audio further into the future
// (audible, growing delay). Each sender gets its own playhead so
// concurrent speakers overlap in playback exactly as they do in real life,
// and each sender's own playhead still keeps their own frames back-to-back
// and gapless.
import { voiceTap } from "./voiceTap";

export function createPlaybackSink(
  ctx: AudioContext,
): (senderKey: string, frame: unknown) => void {
  const playheads = new Map<string, number>();
  return (senderKey, frame) => {
    const audio = frame as AudioData;
    const buf = ctx.createBuffer(audio.numberOfChannels, audio.numberOfFrames, audio.sampleRate);
    for (let ch = 0; ch < audio.numberOfChannels; ch++) {
      const data = new Float32Array(audio.numberOfFrames);
      audio.copyTo(data, { planeIndex: ch, format: "f32-planar" });
      buf.copyToChannel(data, ch);
    }
    audio.close();
    const src = ctx.createBufferSource();
    src.buffer = buf;
    src.connect(ctx.destination);
    const playhead = Math.max(playheads.get(senderKey) ?? 0, ctx.currentTime);
    // seq doesn't survive decoding (AudioDecoder emits bare AudioData), so
    // this reports only the scheduling lag time series; lag is milliseconds.
    voiceTap({
      dir: "play",
      seq: -1,
      t: performance.now(),
      lag: (playhead - ctx.currentTime) * 1000,
    });
    src.start(playhead);
    playheads.set(senderKey, playhead + buf.duration);
  };
}
