// Receive-side screen-share pipeline: reassembled ScreenFrame (from
// moqtScreenWire.ts's frame reassembler) -> per-sender VideoDecoder ->
// caller-supplied onFrame callback. Mirrors voiceReceivePipeline.ts's
// per-sender decoder lifecycle, but the state machine differs: VP8 delta
// frames are meaningless without a preceding keyframe, so each sender
// tracks WaitKey (decoder not configured, deltas dropped) vs Decoding
// (configured, every frame fed to decode()). A decode error/throw drops
// back to WaitKey; the next keyframe re-configures and re-enters Decoding.
//
// Unlike voice's AudioDecoder wrapping (OpusChunkDecoder in useMoqtChat.ts),
// this file stays DOM-free and testable without a browser: the caller owns
// drawing decoded VideoFrames to canvas and calling frame.close() (Part B).

export type ScreenFrameInput = {
  data: Uint8Array;
  keyframe: boolean;
  width?: number;
  height?: number;
  codec?: string;
};

export type SenderState = "WaitKey" | "Decoding";

type Decoder = {
  configure: (config: unknown) => void;
  decode: (chunk: unknown) => void;
  close?: () => void;
};

export type ScreenReceivePipelineDeps = {
  VideoDecoderCtor: new (init: {
    output: (frame: unknown) => void;
    error: (err: unknown) => void;
  }) => Decoder;
  onFrame: (senderKey: string, frame: unknown) => void;
  onDecodeError?: (err: unknown) => void;
};

export type ScreenReceivePipeline = {
  handleFrame: (senderKey: string, frame: ScreenFrameInput) => void;
  stateFor: (senderKey: string) => SenderState;
  closeSender: (senderKey: string) => void;
};

export function createScreenReceivePipeline(
  deps: ScreenReceivePipelineDeps,
): ScreenReceivePipeline {
  const decoders = new Map<string, Decoder>();
  const states = new Map<string, SenderState>();

  const dropDecoder = (senderKey: string) => {
    decoders.delete(senderKey);
    states.set(senderKey, "WaitKey");
  };

  // One VideoDecoder per sender, reused across keyframes -- mirrors
  // voiceReceivePipeline.ts's decoderFor. A keyframe still calls
  // configure() again (VP8 dimensions can change between shares), but
  // that reconfigures the existing decoder instead of leaking it: the
  // previous instance was never closed before being replaced.
  const configure = (senderKey: string, frame: ScreenFrameInput): Decoder => {
    let decoder = decoders.get(senderKey);
    if (!decoder) {
      decoder = new deps.VideoDecoderCtor({
        output: (out) => deps.onFrame(senderKey, out),
        error: (err) => {
          dropDecoder(senderKey);
          deps.onDecodeError?.(err);
        },
      });
      decoders.set(senderKey, decoder);
    }
    decoder.configure({
      codec: frame.codec,
      codedWidth: frame.width,
      codedHeight: frame.height,
    });
    states.set(senderKey, "Decoding");
    return decoder;
  };

  return {
    handleFrame: (senderKey, frame) => {
      const state = states.get(senderKey) ?? "WaitKey";
      if (state === "WaitKey" && !frame.keyframe) return; // no decoder to configure yet

      const decoder = frame.keyframe ? configure(senderKey, frame) : decoders.get(senderKey);
      if (!decoder) return; // defensive: WaitKey + non-keyframe already returned above

      try {
        decoder.decode(frame.data);
      } catch (err) {
        dropDecoder(senderKey);
        deps.onDecodeError?.(err);
      }
    },
    stateFor: (senderKey) => states.get(senderKey) ?? "WaitKey",
    closeSender: (senderKey) => {
      decoders.get(senderKey)?.close?.();
      decoders.delete(senderKey);
      states.delete(senderKey);
    },
  };
}
