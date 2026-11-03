# moqt_chat: camera video, virtual background, and mp4 streaming

Status: approved design, 2026-11-04 (the request itself fixed the
approach). Implementation plan follows this spec.

## Intent

A participant can show themselves on camera, optionally hiding the room
behind a blurred or replaced background, and can instead stream a saved mp4
into the room. Both are turned on and off from the frontend. The request
named the background method: MediaPipe's person segmentation plus a
self-written WebGL compositor, the way LiveKit's track processors work.

## Goals

1. **Camera on/off.** The participant's camera goes out on a new track
   `<id>/camera`. Every other participant sees it in a camera tile.
2. **Virtual background.** While the camera is the source, the participant
   picks `none`, `blur` or `image` (one bundled image).
   - MediaPipe's selfie segmenter cuts out the person.
   - An app-owned WebGL2 shader composites person and background before
     encoding.
   - Changing the mode applies to the next frames, without restarting the
     camera or the track.
3. **Video streaming on/off.** Turning it on streams a saved mp4 on the same
   camera track.
   - The default is a sample mp4 shipped with the app.
   - The participant may pick another local mp4 instead.
   - The file loops, and only its video is sent. Its audio is not sent and
     not played locally.
4. **One source per track.** At most one of camera and file feeds the camera
   track at a time. Choosing one while the other is live switches the source
   without ending the track.
5. **Screen sharing is independent.** It keeps running beside camera or file
   streaming.

## Non-goals

- Sending the mp4's audio.
- More than one bundled background image, or uploading your own.
- Camera device selection: the browser's default camera is used.
- A low-rate variant (track switching) for the camera track.

## Anti-goals

These would make the feature a failure even if it works:

- **Leaking the room.** With a background effect selected, the room must
  never be sent while the segmenter is still loading or after it failed to
  load. Frames are withheld instead (fail-closed).
- **Holding the camera after off.** The camera light must go out when the
  participant turns the camera off, leaves, or switches to the file. This
  includes the case where the camera permission prompt resolves only after
  the participant already switched away.
- **Breaking chat, voice or screen sharing.** A camera failure must not
  break them, the same isolation rule the screen share follows.

## Constraints

- The frontend is a static export on GitHub Pages under `/wired/moqt_chat/`.
  The MediaPipe wasm (~13.5 MB) and the model (~250 KB) are served from the
  app's own origin and base path, not from a CDN.
- **Hub capacity.** The hub's per-peer track limit was 4 (chat, audio,
  screen, screen-lo), and the camera is a fifth track.
  `WIRED_MOQTRUN_MAX_TRACKS_PER_PEER` becomes 5. `WIRED_MOQTRUN_MAX_REQS`
  becomes 128 (32 per session), because a full room now needs 24 request
  streams per peer.
- **Track aliases.** Chat uses 0..3, audio 4..7, screen 10..13 and
  screen-lo 14..17, so the camera takes 18..21. The client's incoming-stream
  routing checks the camera range before its voice fallback.

## Approaches

| Approach | Trade-off | Decision |
|---|---|---|
| MediaPipe Tasks Vision `ImageSegmenter` + own WebGL2 compositor | One dependency; full control; wasm hosted by us | **Chosen** (requested) |
| `@livekit/track-processors` | Fastest to a demo, but built around LiveKit tracks | Rejected |
| Chrome's `backgroundBlur` constraint | Platform-limited, blur only | Rejected |

## Design

### Transport

- The screen-share client (`MoqtScreenClient`) takes a track-kind
  descriptor. The camera instance publishes `<id>/camera` at alias
  18 + index and announces the `[id, "camera"]` namespace. It has no lo
  variant.
- The existing encoder pipeline is reused unchanged except for one setting,
  the content hint, which the camera sets to `motion`. It encodes VP8 in
  480 B chunks with a keyframe every 2 s.
- A source switch forces a keyframe, so receivers can decode the new source.

### Source lifecycle

A pure state machine (events in, state and effects out) owns the source.

- **Events:**
  - from the user: SelectCamera, SelectFile, Off, SetBackground, Leave
  - completions that may arrive late, out of order or not at all: camera
    acquired / failed, file playing / failed, segmenter ready / failed
- **Generations.** Each acquisition carries a generation number. A
  completion from an older generation is released and never published.
- **Effects** are carried out by the hook: acquire, release, publish or end
  the track, load or close the segmenter, show an error.
- **Frame gate.** For each camera frame, the frame is sent raw when the
  mode is none. It is composited when the segmenter is ready, and dropped
  otherwise.

### Background

- **Loading.** `segmenter.ts` lazily loads `ImageSegmenter` (selfie
  segmenter, VIDEO mode) from `<basePath>/mediapipe/`. It tries the GPU
  delegate first and falls back to CPU.
- **Mask.** The segmenter's confidence mask is read as floats and uploaded
  as an 8-bit texture.
- **Compositing.** `backgroundCompositor.ts` draws into an offscreen WebGL2
  canvas: `mix(background, person, smoothstep(lo, hi, mask))`. The
  background is a blurred copy of the frame or the bundled image. A new
  `VideoFrame` is taken from the canvas and fed to the encoder. The local
  preview draws that same frame.

### Receive

- A camera receive pipeline (decoder per sender) and camera tiles are kept
  separate from the screen tiles.
- A tile is removed when its namespace is withdrawn or its frames stall.

### UI

The rail gets a Video section:

- a Camera toggle
- a Background selector: none / blur / image
- a Video file toggle, which streams the bundled mp4 or a picked file

The toggles are disabled while disconnected. Errors show under the
section. Camera tiles show next to the screen tiles.

## Verification

- The source lifecycle is model-checked before implementation, and its
  scenarios become unit tests of the state machine.
- **Unit tests** cover the frame gate, alias ranges and routing, and the
  track kind.
- **e2e** runs two headless Chrome participants with a fake camera:
  - camera on: the peer's camera tile receives frames
  - image background: since the fake camera shows no person, the tile turns
    the bundled image's colour
  - switch to the mp4: the frame size changes to the mp4's
  - off: the tile goes away
  - a late joiner sees a live camera
