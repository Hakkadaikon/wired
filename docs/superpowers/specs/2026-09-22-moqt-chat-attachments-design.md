# moqt_chat: multi-attachment compose (images/video/clipboard) + movie removal

Status: approved design, 2026-09-22. Implementation plan follows this spec.

## Goal

Extend moqt_chat's single-image-send feature (already shipped: `sendImage`,
`moqtImageWire.ts`, `MoqtChatClient.sendImage`/`onImage`) into a general
attachment-compose flow:

1. Multiple files can be attached to one outgoing message (up to 4).
2. Files can be attached by pasting from the clipboard while the text input
   is focused, in addition to the existing file-picker button.
3. Video files can be attached the same way images are, sent as raw bytes
   (no client-side transcode/compression).
4. Attaching a file no longer sends immediately. It queues into a
   send-time draft with a preview (thumbnail for images/video, filename
   chip otherwise), individually removable, until the user presses Send —
   at which point the text (if any) and every remaining attachment go out
   together as one logical message.
5. The server-side `--movie` MP4 live-delivery feature (wired_server.c's
   `publish_movie`, the Dockerfile's `--movie` flag, `assets/movie-live.mp4`)
   and its frontend consumers (`moqtMovieClient.ts`, `moqtLiveClient.ts`,
   `LivePlayer`, `videoRef` wiring) are deleted entirely — not hidden,
   removed.

Attachments continue to ride the existing chat Object channel (no new MOQT
track, no server change beyond the movie removal) — same fixed-room,
same-track-alias design as the shipped image feature, extended per
Attachment Wire Format below.

## Non-goals (explicit, matching the shipped image feature's own scope cuts)

- No image/video compression, resizing, or EXIF stripping.
- No upload progress bar beyond an overall per-attachment/percent indicator
  already implied by chunk count (see UI section) — no fine-grained
  byte-level progress.
- No send-in-progress cancellation.
- No persistence: attachments are never written to disk anywhere (server or
  client); this matches the shipped image feature and is unchanged.
- No clipboard-read() button; paste is the only clipboard entry point.
- No per-file-type icon library; a generic filename chip covers any
  non-image/video MIME type that manages to get attached (accept filters
  restrict the picker to image/video, but paste is not filtered the same
  way — see Compose section).

## Attachment Wire Format (`moqtAttachmentWire.ts`, replaces `moqtImageWire.ts`)

Generalizes the shipped chunk format to (a) carry a `messageId` so multiple
independent Objects/streams belong to one logical chat message, and (b)
carry an `attachmentIdx` so multiple attachments within one message don't
collide in the receiver's reassembly state.

### Text part

One MoQT Object (same one-stream-one-Object shape as the shipped
`buildChatObjectMessage`), payload:

```
marker (1 byte, 0xFE — distinct from the image-chunk marker 0xFF and the
        nickname marker's leading 0x00; see Marker Disambiguation below)
messageId (u32 BE)
attachmentCount (u8)      -- how many attachment parts to expect, 0..4
textLen (u16 BE)
text (UTF-8 bytes, textLen bytes)   -- "" when the message is attachments-only
```

### Attachment chunk part

One MoQT Object per chunk (same shape as the shipped image chunk), payload:

```
marker (1 byte, 0xFD — distinct from 0xFF/0xFE/nickname's 0x00)
messageId (u32 BE)
attachmentIdx (u8)        -- 0..3, this attachment's position in the message
seq (u32 BE)              -- unused cross-message; kept for symmetry with
                              the shipped format's per-attachment identity,
                              always 0 in this design (one attachment is one
                              logical "frame" — messageId+attachmentIdx is
                              the real key, seq is vestigial and fixed at 0
                              rather than removed, to reuse
                              splitImageIntoChunks's exact chunk-splitting
                              logic unchanged)
idx (u16 BE)               -- chunk index within this attachment
count (u16 BE)             -- total chunks for this attachment
(idx===0 only) mimeType length (u8) + mimeType (UTF-8) + totalBytes (u32 BE)
data (remaining bytes)
```

### Marker disambiguation

Four distinct first-byte markers now share the chat Object channel:
`0x00` (nickname), `0xFD` (attachment chunk), `0xFE` (text-with-attachments),
`0xFF` (bare legacy image chunk — kept only if a compatibility path is
needed; see Migration below), and no marker (plain chat text, any valid
UTF-8 first byte, none of which can be 0xFD/0xFE/0xFF per RFC 3629 §3's
leading-byte table, and 0x00 is excluded by construction since chat text
never starts with NUL). `classifyChatPayload` (moqtClient.ts) is extended
with two more branches, ordered marker-byte-first same as today.

### Migration note

The already-shipped `moqtImageWire.ts`/`IMAGE_CHUNK_MARKER=0xFF` single-image
path is superseded by this format. Per this spec's scope (a full replacement,
not a dual-write), `moqtImageWire.ts` is deleted and `moqtClient.ts`'s
`sendImage`/`onImage` are replaced by `sendMessage`/`onMessage`-with-
attachments (see API section). No backward-compat wire shim: this is a
single-repo demo app with no independently-deployed old clients to support.

## Receive-side aggregation (state machine — verified design, see
Verification section)

`MoqtChatClient` gains a `#pendingMessages: Map<string, PendingMessage>`
keyed by `` `${participant}:${messageId}` `` (messageId alone is not
globally unique — it is a per-sender counter, like the shipped `#imageSeq`).

```
PendingMessage = {
  text: string | undefined       -- set once the text part arrives
  attachmentCount: number | undefined  -- set once the text part arrives
                                     (attachmentCount travels on the text
                                     part, not derivable from chunks alone)
  attachments: (ReassembledAttachment | undefined)[]  -- length
                                     attachmentCount once known, filled in
                                     as each attachment's chunks complete
  attachmentReassemblers: Map<attachmentIdx, ImageFrameReassembler>
  firstSeenAt: number            -- Date.now() at creation, for timeout
}
```

Transitions:
- **Text part arrives, no pending entry**: create one, set
  `text`/`attachmentCount`, `firstSeenAt = now`.
- **Text part arrives, pending entry exists (attachment(s) arrived first)**:
  fill in `text`/`attachmentCount` on the existing entry, do not reset
  `firstSeenAt`.
- **Attachment chunk arrives, no pending entry**: create one with `text =
  undefined`, `attachmentCount = undefined`, `firstSeenAt = now`, push the
  chunk into a fresh per-attachmentIdx `ImageFrameReassembler`.
- **Attachment chunk arrives, pending entry exists**: push into that
  attachmentIdx's reassembler (existing per-attachment chunk-completion
  logic, unchanged from the shipped `imageFrameReassemblerPush`).
- **An attachment's reassembler completes**: store the result in
  `attachments[attachmentIdx]`.
- **Completion check** (run after every transition above): if `text !==
  undefined` AND `attachmentCount !== undefined` AND every index in
  `[0, attachmentCount)` of `attachments` is filled, fire `onMessage` with
  the full `{text, attachments}` and delete the pending entry.
- **Timeout**: a periodic sweep (interval TBD in plan, e.g. every 5s) drops
  any pending entry whose `firstSeenAt` is more than 30s old, silently (no
  callback, matching the shipped reassembler's silent-drop convention).
  No unbounded growth: room size is capped at 4 participants
  (`CANDIDATE_PARTICIPANT_IDS`), and each sender can only have one pending
  message maturing at a time in practice (the send path awaits full
  delivery before allowing another `sendMessage` call — see API section) —
  no concurrency cap is enforced in the data structure itself (YAGNI, per
  the approved design decision).

This is the state machine to verify: does every reachable
interleaving of (text-first vs. attachment-first arrival, any attachment
completion order, timeout racing arrival) either (a) eventually fire
exactly one `onMessage` with the correct assembled content, or (b) time out
and drop with no `onMessage` — never firing twice, never firing with a gap,
never leaking a pending entry forever.

## Client-side send API (`moqtClient.ts`)

Replaces `sendImage`/`onImage` with:

```ts
interface AttachmentInput { bytes: Uint8Array; mimeType: string }
async sendMessage(text: string, attachments: AttachmentInput[]): Promise<void>
```

`onImage` in `MoqtChatCallbacks` is replaced by:
```ts
onMessage(participantId: string, text: string, attachments: ReassembledAttachment[]): void
```
(This is a breaking rename of the existing `onMessage(participantId, text)`
signature too — the shipped plain-text path becomes attachments: [] through
the same callback, unifying text-only and attachment-bearing messages
into one path. `onNickname` stays separate/unchanged, still riding its own
marker.)

`sendMessage`'s internal order: assign `messageId = this.#messageSeq++`,
send the text part first (one stream), then each attachment's chunks in
order (one stream per chunk, chunks awaited sequentially within an
attachment — same discipline as shipped `sendImage` — attachments
themselves may be sent one after another, no need for the shipped
"chunks never fired concurrently" rule to extend across attachments since
each chunk stream is independent and the receiver keys by
messageId+attachmentIdx regardless of arrival order).

## Store shape (`moqtChatStore.ts`)

```ts
export type ChatAttachment = {
  bytes: Uint8Array;      // never persisted; kept only for the Blob URL's
                           // underlying data and revoked with it
  mimeType: string;
  url: string;             // URL.createObjectURL(...) result
};

export type ChatMessage = {
  id: number;
  senderId: string;
  text: string;
  at: number;
  own: boolean;
  failed?: boolean;
  attachments: ChatAttachment[];  // replaces imageDataUrl/imageMimeType;
                                    // [] for a plain text message
};
```

`imageDataUrl`/`imageMimeType` fields are removed (migration, not
additive — matches the wire format's full-replacement scope). `addMessage`
signature unchanged in shape (`Omit<ChatMessage, "id">`).

`imageSendError` is renamed `messageSendError` (still `string | null` +
setter), since it now covers any send failure (text-only, attachment-only,
or mixed) uniformly with `sendChat`'s existing failure path — this also
means `sendChat` and `sendImage` collapse into one `sendMessage` hook
callback (see UI section), so there is only one failure surface, not two.

## UI (`page.tsx`)

### `Compose` becomes stateful (`draftAttachments`)

```ts
type Draft = { id: string; bytes: Uint8Array; mimeType: string; previewUrl: string; fileName: string };
```

- File-picker `<input type="file" accept="image/*,video/*" multiple
  data-testid="attachment-file">`: `multiple` lets one picker invocation
  select several files at once (still capped at 4 total including
  already-drafted ones — files beyond the cap are dropped with the same
  `onAttachmentError`/size-style Notice used for the 5MB cap, message
  "up to 4 attachments").
- Paste handler on the text `<input>`'s `onPaste`: iterates
  `e.clipboardData.items`, for each `kind === "file"` item calls
  `getAsFile()` and adds it as a draft (same 4-cap/5MB-cap enforcement as
  the picker path). Does not call `preventDefault()` on the whole paste —
  only suppresses default if a file item was actually found and handled,
  so pasting plain text into the input is unaffected.
- Each draft renders a preview chip in a new row above the input: an
  `<img>` (image) or a `<video muted>` first-frame poster (video, via the
  browser's native poster rendering — no thumbnail generation), else a
  filename chip. Each chip has a small remove (×) button
  (`data-testid="draft-remove"`) that revokes its `previewUrl` and drops
  it from `draftAttachments`.
- `Send` button (renamed from the implicit Enter-only submit — Enter in
  the text input still submits, matching existing behavior) is enabled
  when there is text OR at least one draft attachment (previously: text
  only). On submit: calls `onSendMessage(text, draftAttachments)`, clears
  both `draft` and `draftAttachments` (revoking every `previewUrl` first).

### `Message` component

Renders `m.text` (if non-empty) as today, followed by one `<img>` /
`<video controls>` per `m.attachments[i]` (`data-testid="message-image"`
for image MIME types — kept as-is so the existing e2e scenario's selector
still works; `data-testid="message-video"` for video MIME types), each with
its own unmount-revoke `useEffect` (same pattern as today, now per-
attachment instead of per-message).

## Movie removal

- `wired_server.c`: delete `publish_movie`, the movie track constants
  (`MOVIE_MAX`, `g_movie`, etc.), the `--movie` CLI arg handling, and any
  movie-Group pacing/timer code. Grep `movie` in this file must return
  nothing after.
- `Dockerfile`: drop the `COPY assets/movie-live.mp4` line and the
  `--movie /movie.mp4` ENTRYPOINT arg.
- `assets/movie-live.mp4` (and `assets/movie.mp4` if nothing else
  references it — verify in plan) deleted from the repo.
- Frontend: delete `moqtMovieClient.ts`, `moqtLiveClient.ts`, and their
  test files; remove `LivePlayer`, `videoRef`, and the
  `MOVIE_INIT_TRACK_ALIAS`/`MOVIE_TRACK_ALIAS` branches in
  `useMoqtChat.ts`'s `onUnknownUniStream` handler and `moqtClient.ts` (if
  any movie-specific alias constants live there — verify in plan).
- e2e: delete `run-live-check.mjs` and the `just e2e-live` justfile recipe.
- This is a `src/app/moqt/run/*.c`-adjacent change (wired_server.c, not
  `src/`) — the SDK core (`src/`) is untouched; only the example server
  binary's own `--movie` feature goes. Confirm no `src/` diff in the plan's
  verification section, same discipline as the shipped image feature.

## Verification layers

1. **State transitions/concurrency**: YES — the receive-side aggregation
   state machine above (interleaved text/attachment arrival, timeout races,
   multiple pending messages per sender in the Map). Verified before
   implementation; results (confirmed safe interleavings, any design fix
   the verification forced) feed directly into this spec's aggregation
   section above and the plan's derived test list.
2. **Lean-grade critical algorithm**: NO — chunk encode/decode and
   reassembly are round-trip-testable extensions of the already-shipped,
   already-TDD-covered `moqtImageWire.ts` pattern. No new cryptographic or
   exhaustive-classification property beyond what TDD round-trip tests
   already cover for the shipped feature.
3. **TDD bridge**: the state machine's confirmed-safe interleavings (or any
   fix the verification forced) become the test list for
   `moqtAttachmentWire.test.ts` and `moqtClient.test.ts`'s aggregation
   tests, one test per interleaving/edge case (text-first, attachment-
   first, timeout mid-assembly, multiple concurrent pending messages from
   different senders, 0-attachment text-only message, 4-attachment message).

## Testing scope

- Unit (vitest, TDD): wire encode/decode round-trips (`moqtAttachmentWire.
  test.ts`), aggregation state machine (`moqtClient.test.ts`, informed by
  the verified design), store shape (`moqtChatStore.test.ts`), Compose
  draft/paste/remove logic to the extent it can be isolated as pure
  functions from `page.tsx` (paste-item-filtering, cap enforcement),
  useMoqtChat wiring (`moqtChatCallbacks`'s `onMessage`-with-attachments
  translation to `store.addMessage`).
- e2e (Puppeteer, matching the shipped `s15-image-send.mjs` pattern): one
  new scenario covering the main path — a message with text + 2 attachments
  (at least one image, at least one video) sent and verified byte-identical
  on the receiving end, plus a text-only and an attachments-only case in
  the same scenario file. Clipboard paste is NOT covered by e2e (per the
  approved decision) — covered by a vitest unit test of the paste handler's
  pure logic instead.
- Movie removal: no test needed for removed code; the plan's verification
  step confirms `grep -rn movie` (case-insensitive) returns nothing under
  `examples/moqt_chat/` except this spec/commit history, and the existing
  e2e/unit suites (now without movie tests) stay green.

## Migration/compatibility

None required — single-repo demo, no external deployed clients depend on
the shipped single-image wire format staying stable. The shipped feature's
own files (`moqtImageWire.ts`, its test, the `sendImage`/`onImage` methods)
are replaced, not kept alongside the new format.
