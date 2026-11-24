# moqt_chat design pass (2026-11-24)

Source: external UI review the user pasted (Join screen, room top bar,
sidebar, main area, cross-cutting). Start after P5 of
`tasks/moqt-chat-rooms.md` is reviewed and folded into the plan; runs in
parallel with P3 (C hub hooks, no shared files).

Legend: `[ ]` open, `[~]` partial (what remains on the same line), `[x]` done
(commit hash + test). One line per review item.

Standing constraints (decided earlier, they override the review text):
- UI language is English (user, 2026-11). Japanese labels in the review are
  translated, not adopted.
- Sizes follow the golden-ratio scale already in `globals.css`; the review's
  16/24/32 px map to the nearest scale step.
- No new runtime dependency: icons are inline SVG components in-repo
  (stroke style, one `Icon` set), not Lucide/Heroicons packages.
- Post layout the user specified stays: display_name + gray @name, 0.5-line
  gap, check mark with tooltip, ⋯ bottom-right. Bubbles add avatar for
  everyone and a tint for own posts; no right-alignment (D-18).
- Purple login button stays top-right.

## Join screen
- [x] D-1 Centered card (max-width ~500px), 1px rgba(255,255,255,.08) border, (5dbaf610e; joinScreen/joinForm tests, e2e s24/s25/s26/s8)
      padding on the φ scale; black background unchanged
- [x] D-2 Server URL / certificate hash / profile relays inside a closed (5dbaf610e; joinScreen/joinForm tests, e2e s24/s25/s26/s8)
      "Advanced" disclosure; copy button per field
- [x] D-3 Certificate hash shown as first 8 … last 8; copy copies the full (5dbaf610e; joinScreen/joinForm tests, e2e s24/s25/s26/s8)
      value; tooltip "Server certificate fingerprint"
- [x] D-4 One primary color #7C3AED: Join filled purple; Log in with Nostr (5dbaf610e; joinScreen/joinForm tests, e2e s24/s25/s26/s8)
      outline/tinted purple
- [x] D-5 Participant id: label "Choose a participant slot (max 4)"; (5dbaf610e; joinScreen/joinForm tests, e2e s24/s25/s26/s8)
      selected = purple fill + check; unselected = faint outline; tooltip
      "Join in this slot"
- [x] D-6 Remove the large bottom wordmark (or footer ≤ 40px); header logo (5dbaf610e; joinScreen/joinForm tests, e2e s24/s25/s26/s8)
      slightly larger
- [x] D-7 Open / Login required as a segmented control; Create room below (5dbaf610e; joinScreen/joinForm tests, e2e s24/s25/s26/s8)
      it. Adjusted: Create is enabled when logged in (NIP-98 + NIP-05, the
      room-creation rule), not "only when Login required"; the disabled
      state names the missing requirement in a tooltip
- [x] D-8 Log in button states: spinner + "Connecting…" (disabled, no double (5dbaf610e; joinScreen/joinForm tests, e2e s24/s25/s26/s8)
      click), "Logged in", error text under the button
- [x] D-9 Inline validation under each field (URL, cert hash format); Join (5dbaf610e; joinScreen/joinForm tests, e2e s24/s25/s26/s8)
      disabled until required fields are valid
- [x] D-10 "Clear saved info" → "Delete saved connection info" + confirm (5dbaf610e; joinScreen/joinForm tests, e2e s24/s25/s26/s8)
      dialog naming what goes (server URL, cert hash, participant slot,
      display name, relays — the joinPrefs key)

## Room top bar
- [ ] D-11 States (Mic, Noise suppression) as toggles with aria-pressed;
      actions (Raise hand, Share screen, Leave) as ghost/outline; all with icons
- [ ] D-12 "NS on" → "Noise suppression" + waveform icon; on = accent
- [ ] D-13 Icon + short label on every top-bar button

## Left sidebar
- [ ] D-14 Always visible: participant list + own volume. Video / Background /
      Video file / Tile width / Output move to a settings drawer
- [ ] D-15 Participant rows: avatar + name + mic / screen / hand icons,
      "You" marker, connection dot
- [ ] D-16 File picker: custom "Choose video file" button (no browser-locale
      text), truncated name with full-name tooltip
- [ ] D-17 Volume slider shows its value (0–100)

## Main area
- [ ] D-18 Two columns: video grid (max width) + chat with guaranteed width;
      mobile tabs Video / Chat. Avatar on every message, own message tinted
      purple, others faint gray (layout per standing constraints)
- [ ] D-19 Message separators: none or 1px rgba(255,255,255,.06); gap on φ scale
- [ ] D-20 Composer: 1px border, purple on focus, filled purple Send,
      attach icon always visible
- [ ] D-21 Video tile overlay: name bar bottom-left, mic / screen icons,
      "You" on own tile
- [ ] D-22 Camera off → avatar + name placeholder; "Sharing screen" label;
      play icon while a video file plays
- [ ] D-23 Raise hand: purple button while raised, hand icon in participant
      list and tile, toast "<name> raised their hand" to everyone
- [ ] D-24 Send states: pending (gray + spinner), failed (red + Retry);
      disconnected → composer disabled with "Reconnecting…"
- [ ] D-25 "Share screen" → "Start sharing"; while sharing "Stop sharing"

## Cross-cutting
- [x] D-26 Palette tokens: primary #7C3AED, success #10B981, danger #EF4444, (413c054cf; js-check, e2e s24/s25/s26/s8)
      neutral grays; replace brown/stray accents
- [~] D-27 Inline SVG icon set; every button / state / section header (413c054cf; icons on join + top bar; remaining: room sidebar/chat/tiles in phase B)
- [~] D-28 Spacing and type hierarchy (heading 16 medium, body 14 regular, (413c054cf; CSS scale done; remaining: room screen small text 0.8/0.85em)
      mapped to the φ scale)
- [x] D-29 No Japanese anywhere in the UI/UX (user, 2026-11-24): labels, (738ffb632; noJapanese.test.ts)
      tooltips, toasts, errors, aria-labels, confirm dialogs, and no
      browser-locale widget text (native file input, default validation
      bubbles). Gate: a test that fails on any CJK/kana character in
      `frontend/src/**` outside `__tests__`
- [~] D-30 State never by color alone: icon + text, aria-pressed on toggles, (5dbaf610e; aria-pressed toggles; remaining: connection text with D-33)
      "Connected" / "Disconnected" text
- [ ] D-31 Responsive: desktop 2 columns, tablet sidebar drawer, mobile
      bottom tabs Video / Chat / Settings
- [ ] D-32 Empty states: "Send the first message", "No one has joined yet"
- [ ] D-33 Loading: "Connecting…" / skeleton in the video area after join;
      connection dot in the top bar (green / yellow / red)
- [x] D-34 Focus ring 2px purple on every interactive element; M toggles mute (413c054cf/738ffb632; shortcuts.test.ts)
      (not while typing)
- [~] D-35 Tooltips on every icon button and abbreviation. The small (413c054cf/5dbaf610e; tooltip.test.tsx, join hints moved; remaining: room icon buttons in phase B)
      inline hint/annotation texts (too small to read, user 2026-11-24) move
      into tooltips shown on hover AND keyboard focus (aria-describedby,
      Esc closes, tap on touch); readable size on the φ scale; no hint
      text left at the current small size
- [ ] D-36 Deleted message: "<name> deleted this message" / "You deleted this
      message" (NIP-09: only the author can delete); keeps its height
- [ ] D-37 Remaining time: yellow < 30 min, red < 5 min, toast at 5 min
- [ ] D-38 Copy buttons: room id and "Copy invite link" (`?room=&host=`)

## Verification
- [~] D-39 Unit tests for new pure helpers (hash shortening, validation, (738ffb632; joinForm/shortcuts tests; remaining: timer color, invite link helpers)
      timer color, invite link); `just js-check` green
- [ ] D-40 e2e: existing moqt_chat scenarios still pass with the new markup
      (selectors updated); screenshot check of Join and room at desktop and
      390px width
