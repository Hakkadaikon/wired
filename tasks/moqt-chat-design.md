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
- [x] D-11 States (Mic, Noise suppression) as toggles with aria-pressed; (e09dffec4/ef5f637f8; roomUi/roomTabs/roomStatus/toast tests, e2e s22/s24/s25/s26/s8)
      actions (Raise hand, Share screen, Leave) as ghost/outline; all with icons
- [x] D-12 "NS on" → "Noise suppression" + waveform icon; on = accent (e09dffec4/ef5f637f8; roomUi/roomTabs/roomStatus/toast tests, e2e s22/s24/s25/s26/s8)
- [x] D-13 Icon + short label on every top-bar button (e09dffec4/ef5f637f8; roomUi/roomTabs/roomStatus/toast tests, e2e s22/s24/s25/s26/s8)

## Left sidebar
- [x] D-14 Always visible: participant list + own volume. Video / Background / (e09dffec4/ef5f637f8; roomUi/roomTabs/roomStatus/toast tests, e2e s22/s24/s25/s26/s8)
      Video file / Tile width / Output move to a settings drawer
- [~] D-15 Participant rows: avatar + name + mic / screen / hand icons, (e09dffec4; remaining: remote mute is not transmitted, peers show a speaking icon)
      "You" marker, connection dot
- [x] D-16 File picker: custom "Choose video file" button (no browser-locale (e09dffec4/ef5f637f8; roomUi/roomTabs/roomStatus/toast tests, e2e s22/s24/s25/s26/s8)
      text), truncated name with full-name tooltip
- [x] D-17 Volume slider shows its value (0–100) (e09dffec4/ef5f637f8; roomUi/roomTabs/roomStatus/toast tests, e2e s22/s24/s25/s26/s8)

## Main area
- [x] D-18 Two columns: video grid (max width) + chat with guaranteed width; (e09dffec4/ef5f637f8; roomUi/roomTabs/roomStatus/toast tests, e2e s22/s24/s25/s26/s8)
      mobile tabs Video / Chat. Avatar on every message, own message tinted
      purple, others faint gray (layout per standing constraints)
- [x] D-19 Message separators: none or 1px rgba(255,255,255,.06); gap on φ scale (e09dffec4/ef5f637f8; roomUi/roomTabs/roomStatus/toast tests, e2e s22/s24/s25/s26/s8)
- [x] D-20 Composer: 1px border, purple on focus, filled purple Send, (e09dffec4/ef5f637f8; roomUi/roomTabs/roomStatus/toast tests, e2e s22/s24/s25/s26/s8)
      attach icon always visible
- [~] D-21 Video tile overlay: name bar bottom-left, mic / screen icons, (e09dffec4; remaining: remote mute not transmitted, speaking icon instead)
      "You" on own tile
- [x] D-22 Camera off → avatar + name placeholder; "Sharing screen" label; (e09dffec4/ef5f637f8; roomUi/roomTabs/roomStatus/toast tests, e2e s22/s24/s25/s26/s8)
      play icon while a video file plays
- [x] D-23 Raise hand: purple button while raised, hand icon in participant (e09dffec4/ef5f637f8; roomUi/roomTabs/roomStatus/toast tests, e2e s22/s24/s25/s26/s8)
      list and tile, toast "<name> raised their hand" to everyone
- [~] D-24 Send states: pending (gray + spinner), failed (red + Retry); (e09dffec4; failed + Retry + Disconnected done; remaining: pending state, needs a pre-sign dedup key)
      disconnected → composer disabled with "Reconnecting…"
- [x] D-25 "Share screen" → "Start sharing"; while sharing "Stop sharing" (e09dffec4/ef5f637f8; roomUi/roomTabs/roomStatus/toast tests, e2e s22/s24/s25/s26/s8)

## Cross-cutting
- [x] D-26 Palette tokens: primary #7C3AED, success #10B981, danger #EF4444, (413c054cf; js-check, e2e s24/s25/s26/s8)
      neutral grays; replace brown/stray accents
- [x] D-27 Inline SVG icon set; every button / state / section header (e09dffec4/ef5f637f8; roomUi/roomTabs/roomStatus/toast tests, e2e s22/s24/s25/s26/s8)
- [x] D-28 Spacing and type hierarchy (heading 16 medium, body 14 regular, (e09dffec4/ef5f637f8; roomUi/roomTabs/roomStatus/toast tests, e2e s22/s24/s25/s26/s8)
      mapped to the φ scale)
- [x] D-29 No Japanese anywhere in the UI/UX (user, 2026-11-24): labels, (738ffb632; noJapanese.test.ts)
      tooltips, toasts, errors, aria-labels, confirm dialogs, and no
      browser-locale widget text (native file input, default validation
      bubbles). Gate: a test that fails on any CJK/kana character in
      `frontend/src/**` outside `__tests__`
- [x] D-30 State never by color alone: icon + text, aria-pressed on toggles, (e09dffec4/ef5f637f8; roomUi/roomTabs/roomStatus/toast tests, e2e s22/s24/s25/s26/s8)
      "Connected" / "Disconnected" text
- [x] D-31 Responsive: desktop 2 columns, tablet sidebar drawer, mobile (e09dffec4/ef5f637f8; roomUi/roomTabs/roomStatus/toast tests, e2e s22/s24/s25/s26/s8)
      bottom tabs Video / Chat / Settings
- [x] D-32 Empty states: "Send the first message", "No one has joined yet" (e09dffec4/ef5f637f8; roomUi/roomTabs/roomStatus/toast tests, e2e s22/s24/s25/s26/s8)
- [x] D-33 Loading: "Connecting…" / skeleton in the video area after join; (e09dffec4/ef5f637f8; roomUi/roomTabs/roomStatus/toast tests, e2e s22/s24/s25/s26/s8)
      connection dot in the top bar (green / yellow / red)
- [x] D-34 Focus ring 2px purple on every interactive element; M toggles mute (413c054cf/738ffb632; shortcuts.test.ts)
      (not while typing)
- [x] D-35 Tooltips on every icon button and abbreviation. The small (e09dffec4/ef5f637f8; roomUi/roomTabs/roomStatus/toast tests, e2e s22/s24/s25/s26/s8)
      inline hint/annotation texts (too small to read, user 2026-11-24) move
      into tooltips shown on hover AND keyboard focus (aria-describedby,
      Esc closes, tap on touch); readable size on the φ scale; no hint
      text left at the current small size
- [x] D-36 Deleted message: "<name> deleted this message" / "You deleted this (e09dffec4/ef5f637f8; roomUi/roomTabs/roomStatus/toast tests, e2e s22/s24/s25/s26/s8)
      message" (NIP-09: only the author can delete); keeps its height
- [x] D-37 Remaining time: yellow < 30 min, red < 5 min, toast at 5 min (e09dffec4/ef5f637f8; roomUi/roomTabs/roomStatus/toast tests, e2e s22/s24/s25/s26/s8)
- [x] D-38 Copy buttons: room id and "Copy invite link" (`?room=&host=`) (e09dffec4/ef5f637f8; roomUi/roomTabs/roomStatus/toast tests, e2e s22/s24/s25/s26/s8)

## Verification
- [x] D-39 Unit tests for new pure helpers (hash shortening, validation, (e09dffec4/ef5f637f8; roomUi/roomTabs/roomStatus/toast tests, e2e s22/s24/s25/s26/s8)
      timer color, invite link); `just js-check` green
- [x] D-40 e2e: existing moqt_chat scenarios still pass with the new markup (78d9aa974; e2e s22/s24/s25/s26/s8 PASS, s25 --shots desktop/800x600/390x667)
      (selectors updated); screenshot check of Join and room at desktop and
      390px width
