type KeyLike = Pick<
	KeyboardEvent,
	"key" | "ctrlKey" | "metaKey" | "altKey" | "shiftKey" | "repeat"
> & { target: EventTarget | null };

const TYPING =
	'input, textarea, select, [contenteditable]:not([contenteditable="false"])';

/** M (no modifier, Shift included; no repeat) toggles mute -- never while typing. */
export function isMuteShortcut(e: KeyLike): boolean {
	if (e.key.toLowerCase() !== "m") return false;
	if (e.ctrlKey || e.metaKey || e.altKey || e.shiftKey || e.repeat)
		return false;
	return !(e.target instanceof Element && e.target.closest(TYPING));
}
