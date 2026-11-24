// The room's main column: the stage (a share, or the camera tiles) on top,
// the chat below, split by a draggable separator. Ratios are the stage's
// share of the column's height.

/** "share" while any screen share is live, else "camera". */
export type StageMode = "share" | "camera";

/** One arrow-key move of the splitter. */
export const SPLIT_STEP = 0.05;

const KEY = "moqtChat.stageSplit.";

/** "share" while this page shares or a remote share still delivers
 * frames. A stopped remote share keeps its tile (its track stays
 * published), so a stalled one does not count. */
export function stageMode(
	sharing: boolean,
	tiles: string[],
	stalled: Record<string, boolean>,
): StageMode {
	const live = tiles.some((id) => id !== "own" && !stalled[id]);
	return sharing || live ? "share" : "camera";
}

/** 50 / 50 while a share is live, else the golden minor part (0.382). */
export function defaultSplit(mode: StageMode): number {
	return mode === "share" ? 0.5 : 0.382;
}

/** The ratio kept between both panes' minimum heights (px); a column too
 * short for both splits by the minimums. */
export function clampSplit(
	ratio: number,
	total: number,
	minStage: number,
	minChat: number,
): number {
	const lo = minStage / total;
	const hi = 1 - minChat / total;
	if (lo > hi) return minStage / (minStage + minChat);
	return Math.min(hi, Math.max(lo, ratio));
}

const KEY_MOVES: Record<string, (r: number) => number> = {
	ArrowUp: (r) => r - SPLIT_STEP,
	ArrowLeft: (r) => r - SPLIT_STEP,
	ArrowDown: (r) => r + SPLIT_STEP,
	ArrowRight: (r) => r + SPLIT_STEP,
	Home: () => 0,
	End: () => 1,
};

/** The ratio after a key on the splitter (unclamped), or null for a key
 * the splitter does not handle. */
export function splitKey(ratio: number, key: string): number | null {
	const move = KEY_MOVES[key];
	return move ? move(ratio) : null;
}

/** The viewer's remembered ratio for the mode, else the default. Storage
 * may be missing or blocked: that is the default too. */
export function loadSplit(mode: StageMode): number {
	try {
		const v = Number.parseFloat(localStorage.getItem(KEY + mode) ?? "");
		if (v > 0 && v < 1) return v;
	} catch {}
	return defaultSplit(mode);
}

export function saveSplit(mode: StageMode, ratio: number): void {
	try {
		localStorage.setItem(KEY + mode, String(ratio));
	} catch {}
}

/** Columns for n tiles of the aspect (w/h) in a w x h area: the count that
 * makes each tile largest. */
export function gridColumns(
	n: number,
	width: number,
	height: number,
	aspect = 16 / 9,
): number {
	let best = 1;
	let bestW = 0;
	for (let c = 1; c <= n; c++) {
		const tileW = Math.min(width / c, (height / Math.ceil(n / c)) * aspect);
		if (tileW > bestW) {
			best = c;
			bestW = tileW;
		}
	}
	return best;
}
