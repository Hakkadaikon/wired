"use client";

import { useEffect, useSyncExternalStore } from "react";

export const TOAST_MS = 5000;

// shortcut: one toast at a time (a newer one replaces it); queue them if
// two events within TOAST_MS ever both need reading.
let current: { text: string } | null = null;
const listeners = new Set<() => void>();
const emit = () => {
	for (const l of listeners) l();
};
const subscribe = (l: () => void) => {
	listeners.add(l);
	return () => listeners.delete(l);
};
const snapshot = () => current;
const none = () => null;

/** Shows text in the page's toast for TOAST_MS. */
export function showToast(text: string): void {
	current = { text };
	emit();
}

/** The page's one toast: a polite live region, empty while nothing shows. */
export function Toast() {
	const t = useSyncExternalStore(subscribe, snapshot, none);
	useEffect(() => {
		if (!t) return;
		const h = window.setTimeout(() => {
			current = null;
			emit();
		}, TOAST_MS);
		return () => window.clearTimeout(h);
	}, [t]);
	return (
		<div className="toast" role="status" data-testid="toast">
			{t?.text}
		</div>
	);
}
