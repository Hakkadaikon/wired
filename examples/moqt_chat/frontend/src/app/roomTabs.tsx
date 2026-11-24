"use client";

import { useEffect } from "react";
import { Icon, type IconName } from "./icons";

/** Which room pane shows where only one fits: the phone's bottom tabs pick
 * it, the tablet's drawer opens on "people"; the desktop shows all. */
export type RoomView = "video" | "chat" | "people";

const TABS: { view: RoomView; label: string; icon: IconName }[] = [
	{ view: "video", label: "Video", icon: "video" },
	{ view: "chat", label: "Chat", icon: "chat" },
	{ view: "people", label: "People", icon: "users" },
];

/** The phone layout's bottom tabs (hidden by CSS on wider screens). */
export function RoomTabs({
	view,
	onView,
}: {
	view: RoomView;
	onView: (view: RoomView) => void;
}) {
	return (
		<nav className="room-tabs" aria-label="Room views">
			{TABS.map((t) => (
				<button
					type="button"
					key={t.view}
					aria-current={view === t.view || undefined}
					data-testid={`tab-${t.view}`}
					onClick={() => onView(t.view)}
				>
					<Icon name={t.icon} />
					{t.label}
				</button>
			))}
		</nav>
	);
}

/** While open, Esc calls close (the drawer's keyboard exit). */
export function useEscToClose(open: boolean, close: () => void): void {
	useEffect(() => {
		if (!open) return;
		const onKey = (e: KeyboardEvent) => {
			if (e.key === "Escape") close();
		};
		window.addEventListener("keydown", onKey);
		return () => window.removeEventListener("keydown", onKey);
	}, [open, close]);
}
