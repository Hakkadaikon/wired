// One stroke icon set (24x24, 2px round strokes, currentColor), inline so the
// page needs no icon package. Decorative: the button or text beside it
// carries the name.
const PATHS = {
	mic: "M12 3a3 3 0 0 0-3 3v6a3 3 0 0 0 6 0V6a3 3 0 0 0-3-3zM5 11a7 7 0 0 0 14 0M12 18v3",
	micOff:
		"M3 3l18 18M9 9v3a3 3 0 0 0 5.1 2.1M15 9.3V6a3 3 0 0 0-5.7-1.3M5 11a7 7 0 0 0 11.9 5M19 11a7 7 0 0 1-.6 2.8M12 18v3",
	wave: "M2 12h2M6 8v8M10 4v16M14 7v10M18 10v4M22 12h-2",
	hand: "M8 13V5.5a1.5 1.5 0 0 1 3 0V11M11 10V4.5a1.5 1.5 0 0 1 3 0V11M14 10.5V6.5a1.5 1.5 0 0 1 3 0V15a6 6 0 0 1-6 6h-1a6 6 0 0 1-4.6-2.2L3.2 15.5a1.5 1.5 0 0 1 2.3-1.9L8 16",
	screen: "M3 4h18v12H3zM8 20h8M12 16v4",
	leave: "M10 4H5v16h5M15 8l4 4-4 4M19 12H9",
	check: "M4 12l5 5L20 6",
	copy: "M9 9h11v11H9zM5 15H4V4h11v1",
	info: "M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zM12 11v6M12 7.5v.5",
	login: "M14 4h5v16h-5M10 8l4 4-4 4M14 12H3",
	paperclip:
		"M21 11l-8.5 8.5a5 5 0 0 1-7-7L14 4a3.5 3.5 0 0 1 5 5l-8.5 8.5a2 2 0 0 1-3-3L15 7",
	trash: "M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3",
	plus: "M12 5v14M5 12h14",
	file: "M6 3h8l4 4v14H6zM14 3v4h4M10 11l5 3-5 3z",
	chevron: "M9 6l6 6-6 6",
	rejoin: "M20 12a8 8 0 1 1-2.3-5.7M20 4v5h-5",
	spinner: "M12 3a9 9 0 1 0 9 9",
} as const;

export type IconName = keyof typeof PATHS;

export function Icon({ name }: { name: IconName }) {
	return (
		<svg
			className={name === "spinner" ? "icon icon--spin" : "icon"}
			viewBox="0 0 24 24"
			fill="none"
			stroke="currentColor"
			strokeWidth="2"
			strokeLinecap="round"
			strokeLinejoin="round"
			aria-hidden="true"
			focusable="false"
		>
			<path d={PATHS[name]} />
		</svg>
	);
}
