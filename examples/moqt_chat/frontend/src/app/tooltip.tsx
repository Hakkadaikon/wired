"use client";

import {
	cloneElement,
	type ReactElement,
	type ReactNode,
	useEffect,
	useId,
	useRef,
	useState,
} from "react";
import { Icon } from "./icons";

type Trigger = ReactElement<{
	"aria-describedby"?: string;
	"aria-label"?: string;
}>;

/** The page's one tooltip: shown on hover AND keyboard focus (CSS), a
 * touch tap pins it until the next tap or a tap elsewhere, and Esc hides a
 * shown tip without moving focus (WCAG 1.4.13). The trigger is described
 * by the tip (aria-describedby). */
export function Tooltip({
	tip,
	children,
}: {
	tip: ReactNode;
	children: Trigger;
}) {
	const id = useId();
	const ref = useRef<HTMLSpanElement>(null);
	const [dismissed, setDismissed] = useState(false);
	const [pinned, setPinned] = useState(false);
	useEffect(() => {
		const el = ref.current as HTMLSpanElement;
		const show = () => setDismissed(false);
		const onKey = (e: KeyboardEvent) => {
			if (e.key !== "Escape") return;
			if (!el.matches(":hover, :focus-within, [data-open]")) return;
			setDismissed(true);
			setPinned(false);
		};
		const onTap = (e: PointerEvent) => {
			if (e.pointerType !== "touch") return;
			show();
			setPinned((p) => !p);
		};
		const onDownElsewhere = (e: PointerEvent) => {
			if (!el.contains(e.target as Node)) setPinned(false);
		};
		window.addEventListener("keydown", onKey);
		window.addEventListener("pointerdown", onDownElsewhere);
		el.addEventListener("pointerup", onTap);
		el.addEventListener("mouseenter", show);
		el.addEventListener("focusin", show);
		return () => {
			window.removeEventListener("keydown", onKey);
			window.removeEventListener("pointerdown", onDownElsewhere);
			el.removeEventListener("pointerup", onTap);
			el.removeEventListener("mouseenter", show);
			el.removeEventListener("focusin", show);
		};
	}, []);
	return (
		<span
			className="tip"
			ref={ref}
			data-dismissed={dismissed || undefined}
			data-open={pinned || undefined}
		>
			{/* A label that already says the tip would be read twice. */}
			{cloneElement(
				children,
				children.props["aria-label"] === tip ? {} : { "aria-describedby": id },
			)}
			<span className="tip__text" role="tooltip" id={id}>
				{tip}
			</span>
		</span>
	);
}

/** An (i) button whose tooltip holds a hint too long for a label. */
export function InfoTip({ label, tip }: { label: string; tip: ReactNode }) {
	return (
		<Tooltip tip={tip}>
			<button type="button" className="icon-button" aria-label={label}>
				<Icon name="info" />
			</button>
		</Tooltip>
	);
}
