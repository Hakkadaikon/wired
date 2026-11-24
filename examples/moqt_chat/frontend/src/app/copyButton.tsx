"use client";

import { useEffect, useState } from "react";
import { Icon } from "./icons";
import { Tooltip } from "./tooltip";

const COPY_RESET_MS = 2000;

const COPY_TIP = {
	idle: "Copy",
	empty: "Nothing to copy yet",
	copied: "Copied",
	failed: "Could not copy: select the text and copy it by hand",
};

type CopyResult = { state: "copied" | "failed"; value: string };

/** Copies value; the result shows for COPY_RESET_MS, or until the value
 * changes, and is announced (aria-live). With text, a labelled outline
 * button instead of the icon-only one. */
export function CopyButton({
	value,
	label,
	testId,
	text,
}: {
	value: string;
	label: string;
	testId: string;
	text?: string;
}) {
	const [result, setResult] = useState<CopyResult | null>(null);
	useEffect(() => {
		if (!result) return;
		const t = window.setTimeout(() => setResult(null), COPY_RESET_MS);
		return () => window.clearTimeout(t);
	}, [result]);
	const fresh = result?.value === value ? result.state : null;
	const state = fresh ?? (value ? "idle" : "empty");
	// No clipboard (an insecure context) fails like a refused write.
	const copy = () => {
		if (!value) return;
		(navigator.clipboard?.writeText(value) ?? Promise.reject()).then(
			() => setResult({ state: "copied", value }),
			() => setResult({ state: "failed", value }),
		);
	};
	return (
		<>
			<Tooltip tip={COPY_TIP[state]}>
				<button
					type="button"
					className={text ? "sign sign--outline" : "icon-button"}
					aria-label={label}
					data-testid={testId}
					onClick={copy}
				>
					<Icon name={state === "copied" ? "check" : "copy"} />
					{text}
				</button>
			</Tooltip>
			<span className="sr-only" aria-live="polite">
				{fresh && COPY_TIP[fresh]}
			</span>
		</>
	);
}
