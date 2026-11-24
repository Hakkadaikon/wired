"use client";

import { useRef, useState } from "react";
import type { BackgroundMode } from "@/lib/videoSourceMachine";
import { useMoqtChatStore } from "@/stores/moqtChatStore";
import { Icon } from "./icons";
import { Tooltip } from "./tooltip";

const BACKGROUNDS: { value: BackgroundMode; label: string }[] = [
	{ value: "none", label: "None" },
	{ value: "blur", label: "Blur" },
	{ value: "image", label: "Image" },
];

// One outgoing video source at a time: the camera or an mp4 (the bundled
// sample, or a picked file). Pressing the active one turns it off.
export function VideoSection({
	connected,
	onToggle,
	onBackground,
	onPickFile,
}: {
	connected: boolean;
	onToggle: (source: "camera" | "file") => void;
	onBackground: (mode: BackgroundMode) => void;
	onPickFile: (file: File) => void;
}) {
	const video = useMoqtChatStore((s) => s.video);
	const fileRef = useRef<HTMLInputElement>(null);
	const [fileName, setFileName] = useState("");
	const toggle = (source: "camera" | "file", label: string) => (
		<button
			type="button"
			className={video.source === source ? "sign" : "sign sign--outline"}
			data-testid={source === "camera" ? "camera-toggle" : "video-file-toggle"}
			aria-pressed={video.source === source}
			// turning on needs the session; turning off (releasing the camera) never does
			disabled={!connected && video.source !== source}
			onClick={() => onToggle(source)}
		>
			{label}
		</button>
	);
	return (
		<section className="video">
			<h2>
				<Icon name="video" />
				Video
			</h2>
			{toggle("camera", "Camera")}
			<label className="volume">
				<span className="volume__label">Background</span>
				<select
					data-testid="background-select"
					value={video.background}
					disabled={!connected}
					onChange={(e) => onBackground(e.target.value as BackgroundMode)}
				>
					{BACKGROUNDS.map((b) => (
						<option key={b.value} value={b.value}>
							{b.label}
						</option>
					))}
				</select>
			</label>
			{toggle("file", "Video file")}
			{/* The native input stays hidden: its button and "no file" text
			    follow the browser's locale, not the page's English. */}
			<div className="volume">
				<span className="volume__label">Other mp4</span>
				<button
					type="button"
					className="sign sign--outline"
					disabled={!connected}
					onClick={() => fileRef.current?.click()}
				>
					<Icon name="file" />
					Choose video file
				</button>
				<input
					type="file"
					accept="video/mp4"
					hidden
					ref={fileRef}
					data-testid="video-file-input"
					disabled={!connected}
					onChange={(e) => {
						const file = e.target.files?.[0];
						e.target.value = "";
						if (!file) return;
						setFileName(file.name);
						onPickFile(file);
					}}
				/>
				{fileName && (
					<Tooltip tip={fileName}>
						<span
							className="file-name"
							// biome-ignore lint/a11y/noNoninteractiveTabindex: focusable so a keyboard user can read the full name's tooltip
							tabIndex={0}
							data-testid="video-file-name"
						>
							{fileName}
						</span>
					</Tooltip>
				)}
			</div>
			{video.error && (
				<p className="caption" role="alert" data-testid="video-error">
					{video.error}
				</p>
			)}
		</section>
	);
}
