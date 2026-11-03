// An incoming uni stream the chat client does not own goes to the camera,
// screen or voice receiver by its Track Alias range. Video is matched
// first: MoqtVoiceClient cancels any stream whose alias it doesn't own, so
// a video stream routed there is eaten.

import { isCameraTrackAlias, isScreenTrackAlias } from "./moqtScreenClient";
import type { SubgroupHeader } from "./moqtWire";

type Sink = {
	handleIncomingStream(
		header: SubgroupHeader,
		firstChunk: Uint8Array,
		reader: ReadableStreamDefaultReader<Uint8Array>,
	): void;
} | null;

export function routeUniStream(
	header: SubgroupHeader,
	firstChunk: Uint8Array,
	reader: ReadableStreamDefaultReader<Uint8Array>,
	to: { camera: Sink; screen: Sink; voice: Sink },
): void {
	const a = header.trackAlias;
	const sink = isCameraTrackAlias(a)
		? to.camera
		: isScreenTrackAlias(a)
			? to.screen
			: to.voice;
	// No receiver yet (session still starting): close the stream, don't leak it.
	if (!sink) return void reader.cancel().catch(() => {});
	sink.handleIncomingStream(header, firstChunk, reader);
}
