// MOQT movie transport: SUBSCRIBEs the hub-owned movie tracks
// (examples/moqt_chat/wired_server.c) over the same MOQT session
// moqtClient.ts's MoqtChatClient manages. "movie/init" carries the fMP4
// init segment as a one-shot blob stream (SUBGROUP_HEADER + N Objects +
// FIN, whose payloads concatenate to the segment); readMovie reassembles
// it. The live "movie" track (one fragment per Group) is consumed by
// moqtLiveClient.ts, which reuses decodeBlobObjects per Group stream.
//
// Track Alias space: chat aliases are 0..N-1, audio N..2N-1
// (moqtVoiceClient.ts), the live movie sits at 2N and its init segment at
// 2N+1 so neither collides with anything.

import { CANDIDATE_PARTICIPANT_IDS, type MoqtChatClient } from "./moqtClient";
import {
  concatBytes,
  decodeSubgroupObject,
  MoqtDecodeError,
  readToEof,
  utf8ToBytes,
} from "./moqtWire";

export const MOVIE_TRACK_NAME = "movie";
export const MOVIE_TRACK_ALIAS = 2n * BigInt(CANDIDATE_PARTICIPANT_IDS.length);
export const MOVIE_INIT_TRACK_NAME = "movie/init";
export const MOVIE_INIT_TRACK_ALIAS = MOVIE_TRACK_ALIAS + 1n;

/** Decodes every Object in `bytes` (the COMPLETE stream after its
 * SUBGROUP_HEADER, read to EOF) and returns their payloads concatenated.
 * Object IDs chain by decodeSubgroupObject's FIRST_OBJECT/prev+delta+1
 * rule. Throws MoqtDecodeError on a truncated tail: decodeSubgroupObject
 * slices a short payload without throwing, so that case is checked here. */
export function decodeBlobObjects(bytes: Uint8Array, hasProperties: boolean): Uint8Array {
  const payloads: Uint8Array[] = [];
  let pos = 0;
  let prevObjectId = 0n;
  let isFirst = true;
  while (pos < bytes.length) {
    const { object, len } = decodeSubgroupObject(bytes, pos, hasProperties, prevObjectId, isFirst);
    if (pos + len > bytes.length) throw new MoqtDecodeError("truncated Object payload");
    payloads.push(object.payload);
    prevObjectId = object.objectId;
    isFirst = false;
    pos += len;
  }
  return concatBytes(payloads);
}

/** SUBSCRIBEs the hub's "movie/init" track. The reply is not awaited
 * (moqtClient.ts's subscribeTrack doc); a hub started without a movie
 * answers REQUEST_ERROR and nothing further arrives. */
export function subscribeMovieInit(chat: MoqtChatClient): Promise<void> {
  return chat.subscribeTrack(utf8ToBytes(MOVIE_INIT_TRACK_NAME), MOVIE_INIT_TRACK_NAME);
}

/** Reads the hub's init-segment stream to EOF (from moqtClient.ts's
 * onUnknownUniStream) and returns the reassembled segment, or undefined
 * when the stream was malformed or aborted (dropped, not fatal). */
export async function readMovie(
  firstChunkTail: Uint8Array,
  reader: ReadableStreamDefaultReader<Uint8Array>,
  hasProperties: boolean,
): Promise<Uint8Array | undefined> {
  try {
    return decodeBlobObjects(await readToEof(firstChunkTail, reader), hasProperties);
  } catch {
    return undefined;
  }
}
