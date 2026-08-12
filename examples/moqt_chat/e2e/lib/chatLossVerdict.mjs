// Pure classification for the S3 chat-loss investigation's three-way
// transport crossmatch (see s3-voice-loss.mjs's own doc on the taps this
// consumes). Split out of the scenario so the id-matching logic -- the part
// most likely to have an off-by-one/substring bug -- has a fast,
// deterministic test instead of relying on a lossy e2e run to exercise it.

// A message id like "msg:user1:1" must not match a stream head carrying
// "msg:user1:10" (id 1 is a text-substring of id 10). Every wire payload
// this hub relays ends exactly at the chat text's own last byte (one
// Object per stream, buildChatObjectMessage's own shape), so the id can
// only be truly present if it runs to the head's end OR is immediately
// followed by a non-digit (the same boundary a regex \b would use, but
// hand-rolled since ids can contain ':' which \b does not treat as a
// boundary character).
function headContainsId(head, id) {
  const at = head.indexOf(id);
  if (at < 0) return false;
  const after = head[at + id.length];
  return after === undefined || !/[0-9]/.test(after);
}

function findByHead(streams, id) {
  return streams.find((s) => headContainsId(s.head, id));
}

/**
 * @param {object} args
 * @param {string} args.id "msg:<sender>:<seq>"
 * @param {string} args.receiver participant tag that should have received it
 * @param {Record<string, {head:string,bytes:number,closed:string|null}[]>} args.outUniStreams sender's own outgoing-uni tap, keyed by tag
 * @param {Record<string, {head:string,bytes:number,closed:string|null}[]>} args.uniStreams receiver's incoming-uni tap, keyed by tag
 * @returns {string} a human-readable verdict for report.json
 */
export function classifyMissingChat({ id, receiver, outUniStreams, uniStreams }) {
  const sender = id.split(":")[1];
  const recv = findByHead(uniStreams[receiver] ?? [], id);
  if (recv) {
    return `arrived (bytes=${recv.bytes}, closed=${recv.closed}, head=${JSON.stringify(recv.head)})`;
  }
  const sent = findByHead(outUniStreams[sender] ?? [], id);
  if (sent) {
    return `sent (bytes=${sent.bytes}, closed=${sent.closed}) but never arrived -- upstream/relay loss`;
  }
  return "never sent by the client -- frontend send bug";
}
