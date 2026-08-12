import test from "node:test";
import assert from "node:assert/strict";
import { classifyMissingChat } from "../lib/chatLossVerdict.mjs";

// Test list (S3 chat-loss investigation, C1):
// 1. recv tap has the id -> "arrived" verdict, regardless of send tap
// 2. no recv, but send tap has the id -> "sent...upstream/relay loss"
// 3. no recv, no send -> "never sent...frontend send bug"
// 4. id substring must not false-positive on a different message's head
//    (e.g. "msg:user1:1" must not match a head containing "msg:user1:10")
// 5. sender is derived from the message id's own middle field, not the
//    pair's receiver

test("recv tap present -> arrived, includes byte/closed detail", () => {
  const v = classifyMissingChat({
    id: "msg:user2:3",
    receiver: "user1",
    outUniStreams: {},
    uniStreams: { user1: [{ head: "..msg:user2:3", bytes: 17, closed: "fin" }] },
  });
  assert.match(v, /^arrived/);
  assert.match(v, /bytes=17/);
  assert.match(v, /closed=fin/);
});

test("no recv, sent by sender -> upstream/relay loss verdict", () => {
  const v = classifyMissingChat({
    id: "msg:user2:3",
    receiver: "user1",
    outUniStreams: { user2: [{ head: "..msg:user2:3", bytes: 17, closed: "fin" }] },
    uniStreams: {},
  });
  assert.match(v, /^sent/);
  assert.match(v, /upstream\/relay loss/);
});

test("no recv, not sent -> frontend send bug verdict", () => {
  const v = classifyMissingChat({
    id: "msg:user2:3",
    receiver: "user1",
    outUniStreams: { user2: [] },
    uniStreams: { user1: [] },
  });
  assert.match(v, /never sent/);
  assert.match(v, /frontend send bug/);
});

test("id substring match does not false-positive across sibling ids", () => {
  // "msg:user1:1" is a substring of "msg:user1:10" -- a naive .includes()
  // on the WRONG direction (needle vs haystack swapped, or an id that is a
  // prefix of another) must not misclassify id 1 as arrived using id 10's
  // stream.
  const v = classifyMissingChat({
    id: "msg:user1:1",
    receiver: "user2",
    outUniStreams: {},
    uniStreams: { user2: [{ head: "..msg:user1:10", bytes: 18, closed: "fin" }] },
  });
  assert.doesNotMatch(v, /^arrived/);
});

test("sender is parsed from the id's own field, not the receiver", () => {
  const v = classifyMissingChat({
    id: "msg:user3:7",
    receiver: "user1",
    outUniStreams: { user3: [{ head: "..msg:user3:7", bytes: 17, closed: "fin" }] },
    uniStreams: {},
  });
  assert.match(v, /^sent/);
});
