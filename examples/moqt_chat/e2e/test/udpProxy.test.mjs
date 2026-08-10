// Unit tests for the UDP impairment proxy: transparency, seeded-loss
// determinism, outage window edges, and per-flow upstream socket isolation.

import test from "node:test";
import assert from "node:assert/strict";
import dgram from "node:dgram";
import { startUdpProxy } from "../lib/udpProxy.mjs";

const BASE = 39100; // test-local port range; each test uses its own offset

function bindSink(port) {
  return new Promise((resolve) => {
    const sock = dgram.createSocket("udp4");
    const got = [];
    sock.on("message", (msg, rinfo) => got.push({ msg: msg.toString(), port: rinfo.port }));
    sock.bind(port, "127.0.0.1", () => resolve({ sock, got }));
  });
}

function sendVia(sock, port, text) {
  return new Promise((r) => sock.send(text, port, "127.0.0.1", r));
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

test("transparent: clean profile forwards every packet both ways", async () => {
  const { sock: server, got } = await bindSink(BASE);
  server.on("message", (msg, rinfo) => server.send(`echo:${msg}`, rinfo.port, "127.0.0.1"));
  const proxy = await startUdpProxy({ listenBase: BASE + 10, upstreamPort: BASE, flowCount: 1 });
  const client = dgram.createSocket("udp4");
  const replies = [];
  client.on("message", (m) => replies.push(m.toString()));
  for (let i = 0; i < 20; i++) await sendVia(client, proxy.port(0), `p${i}`);
  await sleep(200);
  assert.equal(got.length, 20);
  assert.equal(replies.length, 20);
  assert.ok(replies.includes("echo:p0") && replies.includes("echo:p19"));
  client.close();
  proxy.close();
  server.close();
});

test("seeded loss is deterministic across runs", async () => {
  async function run(offset) {
    const { sock: server, got } = await bindSink(BASE + offset);
    const proxy = await startUdpProxy({
      listenBase: BASE + offset + 10,
      upstreamPort: BASE + offset,
      flowCount: 1,
      profile: { lossRate: 0.3, seed: 42 },
    });
    const client = dgram.createSocket("udp4");
    for (let i = 0; i < 100; i++) await sendVia(client, proxy.port(0), `i${i}`);
    await sleep(200);
    client.close();
    proxy.close();
    server.close();
    return got.map((g) => g.msg).sort();
  }
  const a = await run(20);
  const b = await run(40);
  assert.ok(a.length > 40 && a.length < 90); // ~30% loss actually applied
  assert.deepEqual(a, b);
});

test("outage window drops during, passes before and after", async () => {
  const { got, sock: server } = await bindSink(BASE + 60);
  const proxy = await startUdpProxy({ listenBase: BASE + 70, upstreamPort: BASE + 60, flowCount: 1 });
  const client = dgram.createSocket("udp4");
  await sendVia(client, proxy.port(0), "before");
  await sleep(50);
  proxy.outage(0, 200);
  await sendVia(client, proxy.port(0), "during");
  await sleep(300); // outage expired
  await sendVia(client, proxy.port(0), "after");
  await sleep(100);
  const msgs = got.map((g) => g.msg);
  assert.ok(msgs.includes("before"));
  assert.ok(!msgs.includes("during"));
  assert.ok(msgs.includes("after"));
  client.close();
  proxy.close();
  server.close();
});

test("flows use separate upstream sockets; rebind changes the source port", async () => {
  const { got, sock: server } = await bindSink(BASE + 80);
  const proxy = await startUdpProxy({ listenBase: BASE + 90, upstreamPort: BASE + 80, flowCount: 2 });
  const c0 = dgram.createSocket("udp4");
  const c1 = dgram.createSocket("udp4");
  await sendVia(c0, proxy.port(0), "f0");
  await sendVia(c1, proxy.port(1), "f1");
  await sleep(100);
  const port0 = got.find((g) => g.msg === "f0").port;
  const port1 = got.find((g) => g.msg === "f1").port;
  assert.notEqual(port0, port1); // per-flow 5-tuple isolation
  proxy.rebind(0);
  await sendVia(c0, proxy.port(0), "f0b");
  await sleep(100);
  const port0b = got.find((g) => g.msg === "f0b").port;
  assert.notEqual(port0b, port0); // NAT rebind = new source port
  c0.close();
  c1.close();
  proxy.close();
  server.close();
});
