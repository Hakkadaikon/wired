// In-process UDP impairment proxy (no root, no tc): each client flow gets
// its own downstream listen port (listenBase+i) AND its own upstream socket.
// One shared upstream socket would merge every client into a single 5-tuple
// at the server and silently change connection routing -- per-flow sockets
// are a correctness requirement, not a style choice.
//
// Impairments per profile: seeded random loss (reproducible via seed),
// jitter (base+spread ms; independent timers reorder naturally), burst
// outage (outage(i, ms), callable mid-run), NAT rebind (rebind(i),
// report-only). Bandwidth caps deliberately not implemented.

import dgram from "node:dgram";

// Deterministic LCG (Numerical Recipes constants) so a loss pattern can be
// reproduced exactly from --impair-seed. One stream per flow.
function lcg(seed) {
  let s = seed >>> 0;
  return () => {
    s = (Math.imul(s, 1664525) + 1013904223) >>> 0;
    return s / 2 ** 32;
  };
}

function bindSocket(port) {
  return new Promise((resolve, reject) => {
    const sock = dgram.createSocket("udp4");
    sock.once("error", reject);
    sock.bind(port, "127.0.0.1", () => resolve(sock));
  });
}

/**
 * @param {object} opts
 * @param {number} opts.listenBase    flow i listens on listenBase+i
 * @param {number} opts.upstreamPort  the real server's UDP port
 * @param {number} opts.flowCount
 * @param {object} [opts.profile]     {lossRate=0, seed=1, jitterBaseMs=0, jitterSpreadMs=0}
 */
export async function startUdpProxy({
  listenBase,
  upstreamPort,
  flowCount,
  profile = {},
}) {
  const { lossRate = 0, seed = 1, jitterBaseMs = 0, jitterSpreadMs = 0 } = profile;
  const upstreamHost = "127.0.0.1";
  const flows = [];

  const impair = (flow, deliver) => {
    flow.stats.seen++;
    if (Date.now() < flow.outageUntil) {
      flow.stats.dropped++;
      return;
    }
    if (lossRate > 0 && flow.rand() < lossRate) {
      flow.stats.dropped++;
      return;
    }
    flow.stats.forwarded++;
    if (jitterBaseMs > 0 || jitterSpreadMs > 0) {
      setTimeout(deliver, jitterBaseMs + flow.rand() * jitterSpreadMs);
      return;
    }
    deliver();
  };

  for (let i = 0; i < flowCount; i++) {
    const down = await bindSocket(listenBase + i);
    const flow = {
      down,
      up: null,
      clientPort: null,
      outageUntil: 0,
      rand: lcg(seed + i),
      stats: { seen: 0, forwarded: 0, dropped: 0, rebinds: 0 },
    };
    const attachUpstream = (sock) => {
      sock.on("message", (msg) => {
        if (flow.clientPort === null) return;
        impair(flow, () => flow.down.send(msg, flow.clientPort, "127.0.0.1"));
      });
    };
    flow.up = dgram.createSocket("udp4");
    attachUpstream(flow.up);
    flow.attachUpstream = attachUpstream;
    down.on("message", (msg, rinfo) => {
      flow.clientPort = rinfo.port;
      impair(flow, () => flow.up.send(msg, upstreamPort, upstreamHost));
    });
    flows.push(flow);
  }

  return {
    port(i) {
      return listenBase + i;
    },
    outage(i, ms) {
      flows[i].outageUntil = Date.now() + ms;
    },
    rebind(i) {
      const old = flows[i].up;
      flows[i].up = dgram.createSocket("udp4");
      flows[i].attachUpstream(flows[i].up);
      flows[i].stats.rebinds++;
      old.close();
    },
    stats() {
      return flows.map((f) => ({ ...f.stats }));
    },
    close() {
      for (const f of flows) {
        f.down.close();
        f.up.close();
      }
    },
  };
}
