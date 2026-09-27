import { describe, expect, it } from "bun:test";
import { request as httpsRequest } from "node:https";
import { connect as netConnect } from "node:net";
import { connect as tlsConnect } from "node:tls";

// 192.0.2.1 is RFC 5737 TEST-NET-1: reserved for documentation and never routed,
// so the TCP handshake never completes and the socket stays in the connecting
// state. Nothing outside the test process is contacted.
//
// Do not use RFC 1918 space such as 10.255.255.1 here. It is real address space:
// on a network that routes or occupies it the connect fails in 2ms instead of
// hanging, and every assertion below then passes or fails for the wrong reason.
const UNROUTABLE = { host: "192.0.2.1", port: 443 } as const;
const BOUND = 500;

// Every test here needs the connect to HANG. If the environment routes TEST-NET,
// the suite must say so rather than report a result it did not measure.
async function connectHangs(): Promise<boolean> {
  const { promise, resolve } = Promise.withResolvers<boolean>();
  const socket = netConnect({ ...UNROUTABLE });
  const finish = (v: boolean) => { try { socket.destroy(); } catch {} resolve(v); };
  socket.on("error", () => finish(false));
  socket.on("connect", () => finish(false));
  setTimeout(() => finish(true), 1500).unref();
  return promise;
}

function liveTLSSocketCount(): number {
  const snapshot = Bun.generateHeapSnapshot() as any;
  const cls = snapshot.nodeClassNames.indexOf("TLSSocket");
  if (cls < 0) return 0;
  const nodes = snapshot.nodes;
  let count = 0;
  // nodes has a stride of 4: (id, size, classIndex, flags)
  for (let i = 0; i < nodes.length; i += 4) if (nodes[i + 2] === cls) count++;
  return count;
}

describe("node:http client timeout during connect", () => {
  it("precondition: the test address does not complete a TCP handshake", async () => {
    expect(await connectHangs()).toBe(true);
  });

  // The net and tls layers already bound a connecting socket. These two pass,
  // and they are here so a failure in the https case cannot be blamed on them.
  it("net.connect({ timeout }) fires while still connecting", async () => {
    const { promise, resolve } = Promise.withResolvers<boolean>();
    const socket = netConnect({ ...UNROUTABLE, timeout: BOUND });
    socket.on("timeout", () => resolve(true));
    socket.on("error", () => {});
    setTimeout(() => resolve(false), BOUND * 6).unref();
    expect(await promise).toBe(true);
    socket.destroy();
  });

  it("tls.connect({ timeout }) fires while still connecting", async () => {
    const { promise, resolve } = Promise.withResolvers<boolean>();
    const socket = tlsConnect({ ...UNROUTABLE, rejectUnauthorized: false, timeout: BOUND });
    socket.on("timeout", () => resolve(true));
    socket.on("error", () => {});
    setTimeout(() => resolve(false), BOUND * 6).unref();
    expect(await promise).toBe(true);
    socket.destroy();
  });

  // The actual defect. req.setTimeout() is the only bound the OpenTelemetry OTLP
  // HTTP exporter places on an export, so when it does not fire the export is
  // unbounded.
  it("req.setTimeout() fires when the connect never completes", async () => {
    const { promise, resolve } = Promise.withResolvers<string>();

    const req = httpsRequest({
      ...UNROUTABLE,
      method: "POST",
      path: "/v1/traces",
      rejectUnauthorized: false,
    });
    req.setTimeout(BOUND, () => resolve("timeout"));
    req.on("error", () => resolve("error"));
    req.on("close", () => resolve("close"));
    req.end(Buffer.alloc(64));

    const bail = setTimeout(() => resolve("nothing-fired"), BOUND * 12);
    bail.unref();

    const outcome = await promise;
    req.destroy();
    expect(outcome).toBe("timeout");
  });

  // Consequence of the above: each unbounded request leaves a TLSSocket that is
  // pinned by a native strong root (StrongRootBlock in a heap snapshot), so it
  // is never collected and the process grows without bound for as long as the
  // collector is unreachable.
  it("does not retain a TLSSocket per unbounded request", async () => {
    const before = liveTLSSocketCount();
    const N = 50;

    for (let i = 0; i < N; i++) {
      const req = httpsRequest({
        ...UNROUTABLE,
        method: "POST",
        path: "/v1/traces",
        rejectUnauthorized: false,
      });
      req.setTimeout(BOUND, () => req.destroy());
      req.on("error", () => {});
      req.end(Buffer.alloc(1024));
    }

    await Bun.sleep(BOUND * 8);
    Bun.gc(true);

    const after = liveTLSSocketCount();
    // Sockets torn down by the bound are collectable; retained ones are not.
    expect(after - before).toBeLessThan(N);
  });
});
