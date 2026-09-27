// Bun: req.setTimeout() does not bound the TCP connect phase, and a socket left
// in connect is pinned by a native strong root, so it is never collected.
//
//   node repro.cjs   -> the bound fires for every request; nothing accumulates
//   bun  repro.cjs   -> the bound never fires; TLSSockets accumulate
//
// 192.0.2.1 is unroutable, so the TCP handshake never completes. Nothing
// outside this process is contacted.
const https = require('https');
const HOST = process.env.HOST ?? '192.0.2.1';
const PORT = Number(process.env.PORT ?? 443);

// The repro is only valid if a connect to TEST-NET space HANGS. On some networks
// it is routed or answered, and then nothing here measures what it claims to.
function checkPrecondition() {
  return new Promise((resolve) => {
    const net = require('net');
    const s = net.connect({ host: HOST, port: PORT });
    let done = false;
    const finish = (v) => { if (!done) { done = true; try { s.destroy(); } catch {} resolve(v); } };
    s.on('error', (e) => finish('errors immediately (' + e.code + ')'));
    s.on('connect', () => finish('accepts the connection'));
    setTimeout(() => finish(null), 1500);
  });
}


const N = Number(process.env.N ?? 300);
const BOUND_MS = Number(process.env.BOUND_MS ?? 500);
const SETTLE_MS = Number(process.env.SETTLE_MS ?? 6000);

let timeoutFired = 0, closed = 0, errored = 0;

// Live TLSSocket count, and the DOMINANT retaining chain across every instance.
//
// Reporting the shallowest instance is not good enough: a fresh process holds a
// few TLSSockets reachable through module structures, and picking one of those
// names the wrong retainer. So every instance is traced, grouped by the shape of
// its chain, and the shapes are ranked by how many instances share them.
//
// Measured layout of Bun.generateHeapSnapshot(), not assumed:
//   nodes  stride 4: (id, size, classIndex, flags)
//   edges  stride 4: (fromNodeId, toNodeId, typeIndex, edgeNameIndex)
//   Both edge endpoints are IDs, not indices.
function tlsSocketReport() {
  if (typeof Bun === 'undefined') return null;
  const s = Bun.generateHeapSnapshot();
  const n = s.nodes, cn = s.nodeClassNames, e = s.edges, et = s.edgeTypes, en = s.edgeNames;
  const N2 = n.length / 4, E = e.length / 4;
  const cls = cn.indexOf('TLSSocket');
  if (cls < 0) return { count: 0, sizeMB: 0, shapes: [] };

  const id2i = new Map();
  for (let i = 0; i < N2; i++) id2i.set(n[i * 4], i);

  const from = new Uint32Array(E), to = new Uint32Array(E);
  let kept = 0;
  for (let k = 0; k < E; k++) {
    const a = id2i.get(e[k * 4]), b = id2i.get(e[k * 4 + 1]);
    if (a === undefined || b === undefined) continue;
    from[kept] = a; to[kept] = b; kept++;
  }
  const deg = new Uint32Array(N2 + 1);
  for (let k = 0; k < kept; k++) deg[from[k] + 1]++;
  for (let i = 0; i < N2; i++) deg[i + 1] += deg[i];
  const cursor = deg.slice(0, N2);
  const adjTo = new Uint32Array(kept), adjEdge = new Uint32Array(kept);
  for (let k = 0; k < kept; k++) { const p = cursor[from[k]]++; adjTo[p] = to[k]; adjEdge[p] = k; }

  let root = 0;
  for (let i = 0; i < N2; i++) if (n[i * 4 + 2] === 0) { root = i; break; }
  const parent = new Int32Array(N2).fill(-1), pedge = new Int32Array(N2).fill(-1);
  const q = new Uint32Array(N2); let qh = 0, qt = 0;
  q[qt++] = root; parent[root] = root;
  while (qh < qt) {
    const u = q[qh++];
    for (let p = deg[u]; p < deg[u + 1]; p++) {
      const v = adjTo[p];
      if (parent[v] === -1) { parent[v] = u; pedge[v] = adjEdge[p]; q[qt++] = v; }
    }
  }

  let count = 0, bytes = 0;
  const shapes = new Map();
  for (let i = 0; i < N2; i++) {
    if (n[i * 4 + 2] !== cls) continue;
    count++; bytes += n[i * 4 + 1];
    if (parent[i] === -1) continue;
    const chain = [];
    let cur = i, guard = 0;
    while (cur !== root && guard++ < 16) {
      const k = pedge[cur], p = parent[cur];
      chain.push(`${et[e[k * 4 + 2]]}:${en[e[k * 4 + 3]] ?? ''}  <-  ${cn[n[p * 4 + 2]]}`);
      cur = p;
    }
    const sig = chain.join(' | ');
    if (!shapes.has(sig)) shapes.set(sig, { instances: 0, chain });
    shapes.get(sig).instances++;
  }

  return {
    count, sizeMB: +(bytes / 1048576).toFixed(1),
    shapes: [...shapes.values()].sort((a, b) => b.instances - a.instances).slice(0, 3),
  };
}

const runtime = typeof Bun !== 'undefined' ? `bun ${Bun.version}` : `node ${process.version}`;
console.log(`runtime: ${runtime}`);
console.log(`${N} HTTPS requests to unroutable ${HOST}:${PORT}, req.setTimeout(${BOUND_MS})\n`);

async function main() {
  const bad = await checkPrecondition();
  if (bad) {
    console.log(`SKIP: ${HOST}:${PORT} ${bad}. This repro needs an address whose TCP handshake never completes.`);
    process.exit(2);
  }

for (let i = 0; i < N; i++) {
  const req = https.request({
    host: HOST, port: PORT, method: 'POST', path: '/v1/traces',
    rejectUnauthorized: false,
  });
  req.setTimeout(BOUND_MS, () => { timeoutFired++; req.destroy(); });
  req.on('error', () => { errored++; });
  req.on('close', () => { closed++; });
  req.end(Buffer.alloc(1024));
}

setTimeout(() => {
  console.log(`after ${SETTLE_MS}ms:`);
  console.log(`  setTimeout fired : ${timeoutFired} / ${N}`);
  console.log(`  'close' emitted  : ${closed} / ${N}`);
  console.log(`  'error' emitted  : ${errored} / ${N}`);

  const r = tlsSocketReport();
  if (r) {
    console.log(`  live TLSSocket   : ${r.count}  (${r.sizeMB} MB)`);
    for (const sh of r.shapes) {
      console.log(`\n  ${sh.instances} instances retained by:`);
      for (const step of sh.chain) console.log(`    ${step}`);
    }
  }

  const bounded = timeoutFired >= N;
  console.log(`\n${bounded ? 'PASS: every connect was bounded.'
    : `FAIL: ${N - timeoutFired}/${N} connects never bounded; sockets retained.`}`);
  process.exit(bounded ? 0 : 1);
}, SETTLE_MS);
}

main();
