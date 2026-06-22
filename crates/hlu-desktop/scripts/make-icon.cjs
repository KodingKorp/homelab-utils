// Generates a placeholder 1024x1024 source icon (PNG) for `tauri icon`.
// A "radar" mark on a teal→navy gradient — replace with real branding later.
// Usage: node scripts/make-icon.cjs [out.png]
const fs = require("fs");
const zlib = require("zlib");

const W = 1024;
const H = 1024;
const cx = W / 2;
const cy = H / 2;
const data = Buffer.alloc(W * H * 4);

const lerp = (a, b, t) => Math.round(a + (b - a) * t);
const teal = [14, 165, 164];
const navy = [11, 32, 53];
const ink = [230, 255, 250];
const satellites = [
  [cx, cy - 300],
  [cx + 260, cy + 150],
  [cx - 260, cy + 150],
];

for (let y = 0; y < H; y++) {
  for (let x = 0; x < W; x++) {
    const t = (x + y) / (W + H);
    let r = lerp(teal[0], navy[0], t);
    let g = lerp(teal[1], navy[1], t);
    let b = lerp(teal[2], navy[2], t);

    const dist = Math.hypot(x - cx, y - cy);
    for (const ring of [300, 210]) {
      if (Math.abs(dist - ring) < 13) [r, g, b] = ink;
    }
    if (dist < 58) [r, g, b] = ink;
    for (const [sx, sy] of satellites) {
      if (Math.hypot(x - sx, y - sy) < 40) [r, g, b] = ink;
    }

    const i = (y * W + x) * 4;
    data[i] = r;
    data[i + 1] = g;
    data[i + 2] = b;
    data[i + 3] = 255;
  }
}

const crcTable = (() => {
  const table = [];
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = crcTable[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function chunk(type, body) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(body.length, 0);
  const typeBuf = Buffer.from(type, "ascii");
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([typeBuf, body])), 0);
  return Buffer.concat([len, typeBuf, body, crc]);
}

const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
const ihdr = Buffer.alloc(13);
ihdr.writeUInt32BE(W, 0);
ihdr.writeUInt32BE(H, 4);
ihdr[8] = 8; // bit depth
ihdr[9] = 6; // color type RGBA
const raw = Buffer.alloc(H * (1 + W * 4));
for (let y = 0; y < H; y++) {
  raw[y * (1 + W * 4)] = 0; // no filter
  data.copy(raw, y * (1 + W * 4) + 1, y * W * 4, y * W * 4 + W * 4);
}
const png = Buffer.concat([
  signature,
  chunk("IHDR", ihdr),
  chunk("IDAT", zlib.deflateSync(raw)),
  chunk("IEND", Buffer.alloc(0)),
]);

const out = process.argv[2] || "app-icon.png";
fs.writeFileSync(out, png);
console.log(`wrote ${out} (${png.length} bytes)`);
