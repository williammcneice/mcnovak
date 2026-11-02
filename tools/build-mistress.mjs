// Builds the password-protected look book at lookbook/.
//
// The repository is public, so nothing readable may be committed: the page
// and every image are encrypted (AES-256-GCM, key from PBKDF2-SHA256) and
// only the password decrypts them in the browser.
//
// Usage:
//   MISTRESS_PASSWORD=... node tools/build-mistress.mjs <lookbook.html> <images-dir>
//
// <images-dir> holds one file per /_blob/<id> reference in the HTML, named
// <id>.jpg. Keep both inputs out of the repo (private/ is gitignored).

import { readFileSync, writeFileSync, mkdirSync, rmSync, existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { webcrypto as crypto, createHash } from 'node:crypto';

const ITERATIONS = 600000;
const OUT = 'lookbook';
const [src, imgDir] = process.argv.slice(2);
const password = process.env.MISTRESS_PASSWORD;
if (!src || !imgDir || !password) {
  console.error('Usage: MISTRESS_PASSWORD=... node tools/build-mistress.mjs <lookbook.html> <images-dir>');
  process.exit(1);
}

const b64 = (buf) => Buffer.from(buf).toString('base64');
// Reuse the published salt so the key never changes between builds: a
// browser holding a cached page from an earlier build can still decrypt
// freshly published images, and the reverse.
const prev = existsSync(join(OUT, 'index.html')) ? readFileSync(join(OUT, 'index.html'), 'utf8') : '';
const prevSalt = prev.match(/var SALT="([^"]+)",ITER=(\d+)/);
const salt = prevSalt && +prevSalt[2] === ITERATIONS
  ? new Uint8Array(Buffer.from(prevSalt[1], 'base64'))
  : crypto.getRandomValues(new Uint8Array(16));
const baseKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
const key = await crypto.subtle.deriveKey(
  { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: ITERATIONS },
  baseKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);

async function seal(bytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes));
  const out = new Uint8Array(12 + ct.length);
  out.set(iv); out.set(ct, 12);
  return out;
}

// Images: encrypt each referenced blob to lookbook/assets/<id>.bin
let html = readFileSync(src, 'utf8');
const ids = [...new Set([...html.matchAll(/\/_blob\/([0-9a-f]+)/g)].map((m) => m[1]))];
mkdirSync(join(OUT, 'assets'), { recursive: true });
for (const f of readdirSync(join(OUT, 'assets'))) {
  if (!ids.includes(f.replace(/\.bin$/, ''))) rmSync(join(OUT, 'assets', f));
}
async function open(bytes) {
  try { return Buffer.from(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes.slice(0, 12) }, key, bytes.slice(12))); }
  catch { return null; }
}
// Pixel size of a JPEG, read from its start-of-frame marker.
function jpegSize(buf) {
  for (let i = 2; i < buf.length - 9;) {
    if (buf[i] !== 0xff) { i++; continue; }
    const m = buf[i + 1], len = buf.readUInt16BE(i + 2);
    if (m >= 0xc0 && m <= 0xcf && m !== 0xc4 && m !== 0xc8 && m !== 0xcc) return [buf.readUInt16BE(i + 7), buf.readUInt16BE(i + 5)];
    i += 2 + len;
  }
  return null;
}
const missing = [], version = {}, size = {};
let rewritten = 0;
for (const id of ids) {
  const file = join(imgDir, `${id}.jpg`), out = join(OUT, 'assets', `${id}.bin`);
  if (!existsSync(file)) { missing.push(id); continue; }
  const plain = readFileSync(file);
  size[id] = jpegSize(plain);
  let sealed = existsSync(out) ? new Uint8Array(readFileSync(out)) : null;
  const same = sealed && (await open(sealed))?.equals(plain);
  if (!same) { sealed = await seal(plain); writeFileSync(out, sealed); rewritten++; }
  // The address changes whenever the file does, so no cache can serve a stale copy.
  version[id] = createHash('sha256').update(sealed).digest('hex').slice(0, 10);
}

// Page: images get their encrypted path in data-enc; a loader decrypts them.
html = html.replace(/src="\/_blob\/([0-9a-f]+)"/g, (_, id) => (size[id] ? `width="${size[id][0]}" height="${size[id][1]}" ` : '') + `data-enc="assets/${id}.bin?v=${version[id] || 0}"`);
// Width and height let the browser reserve each image's space before it is decrypted.
const loader = `<script>(async function(){
  var raw=sessionStorage.getItem('mistress-key');if(!raw)return;
  var k=await crypto.subtle.importKey('raw',Uint8Array.from(atob(raw),function(c){return c.charCodeAt(0)}),'AES-GCM',false,['decrypt']);
  var imgs=[].slice.call(document.querySelectorAll('img[data-enc]')),i=0;
  async function get(u,c){var b=new Uint8Array(await (await fetch(u,{cache:c})).arrayBuffer());
    return crypto.subtle.decrypt({name:'AES-GCM',iv:b.slice(0,12)},k,b.slice(12));}
  async function next(){while(i<imgs.length){var img=imgs[i++],p;
    try{p=await get(img.dataset.enc,'default')}catch(e){try{p=await get(img.dataset.enc,'reload')}catch(e2){continue}}
    img.src=URL.createObjectURL(new Blob([p],{type:'image/jpeg'}));}}
  for(var n=0;n<4;n++)next();
})();</script>`;
html = html.replace('</body>', loader + '</body>');
html = html.replace('<head>', '<head><meta name="robots" content="noindex, nofollow">');
const page = await seal(new TextEncoder().encode(html));

const gate = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex, nofollow">
<title>The Mistress — Look Book</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300..700&family=Source+Serif+4:wght@300..600&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box}
html,body{margin:0;height:100%;background:#16181a;color:#f0ece6;font-family:Inter,-apple-system,Helvetica,Arial,sans-serif;color-scheme:dark}
main{min-height:100%;display:flex;flex-direction:column;justify-content:center;padding:clamp(24px,8vmin,96px);gap:clamp(18px,3vmin,32px);max-width:44rem}
.kicker{margin:0;font-size:13px;letter-spacing:.18em;text-transform:uppercase;color:#d94434;font-weight:500}
h1{margin:0;font-family:"Source Serif 4",Georgia,serif;font-weight:400;font-size:clamp(48px,10vmin,120px);line-height:1}
form{display:flex;gap:10px;flex-wrap:wrap}
input{flex:1 1 14rem;font:inherit;font-size:17px;padding:.75em .9em;background:#0e0f10;color:inherit;border:1px solid #3a3d40;border-radius:0}
input:focus{outline:none;border-color:#949ca4}
button{font:inherit;font-size:15px;letter-spacing:.06em;padding:.75em 1.4em;background:#f0ece6;color:#16181a;border:0;border-radius:0;cursor:pointer}
button:disabled{opacity:.5}
.msg{margin:0;min-height:1.4em;font-size:14px;color:#949ca4}
.msg.err{color:#d94434}
a{color:#949ca4}
</style></head><body><main>
<p class="kicker">Look book · private</p>
<h1>The Mistress</h1>
<form id="f"><input id="p" type="password" autocomplete="current-password" placeholder="Password" aria-label="Password" required autofocus><button id="b">Open</button></form>
<p class="msg" id="m">For producers and collaborators. Request access at <a href="mailto:will@mcnovak.net?subject=The%20Mistress%20%E2%80%94%20look%20book">will@mcnovak.net</a>.</p>
</main>
<script>
var SALT="${b64(salt)}",ITER=${ITERATIONS},DATA="${b64(page)}";
function bytes(s){return Uint8Array.from(atob(s),function(c){return c.charCodeAt(0)})}
async function open(k,raw){
  var d=bytes(DATA),p=await crypto.subtle.decrypt({name:'AES-GCM',iv:d.slice(0,12)},k,d.slice(12));
  sessionStorage.setItem('mistress-key',raw);
  document.open();document.write(new TextDecoder().decode(p));document.close();
}
async function fromRaw(raw){return crypto.subtle.importKey('raw',bytes(raw),'AES-GCM',false,['decrypt'])}
addEventListener('DOMContentLoaded',async function(){var raw=sessionStorage.getItem('mistress-key');if(raw){try{await open(await fromRaw(raw),raw)}catch(e){sessionStorage.removeItem('mistress-key')}}});
document.getElementById('f').addEventListener('submit',async function(e){
  e.preventDefault();var m=document.getElementById('m'),b=document.getElementById('b');
  b.disabled=true;m.className='msg';m.textContent='Opening…';
  try{
    var base=await crypto.subtle.importKey('raw',new TextEncoder().encode(document.getElementById('p').value),'PBKDF2',false,['deriveKey']);
    var k=await crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt:bytes(SALT),iterations:ITER},base,{name:'AES-GCM',length:256},true,['decrypt']);
    var raw=btoa(String.fromCharCode.apply(null,new Uint8Array(await crypto.subtle.exportKey('raw',k))));
    await open(k,raw);
  }catch(err){m.className='msg err';m.textContent='That password is not right.';b.disabled=false;}
});
</script></body></html>
`;
writeFileSync(join(OUT, 'index.html'), gate);

console.log(`lookbook/index.html written; ${ids.length - missing.length}/${ids.length} images present, ${rewritten} re-encrypted; salt ${prevSalt ? 'kept' : 'new'}.`);
if (missing.length) console.log('Missing images:\n' + missing.map((m) => '  ' + m).join('\n'));
