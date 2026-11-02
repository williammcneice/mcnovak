// Builds the password-protected treatment at treatment/ and the access page
// at mistress/, which asks once for the password and then offers both the
// treatment and the look book.
//
// The repository is public, so the treatment page and its PDF are encrypted
// (AES-256-GCM) with the same key as the look book: the salt is read from
// lookbook/index.html, and the password is checked against the look book
// before anything is written. One password, entered once per tab, opens
// all three pages, because each stores the derived key in sessionStorage
// under 'mistress-key', which the look book already reads.
//
// Usage:
//   MISTRESS_PASSWORD=... node tools/build-treatment.mjs <treatment.html> [<treatment.pdf>]
//
// Keep both inputs out of the repo (private/ is gitignored). Run after
// tools/build-mistress.mjs whenever the look book is rebuilt.

import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { webcrypto as crypto, createHash } from 'node:crypto';

const [src, pdf] = process.argv.slice(2);
const password = process.env.MISTRESS_PASSWORD;
if (!src || !password) {
  console.error('Usage: MISTRESS_PASSWORD=... node tools/build-treatment.mjs <treatment.html> [<treatment.pdf>]');
  process.exit(1);
}

const b64 = (buf) => Buffer.from(buf).toString('base64');
const lookbook = readFileSync('lookbook/index.html', 'utf8');
const m = lookbook.match(/var SALT="([^"]+)",ITER=(\d+),DATA="([^"]+)"/);
if (!m) { console.error('Could not read the salt from lookbook/index.html.'); process.exit(1); }
const salt = new Uint8Array(Buffer.from(m[1], 'base64'));
const ITERATIONS = +m[2];

const baseKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
const key = await crypto.subtle.deriveKey(
  { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: ITERATIONS },
  baseKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);

// Refuse a password that does not open the look book.
try {
  const d = new Uint8Array(Buffer.from(m[3], 'base64'));
  await crypto.subtle.decrypt({ name: 'AES-GCM', iv: d.slice(0, 12) }, key, d.slice(12));
} catch {
  console.error('That password does not open the look book. Nothing written.');
  process.exit(1);
}

async function seal(bytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes));
  const out = new Uint8Array(12 + ct.length);
  out.set(iv); out.set(ct, 12);
  return out;
}

// PDF: sealed to treatment/assets/treatment.bin; re-encrypted only when it changes.
let html = readFileSync(src, 'utf8');
let pdfVersion = '0';
if (pdf) {
  const plain = readFileSync(pdf), out = join('treatment', 'assets', 'treatment.bin');
  mkdirSync(join('treatment', 'assets'), { recursive: true });
  let sealed = existsSync(out) ? new Uint8Array(readFileSync(out)) : null;
  let same = false;
  if (sealed) {
    try { same = Buffer.from(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: sealed.slice(0, 12) }, key, sealed.slice(12))).equals(plain); } catch {}
  }
  if (!same) { sealed = await seal(plain); writeFileSync(out, sealed); }
  pdfVersion = createHash('sha256').update(sealed).digest('hex').slice(0, 10);
}
html = html.replace('__PDF_VERSION__', pdfVersion);
html = html.replace('<head>', '<head><meta name="robots" content="noindex, nofollow">');
const page = await seal(new TextEncoder().encode(html));
// A small sealed token lets the access page check the password without carrying a document.
const check = await seal(new TextEncoder().encode('mistress'));

// Shared look of the private pages: the look book's own gate.
const head = (title) => `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex, nofollow">
<title>${title}</title>
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
button,.btn{font:inherit;font-size:15px;letter-spacing:.06em;padding:.75em 1.4em;background:#f0ece6;color:#16181a;border:0;border-radius:0;cursor:pointer;text-decoration:none;display:inline-block}
button:disabled{opacity:.5}
.btn:hover,.btn:focus-visible{background:#d94434;color:#f0ece6;outline:none}
.choices{display:flex;gap:10px;flex-wrap:wrap}
.choices .btn{flex:1 1 12rem;text-align:center}
[hidden]{display:none!important}
.msg{margin:0;min-height:1.4em;font-size:14px;color:#949ca4}
.msg.err{color:#d94434}
a{color:#949ca4}
</style></head><body><main>
`;
const form = `<form id="f"><input id="p" type="password" autocomplete="current-password" placeholder="Password" aria-label="Password" required autofocus><button id="b">Open</button></form>`;
const request = (what) => `For producers and collaborators. Request the password at <a href="mailto:will@mcnovak.net?subject=The%20Mistress%20%E2%80%94%20${encodeURIComponent(what)}">will@mcnovak.net</a>.`;
// Derives the key from the typed password, then hands it to unlock(k, raw).
const keyScript = `var SALT="${b64(salt)}",ITER=${ITERATIONS};
function bytes(s){return Uint8Array.from(atob(s),function(c){return c.charCodeAt(0)})}
async function fromRaw(raw){return crypto.subtle.importKey('raw',bytes(raw),'AES-GCM',false,['decrypt'])}
async function dec(k,s){var d=bytes(s);return crypto.subtle.decrypt({name:'AES-GCM',iv:d.slice(0,12)},k,d.slice(12))}
(async function(){var raw=sessionStorage.getItem('mistress-key');if(raw){try{await unlock(await fromRaw(raw),raw)}catch(e){sessionStorage.removeItem('mistress-key')}}})();
document.getElementById('f').addEventListener('submit',async function(e){
  e.preventDefault();var m=document.getElementById('m'),b=document.getElementById('b');
  b.disabled=true;m.className='msg';m.textContent='Opening…';
  try{
    var base=await crypto.subtle.importKey('raw',new TextEncoder().encode(document.getElementById('p').value),'PBKDF2',false,['deriveKey']);
    var k=await crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt:bytes(SALT),iterations:ITER},base,{name:'AES-GCM',length:256},true,['decrypt']);
    var raw=btoa(String.fromCharCode.apply(null,new Uint8Array(await crypto.subtle.exportKey('raw',k))));
    await unlock(k,raw);
  }catch(err){m.className='msg err';m.textContent='That password is not right.';b.disabled=false;}
});`;

// Treatment gate: decrypts the page in place, as the look book does.
const treatmentGate = head('The Mistress — Treatment') + `<p class="kicker">Treatment · private</p>
<h1>The Mistress</h1>
${form}
<p class="msg" id="m">${request('treatment')}</p>
</main>
<script>
var DATA="${b64(page)}";
async function unlock(k,raw){
  var p=await dec(k,DATA);
  sessionStorage.setItem('mistress-key',raw);
  document.open();document.write(new TextDecoder().decode(p));document.close();
}
${keyScript}
</script></body></html>
`;

// Access page: one password, then a choice of treatment or look book.
const access = head('The Mistress — Treatment and look book') + `<p class="kicker">Private · password on request</p>
<h1>The Mistress</h1>
<div id="lock">
${form}
</div>
<div class="choices" id="open" hidden>
<a class="btn" href="../treatment/">Treatment</a>
<a class="btn" href="../lookbook/">Look book</a>
</div>
<p class="msg" id="m">${request('treatment and look book')}</p>
<p class="msg"><a href="../">← McNovak</a></p>
</main>
<script>
var CHECK="${b64(check)}";
async function unlock(k,raw){
  await dec(k,CHECK);
  sessionStorage.setItem('mistress-key',raw);
  document.getElementById('lock').hidden=true;
  document.getElementById('open').hidden=false;
  var m=document.getElementById('m');m.className='msg';m.textContent='';
  document.querySelector('#open .btn').focus();
}
${keyScript}
</script></body></html>
`;

mkdirSync('treatment', { recursive: true });
mkdirSync('mistress', { recursive: true });
writeFileSync(join('treatment', 'index.html'), treatmentGate);
writeFileSync(join('mistress', 'index.html'), access);
console.log(`treatment/index.html and mistress/index.html written${pdf ? `; PDF sealed (v=${pdfVersion})` : ''}.`);
