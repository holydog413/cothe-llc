// Encrypts the quote builder source into quote/quote.enc.json. Password read from env COTHE_SALES_PASSWORD.
import { readFileSync, writeFileSync } from "fs";
import { webcrypto as C } from "crypto";
const [src, out] = process.argv.slice(2);
const pw = process.env.COTHE_SALES_PASSWORD;
if (!pw) { console.error("COTHE_SALES_PASSWORD not set"); process.exit(1); }
const r = f => readFileSync(`${src}/${f}`, "utf8");
const payload = JSON.stringify({ css: r("builder.css"), html: r("builder.html"), js: [r("tax-data.js"), r("quote.js")] });
const ITER = 600000, salt = C.getRandomValues(new Uint8Array(16)), iv = C.getRandomValues(new Uint8Array(12));
const base = await C.subtle.importKey("raw", new TextEncoder().encode("sales:" + pw), "PBKDF2", false, ["deriveKey"]);
const key = await C.subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt, iterations: ITER }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
const ct = new Uint8Array(await C.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(payload)));
const b64 = u => Buffer.from(u).toString("base64");
writeFileSync(out, JSON.stringify({ v: 1, kdf: "PBKDF2-SHA256", iter: ITER, salt: b64(salt), iv: b64(iv), ct: b64(ct) }));
console.log("wrote", out, ct.length, "bytes ciphertext");
