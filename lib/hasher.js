import { md5 } from "./md5.js";

async function subtle(algo, str) {
  const data = new TextEncoder().encode(str);
  const buf = await crypto.subtle.digest(algo, data);
  return [...new Uint8Array(buf)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export const HASHES = [
  { label: "MD5", fn: (s) => md5(s) },
  { label: "SHA-1", fn: (s) => subtle("SHA-1", s) },
  { label: "SHA-256", fn: (s) => subtle("SHA-256", s) },
  { label: "SHA-384", fn: (s) => subtle("SHA-384", s) },
  { label: "SHA-512", fn: (s) => subtle("SHA-512", s) },
];

export async function hashAll(str) {
  const results = {};
  results.MD5 = md5(str);
  results["SHA-1"] = await subtle("SHA-1", str);
  results["SHA-256"] = await subtle("SHA-256", str);
  results["SHA-384"] = await subtle("SHA-384", str);
  results["SHA-512"] = await subtle("SHA-512", str);
  return results;
}
