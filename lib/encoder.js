export function urlEncode(s) {
  return encodeURIComponent(s);
}

export function urlDecode(s) {
  try {
    return decodeURIComponent(s);
  } catch (e) {
    return "Invalid URL encoding";
  }
}

export function urlDoubleEncode(s) {
  return encodeURIComponent(encodeURIComponent(s));
}

export function urlDoubleDecode(s) {
  try {
    return decodeURIComponent(decodeURIComponent(s));
  } catch (e) {
    return "Invalid double URL encoding";
  }
}

export function base64Encode(s) {
  const bytes = new TextEncoder().encode(s);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

export function base64Decode(s) {
  try {
    const bin = atob(s.replace(/\s+/g, ""));
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  } catch (e) {
    return "Invalid Base64";
  }
}

export function hexEncode(s) {
  return [...new TextEncoder().encode(s)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function hexDecode(s) {
  try {
    const clean = s.replace(/0x|\s|:|\\x/gi, "");
    const bytes = (clean.match(/.{1,2}/g) || []).map((h) => parseInt(h, 16));
    return new TextDecoder().decode(Uint8Array.from(bytes));
  } catch (e) {
    return "Invalid Hex";
  }
}

export function htmlEncode(s) {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export function htmlDecode(s) {
  const el = document.createElement("textarea");
  el.innerHTML = s;
  return el.value;
}

export function unicodeEncode(s) {
  return [...s]
    .map((c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"))
    .join("");
}

export function unicodeDecode(s) {
  return s.replace(/\\u([0-9a-fA-F]{4})/g, (_, h) =>
    String.fromCharCode(parseInt(h, 16))
  );
}

export function jwtDecode(s) {
  try {
    const part = s.trim().split(".")[1];
    return JSON.stringify(
      JSON.parse(base64Decode(part.replace(/-/g, "+").replace(/_/g, "/"))),
      null,
      2
    );
  } catch (e) {
    return "Invalid JWT";
  }
}

export function reverseStr(s) {
  return [...s].reverse().join("");
}

export function rot13(s) {
  return s.replace(/[a-z]/gi, (c) => {
    const base = c <= "Z" ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
  });
}

export const TRANSFORMS = [
  { label: "URL enc", fn: urlEncode },
  { label: "URL dec", fn: urlDecode },
  { label: "URL2x enc", fn: urlDoubleEncode },
  { label: "URL2x dec", fn: urlDoubleDecode },
  { label: "Base64 enc", fn: base64Encode },
  { label: "Base64 dec", fn: base64Decode },
  { label: "Hex enc", fn: hexEncode },
  { label: "Hex dec", fn: hexDecode },
  { label: "HTML enc", fn: htmlEncode },
  { label: "HTML dec", fn: htmlDecode },
  { label: "Unicode enc", fn: unicodeEncode },
  { label: "Unicode dec", fn: unicodeDecode },
  { label: "JWT dec", fn: jwtDecode },
  { label: "ROT13", fn: rot13 },
  { label: "Reverse", fn: reverseStr },
  { label: "MySQL CHAR()", fn: (s) => [...s].map((c) => "CHAR(" + c.charCodeAt(0) + ")").join(",") },
  { label: "MSSQL CHAR()", fn: (s) => [...s].map((c) => "CHAR(" + c.charCodeAt(0) + ")").join("+") },
  { label: "Oracle CHR()", fn: (s) => [...s].map((c) => "CHR(" + c.charCodeAt(0) + ")").join("||") },
  { label: "UPPER", fn: (s) => s.toUpperCase() },
  { label: "lower", fn: (s) => s.toLowerCase() },
];
