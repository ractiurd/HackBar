// gap/gap_core.js
// GAP — ported to JavaScript for the HackBar.
// Original GAP by /XNL-h4ck3r (@xnl_h4ck3r): https://github.com/xnl-h4ck3r/GAP-Burp-Extension
// This module is a faithful JS port of GAP's link / parameter / word / "sus param"
// extraction engine. It operates on a single HTTP response body (the page HTML/JS),
// exactly like GAP processes one Burp request/response.

/* ----------------------------- constants ----------------------------- */

export const COMMON_TLDS = new Set([
  "com","de","net","org","uk","cn","ga","nl","cf","ml","tk","ru","br","gq","xyz","fr","eu",
  "info","co","au","ca","it","in","ch","pl","es","online","us","top","jp","biz","se","at",
  "dk","cz","za","me","ir","icu","shop","kr","site","mx","hu","io","cc","club","no","cyou","store",
]);

export const SUS_CMDI = new Set(["execute","dir","daemon","cli","log","cmd","download","ip","upload","message","input_file","format","expression","data","bsh","bash","shell","command","range","sort","host","exec","code"]);
export const SUS_DEBUG = new Set(["test","reset","config","shell","admin","exec","load","cfg","dbg","edit","root","create","access","disable","alter","make","grant","adm","toggle","execute","clone","delete","enable","rename","debug","modify","stacktrace"]);
export const SUS_FILEINC = new Set(["root","directory","path","style","folder","default-language","url","platform","textdomain","document","template","pg","php_path","doc","type","lang","token","name","pdf","file","etc","api","app","resource-type","controller","filename","page","f","view","input_file"]);
export const SUS_IDOR = new Set(["count","key","user","id","extended_data","uid2","group","team_id","data-id","no","username","email","account","doc","uuid","profile","number","user_id","edit","report","order"]);
export const SUS_OPENREDIRECT = new Set(["u","redirect_uri","failed","r","referer","return_url","redirect_url","prejoin_data","continue","redir","return_to","origin","redirect_to","next"]);
export const SUS_SQLI = new Set(["process","string","id","referer","password","pwd","field","view","sleep","column","log","token","sel","select","sort","from","search","update","pub_group_id","row","results","role","table","multi_layer_map_list","order","filter","params","user","fetch","limit","keyword","email","query","c","name","where","number","phone_number","delete","report","q","sql"]);
export const SUS_SSRF = new Set(["sector_identifier_uri","request_uris","logo_uri","jwks_uri","start","path","domain","source","url","site","view","template","page","show","val","dest","metadata","out","feed","navigation","image_host","uri","next","continue","host","window","dir","reference","filename","html","to","return","open","port","stop","validate","resturl","callback","name","data","ip","redirect","target","referer"]);
export const SUS_SSTI = new Set(["preview","activity","id","name","content","view","template","redirect"]);
export const SUS_XSS = new Set(["path","admin","class","atb","redirect_uri","other","utm_source","currency","dir","title","endpoint","return_url","users","cookie","state","callback","militarybranch","e","referer","password","author","body","status","utm_campaign","value","text","search","flaw","vote","pathname","params","user","t","utm_medium","q","email","what","file","data-original","description","subject","action","u","nickname","color","language_id","auth","samlresponse","return","readyfunction","where","tags","cvo_sid1","target","format","back","term","r","id","url","view","username","sequel","type","city","src","p","label","ctx","style","html","ad_type","s","issues","query","c","shop","redirect","page","prefv1","destination","mode","data","error","editor","wysiwyg","widget","msg"]);
export const SUS_MASSASSIGNMENT = new Set(["user","profile","role","settings","data","attributes","post","comment","order","product","form_fields","request"]);

export const DEFAULT_EXCLUSIONS = ".css,.jpg,.jpeg,.png,.svg,.img,.gif,.mp4,.flv,.ogv,.webm,.webp,.mov,.mp3,.m4a,.m4p,.scss,.tif,.tiff,.ttf,.otf,.woff,.woff2,.bmp,.ico,.eot,.htc,.rtf,.swf,.image,w3.org,doubleclick.net,youtube.com,.vue,jquery,bootstrap,font,jsdelivr.net,vimeo.com,pinterest.com,facebook,linkedin,twitter,instagram,google,mozilla.org,jibe.com,schema.org,schemas.microsoft.com,wordpress.org,w.org,wix.com,parastorage.com,whatwg.org,polyfill,typekit.net,schemas.openxmlformats.org,openweathermap.org,openoffice.org,reactjs.org,angularjs.org,java.com,purl.org,/image,/img,/css,/wp-json,/wp-content,/wp-includes,/theme,/audio,/captcha,/font,node_modules,.wav,.gltf,.pict,.svgz,.eps,.midi,.mid,.avif,.jfi,.jfif,.jfif-tbnl,.jif,.jpe,.pjpg";

export const FILEEXT_EXCLUSIONS = DEFAULT_FILEEXT();
function DEFAULT_FILEEXT() {
  return ".zip,.dmg,.rpm,.deb,.gz,.tar,.jpg,.jpeg,.png,.svg,.img,.gif,.mp4,.flv,.ogv,.webm,.webp,.mov,.mp3,.m4a,.m4p,.scss,.tif,.tiff,.ttf,.otf,.woff,.woff2,.bmp,.ico,.eot,.htc,.rtf,.swf,.image,.wav,.gltf,.pict,.svgz,.eps,.midi,.mid,.pdf,.jfi,.jfif,.jfif-tbnl,.jif,.jpe,.pjpg".split(",");
}

export const LINK_REGEX_FILES = "php|php3|php5|asp|aspx|ashx|cfm|cgi|pl|jsp|jspx|json|js|action|html|xhtml|htm|bak|do|txt|wsdl|wadl|xml|xls|xlsx|bin|conf|config|bz2|bzip2|gzip|tar\\.gz|tgz|log|src|zip|js\\.map";

const LINK_REGEX_NONSTANDARD_FILES = LINK_REGEX_FILES.split("|")
  .filter((e) => e.length > 4 || /\d/.test(e))
  .join("|");

const DEFAULT_STOP_WORDS = "a,about,above,after,again,against,all,am,an,and,any,are,aren,as,at,be,because,been,before,being,below,between,both,but,by,can,cannot,could,did,didn,do,does,doesn,doing,down,during,each,few,for,from,further,had,hadn,has,hasn,have,haven,having,he,her,here,hers,herself,him,himself,his,how,i,if,in,into,is,isn,it,its,itself,just,me,more,most,my,myself,no,nor,not,now,of,off,on,once,only,or,other,our,ours,ourselves,out,over,own,same,she,should,so,some,such,than,that,the,their,theirs,them,themselves,then,there,these,they,this,those,through,to,too,under,until,up,very,was,wasn,we,were,weren,what,when,where,which,while,who,whom,why,will,with,won,would,you,your,yours,yourself,yourselves";

/* ----------------------------- regexes ----------------------------- */

function buildRegex(src, flags) {
  try {
    return new RegExp(src, flags || "gi");
  } catch (e) {
    console.warn("[GAP] regex compile failed:", src.slice(0, 80), e.message);
    return null;
  }
}

const LINKS_SRC =
  String.raw`(?:(?<=^)|(?<=\"|'|\n|\r|\s))(((?:[a-zA-Z]{1,10}:\/\/|\/\/)([^\"'\/\s]{1,255}\.[a-zA-Z]{2,24}|localhost)[^\"'\n\s]{0,255})|((?:#?\/|\.\.\/|\.\/)[^\"'><,;| *()(%%$^\/\\\[\]][^\"'><,;|()\s]{1,255})|([a-zA-Z0-9_\-\/]{1,}\/[a-zA-Z0-9_\-\/\.]{1,255}\.(?:[a-zA-Z]{1,4}` +
  LINK_REGEX_NONSTANDARD_FILES +
  String.raw`)(?:[\?|\/][^\"|']{0,1000}|))|([a-zA-Z0-9_\-\.]{1,255}\.(?:` +
  LINK_REGEX_FILES +
  String.raw`)(?:\?[^\"|^']{0,255}|)))(?=$|\"|'|\n|\r|\s)|(?<=^Disallow:\s)[^\$\n]{0,500}|(?<=^Allow:\s)[^\$\n]{0,500}|(?<= Domain\=)[^\";']{0,500}|(?<=\<)https?:\/\/[^>\n]{0,1000}|(\"|\')([A-Za-z0-9_-]+\/)+[A-Za-z0-9_-]+(\.[A-Za-z0-9]{2,}|\/?(\?|\#)[A-Za-z0-9_\-&=\[\]]{0,500})(\"|\')|(?<=\<Key\>)[^\<]{1,500}\<\/Key\>`;

const RE = {
  LINKS: buildRegex(LINKS_SRC, "gi"),
  LINKS_EXTRA: buildRegex(String.raw`(?:[a-zA-Z0-9%\u0080-\uFFFF_-]+\.){0,5}[a-zA-Z0-9%\u0080-\uFFFF_-]+\.[a-zA-Z]{2,24}(?:\/[^\s\"'<>()\[\]{}]{0,500})?`, "gi"),
  LINKS_JSBUILT: buildRegex("\\.(?:get|post|put|delete|patch)\\(\\s*[\"'`]([^)]{0,1000}?)\\)", "gi"),
  LINKS_FETCH: buildRegex("fetch\\s*\\(\\s*[\"'`]((?:\\/|https?:\\/\\/)[^\"'`)]{0,1000})[\"'`]", "gi"),
  LINKSSLASH: buildRegex(String.raw`(\\&#x2f;|\&#0?2f|%2f|\u002f|\\u002f|\\/)`, "gi"),
  LINKSCOLON: buildRegex(String.raw`(\\&#x3a;|\&#0?3a|%3a|\u003a|\\u003a)`, "gi"),
  LINKSAND: buildRegex(String.raw`%26|\&amp;|\&#0?38;|\u0026|u0026|x26|\x26`, "gi"),
  LINKSEQUAL: buildRegex(String.raw`%3d|\&equals;|\&#0?61;|\u003d|u003d|x3d|\x3d`, "gi"),
  LINKSEARCH4: buildRegex(String.raw`<\/`, ""),
  LINKBRACKET: buildRegex(String.raw`\(.*\)`, ""),
  LINKBRACES: buildRegex(String.raw`\{.*\}`, ""),
  VALIDHOST: buildRegex(String.raw`^([A-Za-z0-9_-]{1,100}\.){1,100}[A-Za-z0-9_-]{2,}$`, ""),

  PARAM: buildRegex(String.raw`^[A-Za-z0-9_.~\-\[\]]+$`, ""),
  SUSPARAM: buildRegex(String.raw`^[A-Za-z0-9_-]{1,500}$`, ""),
  PARAMKEYS: buildRegex(String.raw`(?<=\?|&)[^\=\&\n].{0,1000}?(?=\=|&|\n)`, "gi"),
  PARAMSPOSSIBLE: buildRegex(String.raw`(?<=[^\&|%26|\&amp;|\&?#0?38;|\u0026|\\u0026|\\\\u0026|\\x26|\x26])(\?|%3f|\&?#0?63;|\u003f|\\u003f|\\\\u003f|\&|%26|\&amp;|\&?#0?38;|\u0026|\\u0026|\\\\u0026|\\x26|%3d|\&?#0?61;|\u003d|\\u003d|\\\\u003d|\\x3d|\&quot;|\&?#0?34;|\u0022|\\u0022|\\\\u0022|\&#0?39;)[a-z0-9_\-]{3,}(\=|%3d|\&?#0?61;|\u003d|\\u003d|\\\\u003d|\x3d|\\x3d)(?=[^\=|%3d|\&?#0?61;|\u003d|\\u003d|\\\\u003d|\x3d|\\x3d])`, "gi"),
  PARAMSSUB: buildRegex(String.raw`\?|%3f|\&?#0?63;|\u003f|\\u003f|\\\\u003f|\=|%3d|\&?#0?61;|\u003d|\\u003d|\\\\u003d|\\x3d|\x3d|%26|\&amp;|\&?#0?38;|\u0026|\\u0026|\\\\u0026|\\x26|\x26|\&quot;|\&?#0?34;|\u0022|\\u0022|\\\\u0022|\\x22|\x22|\&#0?39;`, "gi"),
  JSONKEYS: buildRegex(String.raw`"([a-zA-Z0-9$_\.-]{0,1000}?)"\s*:`, "gi"),
  XMLATTR: buildRegex(String.raw`<([a-zA-Z0-9$_\.-]{0,1000}?)>`, "gi"),
  HTMLINP: buildRegex(String.raw`<(input|textarea|select|button)(.*?)>`, "gi"),
  HTMLINP_NAME: buildRegex(String.raw`(?<=\sname)[\s]{0,10}\=[\s]{0,10}(\"|')(.{0,1000}?)(?=(\"|'))`, "gi"),
  HTMLINP_ID: buildRegex(String.raw`(?<=\sid)[\s]{0,10}\=[\s]{0,10}(\"|')(.{0,1000}?)(?=(\"|'))`, "gi"),
  JSLET: buildRegex(String.raw`(?<=let[\s])[\s]{0,10}[a-zA-Z$_][a-zA-Z0-9$_]{0,1000}[\s]{0,10}(?=(\=|;|\n|\r))`, "gi"),
  JSVAR: buildRegex(String.raw`(?<=var\s)[\s]{0,10}[a-zA-Z$_][a-zA-Z0-9$_]{0,1000}?(?=(\s|=|,|;|\n))`, "gi"),
  JSCONSTS: buildRegex(String.raw`(?<=const\s)[\s]{0,10}[a-zA-Z$_][a-zA-Z0-9$_]{0,1000}?(?=(\s|=|,|;|\n))`, "gi"),
  JSNESTED: buildRegex(String.raw`(^|\s?)(JSON\.stringify\(|dataLayer\.push\(|(var|let|const)\s{1,10}[\$A-Za-z0-9-_\[\]]{1,1000}\s{0,10}=)\s{0,10}\{`, "gi"),
  JSNESTEDPARAM: buildRegex(String.raw`('|\"|\[])?[A-Za-z0-9-_\.]{1,1000}('|\"|\])?\s{0,10}\:`, "gi"),
  SOURCEMAP: buildRegex(String.raw`(?<=SourceMap\:\s).{0,1000}?(?=\n)`, "gi"),

  WORDS: buildRegex(String.raw`(?<![\/])\b\w{3,}\b(?![\/])`, "g"),
  WORDSUB: buildRegex(String.raw`\"|%22|<|%3c|>|%3e|\(|%28|\)|%29|\s|%20`, "gi"),

  PORT80: buildRegex(String.raw`:80[^0-9]`, ""),
  PORT443: buildRegex(String.raw`:443[^0-9]`, ""),
  PORTSUB80: buildRegex(String.raw`:80`, "g"),
  PORTSUB443: buildRegex(String.raw`:443`, "g"),
};

/* ----------------------------- helpers ----------------------------- */

const CHUNK_SIZE = 40000;
const CHUNK_OVERLAP = 5000;
const LARGE_THRESHOLD = 50000;

function findAll(re, str) {
  if (!re) return [];
  re.lastIndex = 0;
  const out = [];
  let m;
  while ((m = re.exec(str)) !== null) {
    out.push(m[0]);
    if (m.index === re.lastIndex) re.lastIndex++; // avoid zero-length loop
  }
  return out;
}

// port of safe_regex_findall_chunked
function findAllChunked(re, str) {
  if (!re) return [];
  if (str.length <= LARGE_THRESHOLD) return findAll(re, str);
  const out = [];
  let start = 0;
  while (start < str.length) {
    const end = Math.min(start + CHUNK_SIZE, str.length);
    const chunk = str.slice(start, end);
    const ms = findAll(re, chunk);
    for (const k of ms) out.push(k);
    start += CHUNK_SIZE - CHUNK_OVERLAP;
  }
  return Array.from(new Set(out));
}

function stripUnbalanced(link) {
  const pairs = { "(": ")", "[": "]", "{": "}" };
  const opening = "([{";
  const closing = ")]}";
  const stack = [];
  let lastValid = link.length;
  for (let i = 0; i < link.length; i++) {
    const c = link[i];
    if (opening.indexOf(c) >= 0) stack.push([c, i]);
    else if (closing.indexOf(c) >= 0) {
      if (stack.length && pairs[stack[stack.length - 1][0]] === c) stack.pop();
      else { lastValid = i; break; }
    }
  }
  if (stack.length) lastValid = Math.min(lastValid, stack[0][1]);
  return link.slice(0, lastValid);
}

function cleanBody(body) {
  try {
    return body.replace(/eyJ[a-zA-Z0-9+/]+(?:=|\b|\n)/g, (s) =>
      s.length > 10000 ? "BASE64_REPLACED_BY_GAP" : s
    );
  } catch (e) {
    return body;
  }
}

function removeStdPort(url) {
  try {
    if (url.indexOf(":443") > 0 && url.startsWith("https:") && RE.PORT443 && RE.PORT443.test(url)) {
      return url.replace(RE.PORTSUB443, "");
    }
    if (url.indexOf(":80") > 0 && url.startsWith("http:") && RE.PORT80 && RE.PORT80.test(url)) {
      return url.replace(RE.PORTSUB80, "");
    }
  } catch (e) {}
  return url;
}

// includeLink — port of GAP includeLink
function includeLink(link, opts) {
  let include = true;
  try {
    let host = "";
    try { host = new URL(link).hostname || ""; } catch (e) {}
    if (host && RE.VALIDHOST && !RE.VALIDHOST.test(host)) include = false;
  } catch (e) {}

  if (include) {
    if (
      (link.split("\n").length - 1) > 1 ||
      (link.startsWith("#") && !link.startsWith("#/")) ||
      link.startsWith("$") ||
      link.startsWith("\\") ||
      link.startsWith("/=") ||
      link.startsWith("-") ||
      link.startsWith("...")
    ) include = false;
  }
  if (include) include = !/\s/.test(link);
  if (include) include = !/\n/.test(link);
  if (include) include = /[0-9a-zA-Z]/.test(link);
  if (include) include = !/\\(s|S)/.test(link);
  if (include)
    include = !/^(application\/|image\/|model\/|video\/|audio\/|text\/)/i.test(link);
  if (include) {
    for (const ch of link) {
      if (ch.charCodeAt(0) < 32) { include = false; break; }
    }
  }

  if (include && opts.useExclusions) {
    const list = (opts.exclusions || "").split(",");
    const linkNoQs = link.split("?")[0].toLowerCase();
    for (const exc of list) {
      const e = (exc || "").toLowerCase();
      if (e && linkNoQs.indexOf(e) >= 0) { include = false; break; }
    }
  }
  return include;
}

function getSusVulnTypes(param) {
  const types = [];
  const min = [];
  if (SUS_OPENREDIRECT.has(param)) { types.push("Open Redirect"); min.push("OR"); }
  if (SUS_DEBUG.has(param)) { types.push("Active Debugging"); min.push("DEBUG"); }
  if (SUS_XSS.has(param)) { types.push("Cross-site Scripting (XSS)"); min.push("XSS"); }
  if (SUS_IDOR.has(param)) { types.push("Insecure Direct Object Reference (IDOR)"); min.push("IDOR"); }
  if (SUS_FILEINC.has(param)) { types.push("File Inclusion"); min.push("LFI/RFI"); }
  if (SUS_CMDI.has(param)) { types.push("OS Command Injection"); min.push("CMDi"); }
  if (SUS_SQLI.has(param)) { types.push("SQL Injection (SQLi)"); min.push("SQLi"); }
  if (SUS_SSRF.has(param)) { types.push("Server-side Request Forgery (SSRF)"); min.push("SSRF"); }
  if (SUS_SSTI.has(param)) { types.push("Server-side Template Injection (SSTI)"); min.push("SSTI"); }
  if (SUS_MASSASSIGNMENT.has(param)) { types.push("Mass Assignment"); min.push("MASS-ASSIGN"); }
  return { types: types.join(", "), min: min.join(", ") };
}

function sanitizeWord(word) {
  // encode non-ascii like urllib.quote
  let out = "";
  for (const ch of word) {
    const code = ch.charCodeAt(0);
    if (code > 127) {
      try {
        const enc = encodeURIComponent(ch);
        out += enc;
      } catch (e) { /* skip */ }
    } else out += ch;
  }
  if (RE.WORDSUB) out = out.replace(RE.WORDSUB, "");
  return out;
}

function processPlural(original) {
  let newWord = "";
  const word = (original || "").trim().toLowerCase();
  if (!word) return "";
  const last = word.slice(-1);
  const last2 = word.slice(-2);
  const last3 = word.slice(-3);
  const last4 = word.slice(-4);
  const isUpper = original === original.toUpperCase() && /[A-Z]/.test(original);

  const vow = ["a", "e", "i", "o", "u"];
  try {
    if (word.length > 30 || (/\d/.test(word) && word.length > 10) || last3 === "ous") {
      newWord = "";
    } else if (["xes", "oes"].includes(last3) || last4 === "sses") {
      newWord = original.slice(0, -2);
    } else if (last3 === "ies") {
      if (word.length === 4) newWord = original[1] + (isUpper ? "IE" : "ie");
      else newWord = original.slice(0, -3) + (isUpper ? "Y" : "y");
    } else if (last === "s" && word.slice(-2, -1) !== "s") {
      newWord = original.slice(0, -1);
    } else if (["x", "o"].includes(last) || last2 === "ss") {
      newWord = original + (isUpper ? "ES" : "es");
    } else if (last === "y" && !vow.includes(word.slice(-2, -1))) {
      newWord = original.slice(0, -1) + (isUpper ? "IES" : "ies");
    } else if (last === "o" && !vow.includes(word.slice(-2, -1))) {
      newWord = original.slice(0, -1) + (isUpper ? "ES" : "es");
    } else {
      newWord = original + (isUpper ? "S" : "s");
    }
  } catch (e) {}
  return newWord;
}

/* ----------------------------- link finding ----------------------------- */

function cleanRawLink(link) {
  link = link.trim().replace(/^["'\n\r( ]+/, "").replace(/\\n.*$/, "").replace(/\\r.*$/, "").replace(/\\\./g, ".");
  if (!link) return "";
  try {
    const first = link[0];
    const last = link[link.length - 1];
    const first2 = link.slice(0, 2);
    const last2 = link.slice(-2);
    const isQuote = (c, c2) => c === '"' || c === "'" || c === "\n" || c === "\r" || c2 === "\\n" || c2 === "\\r";
    if (isQuote(first, first2) && isQuote(last, last2)) {
      const start = first2 === "\\n" || first2 === "\\r" ? 2 : 1;
      const end = last2 === "\\n" || last2 === "\\r" ? 2 : 1;
      link = link.slice(start, link.length - end);
    }
    link = link.replace(/[\\]+$/, "");
    link = link.replace(/[>;]+$/, "");
    link = link.replace(/[;]+$/, "").replace(/[,]+$/, "").replace(/[=]+$/, "");
    link = link.replace(/[:]+$/, "").replace(/[.]+$/, "").replace(/[|]+$/, "");
    link = link.split("`")[0];
    link = stripUnbalanced(link);
    if (RE.LINKSEARCH4 && RE.LINKSEARCH4.test(link)) link = link.split("</", 1)[0];
  } catch (e) {}
  return link;
}

function sameOrigin(linkUrl, origin) {
  try {
    const a = new URL(linkUrl);
    const o = new URL(origin);
    return a.protocol === o.protocol && a.host === o.host;
  } catch (e) {
    return true;
  }
}

// findLinks — port of getResponseLinks + addLink
export function findLinks(body, header, originUrl, opts) {
  const links = new Set();
  const linksWithOrigin = new Set();
  if (!body) return { list: [], withOrigin: [] };

  let search = (header || "").replace(/ /g, "\n") + "\n" + body;
  search = search
    .replace(/&#34;/g, '"').replace(/%22/g, '"').replace(/\x22/g, '"').replace(/\u0022/g, '"');

  let linkKeys = findAllChunked(RE.LINKS, search);

  // extra links (tldextract-like: validate via COMMON_TLDS)
  try {
    const extra = findAllChunked(RE.LINKS_EXTRA, search);
    for (const key of extra) {
      const m = key.match(/^([a-zA-Z0-9%\u0080-\uFFFF_-]+)\.([a-zA-Z]{2,24})/);
      if (!m) continue;
      const domain = m[1];
      const suffix = m[2].toLowerCase();
      const badDomain = ["this","self","target","value","values","prop","properties","proparray","useragent","rect","paddiing","style","rule","bound","child","global","element","div","prototype","event","feature","path"];
      const badSuffix = ["call","skin","menu","style","rest","next","top"];
      if (badSuffix.includes(suffix)) continue;
      if (domain.length <= 2) continue;
      if (domain.startsWith("_")) continue;
      if (badDomain.includes(domain.toLowerCase())) continue;
      if (suffix === "map" && domain.toLowerCase() !== "js") continue;
      if (!COMMON_TLDS.has(suffix)) continue;
      linkKeys.push("//" + key);
    }
  } catch (e) {}

  // JS built endpoints (.get/.post/...)
  try {
    if (RE.LINKS_JSBUILT) {
      let m;
      RE.LINKS_JSBUILT.lastIndex = 0;
      while ((m = RE.LINKS_JSBUILT.exec(search)) !== null) {
        let key = (m[1] || "").trim();
        if (!key) continue;
        if (/^['"`]/.test(key)) continue;
        if (key.includes("<") || key.includes(">")) continue;
        if (!key.includes("/")) continue;
        if (key.startsWith("$")) continue;
        if ((key.match(/:\/\//g) || []).length === 1) {
          const idx = key.indexOf("://");
          if (key.slice(0, idx).includes(".")) continue;
        }
        if (!key.startsWith("/") && !key.startsWith("http")) key = "/" + key;
        key = key.split('"')[0].split("'")[0].split("`")[0];
        linkKeys.push(key);
      }
    }
  } catch (e) {}

  // fetch() links
  try {
    if (RE.LINKS_FETCH) {
      let m;
      RE.LINKS_FETCH.lastIndex = 0;
      while ((m = RE.LINKS_FETCH.exec(search)) !== null) {
        let key = (m[1] || "").trim();
        if (!key) continue;
        if (!key.startsWith("/") && !key.startsWith("http")) key = "/" + key;
        linkKeys.push(key);
      }
    }
  } catch (e) {}

  const processed = new Set();
  for (let key of Array.from(new Set(linkKeys))) {
    if (!key || key.trim().length <= 1) continue;
    let link = cleanRawLink(key);
    if (!link || processed.has(link)) continue;
    processed.add(link);

    // source map directive
    if (link.indexOf("//# sourceMappingURL") >= 0) {
      const eq = link.lastIndexOf("=");
      let nl = link.indexOf("\n");
      if (nl <= 0) nl = link.length;
      const mapFile = link.slice(eq + 1, nl).replace(/\n/g, "");
      const lastSlash = originUrl.lastIndexOf("/");
      link = originUrl.slice(0, lastSlash + 1) + mapFile;
    }

    if (!link) continue;
    if (link[0] === "." && link[1] !== "." && link[1] !== "/") link = link.slice(1);

    if (!includeLink(link, opts)) continue;

    // prefix relative links
    const relative = link.startsWith("./") || link.startsWith("../");
    let hasHost = false;
    try { if (new URL(link).host) hasHost = true; } catch (e) {}

    const produced = new Set();
    if (!hasHost) {
      if (opts.prefixOrigin && relative) {
        produced.add(joinOrigin(originUrl, link, true));
        if (opts.unPrefixed) produced.add(link);
      } else if (opts.prefixOrigin) {
        if (link[0] !== "/") link = "/" + link;
        produced.add(joinOrigin(originUrl, link, false));
        if (opts.unPrefixed) produced.add(link);
      } else {
        produced.add(link);
      }
    } else {
      produced.add(link);
    }

    for (let u of produced) {
      u = removeStdPort(u);
      if (opts.inScopeOnly && hasHost && !sameOrigin(u, originUrl)) continue;
      links.add(u);
      linksWithOrigin.add(u + "  [" + originUrl + "]");
    }
  }

  // X-SourceMap / SourceMap header
  if (header && RE.SOURCEMAP) {
    const sm = findAll(RE.SOURCEMAP, header);
    for (const mf of sm) { links.add(mf); linksWithOrigin.add(mf + "  [" + originUrl + "]"); }
  }

  return { list: Array.from(links), withOrigin: Array.from(linksWithOrigin) };
}

function joinOrigin(originUrl, link, relative) {
  try {
    const o = new URL(originUrl);
    const base = o.protocol + "//" + o.host;
    if (relative) return new URL(link, base + "/").href;
    return new URL(link, base).href;
  } catch (e) {
    return (relative ? originUrl + "/" : originUrl) + link;
  }
}

/* ----------------------------- parameter finding ----------------------------- */

function addParam(raw, paramSet, susSet, opts) {
  let param = raw;
  try { param = decodeURIComponent(param); } catch (e) {}
  // part after '?'
  if (param.indexOf("?") >= 0) param = param.split("?")[1] || param.split("?")[0];
  param = param.replace(/%5b/gi, "").replace(/%5d/gi, "");
  param = param.replace(/\\/g, "").replace(/\//g, "").replace("quot;", "").replace("apos;", "").replace("amp;", "");
  if (!param) return;
  const matched = RE.PARAM && RE.PARAM.test(param);
  RE.PARAM && (RE.PARAM.lastIndex = 0);
  if (!matched) return;

  paramSet.add(param);

  if (opts.susParams && param.length < 20 && RE.SUSPARAM && RE.SUSPARAM.test(param)) {
    RE.SUSPARAM.lastIndex = 0;
    const s = getSusVulnTypes(param);
    if (s.min) susSet.add(param + "  [" + s.min + "]");
  }
}

function findBalancedBraces(text, start) {
  let i = text.indexOf("{", start);
  if (i === -1) return [null, start];
  const stack = [];
  let end = text.length;
  while (i < text.length) {
    if (text[i] === "{") stack.push("{");
    else if (text[i] === "}") { stack.pop(); if (!stack.length) { end = i + 1; break; } }
    i++;
  }
  return [text.slice(start, end), end];
}

// findParams — port of getResponseParams (+ getPathWords params)
export function findParams(body, mimeType, originUrl, opts) {
  const paramSet = new Set();
  const susSet = new Set();
  if (!body) return { list: [], sus: [] };

  // response params (?/&PARAM=)
  try {
    if (RE.PARAMSPOSSIBLE) {
      let m;
      RE.PARAMSPOSSIBLE.lastIndex = 0;
      const seen = new Set();
      while ((m = RE.PARAMSPOSSIBLE.exec(body)) !== null) {
        let p = (m[0] || "").replace(/%5c/gi, "");
        if (seen.has(p)) continue;
        seen.add(p);
        if (RE.PARAMSSUB) p = p.replace(RE.PARAMSSUB, "").trim();
        p = p.replace(/\\/g, "").replace(/&/g, "");
        addParam(p, paramSet, susSet, opts);
      }
    }
  } catch (e) {}

  // JS variables
  if (opts.paramJsVars) {
    for (const re of [RE.JSLET, RE.JSVAR, RE.JSCONSTS]) {
      if (!re) continue;
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(body)) !== null) {
        addParam((m[0] || "").trim(), paramSet, susSet, opts);
      }
    }
    // nested JSON objects
    try {
      let start = 0;
      while (start < body.length) {
        RE.JSNESTED.lastIndex = start;
        const match = RE.JSNESTED.exec(body);
        if (!match) break;
        const [full] = findBalancedBraces(body, match.index);
        if (full && RE.JSNESTEDPARAM) {
          RE.JSNESTEDPARAM.lastIndex = 0;
          let pm;
          while ((pm = RE.JSNESTEDPARAM.exec(full)) !== null) {
            let parameter = (pm[0] || "").trim().replace(/:$/, "").replace(/['"]/g, "").replace(/[\[\]]/g, "");
            addParam(parameter, paramSet, susSet, opts);
          }
        }
        const end = full ? match.index + full.length : match.index + 1;
        if (end <= start) break;
        start = end;
      }
    } catch (e) {}
  }

  const mime = (mimeType || "").toUpperCase();
  // JSON keys
  if (mime === "JSON" && opts.paramJson && RE.JSONKEYS) {
    RE.JSONKEYS.lastIndex = 0;
    let m;
    while ((m = RE.JSONKEYS.exec(body)) !== null) {
      addParam((m[1] || "").trim(), paramSet, susSet, opts);
    }
  }
  // XML attributes
  else if (mime === "XML" && opts.paramXml && RE.XMLATTR) {
    RE.XMLATTR.lastIndex = 0;
    let m;
    while ((m = RE.XMLATTR.exec(body)) !== null) {
      addParam((m[1] || "").trim(), paramSet, susSet, opts);
    }
  }
  // HTML input fields
  else if ((mime === "HTML" || mime === "JAVASCRIPT") && opts.paramInput && RE.HTMLINP) {
    RE.HTMLINP.lastIndex = 0;
    let m;
    while ((m = RE.HTMLINP.exec(body)) !== null) {
      const tag = m[1] || "";
      const attrs = m[2] || "";
      if (RE.HTMLINP_NAME) {
        RE.HTMLINP_NAME.lastIndex = 0;
        let nm;
        while ((nm = RE.HTMLINP_NAME.exec(attrs)) !== null) {
          addParam(nm[2] || "", paramSet, susSet, opts);
        }
      }
      if (RE.HTMLINP_ID) {
        RE.HTMLINP_ID.lastIndex = 0;
        let idm;
        while ((idm = RE.HTMLINP_ID.exec(attrs)) !== null) {
          addParam(idm[2] || "", paramSet, susSet, opts);
        }
      }
    }
  }

  // params from links found
  if (opts.paramFromLinks && opts.linksList) {
    for (const link of opts.linksList) {
      if (link.indexOf("?") <= 0) continue;
      let l = link.replace(/%5c/g, "").replace(/\\/g, "");
      if (RE.LINKSAND) l = l.replace(RE.LINKSAND, "&");
      if (RE.LINKSEQUAL) l = l.replace(RE.LINKSEQUAL, "=");
      if (!RE.PARAMKEYS) continue;
      RE.PARAMKEYS.lastIndex = 0;
      let pm;
      while ((pm = RE.PARAMKEYS.exec(l)) !== null) {
        addParam((pm[0] || "").trim(), paramSet, susSet, opts);
      }
    }
  }

  // path words as params
  if (opts.paramPathWords) {
    let path = "";
    try { path = new URL(originUrl).pathname; } catch (e) { path = originUrl; }
    const parts = new Set();
    path.split(/[:/?=\-&#]+/).forEach((p) => p.split(",").forEach((x) => parts.add(x)));
    for (const word of parts) {
      if (word && !word.includes(".") && !/^\d+$/.test(word) && !(word.length === 1 && !/[a-zA-Z]/.test(word))) {
        addParam(word.trim(), paramSet, susSet, opts);
      }
    }
  }

  return { list: Array.from(paramSet), sus: Array.from(susSet) };
}

/* ----------------------------- word finding ----------------------------- */

const META_KEYS = new Set([
  "og:title","og:description","title","og:site_name","fb:admins","description","keywords",
  "twitter:title","twitter:description","application-name","author","subject","copyright",
  "abstract","topic","summary","owner","directory","category","og:type","csrf-param",
  "apple-mobile-web-app-title","twitter:label1","twitter:data1","twitter:label2","twitter:data2",
]);

// findWords — port of getResponseWords (uses DOM for HTML text extraction)
export function findWords(body, mimeType, originUrl, opts) {
  const wordSet = new Set();
  if (!body) return [];
  const stop = new Set((opts.stopWords || DEFAULT_STOP_WORDS).split(",").map((s) => s.trim().toLowerCase()));
  let minLen = parseInt(opts.wordMin, 10);
  if (isNaN(minLen) || minLen < 1) minLen = 3;
  let maxLen = parseInt(opts.wordMax, 10);
  if (isNaN(maxLen) || maxLen === 0) maxLen = null;

  // gather text — prefer DOM for HTML, raw regex otherwise
  let allText = "";
  const mime = (mimeType || "").toUpperCase();
  const isHtml = mime === "HTML" || mime === "" || mime === "JAVASCRIPT" || /<html|<!doctype|<body|<script/i.test(body);

  if (isHtml) {
    try {
      const doc = new DOMParser().parseFromString(body, "text/html");
      // meta contents
      doc.querySelectorAll("meta[content]").forEach((tag) => {
        const prop = (tag.getAttribute("property") || "").toLowerCase();
        const name = (tag.getAttribute("name") || "").toLowerCase();
        if (META_KEYS.has(prop) || META_KEYS.has(name)) allText += tag.getAttribute("content") + " ";
      });
      // link titles
      doc.querySelectorAll("link[title]").forEach((tag) => {
        const rel = (tag.getAttribute("rel") || "").toLowerCase();
        if (["alternate","index","start","prev","next","search"].includes(rel)) allText += tag.getAttribute("title") + " ";
      });
      if (opts.wordImgAlt) doc.querySelectorAll("img[alt]").forEach((img) => { allText += img.getAttribute("alt") + " "; });
      if (opts.wordComments) {
        const walker = doc.createTreeWalker(doc, NodeFilter.SHOW_COMMENT);
        let node;
        while ((node = walker.nextNode())) allText += node.textContent + " ";
      }
      doc.querySelectorAll("style, script, link").forEach((n) => n.remove());
      allText += " " + (doc.body ? doc.body.textContent : doc.textContent);
    } catch (e) {
      allText = stripTags(body);
    }
  } else {
    // JSON / XML / plain — strip tags loosely
    allText = stripTags(body);
  }

  if (opts.wordPaths) {
    let path = "";
    try { path = new URL(originUrl).pathname; } catch (e) { path = originUrl; }
    path.split(/[:/?=\-&#]+/).forEach((p) => p.split(",").forEach((x) => {
      const w = x.trim();
      if (w && !w.includes(".") && !/^\d+$/.test(w)) addWord(w, originUrl, wordSet, opts, stop, minLen, maxLen);
    }));
  }

  if (opts.wordParams && opts.paramsList) {
    for (const p of opts.paramsList) addWord(p, originUrl, wordSet, opts, stop, minLen, maxLen);
  }

  let m;
  RE.WORDS.lastIndex = 0;
  while ((m = RE.WORDS.exec(allText)) !== null) {
    const w = m[0];
    // robots.txt special-case
    if (/robots\.txt/i.test(originUrl) && ["allow","disallow","sitemap","user-agent"].includes(w.toLowerCase())) continue;
    addWord(w, originUrl, wordSet, opts, stop, minLen, maxLen);
  }

  return Array.from(wordSet);
}

function stripTags(body) {
  return body.replace(/<style[\s\S]*?<\/style>/gi, " ").replace(/<script[\s\S]*?<\/script>/gi, " ").replace(/<[^>]+>/g, " ");
}

function addWord(word, origin, wordSet, opts, stop, minLen, maxLen) {
  word = sanitizeWord(word);
  if (!word) return;
  if (!opts.wordDigits && /\d/.test(word)) return;
  // word.upper().isupper() equivalent — must be all letters
  if (!/^[A-Za-z]+$/.test(word)) {
    // allow words with allowed chars; GAP requires alpha for the isupper branch
    if (!/^[A-Za-z][A-Za-z0-9._-]*$/.test(word)) return;
  }
  word = word.replace(/'/g, "");
  if (!word) return;
  if (word.toLowerCase() === word && !/^[a-z]+$/.test(word)) {
    // keep mixed-case alnum words only if they pass the length checks below
  }
  const len = word.length;
  if (len < minLen) return;
  if (maxLen !== null && len > maxLen) return;
  if (stop.has(word.toLowerCase())) return;

  wordSet.add(word);
  if (opts.wordLower && word !== word.toLowerCase()) wordSet.add(word.toLowerCase());

  if (opts.wordPlurals) {
    const nw = processPlural(word);
    if (nw && nw.length >= minLen && !stop.has(nw.toLowerCase())) {
      wordSet.add(nw);
      if (opts.wordLower && nw !== nw.toLowerCase()) wordSet.add(nw.toLowerCase());
    }
  }
}

/* ----------------------------- orchestration ----------------------------- */

// Run GAP against a single response. opts fields:
//   html, header, url, contentType, mimeType,
//   modes: { links, params, words },
//   links options + param options + word options (see defaults below)
export function runGAP(opts) {
  const o = Object.assign({}, opts);
  o.modes = Object.assign({ links: true, params: true, words: false }, opts.modes);
  const html = o.html || "";
  const header = o.header || "";
  const url = o.url || "";
  const ct = (o.contentType || "").toLowerCase();

  // content-type gate: GAP only processes "interesting" content types.
  // In a browser we keep most text-like types; skip obvious binaries/images.
  const ctExclude = /^(image\/|video\/|audio\/|font\/|application\/(pdf|zip|octet-stream|x-tar|gzip|x-7z-compressed))/i;
  if (ct && ctExclude.test(ct)) {
    return { skipped: true, links: [], params: [], words: [], sus: [] };
  }

  // prepare body for link finding
  let linkBody = cleanBody(html || "");
  linkBody = (RE.LINKSSLASH ? linkBody.replace(RE.LINKSSLASH, "/") : linkBody);
  linkBody = (RE.LINKSCOLON ? linkBody.replace(RE.LINKSCOLON, ":") : linkBody);
  linkBody = linkBody.replace(/&quot;/g, '"').replace(/&nbsp;/g, " ");

  const out = { links: [], params: [], words: [], sus: [] };

  let linkResult = null;
  if (o.modes.links) {
    linkResult = findLinks(linkBody, header, url, {
      useExclusions: o.useExclusions !== false,
      exclusions: o.exclusions != null ? o.exclusions : DEFAULT_EXCLUSIONS,
      relativeLinks: o.relativeLinks !== false,
      inScopeOnly: !!o.inScopeOnly,
      prefixOrigin: o.prefixOrigin !== false,
      unPrefixed: !!o.unPrefixed,
    });
    out.links = linkResult.list;
  }

  if (o.modes.params) {
    const pr = findParams(html || "", o.mimeType, url, {
      paramFromLinks: !!o.paramFromLinks,
      paramJson: o.paramJson !== false,
      paramXml: o.paramXml !== false,
      paramInput: o.paramInput !== false,
      paramJsVars: o.paramJsVars !== false,
      paramPathWords: !!o.paramPathWords,
      susParams: o.susParams !== false,
      linksList: linkResult ? linkResult.list : null,
    });
    out.params = pr.list;
    out.sus = pr.sus;
  }

  if (o.modes.words) {
    out.words = findWords(html || "", o.mimeType, url, {
      wordMin: o.wordMin || 3,
      wordMax: o.wordMax || 0,
      wordPlurals: !!o.wordPlurals,
      wordLower: !!o.wordLower,
      wordDigits: !!o.wordDigits,
      wordPaths: !!o.wordPaths,
      wordComments: !!o.wordComments,
      wordImgAlt: !!o.wordImgAlt,
      wordParams: !!o.wordParams,
      stopWords: o.stopWords != null ? o.stopWords : DEFAULT_STOP_WORDS,
      paramsList: out.params,
    });
  }

  return out;
}

export { DEFAULT_STOP_WORDS };
