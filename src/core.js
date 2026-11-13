const https = require("https");
const http2 = require("http2");
const tls = require("tls");
const fs = require("fs");
const path = require("path");
const zlib = require("zlib");
const WebSocket = require("ws");
const { HttpsProxyAgent } = require("https-proxy-agent");
const { hashTokenForProfile, canIdentify, recordIdentify, isOnCooldown, markFailed, IDENTIFY_LIMIT } = require("./security");

const PROXIES_FILE = path.join(__dirname, "..", "proxies.txt");
const PROFILES_FILE = path.join(__dirname, "..", "profiles.json");

const BROWSERS = [
  { ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36", browser: "Chrome", ver: "125.0.0.0", secCh: '"Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="24"', platform: "Windows" },
  { ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36", browser: "Chrome", ver: "126.0.0.0", secCh: '"Google Chrome";v="126", "Chromium";v="126", "Not.A/Brand";v="24"', platform: "Windows" },
  { ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36", browser: "Chrome", ver: "124.0.0.0", secCh: '"Google Chrome";v="124", "Chromium";v="124", "Not.A/Brand";v="24"', platform: "Windows" },
  { ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0", browser: "Firefox", ver: "126.0", secCh: null, platform: "Windows" },
  { ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36", browser: "Chrome", ver: "125.0.0.0", secCh: '"Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="24"', platform: "macOS" },
  { ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15", browser: "Safari", ver: "17.5", secCh: null, platform: "macOS" },
  { ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0", browser: "Edge", ver: "125.0.0.0", secCh: '"Microsoft Edge";v="125", "Chromium";v="125", "Not.A/Brand";v="24"', platform: "Windows" },
  { ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0", browser: "Firefox", ver: "127.0", secCh: null, platform: "Windows" },
];

const BUILD_NUMS = [567600, 567510, 567420, 567330, 567240, 567150, 567060, 566970, 566880, 566790, 566700, 566610, 566520, 566430, 566340];
const LOCALES = ["en-US", "en-GB", "en-AU", "en-CA", "hi-IN", "es-ES", "fr-FR", "de-DE", "ja-JP", "pt-BR"];
const TIMEZONES = ["Asia/Kolkata", "America/New_York", "Europe/London", "Asia/Tokyo", "Australia/Sydney", "America/Chicago", "Europe/Berlin", "Asia/Dubai"];

const REFERERS = {
  "Check": "https://discord.com/channels/@me",
  "List Guilds": "https://discord.com/channels/@me",
  "Join Guild": "https://discord.com/channels/@me",
  "Leave Guild": "https://discord.com/channels/@me",
  "Invite": "https://discord.com/channels/@me",
  "Nickname": "https://discord.com/channels/@me",
  "Name": "https://discord.com/settings/profile",
  "Bio": "https://discord.com/settings/profile",
  "Friend": "https://discord.com/channels/@me",
  "Settings": "https://discord.com/settings",
  "React": "https://discord.com/channels/@me",
  "Messages": "https://discord.com/channels/@me",
  "Interact": "https://discord.com/channels/@me",
  "Default": "https://discord.com/channels/@me",
};

function maskToken(token) {
  if (!token || token.length < 20) return "???";
  return token.slice(0, 6) + "..." + token.slice(-4);
}

const _gatewayConnections = {};

function closeGateway(token) {
  const conn = _gatewayConnections[token];
  if (conn) {
    clearInterval(conn.hbTimer);
    clearTimeout(conn.reconnectTimer);
    try { conn.ws.close(1000); } catch {}
    delete _gatewayConnections[token];
  }
}

function closeAllGateways() {
  for (const token of Object.keys(_gatewayConnections)) {
    closeGateway(token);
  }
}

let _proxies = null;
let _profileStore = null;

function loadProxies() {
  if (_proxies !== null) return _proxies;
  try {
    if (fs.existsSync(PROXIES_FILE)) {
      const content = fs.readFileSync(PROXIES_FILE, "utf-8");
      _proxies = content.split(/\r?\n/).map(l => l.trim()).filter(l => l && !l.startsWith("#"));
    }
  } catch {}
  if (!_proxies) _proxies = [];
  return _proxies;
}

const BROWSER_CIPHERS = [
  "TLS_AES_128_GCM_SHA256",
  "TLS_AES_256_GCM_SHA384",
  "TLS_CHACHA20_POLY1305_SHA256",
  "ECDHE-ECDSA-AES128-GCM-SHA256",
  "ECDHE-RSA-AES128-GCM-SHA256",
  "ECDHE-ECDSA-AES256-GCM-SHA384",
  "ECDHE-RSA-AES256-GCM-SHA384",
  "ECDHE-ECDSA-CHACHA20-POLY1305",
  "ECDHE-RSA-CHACHA20-POLY1305",
  "ECDHE-RSA-AES128-SHA",
  "ECDHE-RSA-AES256-SHA",
].join(":");

const BROWSER_TLS_OPTIONS = {
  ciphers: BROWSER_CIPHERS,
  honorCipherOrder: true,
  secureOptions: tls.SSL_OP_NO_SSLv2 | tls.SSL_OP_NO_SSLv3 | tls.SSL_OP_NO_TLSv1 | tls.SSL_OP_NO_TLSv1_1,
  ALPNProtocols: ["h2", "http/1.1"],
  sessionTimeout: 300,
  minVersion: "TLSv1.2",
};

const _proxyBlacklist = {};

function getRandomProxy() {
  const proxies = loadProxies();
  if (proxies.length === 0) return { agent: null, url: null };
  const now = Date.now();
  const active = proxies.filter((p) => {
    const entry = _proxyBlacklist[p];
    return !entry || entry.until < now;
  });
  if (active.length === 0) {
    const oldest = Object.entries(_proxyBlacklist).sort((a, b) => a[1].until - b[1].until)[0];
    if (oldest) { delete _proxyBlacklist[oldest[0]]; return { agent: new HttpsProxyAgent(oldest[0]), url: oldest[0] }; }
    return { agent: null, url: null };
  }
  const url = active[Math.floor(Math.random() * active.length)];
  return { agent: new HttpsProxyAgent(url), url };
}

function markProxyFailed(agent) {
  if (!agent || !agent.proxy) return;
  const url = typeof agent.proxy === "object" ? agent.proxy.href || agent.proxy.toString() : agent.proxy.toString();
  const now = Date.now();
  const entry = _proxyBlacklist[url] || { count: 0, until: 0 };
  entry.count++;
  entry.until = now + Math.min(300000, Math.pow(2, entry.count) * 10000);
  _proxyBlacklist[url] = entry;
}

function randomItem(arr) { return arr[Math.floor(Math.random() * arr.length)]; }

function uuid() {
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
    const r = Math.random() * 16 | 0;
    return (c === "x" ? r : (r & 0x3 | 0x8)).toString(16);
  });
}

function parseCookies(setCookieHeaders) {
  if (!setCookieHeaders) return "";
  const arr = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];
  return arr.map(c => c.split(";")[0].trim()).filter(c => c.startsWith("__dcfduid=") || c.startsWith("__sdcfduid=") || c.startsWith("_cfuvid=")).join("; ");
}

function loadProfiles() {
  if (_profileStore) return _profileStore;
  try {
    if (fs.existsSync(PROFILES_FILE)) {
      _profileStore = JSON.parse(fs.readFileSync(PROFILES_FILE, "utf-8"));
    }
  } catch {}
  if (!_profileStore) _profileStore = {};
  return _profileStore;
}

function saveProfiles() {
  try {
    const sanitized = {};
    for (const [key, val] of Object.entries(_profileStore)) {
      sanitized[key] = {
        locale: val.locale,
        timezone: val.timezone,
        browser: val.browser,
        ver: val.ver,
        secCh: val.secCh,
        platform: val.platform,
        ua: val.ua,
        deviceId: val.deviceId,
        initDone: val.initDone,
      };
    }
    fs.writeFileSync(PROFILES_FILE, JSON.stringify(sanitized, null, 2), "utf-8");
  } catch {}
}

function getOrCreateProfile(token) {
  const key = hashTokenForProfile(token);
  const store = loadProfiles();
  if (!store[key]) {
    const uaInfo = randomItem(BROWSERS);
    store[key] = {
      locale: randomItem(LOCALES),
      timezone: randomItem(TIMEZONES),
      browser: uaInfo.browser,
      ver: uaInfo.ver,
      secCh: uaInfo.secCh,
      platform: uaInfo.platform,
      ua: uaInfo.ua,
      deviceId: uuid(),
      cookieStr: "",
      initDone: false,
    };
    saveProfiles();
  }
  if (store[key].cookies && !store[key].cookieStr) {
    store[key].cookieStr = store[key].cookies;
    delete store[key].cookies;
    saveProfiles();
  }
  return store[key];
}

function b64(str) { return Buffer.from(str, "utf-8").toString("base64"); }

function buildHeaders(token, ctxKey) {
  const profile = getOrCreateProfile(token);
  const buildNum = randomItem(BUILD_NUMS);
  const referer = REFERERS[ctxKey] || REFERERS.Default;
  const isJoin = ctxKey === "Join Guild";

  const spObj = {
    os: "Windows",
    device: "",
    system_locale: profile.locale,
    has_client_mods: false,
    os_version: "10",
    referrer: "",
    referring_domain: "",
    referrer_current: "",
    referring_domain_current: "",
    release_channel: "stable",
    client_build_number: buildNum,
    client_event_source: null,
    client_launch_id: uuid(),
    client_app_state: "unfocused",
    launch_signature: (() => {
      const bits = 0b00000000100000000001000000010000000010000001000000001000000000000010000010000001000000000100000000000001000000000000100000000000n;
      const r = BigInt('0x' + uuid().replace(/-/g, ''));
      const cleaned = r & ~(bits & ((1n << 128n) - 1n));
      const hex = cleaned.toString(16).padStart(32, '0');
      return hex.slice(0,8) + '-' + hex.slice(8,12) + '-' + hex.slice(12,16) + '-' + hex.slice(16,20) + '-' + hex.slice(20,32);
    })(),
    client_heartbeat_session_id: uuid(),
  };

  const clientVer = "1.0.396";
  const clientUA = `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) discord/${clientVer} Chrome/138.0.0.0 Safari/537.36`;
  const clientSecCh = `"Chromium";v="138", "Discord";v="${clientVer}", "Not;A=Brand";v="99"`;

  if (isJoin) {
    spObj.browser = "Discord Client";
    spObj.client_version = clientVer;
    spObj.os_arch = "x64";
    spObj.app_arch = "x64";
  } else {
    spObj.browser = "Discord Client";
    spObj.browser_user_agent = clientUA;
    spObj.browser_version = clientVer;
    spObj.client_version = clientVer;
    spObj.os_arch = "x64";
    spObj.app_arch = "x64";
  }

  const superProps = b64(JSON.stringify(spObj));

  const csp = b64(JSON.stringify({ location: ctxKey || "Discord Client" }));

  const ua = clientUA;

  const h = {
    "accept": "*/*",
    "accept-encoding": "gzip, deflate, br",
    "accept-language": profile.locale + ",en;q=0.9",
    "authorization": token,
    "content-type": "application/json",
    "origin": "https://discord.com",
    "referer": referer,
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-origin",
    "user-agent": ua,
    "x-context-properties": csp,
    "x-debug-options": "bugReporterEnabled",
    "x-discord-device-id": profile.deviceId,
    "x-discord-locale": profile.locale,
    "x-discord-timezone": profile.timezone,
    "x-super-properties": superProps,
  };

  if (profile.cookieStr) h["cookie"] = profile.cookieStr;
  h["sec-ch-ua"] = clientSecCh;
  h["sec-ch-ua-mobile"] = "?0";
  h["sec-ch-ua-platform"] = '"Windows"';

  return { headers: h, profile };
}

// HTTP/2 connection pool (one per origin, reuses across requests)
let _h2Session = null;
function getH2Session() {
  if (_h2Session && !_h2Session.closed) return _h2Session;
  _h2Session = http2.connect("https://discord.com", {
    ...BROWSER_TLS_OPTIONS,
    settings: { enablePush: false, initialWindowSize: 65535, maxConcurrentStreams: 100 },
  });
  _h2Session.on("error", () => { _h2Session = null; });
  _h2Session.on("close", () => { _h2Session = null; });
  return _h2Session;
}

function parseBody(buf, encoding) {
  return new Promise((resolve) => {
    const raw = Buffer.isBuffer(buf) ? buf : Buffer.from(buf);
    if (!encoding || encoding === "identity") {
      const s = raw.toString("utf8");
      try { resolve(JSON.parse(s)); } catch { resolve(s); }
      return;
    }
    const cb = (e, d) => {
      if (e) { const s = raw.toString("utf8"); try { resolve(JSON.parse(s)); } catch { resolve(s); } return; }
      const s = d.toString("utf8");
      try { resolve(JSON.parse(s)); } catch { resolve(s); }
    };
    if (encoding.includes("gzip")) zlib.gunzip(raw, cb);
    else if (encoding.includes("deflate")) zlib.inflate(raw, cb);
    else if (encoding.includes("br")) zlib.brotliDecompress(raw, cb);
    else { const s = raw.toString("utf8"); try { resolve(JSON.parse(s)); } catch { resolve(s); } }
  });
}

function resolveResult(status, chunks, encoding, setCookie) {
  const buf = Buffer.concat(chunks);
  return parseBody(buf, encoding).then(data => ({ status, data, setCookie }));
}

function makeH2Request(method, path, headers, bodyData) {
  return new Promise((resolve) => {
    try {
      const session = getH2Session();
      if (!session || session.closed || session.destroyed) {
        _h2Session = null;
        return makeH1Request(method, path, null, headers, bodyData).then(resolve);
      }
      const reqHeaders = { ":method": method, ":path": path, ...headers };
      if (bodyData) reqHeaders["content-length"] = Buffer.byteLength(bodyData);
      let req;
      try {
        req = session.request(reqHeaders);
      } catch (err) {
        _h2Session = null;
        return makeH1Request(method, path, null, headers, bodyData).then(resolve);
      }
      let chunks = [];
      let status = 0;
      let encoding = null;
      let setCookie = null;
      req.on("response", (respHeaders) => {
        status = Number(respHeaders[":status"]);
        const raw = respHeaders["set-cookie"];
        if (raw) setCookie = Array.isArray(raw) ? raw : [raw];
        encoding = respHeaders["content-encoding"] || null;
      });
      req.on("data", (c) => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
      req.on("end", () => resolveResult(status, chunks, encoding, setCookie).then(resolve));
      req.on("error", () => {
        _h2Session = null;
        makeH1Request(method, path, null, headers, bodyData).then(resolve);
      });
      if (bodyData) req.write(bodyData);
      req.end();
    } catch {
      _h2Session = null;
      makeH1Request(method, path, null, headers, bodyData).then(resolve);
    }
  });
}

function makeH1Request(method, path, agent, headers, bodyData) {
  return new Promise((resolve) => {
    const opts = { hostname: "discord.com", path, method, headers, setHost: true };
    if (agent) opts.agent = agent;
    if (bodyData) headers["content-length"] = Buffer.byteLength(bodyData);
    const req = https.request(opts, (res) => {
      let chunks = [];
      res.on("data", (c) => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
      res.on("end", () => resolveResult(res.statusCode, chunks, res.headers["content-encoding"], res.headers["set-cookie"]).then(resolve));
    });
    req.on("error", (err) => { resolve({ status: 0, data: err.message }); });
    if (bodyData) req.write(bodyData);
    req.end();
  });
}

let _pwBrowser = null;

async function solveCaptcha(sitekey, rqdata) {
  let dc;
  try {
    dc = require("darkcaptcha");
  } catch {
    return { solved: false, error: "darkcaptcha module not installed" };
  }
  const { chromium } = require("playwright");

  if (!_pwBrowser) {
    try {
      _pwBrowser = await chromium.launch({
        headless: !process.env.DC_DEBUG,
        args: [
          "--no-sandbox", "--disable-setuid-sandbox",
          "--disable-blink-features=AutomationControlled",
          "--disable-web-security",
          "--disable-features=IsolateOrigins,site-per-process",
          "--window-size=1280,720",
        ],
      });
    } catch (err) {
      return { solved: false, error: `Browser launch failed: ${err.message}` };
    }
  }

  let ctx = null;
  try {
    ctx = await _pwBrowser.newContext({
      userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
      locale: "en-US",
      viewport: { width: 1280, height: 720 },
    });
    await ctx.addInitScript(() => {
      Object.defineProperty(navigator, "webdriver", { get: () => false });
    });
    const page = await ctx.newPage();

    const safeSitekey = JSON.stringify(sitekey || "");
    const safeRqdata = JSON.stringify(rqdata || "");

    const html = `<!DOCTYPE html><html><head>
<script src="https://js.hcaptcha.com/1/api.js?render=explicit&onload=dcL" async defer></script>
<style>body{display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#f0f0f0}</style>
</head><body><div id="dc-hc"></div>
<script>
window.dcL=function() {
  hcaptcha.render("dc-hc", {
    sitekey: ${safeSitekey},
    rqdata: ${safeRqdata},
    callback:function(t){ document.title="TOKEN:"+t; },
    errorCallback:function(){ document.title="ERR_CAPTCHA"; },
    expiredCallback:function(){ document.title="EXPIRED"; }
  });
};
setTimeout(function(){
  if(!document.title) document.title="TIMEOUT";
}, 90000);
</script></body></html>`;

    await page.route("**/*", (route) => {
      const u = route.request().url();
      if (u === "https://discord.com/" || u === "https://discord.com" || u.startsWith("https://discord.com/?")) {
        route.fulfill({ status: 200, contentType: "text/html", body: html });
      } else if (u.startsWith("https://discord.com")) {
        route.fulfill({ status: 200, contentType: "text/html", body: html });
      } else {
        route.continue();
      }
    });

    await page.goto("https://discord.com/", { waitUntil: "domcontentloaded", timeout: 15000 });
    await page.waitForTimeout(3000);

    // Wait for hCaptcha iframe
    let hcaptchaFrame = null;
    for (let i = 0; i < 20; i++) {
      try {
        hcaptchaFrame = page.frameLocator('iframe[src*="hcaptcha.com"]').first();
        const cb = hcaptchaFrame.locator('#checkbox');
        if (await cb.isVisible({ timeout: 1000 }).catch(() => false)) break;
      } catch {}
      await sleep(500);
    }

    // Click checkbox
    if (hcaptchaFrame) {
      try {
        const cb = hcaptchaFrame.locator('#checkbox, .hcaptcha-box, [role="checkbox"]');
        if (await cb.isVisible({ timeout: 3000 }).catch(() => false)) {
          await cb.click({ timeout: 5000 });
          await page.waitForTimeout(2000);
        }
      } catch {}
    }

    // Handle challenge (image or audio)
    let token = await _getToken(page);
    if (token) return { solved: true, token };

    // Try AI image challenge solving
    if (dc && dc.CLIPSolver && dc.CLIPSolver.isAvailable()) {
      token = await _solveImageChallenge(page, hcaptchaFrame, dc);
      if (token) return { solved: true, token };
    }

    // Try audio challenge fallback
    token = await _solveAudioChallenge(page, hcaptchaFrame, dc);
    if (token) return { solved: true, token };

    // Final attempt: read textarea directly
    token = await _getToken(page);
    return token ? { solved: true, token } : { solved: false, error: "hCaptcha solve failed" };
  } catch (err) {
    return { solved: false, error: err.message || "Captcha solve exception" };
  } finally {
    if (ctx) {
      try { await ctx.close(); } catch {}
    }
  }
}

async function _getToken(page) {
  const t = await page.evaluate(() => document.title).catch(() => "");
  if (t.startsWith("TOKEN:")) return t.slice(6);
  const ta = await page.evaluate(() => {
    const el = document.querySelector('textarea[name="h-captcha-response"]');
    return el?.value || null;
  }).catch(() => null);
  return ta || null;
}

async function _solveImageChallenge(page, frame, dc) {
  try {
    const f = frame || page.frameLocator('iframe[src*="hcaptcha.com"]').first();
    const challengeData = await f.evaluate(() => {
      const promptEl = document.querySelector('.prompt, .task-description, [class*="prompt"], [class*="challenge"] p');
      const prompt = promptEl?.textContent?.trim() || "";
      if (!prompt) return null;
      const tiles = [];
      document.querySelectorAll('img[class*="image"], .image-grid img, canvas[class*="image"], td img, [role="button"] img')
        .forEach(el => {
          const src = el.src || (el.toDataURL ? el.toDataURL() : null);
          if (src) tiles.push(src);
        });
      return tiles.length > 0 ? { prompt, tiles } : null;
    }).catch(() => null);
    if (!challengeData) return null;

    const solver = new dc.CLIPSolver();
    const matches = await solver.findMatchingIcons(challengeData.tiles, challengeData.prompt);
    if (matches.length === 0) return null;

    for (const idx of matches) {
      const els = await f.locator('img[class*="image"], .image-grid img, canvas[class*="image"], td img, [role="button"] img').all();
      if (els[idx]) await els[idx].click().catch(() => {});
      await sleep(200);
    }

    const submitBtn = f.locator('#submit, button[type="submit"], [aria-label*="submit"], button:has-text("Verify"), button:has-text("Next")');
    if (await submitBtn.isVisible({ timeout: 2000 }).catch(() => false)) {
      await submitBtn.click({ timeout: 3000 });
    }

    // Wait for token
    for (let i = 0; i < 30; i++) {
      const t = await _getToken(page);
      if (t) return t;
      await sleep(500);
    }
  } catch {}
  return null;
}

async function _solveAudioChallenge(page, frame, dc) {
  try {
    const f = frame || page.frameLocator('iframe[src*="hcaptcha.com"]').first();
    const audioBtn = f.locator('#audioButton, [aria-label="audio"], .audio-control, button:has-text("Audio")');
    if (!(await audioBtn.isVisible({ timeout: 3000 }).catch(() => false))) return null;

    await audioBtn.click();
    await sleep(2000);

    const audioSrc = await f.evaluate(() => {
      const el = document.querySelector('audio source, audio');
      return el?.src || el?.currentSrc || null;
    }).catch(() => null);
    if (!audioSrc) return null;

    const resp = await page.context().request.get(audioSrc);
    const audioBuf = await resp.body();
    const result = await dc.transcribeAudio(audioBuf);
    if (!result?.text) return null;

    const input = f.locator('#audioResponse, input[placeholder*="answer"], input[type="text"], [class*="input"]');
    await input.fill(result.text.replace(/\s+/g, " ").trim());
    await sleep(500);

    const verify = f.locator('#verifyButton, button:has-text("Verify"), #audioVerify, button[type="submit"]');
    await verify.click({ timeout: 3000 });

    for (let i = 0; i < 30; i++) {
      const t = await _getToken(page);
      if (t) return t;
      await sleep(500);
    }
  } catch {}
  return null;
}

function detectCaptcha(data) {
  const parsed = typeof data === "object" ? data : null;
  if (!parsed?.captcha_key || !Array.isArray(parsed.captcha_key)) return null;
  const joined = parsed.captcha_key.join(" ");
  if (joined.includes("captcha-required") || joined.includes("update your app") || joined.includes("update discord")) {
    return { sitekey: parsed.captcha_sitekey || "", rqdata: parsed.captcha_rqdata || "" };
  }
  return null;
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function randomDelay(min, max) {
  return sleep(Math.floor(Math.random() * (max - min + 1)) + min);
}

// ---- Global rate-limit coordination ----
function loadCoreConfig() {
  try {
    const cfgFile = path.join(__dirname, "..", "config.json");
    if (fs.existsSync(cfgFile)) return JSON.parse(fs.readFileSync(cfgFile, "utf-8"));
  } catch {}
  return {};
}

const RL_MIN_SPACING = Math.max(100, parseInt(loadCoreConfig().request_delay_ms) || 400);
let _lastReqTs = 0;
let _cooldownUntil = 0;
let _burst429 = 0;

async function rlGate() {
  for (;;) {
    const now = Date.now();
    const target = Math.max(_cooldownUntil, _lastReqTs + RL_MIN_SPACING);
    if (target <= now) break;
    await sleep(Math.min(target - now, 2000));
  }
  _lastReqTs = Date.now();
}

// Unified request: HTTP/2 for direct, HTTP/1.1 for proxied
async function makeRequest(method, path, token, ctx, bodyData) {
  await rlGate();
  const { headers, profile } = buildHeaders(token, ctx || "Default");

  if (!bodyData && (method === "GET" || method === "DELETE")) {
    delete headers["content-type"];
  }

  if (token && profile && !profile.initDone) {
    profile.initDone = true;
    const { agent: initAgent } = getRandomProxy();
    const expOpts = { hostname: "discord.com", path: "/api/v9/experiments", method: "GET", headers: { authorization: token, "user-agent": profile.ua }, setHost: true };
    if (initAgent) expOpts.agent = initAgent;
    const e = https.request(expOpts, (r) => {
      let b = ""; r.on("data", c => b += c); r.on("end", () => {
        const cs = parseCookies(r.headers["set-cookie"]);
        if (cs) {
          profile.cookieStr = cs;
          saveProfiles();
        }
      });
    });
    e.on("error", () => {});
    e.end();
  }

  const versioned = path.replace(/^\/api\/v\d+\//, () => `/api/v9/`);
  const { agent, url } = getRandomProxy();

  let result;
  if (agent) {
    result = await makeH1Request(method, versioned, agent, headers, bodyData);
    if (result.status === 429 || result.status === 0) markProxyFailed(agent);
  } else {
    result = await makeH2Request(method, versioned, headers, bodyData);
  }

  const cs = parseCookies(result.setCookie);
  if (cs && profile && profile.cookieStr !== cs) {
    profile.cookieStr = cs;
    saveProfiles();
  }

  if (result.status === 429) {
    const retryAfter = typeof result.data === "object" && result.data ? (result.data.retry_after || 1) : 1;
    _burst429++;
    const backoff = Math.min(120000, retryAfter * 1000 * Math.pow(1.5, _burst429)) + Math.random() * 1000;
    _cooldownUntil = Date.now() + backoff;
    await sleep(backoff);
    return makeRequest(method, path, token, ctx, bodyData);
  }

  _burst429 = 0;
  return result;
}

async function apiRequest(method, path, token, ctx) {
  return makeRequest(method, path, token, ctx);
}

function resolveInvite(inviteCode) {
  return apiRequest("GET", `/api/v9/invites/${inviteCode}?with_counts=true`, "", "Invite");
}

function getUsersGuilds(token) {
  return apiRequest("GET", "/api/v9/users/@me/guilds", token, "List Guilds");
}

function isAlreadyMember(guilds, targetGuildId) {
  return guilds.data.some((g) => g.id === targetGuildId);
}

function joinWithCaptcha(token, inviteCode, captchaToken) {
  const bd = captchaToken ? JSON.stringify({ captcha_key: captchaToken }) : "{}";
  return makeRequest("POST", `/api/v9/invites/${inviteCode}`, token, "Join Guild", bd).then(async (r) => {
    if (r.status === 200 || r.status === 201) {
      return { success: true, token: token.slice(0, 20) + "...", captchaSolved: !!captchaToken };
    }

    const parsed = typeof r.data === "object" ? r.data : null;
    const captchaInfo = detectCaptcha(parsed);

    if (captchaInfo) {
      const cached = global._solvedCaptchaToken;
      if (cached && cached.expires > Date.now()) {
        const retry = await joinWithCaptcha(token, inviteCode, cached.token);
        if (retry.success) return retry;
      }

      const solved = await solveCaptcha(captchaInfo.sitekey, captchaInfo.rqdata);
      if (solved.solved) {
        global._solvedCaptchaToken = { token: solved.token, expires: Date.now() + 120000 };
        return joinWithCaptcha(token, inviteCode, solved.token);
      }

      global._pendingCaptcha = { sitekey: captchaInfo.sitekey, rqdata: captchaInfo.rqdata, id: ++global._captchaSeq || (global._captchaSeq = 1) };
      return { success: false, token: token.slice(0, 20) + "...", reason: "Captcha required", captchaPending: global._pendingCaptcha.id, captcha: captchaInfo };
    }

    const reason = parsed?.captcha_key?.join(", ") || parsed?.message || r.data || "Unknown";
    return { success: false, token: token.slice(0, 20) + "...", reason, captcha: null };
  });
}

async function warmupToken(token) {
  const profile = getOrCreateProfile(token);
  if (profile.warmedUp) return;
  await Promise.allSettled([
    apiRequest("GET", "/api/v9/users/@me", token, "Check"),
    apiRequest("GET", "/api/v9/users/@me/guilds", token, "List Guilds"),
    apiRequest("GET", "/api/v9/users/@me/relationships", token, "Check"),
    apiRequest("GET", "/api/v9/users/@me/settings", token, "Settings"),
  ]);
  profile.warmedUp = true;
}

async function joinServer(token, inviteCode) {
  const profile = getOrCreateProfile(token);
  if (!profile.warmedUp) {
    await warmupToken(token);
    await sleep(3000 + Math.random() * 7000);
  }
  const cached = global._solvedCaptchaToken;
  if (cached && cached.expires > Date.now()) {
    return joinWithCaptcha(token, inviteCode, cached.token);
  }
  return joinWithCaptcha(token, inviteCode, null);
}

function leaveServer(token, guildId) {
  return makeRequest("DELETE", `/api/v9/users/@me/guilds/${guildId}`, token, "Leave Guild").then((r) => {
    if (r.status === 204 || r.status === 200) return { success: true };
    const parsed = typeof r.data === "object" ? r.data : null;
    const reason = parsed?.message || (typeof r.data === "string" && r.data ? r.data : null) || `HTTP ${r.status}`;
    if (r.status === 404) return { success: false, reason: "Not in server / not found" };
    return { success: false, reason };
  });
}

function changeNickname(token, guildId, nickname) {
  return makeRequest("PATCH", `/api/v9/guilds/${guildId}/members/@me`, token, "Nickname", JSON.stringify({ nick: nickname })).then((r) => {
    if (r.status === 200) return { success: true };
    return { success: false, reason: typeof r.data === "object" ? r.data?.message : r.data || "Unknown" };
  });
}

function changeGlobalName(token, name) {
  return makeRequest("PATCH", "/api/v9/users/@me", token, "Name", JSON.stringify({ global_name: name })).then((r) => {
    if (r.status === 200) return { success: true };
    return { success: false, reason: typeof r.data === "object" ? r.data?.message : r.data || "Unknown" };
  });
}

function changeBio(token, bio) {
  return makeRequest("PATCH", "/api/v9/users/@me", token, "Bio", JSON.stringify({ bio })).then((r) => {
    if (r.status === 200) return { success: true };
    return { success: false, reason: typeof r.data === "object" ? r.data?.message : r.data || "Unknown" };
  });
}

function sendFriendRequest(token, targetUserId) {
  return makeRequest("PUT", `/api/v9/users/@me/relationships/${targetUserId}`, token, "Friend", "{}").then((r) => {
    if (r.status === 204) return { success: true };
    return { success: false, reason: typeof r.data === "object" ? r.data?.message : r.data || "Unknown" };
  });
}

function changeStatus(token, status) {
  closeGateway(token);
  return makeRequest("GET", "/api/v9/gateway", token, "Settings").then((r) => {
    return new Promise((resolve) => {
      try {
        const url = typeof r.data === "object" ? r.data.url : JSON.parse(r.data).url;
        const profile = getOrCreateProfile(token);
        const masked = maskToken(token);

        const connect = (attempt) => {
          const ws = new WebSocket(url + "?v=9&encoding=json", {
            origin: "https://discord.com",
            headers: {
              "User-Agent": profile.ua, "Accept-Language": profile.locale,
              "Cache-Control": "no-cache", "Pragma": "no-cache",
            },
          });
          let hbTimer;
          let connected = false;

          _gatewayConnections[token] = { ws, hbTimer, reconnectTimer: null };

          ws.on("open", () => {
            if (!canIdentify(token)) {
              try { ws.close(1000); } catch {}
              resolve({ success: false, reason: "IDENTIFY limit reached" });
              return;
            }
            recordIdentify(token);
            ws.send(JSON.stringify({
              op: 2, d: {
                token, capabilities: 4093,
                properties: { $os: "windows", $browser: "Discord Client", $device: "", $os_version: "10", $browser_version: profile.ver, system_locale: profile.locale, release_channel: "stable", client_build_number: 286175, client_event_source: null },
                presence: { status, since: 0, activities: [], afk: false },
              },
            }));
          });

          ws.on("message", (raw) => {
            try {
              const msg = JSON.parse(raw);
              if (msg.op === 10) {
                clearInterval(hbTimer);
                hbTimer = setInterval(() => { try { ws.send(JSON.stringify({ op: 1, d: null })); } catch {} }, msg.d.heartbeat_interval);
                connected = true;
                if (_gatewayConnections[token]) _gatewayConnections[token].hbTimer = hbTimer;
                resolve({ success: true, token: masked, close: () => { closeGateway(token); }, _ws: ws, _hb: hbTimer });
              }
              if (msg.op === 9) {
                clearInterval(hbTimer);
                try { ws.close(); } catch {}
                if (!connected) resolve({ success: false, reason: "Invalid token" });
              }
            } catch {}
          });

          ws.on("error", () => {
            clearInterval(hbTimer);
            if (!connected && attempt < 3) {
              const delay = Math.min(5000 * Math.pow(2, attempt), 30000);
              console.log(`[*] ${masked} reconnecting in ${delay / 1000}s (attempt ${attempt + 1}/3)...`);
              if (_gatewayConnections[token]) _gatewayConnections[token].reconnectTimer = setTimeout(() => connect(attempt + 1), delay);
            } else if (!connected) {
              resolve({ success: false, reason: "Connection failed" });
            }
          });

          ws.on("close", (code) => {
            clearInterval(hbTimer);
            if (!connected && code !== 1000 && code !== 1001 && attempt < 3) {
              const delay = Math.min(5000 * Math.pow(2, attempt), 30000);
              console.log(`[*] ${masked} disconnected (${code}), reconnecting in ${delay / 1000}s...`);
              if (_gatewayConnections[token]) _gatewayConnections[token].reconnectTimer = setTimeout(() => connect(attempt + 1), delay);
            } else if (!connected && code !== 1000) {
              resolve({ success: false, reason: `Disconnected (code:${code})` });
            }
          });
        };

        connect(0);
      } catch { resolve({ success: false, reason: "Failed to get gateway" }); }
    });
  });
}

function reactToMessage(token, channelId, messageId, emoji) {
  return makeRequest("PUT", `/api/v9/channels/${channelId}/messages/${messageId}/reactions/${encodeURIComponent(emoji)}/@me`, token, "React").then((r) => {
    if (r.status === 204) return { success: true };
    return { success: false, reason: typeof r.data === "object" ? r.data?.message : r.data || "Unknown" };
  });
}

function fetchChannelMessages(token, channelId, limit) {
  return apiRequest("GET", `/api/v9/channels/${channelId}/messages?limit=${limit || 10}`, token, "Messages");
}

function fetchReactionUsers(token, channelId, messageId, emoji, limit) {
  return makeRequest("GET", `/api/v9/channels/${channelId}/messages/${messageId}/reactions/${encodeURIComponent(emoji)}?limit=${limit || 5}`, token, "ReactUsers").then(r => {
    if (r.status === 200) return { success: true, users: Array.isArray(r.data) ? r.data : [] };
    return { success: false, users: [] };
  });
}

function fetchMessageComponents(token, channelId, messageId) {
  return apiRequest("GET", `/api/v9/channels/${channelId}/messages?limit=50&around=${messageId}`, token, "Messages").then(r => {
    if (r.status !== 200) return { success: false, components: [], error: "Could not fetch messages" };
    const msgs = Array.isArray(r.data) ? r.data : [];
    const msg = msgs.find(m => m.id === messageId);
    if (!msg) return { success: true, components: [] };
    if (!msg?.components) return { success: true, components: [] };
    const btns = [];
    for (const row of msg.components) {
      if (row.type === 1 && Array.isArray(row.components)) {
        for (const c of row.components) {
          if (c.type === 2) btns.push({ label: c.label, customId: c.custom_id, style: c.style, emoji: c.emoji, disabled: c.disabled });
        }
      }
    }
    return { success: true, components: btns };
  });
}

async function clickMessageButton(token, channelId, messageId, customId, cachedMeta = null) {
  let guildId = cachedMeta?.guildId;
  let applicationId = cachedMeta?.applicationId;
  let messageFlags = cachedMeta?.messageFlags || 0;

  if (!applicationId) {
    const channelRes = await apiRequest("GET", `/api/v9/channels/${channelId}`, token, "Messages");
    guildId = channelRes.status === 200 ? channelRes.data?.guild_id : null;

    const msgRes = await apiRequest("GET", `/api/v9/channels/${channelId}/messages?limit=50&around=${messageId}`, token, "Messages");
    if (msgRes.status !== 200) return { success: false, reason: "Could not fetch messages" };
    const msgs = Array.isArray(msgRes.data) ? msgRes.data : [];
    const d = msgs.find(m => m.id === messageId);
    if (!d) return { success: false, reason: "Message not found" };

    applicationId = d.application_id || d.author?.id;
    messageFlags = d.flags || 0;
  }

  const nonce = String(Date.now()) + String(Math.random()).slice(2, 10);
  const payload = {
    type: 3,
    nonce,
    channel_id: channelId,
    message_id: messageId,
    message_flags: messageFlags,
    application_id: applicationId,
    session_id: uuid(),
    data: { component_type: 2, custom_id: customId },
  };
  if (guildId) payload.guild_id = guildId;

  return makeRequest("POST", "/api/v9/interactions", token, "Interact", JSON.stringify(payload)).then(r => {
    if (r.status === 204 || r.status === 200) return { success: true };
    const parsed = typeof r.data === "object" ? r.data : null;
    return { success: false, reason: parsed?.message || r.data || `HTTP ${r.status}` };
  });
}

function testProxyConnection(proxyUrl) {
  return new Promise((resolve) => {
    const start = Date.now();
    try {
      const agent = new HttpsProxyAgent(proxyUrl);
      const req = https.request({
        hostname: "discord.com",
        path: "/api/v9/gateway",
        method: "GET",
        headers: { "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        agent,
        timeout: 8000,
      }, (res) => {
        let b = "";
        res.on("data", c => b += c);
        res.on("end", () => {
          const latency = Date.now() - start;
          if (res.statusCode === 200) {
            resolve({ success: true, latency, status: res.statusCode, proxyUrl });
          } else if (res.statusCode === 429) {
            resolve({ success: false, latency, status: 429, error: "Rate Limited (429)", proxyUrl });
          } else {
            resolve({ success: false, latency, status: res.statusCode, error: `HTTP ${res.statusCode}`, proxyUrl });
          }
        });
      });
      req.on("error", (err) => {
        resolve({ success: false, latency: Date.now() - start, error: err.message, proxyUrl });
      });
      req.on("timeout", () => {
        req.destroy();
        resolve({ success: false, latency: Date.now() - start, error: "Timeout (>8s)", proxyUrl });
      });
      req.end();
    } catch (err) {
      resolve({ success: false, latency: 0, error: err.message, proxyUrl });
    }
  });
}

module.exports = {
  apiRequest, sleep, randomDelay, resolveInvite, getUsersGuilds, isAlreadyMember,
  joinServer, joinWithCaptcha, changeNickname, changeGlobalName, leaveServer,
  changeBio, sendFriendRequest, changeStatus, reactToMessage, fetchChannelMessages,
  fetchReactionUsers, fetchMessageComponents, clickMessageButton, closeAllGateways,
  maskToken, testProxyConnection, getRandomProxy, loadProxies,
};
