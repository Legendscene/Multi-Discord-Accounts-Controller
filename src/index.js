const fs = require("fs");
const path = require("path");
const https = require("https");
const WebSocket = require("ws");
const chalk = require("chalk");
const { HttpsProxyAgent } = require("https-proxy-agent");
const {
  apiRequest, sleep, randomDelay, resolveInvite, getUsersGuilds, isAlreadyMember,
  joinServer, joinWithCaptcha, changeNickname, changeGlobalName, leaveServer,
  changeBio, sendFriendRequest, reactToMessage, fetchReactionUsers,
  fetchMessageComponents, clickMessageButton, closeAllGateways, maskToken,
  testProxyConnection, loadProxies: coreLoadProxies
} = require("./core");
const {
  secureReadTokens, secureWriteTokens, encryptTokens, decryptTokens,
  getOrCreateEncryptionKey, canIdentify, recordIdentify, isOnCooldown,
  markFailed, IDENTIFY_LIMIT, TOKENS_FILE, ENC_TOKENS_FILE, KEY_FILE
} = require("./security");

const CONFIG_FILE = path.join(__dirname, "..", "config.json");
const PROXIES_FILE = path.join(__dirname, "..", "proxies.txt");

let activeVC = [];
const nameCache = {};

let config = { captcha_key: "" };
try {
  if (fs.existsSync(CONFIG_FILE)) {
    config = JSON.parse(fs.readFileSync(CONFIG_FILE, "utf-8"));
  }
} catch {}

const STAGGER_MIN = Math.max(1, parseInt(config.connect_stagger_min_s) || 6) * 1000;
const STAGGER_MAX = Math.max(STAGGER_MIN + 1000, parseInt(config.connect_stagger_max_s) || 14) * 1000;

// Reusable Readline
let _rl = null;
function getReadline() {
  if (!_rl || _rl.closed) {
    const readline = require("readline");
    _rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  }
  return _rl;
}

function askText(question) {
  return new Promise((resolve) => {
    const rl = getReadline();
    rl.question(question, (ans) => { resolve(ans.trim()); });
  });
}

function askNumber(question) {
  return askText(question);
}

// Proxies
let _proxies = null;
function loadProxies() {
  if (_proxies !== null) return _proxies;
  try {
    if (fs.existsSync(PROXIES_FILE)) {
      const content = fs.readFileSync(PROXIES_FILE, "utf-8");
      _proxies = content.split(/\r?\n/).map(l => l.trim()).filter(l => l && !l.startsWith("#") && l.startsWith("http"));
    }
  } catch {}
  if (!_proxies) _proxies = [];
  return _proxies;
}

function getProxy(index) {
  const proxies = loadProxies();
  if (proxies.length === 0) return null;
  return proxies[Math.abs(index) % proxies.length];
}

// Realistic Browser Fingerprints
const _fingerprints = [
  { ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36", os: "windows", browser: "chrome", ver: "126.0.0.0", platform: "Win32" },
  { ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36", os: "windows", browser: "chrome", ver: "125.0.0.0", platform: "Win32" },
  { ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0", os: "windows", browser: "firefox", ver: "126.0", platform: "Win32" },
  { ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36", os: "darwin", browser: "chrome", ver: "125.0.0.0", platform: "MacIntel" },
  { ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0", os: "windows", browser: "chrome", ver: "124.0.0.0", platform: "Win32" },
  { ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36", os: "windows", browser: "chrome", ver: "127.0.0.0", platform: "Win32" },
  { ua: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36", os: "linux", browser: "chrome", ver: "126.0.0.0", platform: "Linux x86_64" },
  { ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15", os: "darwin", browser: "safari", ver: "17.4", platform: "MacIntel" },
];

function randomFingerprint() {
  const fp = _fingerprints[Math.floor(Math.random() * _fingerprints.length)];
  const locales = ["en-US", "en-GB", "hi-IN", "en-AU", "en-CA"];
  const osVersions = ["10.0", "10.0", "10.0", "11.0"];
  return {
    ua: fp.ua,
    os: fp.os,
    browser: fp.browser,
    browserVersion: fp.ver,
    platform: fp.platform,
    locale: locales[Math.floor(Math.random() * locales.length)],
    osVersion: osVersions[Math.floor(Math.random() * osVersions.length)],
  };
}

function randomUA() { return randomFingerprint().ua; }

async function getName(token) {
  if (nameCache[token]) return nameCache[token];
  try {
    const res = await apiRequest("GET", "/api/v9/users/@me", token, "Check");
    let name = "?";
    if (res.status === 200 && res.data && res.data.id) {
      name = (res.data.global_name || res.data.username || res.data.id).replace(/[^\x20-\x7E]/g, "");
      if (!name) name = res.data.id.slice(0, 8);
    } else {
      name = maskToken(token);
    }
    if (name.length > 15) name = name.slice(0, 15);
    nameCache[token] = name;
    return name;
  } catch {
    return maskToken(token);
  }
}

function readTokens(optional) {
  const tokens = secureReadTokens();
  if (tokens.length === 0) {
    if (optional) return [];
    console.error(chalk.red("[!] No tokens found. Add tokens to tokens.txt or use encrypted storage (.enc)."));
    return null;
  }
  return tokens;
}

function extractInviteCode(input) {
  let str = input.trim().replace(/^https?:\/\//, "");
  const match = str.match(
    /(?:discord\.(?:com\/invite|gg|io|me|li)\/)?([a-zA-Z0-9_-]+)$/
  );
  return match ? match[1] : str;
}

// 2Captcha integration
function solveCaptcha(sitekey, rqdata, rqtoken, pageUrl) {
  return new Promise((resolve) => {
    if (!config.captcha_key) {
      resolve(null);
      return;
    }
    console.log(chalk.cyan(`[~] Submitting captcha to 2captcha...`));
    const params = new URLSearchParams({
      key: config.captcha_key,
      method: "hcaptcha",
      sitekey,
      pageurl: pageUrl,
      json: "1",
    });
    if (rqdata) params.set("data", rqdata);

    const req = https.request({
      hostname: "2captcha.com",
      path: `/in.php?${params.toString()}`,
      method: "GET",
    }, (res) => {
      let body = "";
      res.on("data", (c) => (body += c));
      res.on("end", () => {
        try {
          const d = JSON.parse(body);
          if (d.status === 1) {
            const id = d.request;
            console.log(chalk.dim(`[~] Captcha ID: ${id}, waiting...`));
            pollCaptchaSolution(id, resolve);
          } else {
            console.log(chalk.red(`[!] 2captcha submit failed: ${d.request}`));
            resolve(null);
          }
        } catch {
          resolve(null);
        }
      });
    });
    req.on("error", () => resolve(null));
    req.end();
  });
}

function pollCaptchaSolution(id, resolve) {
  const params = new URLSearchParams({
    key: config.captcha_key,
    action: "get",
    id,
    json: "1",
  });
  const req = https.request({
    hostname: "2captcha.com",
    path: `/res.php?${params.toString()}`,
    method: "GET",
  }, (res) => {
    let body = "";
    res.on("data", (c) => (body += c));
    res.on("end", () => {
      try {
        const d = JSON.parse(body);
        if (d.status === 1) {
          console.log(chalk.green(`[+] Captcha solved!`));
          resolve(d.request);
        } else if (d.request === "CAPCHA_NOT_READY") {
          process.stdout.write(chalk.dim("."));
          setTimeout(() => pollCaptchaSolution(id, resolve), 5000);
        } else {
          console.log(chalk.red(`[!] 2captcha error: ${d.request}`));
          resolve(null);
        }
      } catch {
        setTimeout(() => pollCaptchaSolution(id, resolve), 5000);
      }
    });
  });
  req.on("error", () => resolve(null));
  req.end();
}

// 1. Bulk Join
async function handleJoinServer(tokens) {
  const invite = await askText("Invite link (discord.gg/CODE): ");
  if (!invite) return;
  const countStr = await askText(`How many accounts to join? (available: ${tokens.length}): `);
  const count = parseInt(countStr) || tokens.length;

  const inviteCode = extractInviteCode(invite);

  console.log(chalk.cyan(`\n[+] Resolving invite: ${inviteCode}...`));
  const inviteInfo = await resolveInvite(inviteCode).catch(() => null);
  let guildName = "Unknown Server";
  let guildId = null;

  if (inviteInfo && inviteInfo.status === 200) {
    guildName = inviteInfo.data.guild?.name || "Unknown Server";
    guildId = inviteInfo.data.guild?.id || null;
    const guild = inviteInfo.data.guild || {};
    const verifLevel = guild.verification_level;
    if (verifLevel >= 2) {
      console.log(chalk.yellow(`[!] Server has Medium+ verification (level ${verifLevel}). Unverified tokens will be rejected.\n`));
    }
    if (inviteInfo.data.guild?.features?.includes("MEMBER_VERIFICATION_GATE_ENABLED")) {
      console.log(chalk.yellow("[!] Server has Membership Screening. Joined accounts may need to accept rules first.\n"));
    }
    console.log(chalk.green(`[+] Server: ${guildName} (${guildId || "no ID"})\n`));
  } else {
    console.log(chalk.yellow("[!] Could not resolve invite, checking connection...\n"));
  }

  console.log(chalk.cyan("[*] Checking who is already in the server...\n"));
  const selectedTokens = tokens.slice(0, count);
  const toJoin = [];
  let alreadyIn = 0;

  for (let i = 0; i < selectedTokens.length; i++) {
    const token = selectedTokens[i];
    if (guildId) {
      const guilds = await getUsersGuilds(token);
      if (guilds.status === 200 && isAlreadyMember(guilds, guildId)) {
        console.log(chalk.dim(`[~] ${i + 1}/${count} Already in server — ${await getName(token)}`));
        alreadyIn++;
        continue;
      }
    }
    toJoin.push(token);
  }

  console.log(chalk.cyan(`\n[+] Already in server: ${alreadyIn}`));
  console.log(chalk.cyan(`[+] Need to join: ${toJoin.length}\n`));

  if (toJoin.length === 0) {
    console.log(chalk.bold.yellow("[!] All accounts are already in server!\n"));
    return;
  }

  console.log(chalk.cyan(`[*] Fetching account names...`));
  const joinNames = await Promise.all(toJoin.map(t => getName(t)));
  console.log(chalk.green(` Done\n`));

  let success = 0;
  let failed = 0;

  for (let i = 0; i < toJoin.length; i++) {
    const result = await joinServer(toJoin[i], inviteCode);
    const tag = `[${String(i + 1).padStart(3, " ")}/${toJoin.length}]`;
    if (result.success) {
      console.log(chalk.green(`  ${tag} ${joinNames[i].padEnd(15)} ✓ Joined`));
      success++;
    } else {
      console.log(chalk.red(`  ${tag} ${joinNames[i].padEnd(15)} ✗ ${result.reason}`));
      failed++;
    }
    if (i < toJoin.length - 1) await randomDelay(1000, 2000);
  }

  console.log(chalk.bold("\n══════════════════════════════════════"));
  console.log(chalk.bold(`  Already in server: ${alreadyIn}`));
  console.log(chalk.bold.green(`  Newly joined:     ${success}`));
  console.log(chalk.bold.red(`  Failed:           ${failed}`));
  console.log(chalk.bold("══════════════════════════════════════\n"));
}

// 2. Quick Join
async function handleQuickJoin() {
  const token = await askText("Enter token: ");
  if (!token) return;
  const invite = await askText("Invite link (discord.gg/CODE): ");
  if (!invite) return;

  const inviteCode = extractInviteCode(invite);
  console.log(chalk.cyan(`\n[+] Quick joining ${inviteCode}...`));
  const result = await joinServer(token, inviteCode);

  if (result.success) {
    console.log(chalk.green(`[+] Joined OK — ${await getName(token)}\n`));
  } else {
    console.log(chalk.red(`[×] Failed — ${result.reason}\n`));
  }
}

// 3. Change Nickname
async function handleChangeNickname(tokens) {
  const guildId = await askText("Server ID: ");
  if (!guildId) return;
  const nickname = await askText("New nickname for all accounts: ");
  if (!nickname) return;
  const countStr = await askText(`How many accounts? (available: ${tokens.length}): `);
  const count = parseInt(countStr) || tokens.length;

  const selectedTokens = tokens.slice(0, count);
  console.log(chalk.cyan(`[*] Fetching account names...`));
  const names = await Promise.all(selectedTokens.map(t => getName(t)));
  console.log(chalk.green(` Done\n`));

  console.log(chalk.cyan(`[*] Changing nicknames to "${nickname}"...\n`));
  let success = 0;
  let failed = 0;

  for (let i = 0; i < selectedTokens.length; i++) {
    const result = await changeNickname(selectedTokens[i], guildId, nickname);
    if (result.success) {
      console.log(chalk.green(`[+] ${i + 1}/${selectedTokens.length} Nickname changed OK — ${names[i]}`));
      success++;
    } else {
      console.log(chalk.red(`[×] ${i + 1}/${selectedTokens.length} Failed — ${names[i]} (${result.reason})`));
      failed++;
    }
    if (i < selectedTokens.length - 1) await randomDelay(500, 1200);
  }

  console.log(chalk.bold("\n══════════════════════════════════════"));
  console.log(chalk.bold.green(`  Changed: ${success}`));
  console.log(chalk.bold.red(`  Failed:  ${failed}`));
  console.log(chalk.bold("══════════════════════════════════════\n"));
}

// 4. Change Global Display Name
async function handleChangeGlobalName(tokens) {
  const name = await askText("New global display name: ");
  if (!name) return;
  const countStr = await askText(`How many accounts? (available: ${tokens.length}): `);
  const count = parseInt(countStr) || tokens.length;

  const selectedTokens = tokens.slice(0, count);
  console.log(chalk.cyan(`[*] Fetching account names...`));
  const names = await Promise.all(selectedTokens.map(t => getName(t)));
  console.log(chalk.green(` Done\n`));

  console.log(chalk.cyan(`[*] Changing display names to "${name}"...\n`));
  let success = 0;
  let failed = 0;

  for (let i = 0; i < selectedTokens.length; i++) {
    const result = await changeGlobalName(selectedTokens[i], name);
    if (result.success) {
      console.log(chalk.green(`[+] ${i + 1}/${selectedTokens.length} Name changed OK — ${names[i]}`));
      success++;
    } else {
      console.log(chalk.red(`[×] ${i + 1}/${selectedTokens.length} Failed — ${names[i]} (${result.reason})`));
      failed++;
    }
    if (i < selectedTokens.length - 1) await randomDelay(600, 1400);
  }

  console.log(chalk.bold("\n══════════════════════════════════════"));
  console.log(chalk.bold.green(`  Changed: ${success}`));
  console.log(chalk.bold.red(`  Failed:  ${failed}`));
  console.log(chalk.bold("══════════════════════════════════════\n"));
}

// 5. Check Tokens
async function handleCheckTokens(tokens) {
  console.log(chalk.cyan("[*] Checking tokens health...\n"));
  let valid = 0;
  let locked = 0;
  let invalid = 0;

  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    const masked = maskToken(token);
    const res = await apiRequest("GET", "/api/v9/users/@me", token, "Check");
    const tag = `[${String(i + 1).padStart(3, " ")}/${tokens.length}]`;
    if (res.status === 200 && res.data && res.data.id) {
      const name = res.data.global_name || res.data.username || "?";
      console.log(chalk.green(`  ${tag} ${masked} ✓ VALID — ${name} (${res.data.id})`));
      valid++;
    } else if (res.status === 403 || (res.data && res.data.code === 40002)) {
      console.log(chalk.yellow(`  ${tag} ${masked} ⚠ LOCKED / VERIFICATION REQUIRED`));
      locked++;
    } else {
      let reason = typeof res.data === "object" ? res.data?.message : res.data;
      console.log(chalk.red(`  ${tag} ${masked} ✗ INVALID / REVOKED (${reason || res.status})`));
      invalid++;
    }
    if (i < tokens.length - 1) await sleep(200);
  }

  console.log(chalk.bold("\n══════════════════════════════════════"));
  console.log(chalk.bold.green(`  Valid Active:        ${valid}`));
  if (locked > 0) console.log(chalk.bold.yellow(`  Verification Locked: ${locked}`));
  console.log(chalk.bold.red(`  Invalid/Dead:        ${invalid}`));
  console.log(chalk.bold("══════════════════════════════════════\n"));
}

// 6. Remove Invalid Tokens
async function handleCleanTokens() {
  console.log(chalk.cyan("[*] Reading tokens and testing health...\n"));

  const tokens = secureReadTokens();
  if (tokens.length === 0) {
    console.log(chalk.yellow("[!] No tokens found.\n"));
    return;
  }

  const validTokens = [];
  let checked = 0;

  for (const token of tokens) {
    const res = await apiRequest("GET", "/api/v9/users/@me", token, "Check");
    checked++;
    const masked = maskToken(token);
    if (res.status === 200 && res.data && res.data.id) {
      validTokens.push(token);
      const name = res.data.global_name || res.data.username || "?";
      console.log(chalk.green(`[+] ${checked}/${tokens.length} Valid   — ${name} (${masked})`));
    } else {
      console.log(chalk.red(`[×] ${checked}/${tokens.length} Invalid — ${masked}`));
    }
    await sleep(150);
  }

  const removedCount = tokens.length - validTokens.length;
  secureWriteTokens(validTokens);

  console.log(chalk.bold("\n══════════════════════════════════════"));
  console.log(chalk.bold.green(`  Valid tokens kept:   ${validTokens.length}`));
  console.log(chalk.bold.red(`  Invalid purged:      ${removedCount}`));
  console.log(chalk.bold("══════════════════════════════════════\n"));
}

// 7. Add Friends
async function handleAddFriends(tokens) {
  console.log(chalk.cyan("[*] Fetching user IDs for accounts...\n"));

  const accounts = [];
  for (let i = 0; i < tokens.length; i++) {
    const res = await apiRequest("GET", "/api/v9/users/@me", tokens[i], "Check");
    if (res.status === 200 && res.data?.id) {
      accounts.push({ token: tokens[i], id: res.data.id, name: res.data.global_name || res.data.username || "?" });
      console.log(chalk.green(`[+] ${i + 1}/${tokens.length} ${accounts[accounts.length - 1].name} (${res.data.id})`));
    } else {
      console.log(chalk.red(`[×] ${i + 1}/${tokens.length} Invalid token, skipping`));
    }
  }

  if (accounts.length < 2) {
    console.log(chalk.yellow("[!] Need at least 2 valid tokens for friend connections.\n"));
    return;
  }

  console.log(chalk.cyan(`\n[*] Dispatching friend requests between ${accounts.length} accounts...\n`));

  let sent = 0;
  let failed = 0;
  let totalPairs = 0;

  for (let i = 0; i < accounts.length; i++) {
    for (let j = 0; j < accounts.length; j++) {
      if (i === j) continue;
      totalPairs++;
      const result = await sendFriendRequest(accounts[i].token, accounts[j].id);
      if (result.success) {
        console.log(chalk.green(`[+] ${accounts[i].name} → ${accounts[j].name} OK`));
        sent++;
      } else {
        if (result.reason?.includes("already") || result.reason?.includes("existing")) {
          console.log(chalk.dim(`[~] ${accounts[i].name} → ${accounts[j].name} Already friends`));
          sent++;
        } else {
          console.log(chalk.red(`[×] ${accounts[i].name} → ${accounts[j].name} Failed (${result.reason})`));
          failed++;
        }
      }
      await randomDelay(1000, 2500);
    }
  }

  console.log(chalk.bold("\n══════════════════════════════════════"));
  console.log(chalk.bold.green(`  Friend requests sent: ${sent}/${totalPairs}`));
  if (failed > 0) console.log(chalk.bold.red(`  Failed:               ${failed}`));
  console.log(chalk.bold("══════════════════════════════════════\n"));
}

// 8. Change Status (Gateway connections)
const _persistentConnections = {};
let _cyclingActive = false;
const CYCLE_ONLINE_MIN = 20 * 60 * 60 * 1000;
const CYCLE_ONLINE_MAX = 22 * 60 * 60 * 1000;
const CYCLE_OFFLINE_MIN = 2 * 60 * 60 * 1000;
const CYCLE_OFFLINE_MAX = 4 * 60 * 60 * 1000;
const CYCLE_RECONNECT_MIN = 5 * 60 * 1000;
const CYCLE_RECONNECT_MAX = 10 * 60 * 1000;

const BATCH_SIZE = 5;
const BATCH_DELAY = 2000;
const TOKEN_TIMEOUT = 12000;
const MAX_RETRY_ATTEMPTS = 0;

function connectToken(token, status, index, name) {
  const label = name || maskToken(token);
  const numericIndex = typeof index === "number" ? index : parseInt(String(index).split("/")[0]) || 1;
  const id = `${numericIndex}_${Date.now()}`;
  const proxyUrl = getProxy(numericIndex - 1);
  const TIMEOUT = 8000;

  return new Promise((mainResolve) => {
    let done = false;
    let initialConnected = false;
    const finish = (val) => { if (!done) { done = true; mainResolve(val); } };

    const scheduleReconnect = (reason) => {
      if (_persistentConnections[id] || initialConnected) {
        if (_persistentConnections[id]) delete _persistentConnections[id];
        if (!canIdentify(token)) {
          console.log(chalk.red(`[!] ${label} won't reconnect — IDENTIFY limit reached`));
          finish({ id, label, idx: numericIndex, error: "IDENTIFY limit" });
          return;
        }
        if (isOnCooldown(token)) {
          console.log(chalk.red(`[!] ${label} won't reconnect — on cooldown (15min)`));
          finish({ id, label, idx: numericIndex, error: "On cooldown" });
          return;
        }
        const reconnDelay = CYCLE_RECONNECT_MIN + Math.random() * (CYCLE_RECONNECT_MAX - CYCLE_RECONNECT_MIN);
        console.log(chalk.yellow(`[~] ${label} ${reason}, auto-reconnect in ${Math.round(reconnDelay/1000)}s...`));
        setTimeout(() => {
          connectWithTimeout(token, status, numericIndex, name, TOKEN_TIMEOUT);
        }, reconnDelay);
      }
    };

    const attempt = (attemptNum) => {
      if (done || attemptNum > MAX_RETRY_ATTEMPTS) {
        if (!initialConnected) finish({ id, label, idx: numericIndex, error: attemptNum > MAX_RETRY_ATTEMPTS ? "Failed after retries" : "Timeout" });
        return;
      }

      if (isOnCooldown(token)) {
        console.log(chalk.red(`[!] ${label} on cooldown (15min) — skipping`));
        finish({ id, label, idx: numericIndex, error: "On cooldown" });
        return;
      }

      let ws;
      let hbTimer = null;
      const timer = setTimeout(() => {
        try { if (ws) ws.close(); } catch {}
        if (hbTimer) clearInterval(hbTimer);
        if (!done) {
          finish({ id, label, idx: numericIndex, error: "Timeout" });
        }
      }, TIMEOUT);

      const opts = { hostname: "discord.com", path: "/api/v9/gateway", method: "GET", headers: { "User-Agent": randomUA() }, timeout: 4000 };
      if (proxyUrl) opts.agent = new HttpsProxyAgent(proxyUrl);

      https.request(opts, (res) => {
        let body = "";
        res.on("data", c => body += c);
        res.on("end", () => {
          if (done) return;
          try {
            const { url } = JSON.parse(body);
            if (!url) {
              clearTimeout(timer);
              finish({ id, label, idx: numericIndex, error: "No gateway URL" });
              return;
            }
            const fp = randomFingerprint();
            const properties = {
              $os: fp.os, $browser: "Discord Client", $device: "", $os_version: fp.osVersion,
              browser_user_agent: fp.ua,
              browser_version: fp.browserVersion,
              system_locale: fp.locale,
              release_channel: "stable",
              client_build_number: 286175,
              client_event_source: null,
            };
            const wsOpts = { headers: { "User-Agent": fp.ua } };
            if (proxyUrl) wsOpts.agent = new HttpsProxyAgent(proxyUrl);

            ws = new WebSocket(url + "?v=9&encoding=json", wsOpts);
            let seq = null;

            _persistentConnections[id] = { ws, heartbeatTimer: null, token, label, status, sequence: null };

            ws.on("open", () => {
              if (!canIdentify(token)) {
                console.log(chalk.red(`[!] ${label} IDENTIFY limit reached — skipping`));
                try { ws.close(1000); } catch {}
                delete _persistentConnections[id];
                finish({ id, label, idx: numericIndex, error: "IDENTIFY limit" });
                return;
              }
              recordIdentify(token);
              ws.send(JSON.stringify({
                op: 2, d: {
                  token, capabilities: 4093, properties, compress: false,
                  presence: { status, since: 0, activities: [], afk: false },
                  client_state: { guild_hashes: {}, highest_last_message_id: "0", read_state_version: 0, user_guild_settings_version: -1 },
                },
              }));
            });

            ws.on("message", (raw) => {
              try {
                const msg = JSON.parse(raw);
                if (msg.s !== null) seq = msg.s;

                if (msg.op === 10) {
                  clearTimeout(timer);
                  clearInterval(hbTimer);
                  const interval = msg.d.heartbeat_interval;
                  hbTimer = setInterval(() => {
                    try { ws.send(JSON.stringify({ op: 1, d: seq })); } catch {}
                  }, interval);
                  if (_persistentConnections[id]) {
                    _persistentConnections[id].heartbeatTimer = hbTimer;
                    _persistentConnections[id].sequence = seq;
                  }
                  initialConnected = true;
                  finish({ id, label, idx: numericIndex });
                }

                if (msg.op === 9) {
                  clearTimeout(timer);
                  clearInterval(hbTimer);
                  markFailed(token);
                  try { ws.close(); } catch {}
                  delete _persistentConnections[id];
                  finish({ id, label, idx: numericIndex, error: "Invalid session (op 9)" });
                }
              } catch {}
            });

            ws.on("error", (err) => {
              clearTimeout(timer);
              clearInterval(hbTimer);
              markFailed(token);
              finish({ id, label, idx: numericIndex, error: err.message || "Connection error" });
            });

            ws.on("close", (code) => {
              clearTimeout(timer);
              clearInterval(hbTimer);
              const safeReconnectCodes = [1000, 1001, 1006];
              const noReconnectCodes = [4004, 4009, 4010, 4011, 4012, 4013, 4014];

              if (noReconnectCodes.includes(code)) {
                delete _persistentConnections[id];
                markFailed(token);
                finish({ id, label, idx: numericIndex, error: `Closed ${code}` });
              } else if (safeReconnectCodes.includes(code)) {
                scheduleReconnect(`disconnected (${code})`);
              } else {
                markFailed(token);
                finish({ id, label, idx: numericIndex, error: `Closed ${code}` });
              }
            });
          } catch {
            clearTimeout(timer);
            finish({ id, label, idx: numericIndex, error: "Parse error" });
          }
        });
      }).on("error", (err) => {
        clearTimeout(timer);
        finish({ id, label, idx: numericIndex, error: err.message || "Network error" });
      }).on("timeout", function () {
        this.destroy();
        clearTimeout(timer);
        finish({ id, label, idx: numericIndex, error: "Gateway timeout" });
      }).end();
    };

    attempt(0);
  });
}

function disconnectAllPersistent() {
  for (const id of Object.keys(_persistentConnections)) {
    const conn = _persistentConnections[id];
    if (conn) {
      clearInterval(conn.heartbeatTimer);
      try { conn.ws.close(1000); } catch {}
    }
  }
  for (const key of Object.keys(_persistentConnections)) {
    delete _persistentConnections[key];
  }
}

async function connectWithTimeout(token, status, index, name, timeoutMs) {
  return Promise.race([
    connectToken(token, status, index, name),
    new Promise((resolve) => setTimeout(() => resolve({ id: index, label: name || "?", idx: index, error: "Timeout" }), timeoutMs))
  ]);
}

async function connectBatch(tokens, statusFn, count, names) {
  let connected = 0;
  let failed = 0;

  const batchNum = Math.ceil(tokens.length / BATCH_SIZE);
  console.log(chalk.dim(`  ${tokens.length} tokens → ${batchNum} batches of ${BATCH_SIZE}, ${BATCH_DELAY/1000}s gap + jitter\n`));

  for (let i = 0; i < tokens.length; i += BATCH_SIZE) {
    const batch = tokens.slice(i, i + BATCH_SIZE);
    const batchIdx = Math.floor(i / BATCH_SIZE) + 1;
    console.log(chalk.cyan(`  Batch ${batchIdx}/${batchNum} (${batch.length} tokens)...`));

    const batchResults = [];
    for (let j = 0; j < batch.length; j++) {
      const token = batch[j];
      const idx = i + j + 1;
      const status = statusFn(idx - 1);
      const label = (names && names[idx - 1]) ? names[idx - 1] : `#${idx}`;
      const r = await connectWithTimeout(token, status, idx, label, TOKEN_TIMEOUT);
      batchResults.push(r);
      if (j < batch.length - 1) {
        const jitter = 500 + Math.random() * 1500;
        await sleep(jitter);
      }
    }

    for (const r of batchResults) {
      const idxNum = r.idx || 1;
      const display = (names && names[idxNum - 1]) ? names[idxNum - 1].padEnd(15) : r.label.padEnd(15);
      if (r.error) {
        failed++;
        console.log(chalk.red(`    [×] ${display} — ${r.error}`));
      } else {
        connected++;
        console.log(chalk.green(`    [✓] ${display} — connected`));
      }
    }
    console.log(chalk.dim(`  Progress: ${connected} ok, ${failed} failed`));
    if (i + BATCH_SIZE < tokens.length) {
      const batchGap = BATCH_DELAY + Math.random() * 2000;
      await sleep(batchGap);
    }
  }

  return { connected, failed };
}

async function handleChangeStatus(tokens) {
  console.log(chalk.cyan("\n  1. Online\n  2. Idle\n  3. Do Not Disturb\n  4. Invisible (Offline)\n"));
  const statusChoice = await askNumber("Choose status (1-4): ");
  const statuses = ["online", "idle", "dnd", "invisible"];
  let status = statuses[parseInt(statusChoice) - 1] || "online";
  if (status === "invisible") status = "offline";
  const countStr = await askText(`How many accounts? (available: ${tokens.length}): `);
  const count = parseInt(countStr) || tokens.length;

  const selectedTokens = tokens.slice(0, count);
  console.log(chalk.cyan(`[*] Fetching account names...`));
  const names = await Promise.all(selectedTokens.map(t => getName(t)));
  console.log(chalk.green(` Done\n`));

  console.log(chalk.cyan(`\n[*] Connecting ${count} accounts as "${status}"...\n`));
  const { connected, failed } = await connectBatch(selectedTokens, () => status, count, names);

  console.log(chalk.bold("\n══════════════════════════════════════"));
  console.log(chalk.bold.green(`  ${status}: ${connected}/${count}`));
  if (failed > 0) console.log(chalk.bold.red(`  Failed: ${failed}`));
  console.log(chalk.bold("══════════════════════════════════════\n"));

  if (connected > 0) {
    console.log(chalk.green(`[+] ${connected} accounts now ${status} with sleep-cycling mode.`));
    console.log(chalk.cyan("[*] Cycle: 20-22h ONLINE → 2-4h OFFLINE → repeat"));
    console.log(chalk.cyan("[*] Use option 14 to disconnect all connections.\n"));
    startCycling(selectedTokens, () => status, count, names);
  }
}

// 9. Change Bio
async function handleChangeBio(tokens) {
  const bio = await askText("New bio for all accounts: ");
  if (!bio) return;
  const countStr = await askText(`How many accounts? (available: ${tokens.length}): `);
  const count = parseInt(countStr) || tokens.length;

  const selectedTokens = tokens.slice(0, count);
  console.log(chalk.cyan(`[*] Fetching account names...`));
  const names = await Promise.all(selectedTokens.map(t => getName(t)));
  console.log(chalk.green(` Done\n`));

  console.log(chalk.cyan(`\n[*] Updating bios to "${bio}"...\n`));
  let success = 0;
  let failed = 0;

  for (let i = 0; i < selectedTokens.length; i++) {
    const result = await changeBio(selectedTokens[i], bio);
    if (result.success) {
      console.log(chalk.green(`[+] ${i + 1}/${selectedTokens.length} Bio updated OK — ${names[i]}`));
      success++;
    } else {
      console.log(chalk.red(`[×] ${i + 1}/${selectedTokens.length} Failed — ${names[i]} (${result.reason})`));
      failed++;
    }
    if (i < selectedTokens.length - 1) await randomDelay(600, 1500);
  }

  console.log(chalk.bold("\n══════════════════════════════════════"));
  console.log(chalk.bold.green(`  Updated: ${success}`));
  console.log(chalk.bold.red(`  Failed:  ${failed}`));
  console.log(chalk.bold("══════════════════════════════════════\n"));
}

// 10. Random Status
async function handleRandomStatus(tokens) {
  const countStr = await askText(`How many accounts? (available: ${tokens.length}): `);
  const count = parseInt(countStr) || tokens.length;

  const selectedTokens = tokens.slice(0, count);
  const statuses = ["online", "idle", "dnd"];

  console.log(chalk.cyan(`[*] Fetching account names...`));
  const names = await Promise.all(selectedTokens.map(t => getName(t)));
  console.log(chalk.green(` Done\n`));

  console.log(chalk.cyan(`\n[*] Connecting ${count} accounts with randomized statuses...\n`));

  const statusFn = () => statuses[Math.floor(Math.random() * statuses.length)];
  const { connected, failed } = await connectBatch(selectedTokens, statusFn, count, names);

  console.log(chalk.bold("\n══════════════════════════════════════"));
  console.log(chalk.bold.green(`  Connected: ${connected}/${count}`));
  if (failed > 0) console.log(chalk.bold.red(`  Failed:    ${failed}`));
  console.log(chalk.bold("══════════════════════════════════════\n"));

  if (connected > 0) {
    console.log(chalk.green(`[+] ${connected} accounts now online with randomized cycling mode.`));
    console.log(chalk.cyan("[*] Use option 14 to disconnect all connections.\n"));
    startCycling(selectedTokens, statusFn, count, names);
  }
}

// 11. Auto-React (Manual)
async function handleAutoReact(tokens) {
  const channelId = await askText("Channel ID: ");
  if (!channelId) return;
  const messageId = await askText("Message ID: ");
  if (!messageId) return;
  const countStr = await askText(`How many accounts? (available: ${tokens.length}): `);
  const count = parseInt(countStr) || tokens.length;
  const emojiStr = await askText("Emoji(s) separated by space (e.g. 👍 ❤️ 🔥): ");
  if (!emojiStr) return;
  const emojis = emojiStr.trim().split(/\s+/);

  const selectedTokens = tokens.slice(0, count);
  console.log(chalk.cyan(`\n[*] Reacting ${selectedTokens.length} accounts × ${emojis.length} emoji(s) with rate protection...\n`));

  let sent = 0;
  let failed = 0;

  for (let i = 0; i < selectedTokens.length; i++) {
    const token = selectedTokens[i];
    const accName = await getName(token);
    for (const emoji of emojis) {
      const res = await reactToMessage(token, channelId, messageId, emoji);
      if (res.success) {
        sent++;
        console.log(chalk.green(`  [✓] ${accName.padEnd(15)} + ${emoji}`));
      } else {
        failed++;
        console.log(chalk.red(`  [×] ${accName.padEnd(15)} - ${emoji} (${res.reason})`));
      }
      await sleep(350); // safe spacing between reactions
    }
  }

  console.log(chalk.bold("\n══════════════════════════════════════"));
  console.log(chalk.bold.green(`  Sent:   ${sent}/${emojis.length * selectedTokens.length}`));
  if (failed > 0) console.log(chalk.bold.red(`  Failed: ${failed}`));
  console.log(chalk.bold("══════════════════════════════════════\n"));
}

// 12. Auto-Detect React
async function handleAutoDetectReact(tokens) {
  const channelId = await askText("Channel ID: ");
  if (!channelId) return;
  const messageId = await askText("Message ID: ");
  if (!messageId) return;
  const countStr = await askText(`How many accounts? (available: ${tokens.length}): `);
  const count = parseInt(countStr) || tokens.length;

  const selectedTokens = tokens.slice(0, count);
  const firstToken = selectedTokens[0];

  console.log(chalk.cyan(`\n[*] Fetching message ${messageId} to detect reactions...\n`));

  let allEmojis = [];
  const msgRes = await apiRequest("GET", `/api/v9/channels/${channelId}/messages?limit=1&around=${messageId}`, firstToken, "Messages");

  if (msgRes.status === 200 && Array.isArray(msgRes.data) && msgRes.data.length > 0) {
    const target = msgRes.data[0];
    if (target && target.reactions && target.reactions.length > 0) {
      for (const r of target.reactions) {
        if (r.burst_colors && r.burst_colors.length > 0) {
          continue;
        }
        const en = r.emoji.id ? `${r.emoji.name}:${r.emoji.id}` : r.emoji.name;
        allEmojis.push(en);
      }
    }
  } else {
    const errMsg = typeof msgRes.data === "object" ? msgRes.data?.message || JSON.stringify(msgRes.data) : String(msgRes.data || "Unknown");
    console.log(chalk.yellow(`[!] ${msgRes.status}: ${errMsg}\n`));
  }

  if (allEmojis.length === 0) {
    console.log(chalk.yellow("[!] No reactions found on that message.\n"));
    return;
  }

  console.log(chalk.green(`[+] Detected reactions: ${allEmojis.join(", ")}\n`));
  console.log(chalk.cyan(`[*] Applying reactions with rate-limit protection...\n`));

  let sent = 0;
  let failed = 0;

  for (let i = 0; i < selectedTokens.length; i++) {
    const token = selectedTokens[i];
    const accName = await getName(token);
    for (const emoji of allEmojis) {
      const res = await reactToMessage(token, channelId, messageId, emoji);
      if (res.success) {
        sent++;
        console.log(chalk.green(`  [✓] ${accName.padEnd(15)} + ${emoji}`));
      } else {
        failed++;
        console.log(chalk.red(`  [×] ${accName.padEnd(15)} - ${emoji} (${res.reason})`));
      }
      await sleep(350);
    }
  }

  console.log(chalk.bold("\n══════════════════════════════════════"));
  console.log(chalk.bold.green(`  Sent:   ${sent}/${allEmojis.length * selectedTokens.length}`));
  if (failed > 0) console.log(chalk.bold.red(`  Failed: ${failed}`));
  console.log(chalk.bold("══════════════════════════════════════\n"));
}

// 13. Join VC
function connectTokenVC(token, guildId, channelId, index, name, attempt = 0) {
  const label = name || maskToken(token);
  const MAX_RETRIES = 2;
  const VC_TIMEOUT = 10000;
  const numericIndex = typeof index === "number" ? index : parseInt(String(index).split("/")[0]) || 1;
  const proxyUrl = getProxy(numericIndex - 1);

  return new Promise((resolve) => {
    let done = false;
    const finish = (val) => { if (!done) { done = true; resolve(val); } };
    const timer = setTimeout(() => finish({ success: false, reason: "Timeout" }), VC_TIMEOUT);

    const fp = randomFingerprint();
    const reqOpts = {
      hostname: "discord.com",
      path: "/api/v9/gateway",
      method: "GET",
      headers: { "User-Agent": fp.ua },
      timeout: 5000,
    };
    if (proxyUrl) reqOpts.agent = new HttpsProxyAgent(proxyUrl);

    const req = https.request(reqOpts, (res) => {
      let body = "";
      res.on("data", (c) => (body += c));
      res.on("end", () => {
        try {
          const { url } = JSON.parse(body);
          if (!url) {
            clearTimeout(timer);
            finish({ success: false, reason: "No gateway URL" });
            return;
          }

          const wsOpts = { headers: { "User-Agent": fp.ua } };
          if (proxyUrl) wsOpts.agent = new HttpsProxyAgent(proxyUrl);

          const ws = new WebSocket(url + "?v=9&encoding=json", wsOpts);
          let heartbeatTimer;
          let ready = false;

          ws.on("open", () => {
            if (!canIdentify(token)) {
              console.log(chalk.red(`[!] ${label} IDENTIFY limit reached (VC) — skipping`));
              try { ws.close(1000); } catch {}
              finish({ success: false, reason: "IDENTIFY limit" });
              return;
            }
            recordIdentify(token);
            ws.send(JSON.stringify({
              op: 2,
              d: {
                token,
                properties: { $os: "windows", $browser: "Discord Client", $device: "" },
                presence: { status: "online", since: 0, activities: [], afk: false },
              },
            }));
          });

          ws.on("message", (raw) => {
            try {
              const msg = JSON.parse(raw);
              if (msg.op === 10) {
                clearInterval(heartbeatTimer);
                heartbeatTimer = setInterval(() => {
                  try { ws.send(JSON.stringify({ op: 1, d: null })); } catch {}
                }, msg.d.heartbeat_interval);
              }

              if (msg.op === 0 && msg.t === "READY" && !ready) {
                ready = true;
                clearTimeout(timer);
                ws.send(JSON.stringify({ op: 4, d: { guild_id: guildId, channel_id: channelId, self_mute: false, self_deaf: false } }));
                const close = () => { clearInterval(heartbeatTimer); try { ws.close(1000); } catch {} };
                activeVC.push(close);
                finish({ success: true, token: label });
              }
            } catch {}
          });

          ws.on("error", () => {
            clearInterval(heartbeatTimer);
            clearTimeout(timer);
            if (!ready && attempt < MAX_RETRIES) {
              const delay = 3000;
              setTimeout(() => connectTokenVC(token, guildId, channelId, index, name, attempt + 1).then(finish), delay);
            } else if (!ready) {
              finish({ success: false, reason: "Connection error" });
            }
          });

          ws.on("close", (code) => {
            clearInterval(heartbeatTimer);
            clearTimeout(timer);
            if (!ready && code !== 1000 && attempt < MAX_RETRIES) {
              const delay = 3000;
              setTimeout(() => connectTokenVC(token, guildId, channelId, index, name, attempt + 1).then(finish), delay);
            } else if (!ready && code !== 1000) {
              finish({ success: false, reason: `Disconnected (${code})` });
            }
          });
        } catch {
          clearTimeout(timer);
          finish({ success: false, reason: "Failed to parse gateway" });
        }
      });
    });

    req.on("error", () => {
      clearTimeout(timer);
      finish({ success: false, reason: "Network error" });
    });
    req.end();
  });
}

async function handleJoinVCs(tokens) {
  const guildId = await askText("Server ID: ");
  if (!guildId) return;
  const channelId = await askText("Voice Channel ID: ");
  if (!channelId) return;
  const countStr = await askText(`How many accounts? (available: ${tokens.length}): `);
  const count = parseInt(countStr) || tokens.length;

  const selectedTokens = tokens.slice(0, count);

  console.log(chalk.cyan(`[*] Fetching account names...`));
  const names = await Promise.all(selectedTokens.map(t => getName(t)));
  console.log(chalk.green(` Done\n`));

  console.log(chalk.cyan(`\n[*] Connecting ${selectedTokens.length} accounts to Voice Channel ${channelId}...\n`));

  let success = 0;
  let failed = 0;
  const VC_BATCH = 5;
  const VC_BATCH_DELAY = 3000;

  for (let i = 0; i < selectedTokens.length; i += VC_BATCH) {
    const batch = selectedTokens.slice(i, i + VC_BATCH);
    const batchIdx = Math.floor(i / VC_BATCH) + 1;
    const batchTotal = Math.ceil(selectedTokens.length / VC_BATCH);
    console.log(chalk.cyan(`  Batch ${batchIdx}/${batchTotal} (${batch.length} accounts)...`));

    const results = await Promise.all(
      batch.map((t, j) => connectTokenVC(t, guildId, channelId, i + j + 1, names[i + j]))
    );

    for (let j = 0; j < results.length; j++) {
      const r = results[j];
      if (r && r.success) {
        success++;
        console.log(chalk.green(`    [✓] ${names[i + j].padEnd(15)} connected to VC`));
      } else {
        failed++;
        console.log(chalk.red(`    [×] ${names[i + j].padEnd(15)} failed — ${r ? r.reason : 'timeout'}`));
      }
    }

    if (i + VC_BATCH < selectedTokens.length) {
      await sleep(VC_BATCH_DELAY);
    }
  }

  console.log(chalk.bold("\n══════════════════════════════════════"));
  console.log(chalk.bold.green(`  Joined VC: ${success}/${selectedTokens.length}`));
  if (failed > 0) console.log(chalk.bold.red(`  Failed:    ${failed}`));
  console.log(chalk.bold("══════════════════════════════════════\n"));
}

// 14. Disconnect ALL
function handleDisconnectAll() {
  _cyclingActive = false;
  let total = 0;

  if (activeVC.length > 0) {
    const vcCount = activeVC.length;
    console.log(chalk.dim(`[*] Disconnecting ${vcCount} accounts from Voice Channels...`));
    activeVC.forEach((close) => {
      try { close(); } catch {}
    });
    activeVC = [];
    total += vcCount;
  }

  const statusCount = Object.keys(_persistentConnections).length;
  if (statusCount > 0) {
    console.log(chalk.dim(`[*] Disconnecting ${statusCount} gateway status sessions...`));
    disconnectAllPersistent();
    total += statusCount;
  }

  if (total === 0) {
    console.log(chalk.yellow("[!] No active connections found.\n"));
  } else {
    console.log(chalk.green(`[+] All ${total} connections disconnected cleanly.\n`));
  }
}

// 15. Click Message Button
async function handleClickButton(tokens) {
  const channelId = await askText("Channel ID: ");
  if (!channelId) return;
  const messageId = await askText("Message ID: ");
  if (!messageId) return;
  const countStr = await askText(`How many accounts? (available: ${tokens.length}): `);
  const count = parseInt(countStr) || tokens.length;

  const selectedTokens = tokens.slice(0, count);
  const first = await fetchMessageComponents(selectedTokens[0], channelId, messageId);
  if (!first.success || first.components.length === 0) {
    console.log(chalk.yellow("[!] No buttons found on that message.\n"));
    return;
  }
  console.log(chalk.cyan("\n  Available buttons:"));
  first.components.forEach((b, i) => console.log(chalk.cyan(`  ${i + 1}. ${b.label || "No Label"} [${b.customId}]${b.disabled ? " (DISABLED)" : ""}`)));
  console.log();
  const choice = await askNumber("Which button number? ");
  const idx = parseInt(choice) - 1;
  if (idx < 0 || idx >= first.components.length) { console.log(chalk.red("[!] Invalid choice\n")); return; }
  const customId = first.components[idx].customId;

  // Pre-fetch message & guild metadata once to optimize API usage
  const channelRes = await apiRequest("GET", `/api/v9/channels/${channelId}`, selectedTokens[0], "Messages");
  const guildId = channelRes.status === 200 ? channelRes.data?.guild_id : null;
  const msgRes = await apiRequest("GET", `/api/v9/channels/${channelId}/messages?limit=50&around=${messageId}`, selectedTokens[0], "Messages");
  const msgs = Array.isArray(msgRes.data) ? msgRes.data : [];
  const targetMsg = msgs.find(m => m.id === messageId);
  const cachedMeta = {
    guildId,
    applicationId: targetMsg?.application_id || targetMsg?.author?.id,
    messageFlags: targetMsg?.flags || 0,
  };

  console.log(chalk.cyan(`\n[*] Clicking "${customId}" on ${selectedTokens.length} accounts...\n`));

  let success = 0;
  let failed = 0;

  for (let i = 0; i < selectedTokens.length; i++) {
    const r = await clickMessageButton(selectedTokens[i], channelId, messageId, customId, cachedMeta);
    const tag = `[${String(i + 1).padStart(3, " ")}/${selectedTokens.length}]`;
    const accName = await getName(selectedTokens[i]);
    if (r.success) {
      console.log(chalk.green(`  ${tag} ${accName.padEnd(15)} ✓ Clicked`));
      success++;
    } else {
      console.log(chalk.red(`  ${tag} ${accName.padEnd(15)} ✗ ${r.reason}`));
      failed++;
    }
    if (i < selectedTokens.length - 1) await randomDelay(600, 1500);
  }

  console.log(chalk.bold("\n══════════════════════════════════════"));
  console.log(chalk.bold.green(`  Clicked: ${success}`));
  if (failed > 0) console.log(chalk.bold.red(`  Failed:  ${failed}`));
  console.log(chalk.bold("══════════════════════════════════════\n"));
}

// 16. 24/7 Persistent Status
async function handlePersistentStatus(tokens) {
  console.log(chalk.cyan("\n  1. Online\n  2. Idle\n  3. Do Not Disturb\n  4. Random (Each account gets random)\n"));
  const statusChoice = await askNumber("Choose status (1-4): ");
  const statuses = ["online", "idle", "dnd"];
  const isRandom = statusChoice === "4";
  const defaultStatus = statuses[parseInt(statusChoice) - 1] || "online";
  const countStr = await askText(`How many accounts? (available: ${tokens.length}): `);
  const count = parseInt(countStr) || tokens.length;

  const selectedTokens = tokens.slice(0, count);

  console.log(chalk.cyan(`[*] Fetching account names...`));
  const names = await Promise.all(selectedTokens.map(t => getName(t)));
  console.log(chalk.green(` Done\n`));

  const modeText = isRandom ? "random" : defaultStatus;
  console.log(chalk.cyan(`\n[*] Setting 24/7 ${modeText} status for ${count} accounts...\n`));

  const statusFn = isRandom ? () => statuses[Math.floor(Math.random() * statuses.length)] : () => defaultStatus;
  const { connected, failed } = await connectBatch(selectedTokens, statusFn, count, names);

  console.log(chalk.bold("\n══════════════════════════════════════"));
  console.log(chalk.bold.green(`  24/7 Active: ${connected}/${count} (${modeText})`));
  if (failed > 0) console.log(chalk.bold.red(`  Failed:      ${failed}`));
  console.log(chalk.bold("══════════════════════════════════════\n"));

  if (connected > 0) {
    console.log(chalk.green(`[+] ${connected} accounts now active with sleep-cycling mode.`));
    console.log(chalk.cyan("[*] Cycle: 20-22h ONLINE → 2-4h OFFLINE → repeat"));
    console.log(chalk.cyan("[*] Use option 14 to disconnect all connections.\n"));
    startCycling(selectedTokens, statusFn, count, names);
  }
}

// 17. Leave Server(s)
async function handleLeaveServer(tokens) {
  console.log(chalk.dim("  Enter one or more Server IDs separated by commas."));
  console.log(chalk.dim("  Example: 1234567890123, 9876543210987\n"));
  const input = await askText("Server ID(s): ");
  if (!input) return;

  const guildIds = input
    .split(",")
    .map(id => id.trim())
    .filter(id => id.length > 0 && /^\d+$/.test(id));

  if (guildIds.length === 0) {
    console.log(chalk.red("[!] No valid numeric Server IDs provided.\n"));
    return;
  }

  console.log(chalk.cyan(`[+] ${guildIds.length} server(s) to leave: ${guildIds.join(", ")}\n`));
  const countStr = await askText(`How many accounts to leave? (available: ${tokens.length}): `);
  const count = parseInt(countStr) || tokens.length;

  const selectedTokens = tokens.slice(0, count);
  console.log(chalk.cyan(`[*] Fetching account names...`));
  const names = await Promise.all(selectedTokens.map(t => getName(t)));
  console.log(chalk.green(` Done\n`));

  let totalSuccess = 0;
  let totalFailed = 0;
  let totalNotInServer = 0;

  for (const guildId of guildIds) {
    console.log(chalk.bold.cyan(`\n══ Leaving server: ${guildId} ══\n`));
    let success = 0;
    let failed = 0;
    let notInServer = 0;

    for (let i = 0; i < selectedTokens.length; i++) {
      const result = await leaveServer(selectedTokens[i], guildId);
      const tag = `[${String(i + 1).padStart(3, " ")}/${selectedTokens.length}]`;
      if (result.success) {
        console.log(chalk.green(`  ${tag} ${names[i].padEnd(15)} ✓ Left`));
        success++;
      } else if ((result.reason || "").toLowerCase().includes("not in server") || (result.reason || "").includes("Unknown Guild") || (result.reason || "").includes("not found")) {
        console.log(chalk.dim(`  ${tag} ${names[i].padEnd(15)} ~ Not in server`));
        notInServer++;
      } else {
        console.log(chalk.red(`  ${tag} ${names[i].padEnd(15)} ✗ ${result.reason}`));
        failed++;
      }
      if (i < selectedTokens.length - 1) await randomDelay(500, 1500);
    }

    totalSuccess += success;
    totalFailed += failed;
    totalNotInServer += notInServer;
  }

  console.log(chalk.bold("\n══════════════════════════════════════"));
  console.log(chalk.bold.green(`  Total Left:          ${totalSuccess}`));
  console.log(chalk.bold.yellow(`  Total Not in server: ${totalNotInServer}`));
  if (totalFailed > 0) console.log(chalk.bold.red(`  Total Failed:        ${totalFailed}`));
  console.log(chalk.bold("══════════════════════════════════════\n"));
}

// 18. Test Proxies
async function handleTestProxies() {
  const proxies = loadProxies();
  if (proxies.length === 0) {
    console.log(chalk.yellow("[!] No proxies found in proxies.txt. Add proxies first.\n"));
    return;
  }
  console.log(chalk.cyan(`[*] Testing ${proxies.length} proxies against Discord gateway...\n`));

  let alive = 0;
  let dead = 0;

  for (let i = 0; i < proxies.length; i++) {
    const p = proxies[i];
    const masked = p.replace(/\/\/[^:]+:[^@]+@/, "//***:***@");
    process.stdout.write(chalk.dim(`  [${i + 1}/${proxies.length}] Testing ${masked}... `));
    const r = await testProxyConnection(p);
    if (r.success) {
      alive++;
      console.log(chalk.green(`✓ ALIVE (${r.latency}ms)`));
    } else {
      dead++;
      console.log(chalk.red(`✗ DEAD (${r.error || "Failed"})`));
    }
  }

  console.log(chalk.bold("\n══════════════════════════════════════"));
  console.log(chalk.bold.green(`  Working Proxies: ${alive}`));
  if (dead > 0) console.log(chalk.bold.red(`  Dead / Blocked:  ${dead}`));
  console.log(chalk.bold("══════════════════════════════════════\n"));
}

// 19. Token Storage & Encryption
async function handleTokenStorage() {
  console.log(chalk.cyan("\n  Token Storage Security:"));
  console.log(chalk.cyan("  1. Encrypt tokens.txt -> tokens.enc (AES-256-GCM)"));
  console.log(chalk.cyan("  2. Decrypt tokens.enc -> tokens.txt"));
  console.log(chalk.cyan("  3. View current storage status\n"));

  const choice = await askNumber("Choose action (1-3): ");
  if (choice === "1") {
    const tokens = secureReadTokens();
    if (tokens.length === 0) {
      console.log(chalk.yellow("[!] No tokens available to encrypt.\n"));
      return;
    }
    const key = getOrCreateEncryptionKey();
    const encrypted = encryptTokens(tokens, key);
    fs.writeFileSync(ENC_TOKENS_FILE, encrypted, "utf-8");
    console.log(chalk.green(`[+] Successfully encrypted ${tokens.length} tokens to tokens.enc using .key\n`));
  } else if (choice === "2") {
    if (!fs.existsSync(ENC_TOKENS_FILE) || !fs.existsSync(KEY_FILE)) {
      console.log(chalk.yellow("[!] tokens.enc or .key not found.\n"));
      return;
    }
    const encContent = fs.readFileSync(ENC_TOKENS_FILE, "utf-8");
    const decrypted = decryptTokens(encContent);
    if (decrypted.length === 0) {
      console.log(chalk.red("[!] Failed to decrypt tokens.enc. Check .key\n"));
      return;
    }
    fs.writeFileSync(TOKENS_FILE, decrypted.join("\n") + "\n", "utf-8");
    console.log(chalk.green(`[+] Successfully decrypted ${decrypted.length} tokens to tokens.txt\n`));
  } else if (choice === "3") {
    const hasPlain = fs.existsSync(TOKENS_FILE);
    const hasEnc = fs.existsSync(ENC_TOKENS_FILE);
    const hasKey = fs.existsSync(KEY_FILE);
    console.log(chalk.dim(`\n  Plain tokens.txt:     ${hasPlain ? "Present" : "Missing"}`));
    console.log(chalk.dim(`  Encrypted tokens.enc: ${hasEnc ? "Present" : "Missing"}`));
    console.log(chalk.dim(`  Encryption Key .key:  ${hasKey ? "Present" : "Missing"}\n`));
  }
}

// Background sleep-cycling
async function startCycling(selectedTokens, statusFn, count, names) {
  _cyclingActive = true;

  while (_cyclingActive) {
    const onlineTime = CYCLE_ONLINE_MIN + Math.random() * (CYCLE_ONLINE_MAX - CYCLE_ONLINE_MIN);
    const onH = Math.floor(onlineTime / 3600000);
    const onM = Math.floor((onlineTime % 3600000) / 60000);
    console.log(chalk.cyan(`\n[cycle] Accounts ONLINE for ~${onH}h ${onM}m\n`));
    await sleep(onlineTime);
    if (!_cyclingActive) break;

    console.log(chalk.yellow(`\n[cycle] Going OFFLINE for rest period...\n`));
    disconnectAllPersistent();

    const offlineTime = CYCLE_OFFLINE_MIN + Math.random() * (CYCLE_OFFLINE_MAX - CYCLE_OFFLINE_MIN);
    const offH = Math.floor(offlineTime / 3600000);
    const offM = Math.floor((offlineTime % 3600000) / 60000);
    console.log(chalk.yellow(`[cycle] Staying offline ~${offH}h ${offM}m...\n`));
    await sleep(offlineTime);
    if (!_cyclingActive) break;

    console.log(chalk.green(`\n[cycle] Reconnecting all accounts...\n`));
    _cyclingActive = true;
    const { connected } = await connectBatch(selectedTokens, statusFn, count, names);
    console.log(chalk.green(`[cycle] ${connected}/${count} accounts back ONLINE!\n`));
  }
}

// Main Interactive Loop
async function main() {
  console.log(chalk.bold.cyan("\n╔═════════════════════════════════════════════════╗"));
  console.log(chalk.bold.cyan("║        Multi Discord Accounts Controller        ║"));
  console.log(chalk.bold.cyan("║           v2.0 — Enhanced & Optimized           ║"));
  console.log(chalk.bold.cyan("╚═════════════════════════════════════════════════╝\n"));

  const ACTIONS = {
    "1": "join", "2": "quickjoin", "3": "nickname", "4": "globalname",
    "5": "check", "6": "clean", "7": "friend", "8": "status",
    "9": "bio", "10": "randomstatus", "11": "autoreact", "12": "autodetectreact",
    "13": "vcjoin", "14": "disconnectall", "15": "clickbtn", "16": "persistentstatus",
    "17": "leaveserver", "18": "testproxies", "19": "tokenstorage", "0": "exit",
  };

  while (true) {
    console.log(chalk.cyan("  1.  Bulk join server"));
    console.log(chalk.cyan("  2.  Quick join (custom token + server)"));
    console.log(chalk.cyan("  3.  Change server nickname"));
    console.log(chalk.cyan("  4.  Change global display name"));
    console.log(chalk.cyan("  5.  Check tokens (valid / locked / invalid)"));
    console.log(chalk.cyan("  6.  Remove invalid & dead tokens"));
    console.log(chalk.cyan("  7.  Send friend requests"));
    console.log(chalk.cyan("  8.  Set status (Online / Idle / DND / Invisible)"));
    console.log(chalk.cyan("  9.  Change profile bio / About Me"));
    console.log(chalk.cyan("  10. Set random status"));
    console.log(chalk.cyan("  11. Auto-react (manual emoji list)"));
    console.log(chalk.cyan("  12. Auto-react (mirror existing message reactions)"));
    console.log(chalk.cyan("  13. Join Voice Channels (VCs)"));
    console.log(chalk.cyan("  14. Disconnect ALL (Gateway status + Voice Channels)"));
    console.log(chalk.cyan("  15. Click message button (rules / roles / verification)"));
    console.log(chalk.cyan("  16. Set 24/7 persistent status (with sleep cycle)"));
    console.log(chalk.cyan("  17. Leave server(s) — supports multiple IDs"));
    console.log(chalk.cyan("  18. Test proxies (latency & connectivity)"));
    console.log(chalk.cyan("  19. Token storage (AES-256-GCM encryption / decryption)"));
    console.log(chalk.red("  0.  Exit\n"));

    const choice = await askNumber("Enter choice (0-19): ");
    const action = ACTIONS[choice];
    if (!action) { console.log(chalk.red("[!] Invalid choice\n")); continue; }
    if (action === "exit") {
      console.log(chalk.cyan("\nDisconnecting and exiting...\n"));
      handleDisconnectAll();
      closeAllGateways();
      if (_rl) _rl.close();
      break;
    }

    if (action === "quickjoin") {
      await handleQuickJoin();
      continue;
    }

    if (action === "disconnectall") {
      handleDisconnectAll();
      continue;
    }

    if (action === "testproxies") {
      await handleTestProxies();
      continue;
    }

    if (action === "tokenstorage") {
      await handleTokenStorage();
      continue;
    }

    const tokens = readTokens();
    if (!tokens) continue;

    console.log(chalk.green(`[+] Total accounts loaded: ${tokens.length}\n`));

    if (action === "join") await handleJoinServer(tokens);
    else if (action === "nickname") await handleChangeNickname(tokens);
    else if (action === "globalname") await handleChangeGlobalName(tokens);
    else if (action === "check") await handleCheckTokens(tokens);
    else if (action === "clean") await handleCleanTokens();
    else if (action === "friend") await handleAddFriends(tokens);
    else if (action === "status") await handleChangeStatus(tokens);
    else if (action === "bio") await handleChangeBio(tokens);
    else if (action === "randomstatus") await handleRandomStatus(tokens);
    else if (action === "autoreact") await handleAutoReact(tokens);
    else if (action === "autodetectreact") await handleAutoDetectReact(tokens);
    else if (action === "vcjoin") await handleJoinVCs(tokens);
    else if (action === "clickbtn") await handleClickButton(tokens);
    else if (action === "persistentstatus") await handlePersistentStatus(tokens);
    else if (action === "leaveserver") await handleLeaveServer(tokens);
  }
}

main().catch((err) => {
  console.error(chalk.red("[!] Error:"), err);
});

const onExit = () => {
  console.log(chalk.yellow("\n[*] Shutting down cleanly..."));
  disconnectAllPersistent();
  closeAllGateways();
  if (_rl) _rl.close();
  process.exit(0);
};

process.on("SIGINT", onExit);
process.on("SIGTERM", onExit);
process.on("uncaughtException", (e) => { console.error(chalk.red("[!] Uncaught Exception:"), e.message); });
process.on("unhandledRejection", (e) => { console.error(chalk.red("[!] Unhandled Rejection:"), e); });
