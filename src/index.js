const fs = require("fs");
const path = require("path");
const https = require("https");
const WebSocket = require("ws");
const chalk = require("chalk");
const { apiRequest, sleep, randomDelay, resolveInvite, getUsersGuilds, isAlreadyMember, joinServer, joinWithCaptcha, changeNickname, changeGlobalName, leaveServer, changeBio, sendFriendRequest, reactToMessage, fetchReactionUsers, fetchMessageComponents, clickMessageButton, closeAllGateways, maskToken } = require("./core");
const { secureReadTokens, secureWriteTokens, hashTokenForProfile } = require("./security");

const TOKENS_FILE = path.join(__dirname, "..", "tokens.txt");
const CONFIG_FILE = path.join(__dirname, "..", "config.json");

let activeVC = [];
let activeStatus = [];
const nameCache = {};

let config = { captcha_key: "" };
try {
  if (fs.existsSync(CONFIG_FILE)) {
    config = JSON.parse(fs.readFileSync(CONFIG_FILE, "utf-8"));
  }
} catch {}

const STAGGER_MIN = Math.max(1, parseInt(config.connect_stagger_min_s) || 6) * 1000;
const STAGGER_MAX = Math.max(STAGGER_MIN + 1000, parseInt(config.connect_stagger_max_s) || 14) * 1000;

async function getName(token) {
  if (nameCache[token]) return nameCache[token];
  const data = await new Promise((resolve) => {
    let done = false;
    const timer = setTimeout(() => {
      if (!done) { done = true; resolve(null); }
    }, 8000);
    const req = https.request({
      hostname: "discord.com", path: "/api/v9/users/@me", method: "GET",
      headers: { authorization: token },
      timeout: 7000,
    }, (res) => {
      let b = "";
      res.on("data", c => b += c);
      res.on("end", () => { if (!done) { done = true; clearTimeout(timer); try { resolve(JSON.parse(b)); } catch { resolve(null); } } });
    });
    req.on("error", () => { if (!done) { done = true; clearTimeout(timer); resolve(null); } });
    req.on("timeout", () => { req.destroy(); if (!done) { done = true; clearTimeout(timer); resolve(null); } });
    req.end();
  });
  let name = "?";
  if (data && data.id) {
    name = (data.global_name || data.username || data.id).replace(/[^\x20-\x7E]/g, "");
    if (!name) name = data.id.slice(0, 8);
  }
  if (name.length > 12) name = name.slice(0, 12);
  nameCache[token] = name;
  return name;
}

function readTokens(optional) {
  const tokens = secureReadTokens();
  if (tokens.length === 0) {
    if (optional) return [];
    console.error(chalk.red("[!] No tokens found. Add tokens to tokens.txt or use encrypted storage."));
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

function manualCaptchaSolve() {
  return Promise.resolve(null);
}

async function handleJoinServer(tokens) {
  const invite = await askText("Invite link (discord.gg/CODE): ");
  if (!invite) return;
  const countStr = await askText(`How many accounts to join? (available: ${tokens.length}): `);
  const count = parseInt(countStr) || tokens.length;

  const inviteCode = extractInviteCode(invite);

  console.log(chalk.cyan(`\n[+] Resolving invite: ${inviteCode}...`));
  console.log(chalk.dim(`  (from input: ${invite})`));
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
    console.log(chalk.yellow("[!] Could not resolve invite, check link.\n"));
  }

  console.log(chalk.cyan("[*] Checking who's already in the server...\n"));
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
    console.log(chalk.bold.yellow("[!] All already in server, nothing to do!\n"));
    return;
  }

  console.log(chalk.cyan(`[*] Fetching account names...`));
  const joinNames = await Promise.all(toJoin.map(t => getName(t)));
  console.log(chalk.green(` Done`));
  joinNames.forEach((n, i) => console.log(chalk.dim(`  ${i + 1}. ${n}`)));
  console.log();

  let success = 0;
  let failed = 0;

  for (let i = 0; i < toJoin.length; i++) {
    const result = await joinServer(toJoin[i], inviteCode);
    const tag = `[${String(i + 1).padStart(3, " ")}/${toJoin.length}]`;
    if (result.success) {
      console.log(chalk.green(`  ${tag} ${joinNames[i].padEnd(15)} ✓`));
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

async function handleLeaveServer(tokens) {
  console.log(chalk.dim("  Enter one or more Server IDs, separated by commas."));
  console.log(chalk.dim("  Example: 1234567890123, 9876543210987, 5555555555555\n"));
  const input = await askText("Server ID(s): ");
  if (!input) return;

  const guildIds = input
    .split(",")
    .map(id => id.trim())
    .filter(id => id.length > 0 && /^\d+$/.test(id));

  if (guildIds.length === 0) {
    console.log(chalk.red("[!] No valid Server IDs provided. IDs must be numbers only.\n"));
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

    console.log(chalk.dim(`  └─ ${guildId}: Left ${success} | Not in ${notInServer} | Failed ${failed}`));
  }

  console.log(chalk.bold("\n══════════════════════════════════════"));
  console.log(chalk.bold.green(`  Total Left:         ${totalSuccess}`));
  console.log(chalk.bold.yellow(`  Total Not in server: ${totalNotInServer}`));
  console.log(chalk.bold.red(`  Total Failed:        ${totalFailed}`));
  console.log(chalk.bold(`  Servers processed:   ${guildIds.length}`));
  console.log(chalk.bold("══════════════════════════════════════\n"));
}

async function handleChangeNickname(tokens) {
  const guildId = await askText("Server ID (right-click server → Copy ID): ");
  if (!guildId) return;
  const nickname = await askText("New nickname for all accounts: ");
  if (!nickname) return;
  const countStr = await askText(`How many accounts? (available: ${tokens.length}): `);
  const count = parseInt(countStr) || tokens.length;

  const selectedTokens = tokens.slice(0, count);
  console.log(chalk.cyan(`[*] Fetching account names...`));
  const names = await Promise.all(selectedTokens.map(t => getName(t)));
  console.log(chalk.green(` Done\n`));

  console.log(chalk.cyan(`\n[*] Changing nicknames to "${nickname}"...\n`));
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
  }

  console.log(chalk.bold("\n══════════════════════════════════════"));
  console.log(chalk.bold.green(`  Changed: ${success}`));
  console.log(chalk.bold.red(`  Failed:  ${failed}`));
  console.log(chalk.bold("══════════════════════════════════════\n"));
}

async function handleChangeGlobalName(tokens) {
  const name = await askText("New global display name (visible everywhere): ");
  if (!name) return;
  const countStr = await askText(`How many accounts? (available: ${tokens.length}): `);
  const count = parseInt(countStr) || tokens.length;

  const displayName = name;
  const selectedTokens = tokens.slice(0, count);
  console.log(chalk.cyan(`[*] Fetching account names...`));
  const names = await Promise.all(selectedTokens.map(t => getName(t)));
  console.log(chalk.green(` Done\n`));

  console.log(chalk.cyan(`\n[*] Changing display names to "${displayName}"...\n`));
  let success = 0;
  let failed = 0;

  for (let i = 0; i < selectedTokens.length; i++) {
    const result = await changeGlobalName(selectedTokens[i], displayName);
    if (result.success) {
      console.log(chalk.green(`[+] ${i + 1}/${selectedTokens.length} Name changed OK — ${names[i]}`));
      success++;
    } else {
      console.log(chalk.red(`[×] ${i + 1}/${selectedTokens.length} Failed — ${names[i]} (${result.reason})`));
      failed++;
    }
  }

  console.log(chalk.bold("\n══════════════════════════════════════"));
  console.log(chalk.bold.green(`  Changed: ${success}`));
  console.log(chalk.bold.red(`  Failed:  ${failed}`));
  console.log(chalk.bold("══════════════════════════════════════\n"));
}

async function handleCleanTokens() {
  console.log(chalk.cyan("[*] Reading tokens and checking...\n"));

  const tokens = secureReadTokens();
  if (tokens.length === 0) {
    console.log(chalk.yellow("[!] No tokens found.\n"));
    return;
  }

  const validTokens = [];
  let checked = 0;

  for (const token of tokens) {
    const res = await apiRequest("GET", "/api/v9/users/@me", token);
    checked++;
    if (res.status === 200) {
      validTokens.push(token);
      const name = res.data.global_name || res.data.username || "?";
      console.log(chalk.green(`[+] ${checked}/${tokens.length} Valid   — ${name}`));
    } else {
      console.log(chalk.red(`[×] ${checked}/${tokens.length} Invalid — ${maskToken(token)}`));
    }
  }

  const removedCount = tokens.length - validTokens.length;
  secureWriteTokens(validTokens);

  console.log(chalk.bold("\n══════════════════════════════════════"));
  console.log(chalk.bold.green(`  Valid tokens kept:   ${validTokens.length}`));
  console.log(chalk.bold.red(`  Invalid removed:     ${removedCount}`));
  console.log(chalk.bold("══════════════════════════════════════\n"));
}

async function handleCheckTokens(tokens) {
  console.log(chalk.cyan("[*] Checking tokens...\n"));
  let valid = 0;
  let invalid = 0;

  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    const res = await apiRequest("GET", "/api/v9/users/@me", token);
    if (res.status === 200) {
      const name = res.data.global_name || res.data.username || "?";
      console.log(chalk.green(`[+] ${i + 1}/${tokens.length} Valid   — ${name} (${res.data.id})`));
      valid++;
    } else {
      let reason = typeof res.data === "object" ? res.data.message : res.data;
      console.log(chalk.red(`[×] ${i + 1}/${tokens.length} Invalid — ${await getName(token)} (${reason || res.status})`));
      invalid++;
    }
  }

  console.log(chalk.bold("\n══════════════════════════════════════"));
  console.log(chalk.bold.green(`  Valid:   ${valid}`));
  console.log(chalk.bold.red(`  Invalid: ${invalid}`));
  console.log(chalk.bold("══════════════════════════════════════\n"));
}

async function handleAddFriends(tokens) {
  console.log(chalk.cyan("[*] Fetching user IDs for all tokens...\n"));

  const accounts = [];
  for (let i = 0; i < tokens.length; i++) {
    const res = await apiRequest("GET", "/api/v9/users/@me", tokens[i]);
    if (res.status === 200) {
      accounts.push({ token: tokens[i], id: res.data.id, name: res.data.global_name || res.data.username || "?" });
      console.log(chalk.green(`[+] ${i + 1}/${tokens.length} ${accounts[accounts.length - 1].name} (${res.data.id})`));
    } else {
      console.log(chalk.red(`[×] ${i + 1}/${tokens.length} Invalid token, skip`));
    }
  }

  if (accounts.length < 2) {
    console.log(chalk.yellow("[!] Need at least 2 valid tokens for friendships.\n"));
    return;
  }

  console.log(chalk.cyan(`\n[*] Sending friend requests between ${accounts.length} accounts...\n`));

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
      await randomDelay(1000, 3000);
    }
  }

  console.log(chalk.bold("\n══════════════════════════════════════"));
  console.log(chalk.bold.green(`  Friend requests sent: ${sent}/${totalPairs}`));
  console.log(chalk.bold.red(`  Failed:               ${failed}`));
  console.log(chalk.bold("══════════════════════════════════════\n"));
}

const _persistentConnections = {};
let _activeConnections = 0;

// Cycling mode: online 20-22h → offline 2-4h → repeat
let _cyclingActive = false;
const CYCLE_ONLINE_MIN = 20 * 60 * 60 * 1000;
const CYCLE_ONLINE_MAX = 22 * 60 * 60 * 1000;
const CYCLE_OFFLINE_MIN = 2 * 60 * 60 * 1000;
const CYCLE_OFFLINE_MAX = 4 * 60 * 60 * 1000;
const CYCLE_RECONNECT_MIN = 5 * 60 * 1000; // 5 minutes minimum before reconnect
const CYCLE_RECONNECT_MAX = 10 * 60 * 1000; // 10 minutes maximum before reconnect

const MAX_CONCURRENT = 5;

// IDENTIFY rate limiter — Discord allows max 5 IDENTIFY per 24h per token
const _identifyCounts = new Map(); // token -> [timestamps]
const IDENTIFY_LIMIT = 3;
const IDENTIFY_WINDOW = 24 * 60 * 60 * 1000; // 24 hours

function canIdentify(token) {
  const now = Date.now();
  const counts = _identifyCounts.get(token) || [];
  const recent = counts.filter(t => now - t < IDENTIFY_WINDOW);
  _identifyCounts.set(token, recent);
  return recent.length < IDENTIFY_LIMIT;
}function recordIdentify(token) {
  const now = Date.now();
  const counts = _identifyCounts.get(token) || [];
  counts.push(now);
  _identifyCounts.set(token, counts);
}

// Token cooldown — after failure, wait 15 minutes before retrying
const _tokenCooldowns = new Map(); // token -> timestamp of last failure
const COOLDOWN_DURATION = 4 * 60 * 60 * 1000;

function isOnCooldown(token) {
  const lastFail = _tokenCooldowns.get(token);
  if (!lastFail) return false;
  return (Date.now() - lastFail) < COOLDOWN_DURATION;
}

function markFailed(token) {
  _tokenCooldowns.set(token, Date.now());
}




const { HttpsProxyAgent } = require("https-proxy-agent");
const tls = require("tls");

let _proxies = null;
function loadProxies() {
  if (_proxies !== null) return _proxies;
  const proxiesFile = path.join(__dirname, "..", "proxies.txt");
  try {
    if (fs.existsSync(proxiesFile)) {
      const content = fs.readFileSync(proxiesFile, "utf-8");
      _proxies = content.split(/\r?\n/).map(l => l.trim()).filter(l => l && !l.startsWith("#") && l.startsWith("http"));
    }
  } catch {}
  if (!_proxies) _proxies = [];
  if (_proxies.length > 0) console.log(chalk.cyan(`[*] Loaded ${_proxies.length} proxies\n`));
  return _proxies;
}

function getProxy(index) {
  const proxies = loadProxies();
  if (proxies.length === 0) return null;
  return proxies[index % proxies.length];
}

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



function connectToken(token, status, index, name) {
  const label = name || maskToken(token);
  const id = `${index}_${Date.now()}`;
  const proxyUrl = getProxy(parseInt(index) - 1);
  const TIMEOUT = 8000;

  return new Promise((mainResolve) => {
    let done = false;
    let initialConnected = false;
    const finish = (val) => { if (!done) { done = true; mainResolve(val); } };

    const scheduleReconnect = (reason) => {
      if (_persistentConnections[id] || initialConnected) {
        if (_persistentConnections[id]) delete _persistentConnections[id];
        if (!canIdentify(token)) {
          console.log(chalk.red(`[!] ${label} won't reconnect — IDENTIFY limit reached (max ${IDENTIFY_LIMIT}/24h)`));
          finish({ id, label, error: "IDENTIFY limit" });
          return;
        }
        if (isOnCooldown(token)) {
          console.log(chalk.red(`[!] ${label} won't reconnect — on cooldown (15min)`));
          finish({ id, label, error: "On cooldown" });
          return;
        }
        const reconnDelay = CYCLE_RECONNECT_MIN + Math.random() * (CYCLE_RECONNECT_MAX - CYCLE_RECONNECT_MIN);
        console.log(chalk.yellow(`[~] ${label} ${reason}, auto-reconnect in ${Math.round(reconnDelay/1000)}s...`));
        setTimeout(() => {
          connectWithTimeout(token, status, index, name, TOKEN_TIMEOUT);
        }, reconnDelay);
      }
    };

    const attempt = (attemptNum) => {
      if (done || attemptNum > MAX_RETRY_ATTEMPTS) {
        if (!initialConnected) finish({ id, label, error: attemptNum > MAX_RETRY_ATTEMPTS ? "Failed after retries" : "Timeout" });
        return;
      }

      // Cooldown check — don't retry if token recently failed
      if (isOnCooldown(token)) {
        console.log(chalk.red(`[!] ${label} on cooldown (15min) — skipping to protect token`));
        finish({ id, label, error: "On cooldown" });
        return;
      }

      let ws;
      const timer = setTimeout(() => {
        try { if (ws) ws.close(); } catch {}
        if (!done) {
          const retryDelay = 1500 * (attemptNum + 1);
          console.log(chalk.yellow(`[~] ${label} timeout, retry ${attemptNum + 2}/${MAX_RETRY_ATTEMPTS + 1} in ${retryDelay/1000}s...`));
          setTimeout(() => attempt(attemptNum + 1), retryDelay);
        } else if (initialConnected) {
          scheduleReconnect("timeout after connect");
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
              if (!done) {
                const retryDelay = 2000 * (attemptNum + 1);
                console.log(chalk.yellow(`[~] ${label} no gateway URL, retry in ${retryDelay/1000}s...`));
                setTimeout(() => attempt(attemptNum + 1), retryDelay);
              }
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
            let hbTimer = null;
            let seq = null;

            _persistentConnections[id] = { ws, heartbeatTimer: null, token, label, status, sequence: null };

            ws.on("open", () => {
              if (!canIdentify(token)) {
                console.log(chalk.red(`[!] ${label} IDENTIFY limit reached (max ${IDENTIFY_LIMIT}/24h) — skipping`));
                try { ws.close(1000); } catch {}
                delete _persistentConnections[id];
                finish({ id, label, error: "IDENTIFY limit" });
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
                  if (proxyUrl) console.log(chalk.green(`[+] ${index} ${status} — ${label} (proxy)`));
                  else console.log(chalk.green(`[+] ${index} ${status} — ${label}`));
                  finish({ id, label });
                }

                if (msg.op === 9) {
                  clearTimeout(timer);
                  clearInterval(hbTimer);
                  try { ws.close(); } catch {}
                  delete _persistentConnections[id];
                  // DO NOT retry or reconnect on op 9 — token is flagged by Discord
                  console.log(chalk.red(`[!] ${label} INVALID SESSION (op 9) — token flagged, will NOT retry or reconnect`));
                  finish({ id, label, error: "Invalid session" });
                }
              } catch {}
            });

            ws.on("error", () => {
              clearTimeout(timer);
              clearInterval(hbTimer);
              
              if (!done && attemptNum < MAX_RETRY_ATTEMPTS) {
                const retryDelay = 2000 * (attemptNum + 1);
                console.log(chalk.yellow(`[~] ${label} error, retry ${attemptNum + 2}/${MAX_RETRY_ATTEMPTS + 1} in ${retryDelay/1000}s...`));
                setTimeout(() => attempt(attemptNum + 1), retryDelay);
              } else {
                // DO NOT auto-reconnect on error — only on clean close codes
                markFailed(token);
                console.log(chalk.red(`[!] ${label} connection error — on cooldown (15min)`));
                finish({ id, label, error: "Connection error" });
              }
            });

            ws.on("close", (code) => {
              clearTimeout(timer);
              clearInterval(hbTimer);
              
              if (initialConnected) {
                // Only reconnect on SAFE close codes — all others = token might be flagged
                const safeReconnectCodes = [1000, 1001, 1006];
                const noReconnectCodes = [4004, 4009, 4010, 4011, 4012, 4013, 4014];
                
                if (noReconnectCodes.includes(code)) {
                  delete _persistentConnections[id];
                  const reasons = {
                    4004: "Auth failed — token invalid/revoked",
                    4009: "Session invalidated",
                    4010: "Invalid shard",
                    4011: "Sharding required",
                    4012: "Invalid API version",
                    4013: "Invalid intents",
                    4014: "Disallowed intents",
                  };
                  markFailed(token);
                  console.log(chalk.red(`[!] ${label} closed ${code}: ${reasons[code] || "fatal"} — will NOT reconnect`));
                  finish({ id, label, error: `Closed ${code}` });
                } else if (safeReconnectCodes.includes(code)) {
                  scheduleReconnect(`disconnected (${code})`);
                } else {
                  // Unknown/unsafe close code — do NOT reconnect to be safe
                  markFailed(token);
                  console.log(chalk.red(`[!] ${label} closed ${code} (unsafe) — on cooldown (15min)`));
                  finish({ id, label, error: `Closed ${code}` });
                }
              } else if (!done && attemptNum < MAX_RETRY_ATTEMPTS) {
                const retryDelay = 1500 * (attemptNum + 1);
                setTimeout(() => attempt(attemptNum + 1), retryDelay);
              }
            });
          } catch {
            clearTimeout(timer);
            if (!done && attemptNum < MAX_RETRY_ATTEMPTS) {
              const retryDelay = 2000 * (attemptNum + 1);
              setTimeout(() => attempt(attemptNum + 1), retryDelay);
            } else {
              finish({ id, label, error: "Parse error" });
            }
          }
        });
      }).on("error", () => {
        if (!done && attemptNum < MAX_RETRY_ATTEMPTS) {
          const retryDelay = 2000 * (attemptNum + 1);
          setTimeout(() => attempt(attemptNum + 1), retryDelay);
        } else {
          finish({ id, label, error: "Network error" });
        }
      }).on("timeout", function () {
        this.destroy();
        if (!done && attemptNum < MAX_RETRY_ATTEMPTS) {
          const retryDelay = 2000 * (attemptNum + 1);
          setTimeout(() => attempt(attemptNum + 1), retryDelay);
        } else {
          finish({ id, label, error: "Gateway timeout" });
        }
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
  _activeConnections = 0;
}

async function connectWithTimeout(token, status, index, name, timeoutMs) {
  return Promise.race([
    connectToken(token, status, index, name),
    new Promise((resolve) => setTimeout(() => resolve({ id: index, label: name || "?", error: "Timeout" }), timeoutMs))
  ]);
}

const BATCH_SIZE = 5;
const BATCH_DELAY = 2000;
const TOKEN_TIMEOUT = 12000;
const MAX_RETRY_ATTEMPTS = 0; // ZERO retries — save IDENTIFY budget

async function connectBatch(tokens, statusFn, count, names) {
  let connected = 0;
  let failed = 0;

  const batchNum = Math.ceil(tokens.length / BATCH_SIZE);
  console.log(chalk.dim(`  ${tokens.length} tokens → ${batchNum} batches of ${BATCH_SIZE}, ${BATCH_DELAY/1000}s gap + jitter\n`));

  for (let i = 0; i < tokens.length; i += BATCH_SIZE) {
    const batch = tokens.slice(i, i + BATCH_SIZE);
    const batchIdx = Math.floor(i / BATCH_SIZE) + 1;
    console.log(chalk.cyan(`  Batch ${batchIdx}/${batchNum} (${batch.length} tokens)...`));

    // Stagger connections within batch with random jitter (500-2000ms between each)
    const batchResults = [];
    for (let j = 0; j < batch.length; j++) {
      const token = batch[j];
      const idx = i + j + 1;
      const status = statusFn(idx - 1);
      const label = (names && names[idx - 1]) ? names[idx - 1] : `#${idx}`;
      const r = await connectWithTimeout(token, status, `${idx}/${count}`, label, TOKEN_TIMEOUT);
      batchResults.push(r);
      if (j < batch.length - 1) {
        const jitter = 500 + Math.random() * 1500;
        await sleep(jitter);
      }
    }

    for (const r of batchResults) {
      const display = (names && names[r.id?.split('_')[0] - 1]) ? `${names[r.id.split('_')[0] - 1].padEnd(15)}` : `${r.label}`;
      if (r.error) {
        failed++;
        console.log(chalk.red(`    [×] ${display} — ${r.error}`));
      } else {
        connected++;
        console.log(chalk.green(`    [✓] ${display} — connected`));
      }
    }
    console.log(chalk.dim(`  Batch done: ${connected} ok, ${failed} fail so far`));
    if (i + BATCH_SIZE < tokens.length) {
      const batchGap = BATCH_DELAY + Math.random() * 2000;
      await sleep(batchGap);
    }
  }

  return { connected, failed };
}

async function handleChangeStatus(tokens) {    console.log(chalk.cyan("\n  1. Online\n  2. Idle\n  3. Do Not Disturb\n  4. Invisible\n"));
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

  console.log(chalk.cyan(`\n[*] Connecting ${count} accounts as "${status}" (24/7 mode)...\n`));
  console.log(chalk.dim(`[*] Parallel batches of ${BATCH_SIZE}, ${BATCH_DELAY/1000}s gap\n`));

  const { connected, failed } = await connectBatch(selectedTokens, () => status, count, names);

  console.log(chalk.bold("\n══════════════════════════════════════"));
  console.log(chalk.bold.green(`  ${status}: ${connected}/${count}`));
  if (failed > 0) console.log(chalk.bold.red(`  Failed: ${failed}`));
  console.log(chalk.bold("══════════════════════════════════════\n"));

  if (connected > 0) {
    console.log(chalk.green(`[+] ${connected} accounts now ${status} with CYCLING mode.`));
    console.log(chalk.cyan("[*] Cycle: 20-22h ONLINE → 2-4h OFFLINE → repeat"));
    console.log(chalk.cyan("[*] Auto-reconnect enabled if connection drops."));

    console.log(chalk.cyan("[*] Use option 14 to stop all."));
    console.log(chalk.dim("[*] Cycling running in background...\n"));
    startCycling(selectedTokens, () => status, count, names);
  }
}

async function handleQuickJoin() {
  const token = await askText("Enter token: ");
  if (!token) return;
  const invite = await askText("Invite link (discord.gg/CODE): ");
  if (!invite) return;

  const inviteCode = extractInviteCode(invite);

  console.log(chalk.cyan(`\n[+] Joining ${inviteCode}...`));
  console.log(chalk.dim(`  (from input: ${invite})`));
  const result = await joinServer(token, inviteCode);

  if (result.success) {
    console.log(chalk.green(`[+] Joined OK — ${await getName(token)}\n`));
  } else {
    console.log(chalk.red(`[×] Failed — ${result.reason}\n`));
  }
}

async function handleChangeBio(tokens) {
  const bio = await askText("New bio for all accounts: ");
  if (!bio) return;
  const countStr = await askText(`How many accounts? (available: ${tokens.length}): `);
  const count = parseInt(countStr) || tokens.length;

  const selectedTokens = tokens.slice(0, count);
  console.log(chalk.cyan(`[*] Fetching account names...`));
  const names = await Promise.all(selectedTokens.map(t => getName(t)));
  console.log(chalk.green(` Done\n`));

  console.log(chalk.cyan(`\n[*] Changing bios to "${bio}"...\n`));
  let success = 0;
  let failed = 0;

  for (let i = 0; i < selectedTokens.length; i++) {
    const result = await changeBio(selectedTokens[i], bio);
    if (result.success) {
      console.log(chalk.green(`[+] ${i + 1}/${selectedTokens.length} Bio changed OK — ${names[i]}`));
      success++;
    } else {
      console.log(chalk.red(`[×] ${i + 1}/${selectedTokens.length} Failed — ${names[i]} (${result.reason})`));
      failed++;
    }
  }

  console.log(chalk.bold("\n══════════════════════════════════════"));
  console.log(chalk.bold.green(`  Changed: ${success}`));
  console.log(chalk.bold.red(`  Failed:  ${failed}`));
  console.log(chalk.bold("══════════════════════════════════════\n"));
}

async function handleAutoReact(tokens) {
  const guildId = await askText("Server ID: ");
  if (!guildId) return;
  const channelId = await askText("Channel ID: ");
  if (!channelId) return;
  const messageId = await askText("Message ID: ");
  if (!messageId) return;
  const countStr = await askText(`How many accounts? (available: ${tokens.length}): `);
  const count = parseInt(countStr) || tokens.length;
  const emojiStr = await askText("Emoji(s) separated by space (e.g. 👍 ❤️ 🚀): ");
  if (!emojiStr) return;
  const emojis = emojiStr.trim().split(/\s+/);

  const selectedTokens = tokens.slice(0, count);
  console.log(chalk.cyan(`\n[*] Reacting ${selectedTokens.length} accounts × ${emojis.length} emoji(s) in parallel...\n`));

  const allResults = await Promise.all(
    emojis.flatMap(e =>
      selectedTokens.map(t => reactToMessage(t, channelId, messageId, e).then(r => ({ result: r })))
    )
  );

  const sent = allResults.filter(r => r.result.success).length;
  const failed = allResults.filter(r => !r.result.success).length;

  console.log(chalk.green(`  [+] Sent: ${sent}`));
  if (failed > 0) console.log(chalk.red(`  [×] Failed: ${failed}`));

  console.log(chalk.bold("\n══════════════════════════════════════"));
  console.log(chalk.bold.green(`  Sent: ${sent}/${emojis.length * selectedTokens.length}`));
  if (failed > 0) console.log(chalk.bold.red(`  Failed: ${failed}`));
  console.log(chalk.bold("══════════════════════════════════════\n"));
}

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
          console.log(chalk.dim(`[~] Skipping nitro burst: ${r.emoji.name}`));
          continue;
        }
        const en = r.emoji.id ? `${r.emoji.name}:${r.emoji.id}` : r.emoji.name;
        const usersRes = await fetchReactionUsers(firstToken, channelId, messageId, r.emoji.name, 5);
        if (usersRes.success && usersRes.users.some(u => u.premium_type > 0)) {
          console.log(chalk.dim(`[~] Skipping nitro user reaction: ${en}`));
          continue;
        }
        allEmojis.push(en);
      }
    }
  } else {
    const errMsg = typeof msgRes.data === "object" ? msgRes.data?.message || JSON.stringify(msgRes.data) : String(msgRes.data || "Unknown");
    console.log(chalk.yellow(`[!] ${msgRes.status}: ${errMsg}`));
  }

  if (allEmojis.length === 0) {
    console.log(chalk.yellow("[!] No non-nitro reactions found or can't fetch message.\n"));
    return;
  }

  console.log(chalk.green(`[+] Non-nitro emojis: ${allEmojis.join(", ")}\n`));

  const totalOps = allEmojis.length * selectedTokens.length;
  console.log(chalk.cyan(`[*] Reacting all ${totalOps} combinations in parallel...\n`));

  const allResults = await Promise.all(
    allEmojis.flatMap(emoji =>
      selectedTokens.map(t => reactToMessage(t, channelId, messageId, emoji).then(r => ({ emoji, token: t, result: r })))
    )
  );

  const sent = allResults.filter(r => r.result.success).length;
  const failed = allResults.filter(r => !r.result.success).length;

  console.log(chalk.green(`  [+] Sent: ${sent}`));
  if (failed > 0) console.log(chalk.red(`  [×] Failed: ${failed}`));

  console.log(chalk.bold("\n══════════════════════════════════════"));
  console.log(chalk.bold.green(`  Sent: ${sent}/${allEmojis.length * selectedTokens.length}`));
  if (failed > 0) console.log(chalk.bold.red(`  Failed: ${failed}`));
  console.log(chalk.bold("══════════════════════════════════════\n"));
}

async function startCycling(selectedTokens, statusFn, count, names) {
  _cyclingActive = true;

  while (_cyclingActive) {
    const onlineTime = CYCLE_ONLINE_MIN + Math.random() * (CYCLE_ONLINE_MAX - CYCLE_ONLINE_MIN);
    const onH = Math.floor(onlineTime / 3600000);
    const onM = Math.floor((onlineTime % 3600000) / 60000);
    console.log(chalk.cyan(`\n[cycle] Accounts ONLINE for ~${onH}h ${onM}m\n`));
    await sleep(onlineTime);
    if (!_cyclingActive) break;    console.log(chalk.yellow(`\n[cycle] Going OFFLINE for break...\n`));
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

async function handleRandomStatus(tokens) {
  const countStr = await askText(`How many accounts? (available: ${tokens.length}): `);
  const count = parseInt(countStr) || tokens.length;

  const selectedTokens = tokens.slice(0, count);
  const statuses = ["online", "idle", "dnd"];

  console.log(chalk.cyan(`[*] Fetching account names...`));
  const names = await Promise.all(selectedTokens.map(t => getName(t)));
  console.log(chalk.green(` Done\n`));

  console.log(chalk.cyan(`\n[*] Connecting ${count} accounts with random status...\n`));
  console.log(chalk.dim(`[*] Parallel batches of ${BATCH_SIZE}, ${BATCH_DELAY/1000}s gap\n`));

  const statusFn = () => statuses[Math.floor(Math.random() * statuses.length)];
  const { connected, failed } = await connectBatch(selectedTokens, statusFn, count, names);

  console.log(chalk.bold("\n══════════════════════════════════════"));
  console.log(chalk.bold.green(`  Connected: ${connected}/${count}`));
  if (failed > 0) console.log(chalk.bold.red(`  Failed: ${failed}`));
  console.log(chalk.bold("══════════════════════════════════════\n"));

  if (connected > 0) {
    console.log(chalk.green(`[+] ${connected} accounts now online with CYCLING mode.`));
    console.log(chalk.cyan("[*] Cycle: 20-22h ONLINE → 2-4h OFFLINE → repeat"));
    console.log(chalk.cyan("[*] Auto-reconnect enabled if connection drops."));

    console.log(chalk.cyan("[*] Use option 14 to stop all."));
    console.log(chalk.dim("[*] Cycling running in background...\n"));
    startCycling(selectedTokens, statusFn, count, names);
  }
}

function connectTokenVC(token, guildId, channelId, index, name, attempt = 0) {
  const label = name || maskToken(token);
  const MAX_RETRIES = 3;
  const VC_TIMEOUT = 10000;
  return new Promise((resolve) => {
    let done = false;
    const finish = (val) => { if (!done) { done = true; resolve(val); } };
    const timer = setTimeout(() => finish({ success: false, reason: "Timeout" }), VC_TIMEOUT);
    const req = https.get("https://discord.com/api/v9/gateway", (res) => {
      let body = "";
      res.on("data", (c) => (body += c));
      res.on("end", () => {
        try {
          const { url } = JSON.parse(body);
          const ws = new WebSocket(url + "?v=9&encoding=json");
          let heartbeatTimer;
          let ready = false;          ws.on("open", () => {
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
              const delay = Math.min(5000 * Math.pow(2, attempt), 30000);
              console.log(chalk.yellow(`[~] ${label} VC reconnecting in ${delay / 1000}s...`));
              setTimeout(() => connectTokenVC(token, guildId, channelId, index, name, attempt + 1).then(finish), delay);
            } else if (!ready) {
              finish({ success: false, reason: "Connection error" });
            }
          });
          ws.on("close", (code) => {
            clearInterval(heartbeatTimer);
            clearTimeout(timer);
            if (!ready && code !== 1000 && attempt < MAX_RETRIES) {
              const delay = Math.min(5000 * Math.pow(2, attempt), 30000);
              console.log(chalk.yellow(`[~] ${label} VC disconnected (${code}), reconnecting...`));
              setTimeout(() => connectTokenVC(token, guildId, channelId, index, name, attempt + 1).then(finish), delay);
            } else if (!ready && code !== 1000) {
              finish({ success: false, reason: `Disconnected (${code})` });
            }
          });
        } catch {
          clearTimeout(timer);
          if (attempt < MAX_RETRIES) {
            const delay = Math.min(5000 * Math.pow(2, attempt), 30000);
            setTimeout(() => connectTokenVC(token, guildId, channelId, index, name, attempt + 1).then(finish), delay);
          } else {
            finish({ success: false, reason: "Failed to get gateway" });
          }
        }
      });
    });
    req.on("error", () => {
      clearTimeout(timer);
      if (attempt < MAX_RETRIES) {
        const delay = Math.min(5000 * Math.pow(2, attempt), 30000);
        setTimeout(() => connectTokenVC(token, guildId, channelId, index, name, attempt + 1).then(finish), delay);
      } else {
        finish({ success: false, reason: "Network error" });
      }
    });
  });
}

async function handleJoinVCs(tokens) {
  const guildId = await askText("Server ID (right-click server → Copy ID): ");
  if (!guildId) return;
  const channelId = await askText("Voice Channel ID (right-click channel → Copy ID): ");
  if (!channelId) return;
  const countStr = await askText(`How many accounts? (available: ${tokens.length}): `);
  const count = parseInt(countStr) || tokens.length;

  const selectedTokens = tokens.slice(0, count);

  console.log(chalk.cyan(`[*] Fetching account names...`));
  const names = await Promise.all(selectedTokens.map(t => getName(t)));
  console.log(chalk.green(` Done\n`));

  console.log(chalk.cyan(`\n[*] Joining VC ${channelId} with ${selectedTokens.length} accounts...\n`));
  console.log(chalk.dim(`[*] Batches of 5, 3s gap between batches\n`));

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
      batch.map((t, j) => connectTokenVC(t, guildId, channelId, `${i + j + 1}/${selectedTokens.length}`, names[i + j]))
    );

    for (let j = 0; j < results.length; j++) {
      const r = results[j];
      const idx = i + j + 1;
      if (r && r.success) {
        success++;
        console.log(chalk.green(`    [✓] ${names[i + j].padEnd(15)} joined`));
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
  console.log(chalk.bold.green(`  Joined VC:   ${success}/${selectedTokens.length}`));
  if (failed > 0) console.log(chalk.bold.red(`  Failed:      ${failed}`));
  console.log(chalk.bold("══════════════════════════════════════\n"));
  console.log(chalk.cyan("[*] Use 'Disconnect from VC' option to leave.\n"));
}

function handleDisconnectAll() {
  _cyclingActive = false;
  let total = 0;

  if (activeVC.length > 0) {
    console.log(chalk.dim(`[*] Disconnecting ${activeVC.length} accounts from VC...`));
    activeVC.forEach((close) => close());
    activeVC = [];
    total += activeVC.length;
  }

  const statusCount = Object.keys(_persistentConnections).length;
  if (statusCount > 0) {
    console.log(chalk.dim(`[*] Disconnecting ${statusCount} status connections...`));
    disconnectAllPersistent();
    total += statusCount;
  }

  if (total === 0) {
    console.log(chalk.yellow("[!] No active connections found.\n"));
  } else {
    console.log(chalk.green(`[+] All ${total} connections disconnected.\n`));
  }
}

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
  first.components.forEach((b, i) => console.log(chalk.cyan(`  ${i + 1}. ${b.label || "no label"} [${b.customId}]${b.disabled ? " (DISABLED)" : ""}`)));
  console.log();
  const choice = await askNumber("Which button number? ");
  const idx = parseInt(choice) - 1;
  if (idx < 0 || idx >= first.components.length) { console.log(chalk.red("[!] Invalid choice")); return; }
  const customId = first.components[idx].customId;

  console.log(chalk.cyan(`\n[*] Clicking "${customId}" on ${selectedTokens.length} accounts...\n`));

  let success = 0;
  let failed = 0;

  for (let i = 0; i < selectedTokens.length; i++) {
    const r = await clickMessageButton(selectedTokens[i], channelId, messageId, customId);
    const tag = `[${String(i + 1).padStart(3, " ")}/${selectedTokens.length}]`;
    if (r.success) {
      console.log(chalk.green(`  ${tag} ${(await getName(selectedTokens[i])).padEnd(15)} ✓`));
      success++;
    } else {
      console.log(chalk.red(`  ${tag} ${(await getName(selectedTokens[i])).padEnd(15)} ✗ ${r.reason}`));
      failed++;
    }
    if (i < selectedTokens.length - 1) await randomDelay(500, 1500);
  }

  console.log(chalk.bold("\n══════════════════════════════════════"));
  console.log(chalk.bold.green(`  Clicked: ${success}`));
  console.log(chalk.bold.red(`  Failed:  ${failed}`));
  console.log(chalk.bold("══════════════════════════════════════\n"));
}

async function handlePersistentStatus(tokens) {
  console.log(chalk.cyan("\n  1. Online\n  2. Idle\n  3. Do Not Disturb\n  4. Random (each account gets random status)\n"));
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
  console.log(chalk.dim(`[*] Parallel batches of ${BATCH_SIZE}, ${BATCH_DELAY/1000}s gap\n`));

  const statusFn = isRandom ? () => statuses[Math.floor(Math.random() * statuses.length)] : () => defaultStatus;
  const { connected, failed } = await connectBatch(selectedTokens, statusFn, count, names);

  console.log(chalk.bold("\n══════════════════════════════════════"));
  console.log(chalk.bold.green(`  24/7 Active: ${connected}/${count} (${modeText})`));
  if (failed > 0) console.log(chalk.bold.red(`  Failed: ${failed}`));
  console.log(chalk.bold("══════════════════════════════════════\n"));

  if (connected > 0) {
    console.log(chalk.green(`[+] ${connected} accounts now ${modeText} with CYCLING mode.`));
    console.log(chalk.cyan("[*] Cycle: 20-22h ONLINE → 2-4h OFFLINE → repeat"));
    console.log(chalk.cyan("[*] Auto-reconnect enabled if connection drops."));

    console.log(chalk.cyan("[*] Use option 14 to stop all."));
    console.log(chalk.dim("[*] Cycling running in background...\n"));
    startCycling(selectedTokens, statusFn, count, names);
  }
}

function askNumber(question) {
  return new Promise((resolve) => {
    const readline = require("readline");
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(question, (ans) => { rl.close(); resolve(ans.trim()); });
  });
}

function askText(question) {
  return new Promise((resolve) => {
    const readline = require("readline");
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(question, (ans) => { rl.close(); resolve(ans.trim()); });
  });
}

async function askList(question, options) {
  console.log();
  options.forEach((opt, i) => console.log(chalk.cyan(`  ${i + 1}. ${opt.name || opt}`)));
  console.log();
  const choice = await askNumber(question);
  const idx = parseInt(choice) - 1;
  if (idx < 0 || idx >= options.length) return null;
  return options[idx].value !== undefined ? options[idx].value : options[idx];
}

async function main() {
  console.log(chalk.bold.cyan("\n╔══════════════════════════════════════╗"));
  console.log(chalk.bold.cyan("║     Bulk Member Importer v1.0       ║"));
  console.log(chalk.bold.cyan("╚══════════════════════════════════════╝\n"));

  const ACTIONS = {
    "1": "join", "2": "quickjoin", "3": "nickname", "4": "globalname",
    "5": "check", "6": "clean", "7": "friend", "8": "status",
    "9": "bio", "10": "randomstatus", "11": "autoreact", "12": "autodetectreact",
    "13": "vcjoin", "14": "disconnectall", "15": "clickbtn", "16": "persistentstatus",
    "17": "leaveserver", "0": "exit",
  };

  while (true) {
    console.log(chalk.cyan("  1.  Bulk join server"));
    console.log(chalk.cyan("  2.  Quick join (custom token + server)"));
    console.log(chalk.cyan("  3.  Change server nickname"));
    console.log(chalk.cyan("  4.  Change global display name"));
    console.log(chalk.cyan("  5.  Check tokens (valid/invalid)"));
    console.log(chalk.cyan("  6.  Remove invalid tokens"));
    console.log(chalk.cyan("  7.  Send friend requests"));
    console.log(chalk.cyan("  8.  Set status (Online/Idle/DND)"));
    console.log(chalk.cyan("  9.  Change bio"));
    console.log(chalk.cyan("  10. Set random status"));
    console.log(chalk.cyan("  11. Auto-react (manual emoji)"));
    console.log(chalk.cyan("  12. Auto-react (existing reactions)"));
    console.log(chalk.cyan("  13. Join VC's"));
    console.log(chalk.cyan("  14. Disconnect ALL (status + VC)"));
    console.log(chalk.cyan("  15. Click button on message"));
    console.log(chalk.cyan("  16. Set 24/7 persistent status"));
    console.log(chalk.cyan("  17. Leave server(s) — supports multiple IDs"));
    console.log(chalk.red("  0.  Exit\n"));

    const choice = await askNumber("Enter number: ");
    const action = ACTIONS[choice];
    if (!action) { console.log(chalk.red("[!] Invalid choice\n")); continue; }
    if (action === "exit") { console.log(chalk.cyan("\nGoodbye!\n")); break; }

    if (action === "quickjoin") {
      await handleQuickJoin();
      continue;
    }

    if (action === "disconnectall") {
      handleDisconnectAll();
      continue;
    }

    const tokens = readTokens();
    if (!tokens) continue;

    console.log(chalk.green(`[+] Total tokens found: ${tokens.length}\n`));

    if (action === "join") await handleJoinServer(tokens);
    else if (action === "nickname") await handleChangeNickname(tokens);
    else if (action === "globalname") await handleChangeGlobalName(tokens);
    else if (action === "check") await handleCheckTokens(tokens);
    else if (action === "clean") { await handleCleanTokens(); }
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

process.on("SIGINT", () => { console.log(chalk.yellow("\n[*] Shutting down...")); disconnectAllPersistent(); closeAllGateways(); process.exit(0); });
process.on("SIGTERM", () => { console.log(chalk.yellow("\n[*] Shutting down...")); disconnectAllPersistent(); closeAllGateways(); process.exit(0); });
process.on("uncaughtException", (e) => { console.error(chalk.red("[!] Uncaught:"), e.message); });
process.on("unhandledRejection", (e) => { console.error(chalk.red("[!] Unhandled:"), e); });
