const https = require("https");
const WebSocket = require("ws");
const fs = require("fs");
const path = require("path");
const chalk = require("chalk");
const { secureReadTokens } = require("./src/security");

const TOKENS_FILE = path.join(__dirname, "tokens.txt");

// Cycling config
const CYCLE_ONLINE_MIN = 20 * 60 * 60 * 1000;
const CYCLE_ONLINE_MAX = 22 * 60 * 60 * 1000;
const CYCLE_OFFLINE_MIN = 2 * 60 * 60 * 1000;
const CYCLE_OFFLINE_MAX = 4 * 60 * 60 * 1000;
const RECONNECT_MIN = 5 * 60 * 1000; // 5 minutes
const RECONNECT_MAX = 10 * 60 * 1000; // 10 minutes
const BATCH_SIZE = 5;
const BATCH_DELAY = 2000;
const CONNECT_TIMEOUT = 12000;
const MAX_RETRIES = 0; // ZERO retries — save IDENTIFY budget

let cyclingActive = false;
const connections = {};

// IDENTIFY rate limiter — Discord allows max 5 IDENTIFY per 24h per token
const _identifyCounts = new Map();
const IDENTIFY_LIMIT = 3; // Max 3 IDENTIFY per 24h (Discord limit is 5, 2 buffer)
const IDENTIFY_WINDOW = 24 * 60 * 60 * 1000;

function canIdentify(token) {
  const now = Date.now();
  const counts = _identifyCounts.get(token) || [];
  const recent = counts.filter(t => now - t < IDENTIFY_WINDOW);
  _identifyCounts.set(token, recent);
  return recent.length < IDENTIFY_LIMIT;
}

function recordIdentify(token) {
  const now = Date.now();
  const counts = _identifyCounts.get(token) || [];
  counts.push(now);
  _identifyCounts.set(token, counts);
}

// Token cooldown — after failure, wait 15 minutes before retrying
const _tokenCooldowns = new Map();
const COOLDOWN_DURATION = 4 * 60 * 60 * 1000; // 4 hours cooldown after failure

function isOnCooldown(token) {
  const lastFail = _tokenCooldowns.get(token);
  if (!lastFail) return false;
  return (Date.now() - lastFail) < COOLDOWN_DURATION;
}

function markFailed(token) {
  _tokenCooldowns.set(token, Date.now());
}

function readTokens() {
  try {
    const secure = secureReadTokens();
    if (secure && secure.length > 0) return secure;
  } catch {}
  if (!fs.existsSync(TOKENS_FILE)) return [];
  return fs.readFileSync(TOKENS_FILE, "utf-8")
    .split("\n").map(l => l.trim()).filter(l => l && !l.startsWith("#"));
}

const _fingerprints = [
  { ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36", os: "windows", browser: "chrome", ver: "126.0.0.0", platform: "Win32" },
  { ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36", os: "windows", browser: "chrome", ver: "125.0.0.0", platform: "Win32" },
  { ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0", os: "windows", browser: "firefox", ver: "126.0", platform: "Win32" },
  { ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36", os: "darwin", browser: "chrome", ver: "125.0.0.0", platform: "MacIntel" },
  { ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36", os: "windows", browser: "chrome", ver: "127.0.0.0", platform: "Win32" },
  { ua: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36", os: "linux", browser: "chrome", ver: "126.0.0.0", platform: "Linux x86_64" },
];

function randomFingerprint() {
  const fp = _fingerprints[Math.floor(Math.random() * _fingerprints.length)];
  const locales = ["en-US", "en-GB", "hi-IN"];
  return {
    ua: fp.ua, os: fp.os, browser: fp.browser,
    browserVersion: fp.ver, platform: fp.platform,
    locale: locales[Math.floor(Math.random() * locales.length)],
  };
}

function randomUA() { return randomFingerprint().ua; }

function connectOne(token, status, idx, attemptNum = 0) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (val) => { if (!done) { done = true; resolve(val); } };

    // Cooldown check
    if (isOnCooldown(token)) {
      console.log(chalk.red(`  [!] #${idx} on cooldown (15min) — skipping to protect token`));
      finish({ ok: false, error: "on cooldown" });
      return;
    }

    const timer = setTimeout(() => {
      if (!done) {
        if (attemptNum < MAX_RETRIES) {
          const delay = 1500 * (attemptNum + 1);
          console.log(chalk.yellow(`  [~] #${idx} timeout, retry ${attemptNum + 2}/${MAX_RETRIES + 1} in ${delay / 1000}s...`));
          setTimeout(() => connectOne(token, status, idx, attemptNum + 1).then(finish), delay);
        } else {
          finish({ ok: false, error: "timeout" });
        }
      }
    }, CONNECT_TIMEOUT);

    https.get("https://discord.com/api/v9/gateway", { timeout: 4000 }, (res) => {
      let body = "";
      res.on("data", c => body += c);
      res.on("end", () => {
        if (done) return;
        try {
          const { url } = JSON.parse(body);
          if (!url) {
            clearTimeout(timer);
            if (attemptNum < MAX_RETRIES) {
              const delay = 2000 * (attemptNum + 1);
              setTimeout(() => connectOne(token, status, idx, attemptNum + 1).then(finish), delay);
            } else {
              finish({ ok: false, error: "no gateway URL" });
            }
            return;
          }

          const fp = randomFingerprint();
          const properties = {
            $os: fp.os, $browser: fp.browser, $device: "pc", $os_version: "10",
            browser_user_agent: fp.ua, browser_version: fp.browserVersion,
            system_locale: fp.locale, release_channel: "stable",
            client_build_number: 286175, client_event_source: null,
          };
          const ws = new WebSocket(url + "?v=9&encoding=json", { headers: { "User-Agent": fp.ua } });

          let heartbeatTimer = null;
          let seq = null;

          ws.on("open", () => {
            if (!canIdentify(token)) {
              console.log(chalk.red(`  [!] #${idx} IDENTIFY limit reached (max ${IDENTIFY_LIMIT}/24h) — skipping`));
              try { ws.close(1000); } catch {}
              finish({ ok: false, error: "IDENTIFY limit" });
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
                clearInterval(heartbeatTimer);
                const interval = msg.d.heartbeat_interval;
                heartbeatTimer = setInterval(() => {
                  try { ws.send(JSON.stringify({ op: 1, d: seq })); } catch {}
                }, interval);
                finish({ ok: true, ws, heartbeatTimer, seq, status, token, idx });
              }

              if (msg.op === 9) {
                clearTimeout(timer);
                clearInterval(heartbeatTimer);
                markFailed(token);
                ws.close();
                // DO NOT retry on op 9 — token is flagged
                console.log(chalk.red(`  [!] #${idx} INVALID SESSION (op 9) — token flagged, will NOT retry`));
                finish({ ok: false, error: "invalid session" });
              }
            } catch {}
          });

          ws.on("error", () => {
            clearTimeout(timer);
            clearInterval(heartbeatTimer);
            
            if (attemptNum < MAX_RETRIES) {
              const delay = 2000 * (attemptNum + 1);
              setTimeout(() => connectOne(token, status, idx, attemptNum + 1).then(finish), delay);
            } else {
              markFailed(token);
              finish({ ok: false, error: "ws error" });
            }
          });

          ws.on("close", (code) => {
            clearTimeout(timer);
            clearInterval(heartbeatTimer);
            
            const noReconnectCodes = [4004, 4009, 4010, 4011, 4012, 4013, 4014];
            const safeReconnectCodes = [1000, 1001, 1006];
            
            if (noReconnectCodes.includes(code)) {
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
              console.log(chalk.red(`  [!] #${idx} closed ${code}: ${reasons[code] || "fatal"} — will NOT reconnect`));
              return;
            }
            // Only reconnect on safe close codes
            if (cyclingActive && safeReconnectCodes.includes(code)) {
              const reconnDelay = RECONNECT_MIN + Math.random() * (RECONNECT_MAX - RECONNECT_MIN);
              console.log(chalk.yellow(`  [~] #${idx} disconnected (${code}), reconnect in ${Math.round(reconnDelay / 1000)}s...`));
              setTimeout(() => {
                if (cyclingActive) connectOne(token, status, idx, 0).then(r => {
                  if (r.ok) {
                    connections[idx] = r;
                    console.log(chalk.green(`  [+] #${idx} ${r.status} — reconnected`));
                  } else {
                    console.log(chalk.red(`  [x] #${idx} reconnect failed: ${r.error}`));
                  }
                });
              }, reconnDelay);
            }
          });
        } catch {
          clearTimeout(timer);
          if (attemptNum < MAX_RETRIES) {
            const delay = 2000 * (attemptNum + 1);
            setTimeout(() => connectOne(token, status, idx, attemptNum + 1).then(finish), delay);
          } else {
            finish({ ok: false, error: "parse error" });
          }
        }
      });
    }).on("error", () => {
      clearTimeout(timer);
      if (attemptNum < MAX_RETRIES) {
        const delay = 2000 * (attemptNum + 1);
        setTimeout(() => connectOne(token, status, idx, attemptNum + 1).then(finish), delay);
      } else {
        finish({ ok: false, error: "network error" });
      }
    }).on("timeout", function () {
      this.destroy();
      clearTimeout(timer);
      if (attemptNum < MAX_RETRIES) {
        const delay = 2000 * (attemptNum + 1);
        setTimeout(() => connectOne(token, status, idx, attemptNum + 1).then(finish), delay);
      } else {
        finish({ ok: false, error: "gateway timeout" });
      }
    });
  });
}

async function startCycling(tokens, globalStatus) {
  cyclingActive = true;

  while (cyclingActive) {
    const onlineTime = CYCLE_ONLINE_MIN + Math.random() * (CYCLE_ONLINE_MAX - CYCLE_ONLINE_MIN);
    const onH = Math.floor(onlineTime / 3600000);
    const onM = Math.floor((onlineTime % 3600000) / 60000);
    console.log(chalk.cyan(`\n[cycle] Accounts ONLINE for ~${onH}h ${onM}m\n`));
    await new Promise(r => setTimeout(r, onlineTime));
    if (!cyclingActive) break;

    console.log(chalk.yellow("\n[cycle] Going OFFLINE for break...\n"));
    // Disconnect all
    for (const idx of Object.keys(connections)) {
      const c = connections[idx];
      if (c && c.ws) {
        clearInterval(c.heartbeatTimer);
        clearTimeout(c.refreshTimer);
        try { c.ws.close(1000); } catch {}
      }
      delete connections[idx];
    }

    const offlineTime = CYCLE_OFFLINE_MIN + Math.random() * (CYCLE_OFFLINE_MAX - CYCLE_OFFLINE_MIN);
    const offH = Math.floor(offlineTime / 3600000);
    const offM = Math.floor((offlineTime % 3600000) / 60000);
    console.log(chalk.yellow(`[cycle] Staying offline ~${offH}h ${offM}m...\n`));
    await new Promise(r => setTimeout(r, offlineTime));
    if (!cyclingActive) break;

    console.log(chalk.green("\n[cycle] Reconnecting all accounts...\n"));
    let reconnected = 0;
    for (let i = 0; i < tokens.length; i += BATCH_SIZE) {
      const batch = tokens.slice(i, i + BATCH_SIZE);
      const results = await Promise.all(batch.map((token, j) => {
        const status = globalStatus || ["online", "idle", "dnd"][Math.floor(Math.random() * 3)];
        return connectOne(token, status, i + j + 1);
      }));
      for (const r of results) {
        if (r.ok) {
          connections[r.idx] = r;
          reconnected++;
          console.log(chalk.green(`  [+] #${r.idx} ${r.status} — reconnected`));
        } else {
          console.log(chalk.red(`  [x] #${r.idx} failed: ${r.error}`));
        }
      }
      if (i + BATCH_SIZE < tokens.length) await new Promise(r => setTimeout(r, BATCH_DELAY));
    }
    console.log(chalk.green(`[cycle] ${reconnected}/${tokens.length} accounts back ONLINE!\n`));
  }
}

async function main() {
  const tokens = readTokens();
  if (tokens.length === 0) {
    console.log(chalk.red("No tokens found! Add tokens to tokens.txt or use encrypted storage."));
    return;
  }

  const statuses = ["online", "idle", "dnd"];
  const statusArg = process.argv[2];
  const globalStatus = statuses.includes(statusArg) ? statusArg : null;

  console.log(chalk.bold.cyan("\n╔══════════════════════════════════════╗"));
  console.log(chalk.bold.cyan("║     Online Mode v2.0 — Enhanced     ║"));
  console.log(chalk.bold.cyan("╚══════════════════════════════════════╝\n"));
  console.log(chalk.cyan(`Connecting ${tokens.length} accounts${globalStatus ? " as " + globalStatus : " with random status"}...\n`));
  console.log(chalk.dim(`  Features: auto-reconnect, cycling mode`));
  console.log(chalk.dim(`  Batch: ${BATCH_SIZE} per batch, ${BATCH_DELAY / 1000}s gap`));
  console.log(chalk.dim(`  Cycle: 20-22h ONLINE → 2-4h OFFLINE → repeat\n`));

  const start = Date.now();
  let connected = 0;
  let failed = 0;

  for (let i = 0; i < tokens.length; i += BATCH_SIZE) {
    const batch = tokens.slice(i, i + BATCH_SIZE);
    const batchIdx = Math.floor(i / BATCH_SIZE) + 1;
    const batchTotal = Math.ceil(tokens.length / BATCH_SIZE);
    console.log(chalk.cyan(`  Batch ${batchIdx}/${batchTotal} (${batch.length} accounts)...`));

    // Stagger connections within batch with random jitter
    for (let j = 0; j < batch.length; j++) {
      const token = batch[j];
      const status = globalStatus || statuses[Math.floor(Math.random() * statuses.length)];
      const r = await connectOne(token, status, i + j + 1);
      if (r.ok) {
        connections[r.idx] = r;
        connected++;
        console.log(chalk.green(`    [+] #${r.idx} ${r.status} — connected`));
      } else {
        failed++;
        console.log(chalk.red(`    [x] #${r.idx} ${r.error}`));
      }
      if (j < batch.length - 1) {
        const jitter = 500 + Math.random() * 1500;
        await new Promise(r => setTimeout(r, jitter));
      }
    }

    if (i + BATCH_SIZE < tokens.length) {
      const batchGap = BATCH_DELAY + Math.random() * 2000;
      await new Promise(r => setTimeout(r, batchGap));
    }
  }

  const elapsed = Date.now() - start;
  console.log(chalk.bold.green(`\n  ${connected}/${tokens.length} accounts online in ${elapsed}ms!`));
  if (failed > 0) console.log(chalk.bold.red(`  Failed: ${failed}`));
  console.log(chalk.cyan("\n  Auto-reconnect: ENABLED"));
  console.log(chalk.cyan("  IDENTIFY limit: max 4 per 24h per token"));
  console.log(chalk.cyan("  Cycling mode: 20-22h ON → 2-4h OFF → repeat"));
  console.log(chalk.cyan("  Press Ctrl+C to disconnect all.\n"));

  // Start cycling in background
  if (connected > 0) {
    startCycling(tokens, globalStatus);
  }

  process.on("SIGINT", () => {
    console.log(chalk.yellow("\nDisconnecting all..."));
    cyclingActive = false;
    for (const idx of Object.keys(connections)) {
      const c = connections[idx];
      if (c) {
        clearInterval(c.heartbeatTimer);
        clearTimeout(c.refreshTimer);
        try { if (c.ws) c.ws.close(1000); } catch {}
      }
    }
    process.exit(0);
  });

  process.on("SIGTERM", () => {
    cyclingActive = false;
    for (const idx of Object.keys(connections)) {
      const c = connections[idx];
      if (c) {
        clearInterval(c.heartbeatTimer);
        clearTimeout(c.refreshTimer);
        try { if (c.ws) c.ws.close(1000); } catch {}
      }
    }
    process.exit(0);
  });
}

main();
