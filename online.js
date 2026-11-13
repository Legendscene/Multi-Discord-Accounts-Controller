const https = require("https");
const WebSocket = require("ws");
const fs = require("fs");
const path = require("path");
const chalk = require("chalk");
const { HttpsProxyAgent } = require("https-proxy-agent");
const { secureReadTokens, canIdentify, recordIdentify, isOnCooldown, markFailed, IDENTIFY_LIMIT } = require("./src/security");
const { maskToken } = require("./src/core");

const PROXIES_FILE = path.join(__dirname, "proxies.txt");

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

function getProxy(idx) {
  const list = loadProxies();
  if (list.length === 0) return null;
  return list[idx % list.length];
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
  const locales = ["en-US", "en-GB", "hi-IN", "en-AU", "en-CA"];
  return {
    ua: fp.ua, os: fp.os, browser: fp.browser,
    browserVersion: fp.ver, platform: fp.platform,
    locale: locales[Math.floor(Math.random() * locales.length)],
  };
}

function connectOne(token, status, idx, attemptNum = 0) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (val) => { if (!done) { done = true; resolve(val); } };
    const masked = maskToken(token);
    const proxyUrl = getProxy(idx - 1);

    // Cooldown check
    if (isOnCooldown(token)) {
      console.log(chalk.red(`  [!] #${idx} (${masked}) on cooldown (15min) — skipping`));
      finish({ ok: false, error: "on cooldown", idx });
      return;
    }

    let ws = null;
    let heartbeatTimer = null;

    const timer = setTimeout(() => {
      if (!done) {
        if (ws) { try { ws.close(); } catch {} }
        if (heartbeatTimer) clearInterval(heartbeatTimer);
        finish({ ok: false, error: "timeout", idx });
      }
    }, CONNECT_TIMEOUT);

    const reqOpts = {
      hostname: "discord.com",
      path: "/api/v9/gateway",
      method: "GET",
      headers: { "User-Agent": randomFingerprint().ua },
      timeout: 5000,
    };
    if (proxyUrl) {
      reqOpts.agent = new HttpsProxyAgent(proxyUrl);
    }

    const req = https.request(reqOpts, (res) => {
      let body = "";
      res.on("data", c => body += c);
      res.on("end", () => {
        if (done) return;
        try {
          const { url } = JSON.parse(body);
          if (!url) {
            clearTimeout(timer);
            finish({ ok: false, error: "no gateway URL", idx });
            return;
          }

          const fp = randomFingerprint();
          const properties = {
            $os: fp.os, $browser: fp.browser, $device: "pc", $os_version: "10",
            browser_user_agent: fp.ua, browser_version: fp.browserVersion,
            system_locale: fp.locale, release_channel: "stable",
            client_build_number: 286175, client_event_source: null,
          };

          const wsOpts = { headers: { "User-Agent": fp.ua } };
          if (proxyUrl) {
            wsOpts.agent = new HttpsProxyAgent(proxyUrl);
          }

          ws = new WebSocket(url + "?v=9&encoding=json", wsOpts);
          let seq = null;

          ws.on("open", () => {
            if (!canIdentify(token)) {
              console.log(chalk.red(`  [!] #${idx} (${masked}) IDENTIFY limit reached (max ${IDENTIFY_LIMIT}/24h) — skipping`));
              try { ws.close(1000); } catch {}
              finish({ ok: false, error: "IDENTIFY limit", idx });
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
                finish({ ok: true, ws, heartbeatTimer, seq, status, token, idx, proxyUrl });
              }

              if (msg.op === 9) {
                clearTimeout(timer);
                clearInterval(heartbeatTimer);
                markFailed(token);
                try { ws.close(); } catch {}
                console.log(chalk.red(`  [!] #${idx} (${masked}) INVALID SESSION (op 9) — token flagged`));
                finish({ ok: false, error: "invalid session", idx });
              }
            } catch {}
          });

          ws.on("error", (err) => {
            clearTimeout(timer);
            clearInterval(heartbeatTimer);
            markFailed(token);
            finish({ ok: false, error: err.message || "ws error", idx });
          });

          ws.on("close", (code) => {
            clearTimeout(timer);
            clearInterval(heartbeatTimer);

            const noReconnectCodes = [4004, 4009, 4010, 4011, 4012, 4013, 4014];
            const safeReconnectCodes = [1000, 1001, 1006];

            if (noReconnectCodes.includes(code)) {
              markFailed(token);
              console.log(chalk.red(`  [!] #${idx} (${masked}) closed ${code}: fatal — will NOT reconnect`));
              delete connections[idx];
              return;
            }

            if (cyclingActive && safeReconnectCodes.includes(code)) {
              const reconnDelay = RECONNECT_MIN + Math.random() * (RECONNECT_MAX - RECONNECT_MIN);
              console.log(chalk.yellow(`  [~] #${idx} (${masked}) disconnected (${code}), reconnect in ${Math.round(reconnDelay / 1000)}s...`));
              setTimeout(() => {
                if (cyclingActive) {
                  connectOne(token, status, idx, 0).then(r => {
                    if (r.ok) {
                      connections[idx] = r;
                      console.log(chalk.green(`  [+] #${idx} (${masked}) reconnected as ${r.status}`));
                    } else {
                      console.log(chalk.red(`  [×] #${idx} reconnect failed: ${r.error}`));
                    }
                  });
                }
              }, reconnDelay);
            }
          });
        } catch {
          clearTimeout(timer);
          finish({ ok: false, error: "parse error", idx });
        }
      });
    });

    req.on("error", (err) => {
      clearTimeout(timer);
      finish({ ok: false, error: err.message || "network error", idx });
    });

    req.on("timeout", function () {
      this.destroy();
      clearTimeout(timer);
      finish({ ok: false, error: "gateway timeout", idx });
    });

    req.end();
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

    console.log(chalk.yellow("\n[cycle] Going OFFLINE for rest period...\n"));
    for (const idx of Object.keys(connections)) {
      const c = connections[idx];
      if (c && c.ws) {
        clearInterval(c.heartbeatTimer);
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
          console.log(chalk.green(`  [+] #${r.idx} (${maskToken(r.token)}) ${r.status} — reconnected`));
        } else {
          console.log(chalk.red(`  [×] #${r.idx} failed: ${r.error}`));
        }
      }
      if (i + BATCH_SIZE < tokens.length) await new Promise(r => setTimeout(r, BATCH_DELAY));
    }
    console.log(chalk.green(`\n[cycle] ${reconnected}/${tokens.length} accounts back ONLINE!\n`));
  }
}

async function main() {
  const tokens = secureReadTokens();
  if (!tokens || tokens.length === 0) {
    console.log(chalk.red("[!] No tokens found! Add tokens to tokens.txt or use encrypted tokens.enc"));
    return;
  }

  const proxies = loadProxies();
  const statuses = ["online", "idle", "dnd"];
  const statusArg = process.argv[2];
  const globalStatus = statuses.includes(statusArg) ? statusArg : null;

  console.log(chalk.bold.cyan("\n╔══════════════════════════════════════╗"));
  console.log(chalk.bold.cyan("║     Online Mode v2.0 — Enhanced      ║"));
  console.log(chalk.bold.cyan("╚══════════════════════════════════════╝\n"));
  console.log(chalk.cyan(`Connecting ${tokens.length} accounts${globalStatus ? " as " + globalStatus : " with random status"}...\n`));
  if (proxies.length > 0) {
    console.log(chalk.green(`  Proxies: ${proxies.length} loaded from proxies.txt`));
  } else {
    console.log(chalk.dim(`  Proxies: None (Direct mode)`));
  }
  console.log(chalk.dim(`  Features: auto-reconnect, cycling sleep mode`));
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

    for (let j = 0; j < batch.length; j++) {
      const token = batch[j];
      const status = globalStatus || statuses[Math.floor(Math.random() * statuses.length)];
      const r = await connectOne(token, status, i + j + 1);
      if (r.ok) {
        connections[r.idx] = r;
        connected++;
        const pInfo = r.proxyUrl ? " (proxy)" : "";
        console.log(chalk.green(`    [+] #${r.idx} (${maskToken(token)}) ${r.status}${pInfo} — connected`));
      } else {
        failed++;
        console.log(chalk.red(`    [×] #${r.idx} (${maskToken(token)}) — ${r.error}`));
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
  console.log(chalk.cyan("\n  Auto-reconnect: ENABLED (safe codes only)"));
  console.log(chalk.cyan("  IDENTIFY limit: max 3 per 24h per token"));
  console.log(chalk.cyan("  Cycling mode: 20-22h ON → 2-4h OFF → repeat"));
  console.log(chalk.cyan("  Press Ctrl+C to disconnect all.\n"));

  if (connected > 0) {
    startCycling(tokens, globalStatus);
  }

  const cleanup = () => {
    console.log(chalk.yellow("\nDisconnecting all accounts..."));
    cyclingActive = false;
    for (const idx of Object.keys(connections)) {
      const c = connections[idx];
      if (c) {
        clearInterval(c.heartbeatTimer);
        try { if (c.ws) c.ws.close(1000); } catch {}
      }
    }
    console.log(chalk.green("Done. Exiting."));
    process.exit(0);
  };

  process.on("SIGINT", cleanup);
  process.on("SIGTERM", cleanup);
}

main().catch(err => console.error(chalk.red("[!] Online error:"), err));
