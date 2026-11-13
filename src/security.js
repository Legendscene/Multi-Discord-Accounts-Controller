const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const TOKENS_FILE = path.join(__dirname, "..", "tokens.txt");
const ENC_TOKENS_FILE = path.join(__dirname, "..", "tokens.enc");
const KEY_FILE = path.join(__dirname, "..", ".key");

// --- Encryption & Decryption (AES-256-GCM) ---

function getEncryptionKey() {
  if (fs.existsSync(KEY_FILE)) {
    try {
      const keyHex = fs.readFileSync(KEY_FILE, "utf-8").trim();
      if (/^[0-9a-fA-F]{64}$/.test(keyHex)) {
        return Buffer.from(keyHex, "hex");
      }
    } catch {}
  }
  return null;
}

function getOrCreateEncryptionKey() {
  let key = getEncryptionKey();
  if (!key) {
    key = crypto.randomBytes(32);
    try {
      fs.writeFileSync(KEY_FILE, key.toString("hex"), "utf-8");
    } catch {}
  }
  return key;
}

function encryptTokens(tokens, keyBuffer) {
  const key = keyBuffer || getOrCreateEncryptionKey();
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const sanitized = tokens.map(t => t.trim()).filter(t => t && !t.startsWith("#"));
  const plainText = sanitized.join("\n") + "\n";
  let encrypted = cipher.update(plainText, "utf8", "hex");
  encrypted += cipher.final("hex");
  const tag = cipher.getAuthTag();
  return `${iv.toString("hex")}:${tag.toString("hex")}:${encrypted}`;
}

function decryptTokens(encryptedStr, keyBuffer) {
  const key = keyBuffer || getEncryptionKey();
  if (!key || !encryptedStr) return [];
  const parts = encryptedStr.trim().split(":");
  if (parts.length !== 3) return [];
  const [ivHex, tagHex, dataHex] = parts;
  try {
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(ivHex, "hex"));
    decipher.setAuthTag(Buffer.from(tagHex, "hex"));
    let decrypted = decipher.update(Buffer.from(dataHex, "hex"), null, "utf8");
    decrypted += decipher.final("utf8");
    return decrypted.split("\n").map(l => l.trim()).filter(l => l && !l.startsWith("#"));
  } catch (err) {
    return [];
  }
}

function secureReadTokens() {
  // 1. Try reading plain tokens.txt first
  if (fs.existsSync(TOKENS_FILE)) {
    try {
      const content = fs.readFileSync(TOKENS_FILE, "utf-8");
      const tokens = content.split("\n").map(l => l.trim()).filter(l => l && !l.startsWith("#"));
      if (tokens.length > 0) return tokens;
    } catch {}
  }

  // 2. If tokens.txt is missing or empty, try decrypting tokens.enc
  if (fs.existsSync(ENC_TOKENS_FILE) && fs.existsSync(KEY_FILE)) {
    try {
      const encContent = fs.readFileSync(ENC_TOKENS_FILE, "utf-8");
      const decrypted = decryptTokens(encContent);
      if (decrypted.length > 0) return decrypted;
    } catch {}
  }

  return [];
}

function secureWriteTokens(tokens) {
  const sanitized = tokens.map(t => t.trim()).filter(t => t && !t.startsWith("#"));
  const plainContent = sanitized.join("\n") + "\n";

  // Always write / update tokens.txt if it already exists or if tokens.enc does not exist
  try {
    fs.writeFileSync(TOKENS_FILE, plainContent, "utf-8");
  } catch {}

  // If encryption key or encrypted tokens exist, keep tokens.enc synchronized
  if (fs.existsSync(KEY_FILE) || fs.existsSync(ENC_TOKENS_FILE)) {
    try {
      const encrypted = encryptTokens(sanitized);
      fs.writeFileSync(ENC_TOKENS_FILE, encrypted, "utf-8");
    } catch {}
  }
}

function hashTokenForProfile(token) {
  return crypto.createHash("sha256").update(token).digest("hex").slice(0, 16);
}

// --- Shared Rate Limiter & Cooldown State ---

const _identifyCounts = new Map();
const IDENTIFY_LIMIT = 3; // Max 3 IDENTIFY per 24h (Discord allows 5)
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

module.exports = {
  secureReadTokens,
  secureWriteTokens,
  encryptTokens,
  decryptTokens,
  getEncryptionKey,
  getOrCreateEncryptionKey,
  hashTokenForProfile,
  canIdentify,
  recordIdentify,
  isOnCooldown,
  markFailed,
  IDENTIFY_LIMIT,
  TOKENS_FILE,
  ENC_TOKENS_FILE,
  KEY_FILE,
};
