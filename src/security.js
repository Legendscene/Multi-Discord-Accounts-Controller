const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const TOKENS_FILE = path.join(__dirname, "..", "tokens.txt");

function secureReadTokens() {
  if (!fs.existsSync(TOKENS_FILE)) return [];
  try {
    const content = fs.readFileSync(TOKENS_FILE, "utf-8");
    return content.split("\n").map(l => l.trim()).filter(l => l && !l.startsWith("#"));
  } catch { return []; }
}

function secureWriteTokens(tokens) {
  const sanitized = tokens.map(t => t.trim()).filter(t => t && !t.startsWith("#"));
  fs.writeFileSync(TOKENS_FILE, sanitized.join("\n") + "\n", "utf-8");
}

function hashTokenForProfile(token) {
  return crypto.createHash("sha256").update(token).digest("hex").slice(0, 16);
}

module.exports = {
  secureReadTokens,
  secureWriteTokens,
  hashTokenForProfile,
};
