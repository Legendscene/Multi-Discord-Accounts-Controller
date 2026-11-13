<p align="center">
  <img src="assets/banner.svg" alt="Multi Discord Accounts Controller" width="100%" />
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License" /></a>
  <a href="https://nodejs.org/"><img src="https://img.shields.io/badge/Node.js-16%2B-brightgreen.svg" alt="Node.js" /></a>
  <img src="https://img.shields.io/badge/Purpose-Educational%20Only-red.svg" alt="Educational Only" />
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg" alt="Platform" />
  <img src="https://img.shields.io/badge/Status-Active-success.svg" alt="Status" />
</p>

---

> [!CAUTION]
> ### ⚠️ EDUCATIONAL PURPOSE ONLY / DISCLAIMER
> This repository and tool are developed **strictly for educational, research, and security auditing purposes**.
> 
> * Automating user accounts (self-botting) violates the [Discord Terms of Service](https://discord.com/terms) and [Discord Community Guidelines](https://discord.com/guidelines).
> * The author and contributors are **NOT** responsible for any account suspensions, bans, or misuse of this software.
> * Use this project only in controlled environments, private test servers, or for studying network protocol behavior, WebSocket gateway handling, and browser fingerprint emulation.

---

## 📖 Overview

**Multi Discord Accounts Controller** is an educational, multi-threaded Node.js management console designed to demonstrate how large-scale WebSocket gateway connections, API rate budgeting, browser fingerprint emulation, and proxy dispatching operate.

It provides an interactive terminal interface to manage multiple accounts simultaneously, test gateway resilience, automate test actions, and simulate human connection patterns.

---

## 📸 Visual Previews & How It Works

### 1. Interactive Terminal Interface
Below is a visual simulation of the CLI menu in action:

<p align="center">
  <img src="assets/cli_preview.svg" alt="CLI Preview" width="100%" />
</p>

---

### 2. Workflow & Quick Start Guide
Four easy steps to get the controller running:

<p align="center">
  <img src="assets/workflow.svg" alt="Quick Workflow Guide" width="100%" />
</p>

---

### 3. Architecture & Data Flow
How tokens, proxies, WebSocket gateways, and modules interact:

<p align="center">
  <img src="assets/architecture.svg" alt="System Architecture" width="100%" />
</p>

---

## ⚡ Key Features

| # | Feature | Description |
|---|---------|-------------|
| 🚀 | **Bulk Server Joiner** | Joins multiple tokens to a target server via invite with anti-burst delay staggering |
| ⚡ | **Quick Join** | Fast single-account test joiner for targeted guild joins |
| 🏷️ | **Change Nicknames** | Bulk updates guild-specific nicknames across all managed accounts |
| 🌐 | **Change Global Names** | Updates public display names on all connected profiles |
| 🛡️ | **Token Health Checker** | Identifies Valid, Phone Locked (Verification Required), and Disabled accounts |
| 🧹 | **Auto-Clean Dead Tokens** | Automatically filters and purges expired or banned tokens from your list |
| 👥 | **Bulk Friend Requests** | Dispatches friend requests to target usernames or user IDs |
| 🟢 | **Custom Status Controller** | Sets online states (`Online`, `Idle`, `Do Not Disturb`, `Invisible`) |
| 📝 | **Profile Bio Updater** | Bulk updates account "About Me" description text |
| 🎲 | **Randomized Statuses** | Rotates custom statuses with randomized delay timing |
| 😃 | **Auto-React (Manual)** | Mass-adds specified custom or standard emojis to target messages |
| 🔍 | **Auto-React (Detect)** | Automatically scans and mirrors existing reactions on a message |
| 🎙️ | **Voice Channel (VC) Join** | Connects accounts to Discord Voice Channels with mute/deaf & gateway keep-alive |
| 🔌 | **Disconnect All** | Gracefully disconnects all active voice channels and gateway WebSockets |
| 🔘 | **Button Clicker** | Automates interactions with message component buttons (Rules, Verification, Roles) |
| ⏰ | **24/7 Persistent Status** | Continuous gateway daemon with heartbeat keepalive and reconnect logic |
| 🚪 | **Bulk Server Leave** | Leaves single or multiple servers via Guild ID list |
| 🌙 | **Smart Online Daemon** | `online.js` simulates human sleep/wake cycles (e.g. 20h online, 2-4h offline) |

---

## 🛡️ Anti-Detection & Reliability Architecture

* **IDENTIFY Budget Limiter**: Discord strictly limits WebSocket `IDENTIFY` payloads to 5 per 24 hours per token. This tool enforces a maximum budget of 3 IDENTIFY calls per 24 hours to prevent account flagging.
* **Realistic Browser Fingerprints**: Rotates realistic User-Agents (Chrome 124–126, Firefox, Edge, Safari), build numbers, client properties, locales (`en-US`, `hi-IN`, etc.), and timezones.
* **Jittered Stagger Delays**: Configurable random delay windows (e.g. 10s to 25s) between consecutive connections.
* **Token Masking**: Prevents accidental exposure of account credentials in terminal output or screen recordings (`OTk3MD...xxxx`).
* **Proxy Pool Support**: Rotates through HTTP/HTTPS proxies to distribute network origin footprints.
* **Automated Captcha Solving**: Integrates with DarkCaptcha and 2Captcha APIs for automated challenge resolution.

---

## 🚀 Installation

### Prerequisites
* [Node.js](https://nodejs.org/) (Version 16.0.0 or higher)
* [Git](https://git-scm.com/)

### Step 1: Clone the Repository
```bash
git clone https://github.com/Legendscene/Multi-Discord-Accounts-Controller.git
cd Multi-Discord-Accounts-Controller
```

### Step 2: Install Dependencies
```bash
npm install
```

---

## ⚙️ Configuration

### 1. Account Tokens (`tokens.txt`)
Create a `tokens.txt` file in the root directory (or copy from `tokens.example.txt`):
```bash
cp tokens.example.txt tokens.txt
```
Paste your account tokens (one token per line):
```text
OTk3MDExODcyNzE1NDQ0MjI0.xxxxxx.xxxxxx_xxxxxx-xxxxxx
MTAxMjM0NTY3ODkwMTIzNDU2.yyyyyy.yyyyyy_yyyyyy-yyyyyy
```

### 2. Optional Proxies (`proxies.txt`)
Create a `proxies.txt` file (or copy from `proxies.example.txt`):
```bash
cp proxies.example.txt proxies.txt
```
Add your HTTP/HTTPS proxies:
```text
http://username:password@123.45.67.89:8080
http://198.51.100.25:3128
```

### 3. Settings & Captcha (`config.json`)
Create a `config.json` file (or copy from `config.example.json`):
```bash
cp config.example.json config.json
```
Edit settings:
```json
{
  "captcha_key": "YOUR_CAPTCHA_API_KEY",
  "request_delay_ms": 800,
  "connect_stagger_min_s": 10,
  "connect_stagger_max_s": 25
}
```

---

## 💻 Usage

### Launch Interactive CLI Menu
On Windows, you can double-click **`run.bat`** or run:
```bash
npm start
```

### Launch 24/7 Sleep-Cycle Daemon
To run accounts with realistic active/sleep cycles in the background:
```bash
npm run online
```

---

## 📁 Project Structure

```
Multi-Discord-Accounts-Controller/
├── assets/                  # Diagrams, previews, and banner graphics
│   ├── banner.svg           # Project header banner
│   ├── cli_preview.svg      # CLI terminal mockup & visual preview
│   ├── architecture.svg     # Modular architecture diagram
│   └── workflow.svg         # 4-step quickstart visual
├── src/
│   ├── index.js             # Interactive CLI menu & action dispatchers
│   ├── core.js              # Discord REST API, Gateway WebSocket, Fingerprints
│   └── security.js          # Token storage & cryptographic hashing
├── online.js                # Standalone 24/7 online & sleep-cycle daemon
├── run.bat                  # One-click Windows launcher
├── config.example.json      # Sample configuration template
├── tokens.example.txt       # Sample token input format
├── proxies.example.txt      # Sample proxy input format
├── package.json             # Project dependencies and metadata
├── LICENSE                  # MIT License with educational disclaimer
└── README.md                # Documentation and visual guide
```

---

## 🔒 Security Best Practices

* **Never commit sensitive files**: `tokens.txt`, `proxies.txt`, `config.json`, and `.key` are pre-configured in `.gitignore`.
* **Use Proxies**: Always distribute requests across multiple proxies to prevent IP rate-limiting.
* **Keep delays realistic**: Lower delays increase the risk of API threshold blocks and challenge triggers.

---

## 📄 License & Disclaimer

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for details.

> **Final Disclaimer**: This project is published solely for educational exploration of client-server WebSocket protocols and network automation. Neither the creator nor contributors encourage or condone unauthorized access, spamming, or disruption of third-party platforms.
