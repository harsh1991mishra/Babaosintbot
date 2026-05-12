# 🕵️ Cyber Baba OSINT Bot

> **@Babaosintbot** — 18 free intelligence tools in one Telegram bot. Tap buttons, get results. No commands, no paid APIs.

[![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python)](https://python.org)
[![Telegram Bot](https://img.shields.io/badge/Telegram-@Babaosintbot-2CA5E0?logo=telegram)](https://t.me/Babaosintbot)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Free](https://img.shields.io/badge/APIs-100%25%20Free-brightgreen)](https://github.com/harsh1991mishra/Babaosintbot)

---

## 🚀 Features

| Category | Tools |
|---|---|
| **Identity** | 📞 Phone • 📧 Email Breach • 👤 Username Hunt • 🏷 MAC Vendor |
| **Network** | 🌐 IP Geo • 🎯 Shodan • 🔌 Port Scan • 🌍 ASN • 🛡 Reverse IP |
| **Domain/Web** | 🔍 WHOIS • 📡 DNS • 📂 Subdomains • 🔐 SSL/TLS • 🏛 Wayback |
| **URLs** | 🔗 URL Analysis • 🔎 HTTP Headers | 
| **Intelligence** | 💡 Google Dorks • 🔑 Hash Lookup |

## 🆓 Data Sources — All Free

| Tool | Source | Key needed? |
|---|---|---|
| 📞 Phone | Google libphonenumber | ❌ None |
| 📧 Email Breach | LeakCheck.io public API | ❌ None |
| 👤 Username | Sherlock (open-source) | ❌ None |
| 🌐 IP Geo | ip-api.com | ❌ None |
| 🎯 Shodan | internetdb.shodan.io | ❌ None |
| 🔌 Port Scan | HackerTarget nmap API | ❌ None |
| 🌍 ASN | HackerTarget ASN API | ❌ None |
| 🛡 Reverse IP | HackerTarget reverse | ❌ None |
| 🔍 WHOIS | python-whois | ❌ None |
| 📡 DNS | dnspython | ❌ None |
| 📂 Subdomains | crt.sh cert transparency | ❌ None |
| 🔐 SSL/TLS | Python ssl module | ❌ None |
| 🏛 Wayback | archive.org | ❌ None |
| 🔗 URL/Headers | requests library | ❌ None |
| 🏷 MAC Vendor | macvendors.com | ❌ None |
| 💡 Google Dorks | Local generator | ❌ None |
| 🔑 Hash Lookup | CIRCL HashLookup + Cymru | ❌ None |

## ⚙️ Setup & Deploy

### Replit (Recommended)
1. Fork this repo or open in Replit
2. Add `TELEGRAM_BOT_TOKEN` in **Secrets** tab
3. Run `python bot.py` or use the workflow
4. Publish as **Reserved VM** for 24/7 uptime

### Heroku
```bash
heroku create
heroku config:set TELEGRAM_BOT_TOKEN=your_token
git push heroku main
```

### Railway / Any VPS
```bash
export TELEGRAM_BOT_TOKEN=your_token
pip install -r requirements.txt
python bot.py
```

## 📦 Install Dependencies

```bash
pip install python-telegram-bot==21.6 phonenumbers dnspython python-whois requests sherlock-project
```

## 🔐 Security

- **Never hardcode API keys** — use environment variables
- `TELEGRAM_BOT_TOKEN` is the only required secret
- All other tools use public APIs with no authentication
- `.gitignore` blocks `.env`, `config.py`, `secrets.py`, `*.key`, `*.pem` etc.

## 💬 Usage

Start the bot on Telegram: **[@Babaosintbot](https://t.me/Babaosintbot)**

Simply tap any button from the menu — no commands needed!

```
/start    — show main menu
/menu     — show main menu  
/ip       — IP geolocation
/shodan   — Shodan InternetDB
/portscan — port scanner
/asn      — ASN lookup
/whois    — domain WHOIS
/dns      — DNS records
/sub      — subdomain finder
/ssl      — SSL/TLS certificate
/wayback  — Wayback Machine
/phone    — phone intelligence
/email    — email breach check
/user     — username hunt
/mac      — MAC vendor lookup
/dork     — Google dork generator
/hash     — hash lookup
/url      — URL analysis
/headers  — HTTP headers
/reverse  — reverse IP
/myip     — server IP info
```

## 🏗 Architecture

- **Single-file Python bot** (`bot.py`) — simple, fast to iterate
- **State machine** via `user_data["mode"]` — no ConversationHandler complexity
- **Button-first UX** — all tools accessible via inline keyboard
- **Smart auto-detect** — free-text IPs, emails, hashes, phones auto-routed
- **Async executor** — blocking lookups run in thread pool (non-blocking bot)
- **Graceful degradation** — rate limits shown as helpful messages, not crashes

## 👤 Creator

**Harsh Mishra** — [@harsh1991mishra](https://github.com/harsh1991mishra)

---

*Made with ❤️ for the OSINT community. Use responsibly and legally.*
