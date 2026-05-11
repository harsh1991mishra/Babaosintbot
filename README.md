# 🕵️ Cyber Baba OSINT Bot

> Free, open-source OSINT toolkit delivered via Telegram — **no paid APIs, no AI hallucinations, just real intelligence data.**

[![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python)](https://python.org)
[![python-telegram-bot](https://img.shields.io/badge/python--telegram--bot-21.6-blue)](https://python-telegram-bot.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Telegram](https://img.shields.io/badge/Telegram-@Babaosintbot-blue?logo=telegram)](https://t.me/Babaosintbot)

---

## 🔍 What is it?

**@Babaosintbot** is a Telegram bot that runs real OSINT (Open Source Intelligence) operations directly in your chat. No ChatGPT, no Gemini — just battle-tested free tools and open APIs queried live.

Built by **Harsh Mishra** (`harsh1991mishra`) for security researchers, data analysts, and curious minds.

---

## ⚡ Features & Commands

| Command | Description | Data Source |
|---------|-------------|-------------|
| `/ip <IP/domain>` | Geolocation, ISP, ASN, proxy/VPN detection | ip-api.com |
| `/whois <domain>` | Registrar, registrant, dates, nameservers | python-whois |
| `/dns <domain>` | A, AAAA, MX, NS, TXT, CNAME, SOA records | dnspython |
| `/user <username>` | Check username across 20+ social platforms | HTTP enumeration |
| `/phone <+number>` | Country, carrier, line type, number format | phonenumbers |
| `/url <url>` | Unshorten, follow redirects, HTTPS/HSTS check | requests |
| `/headers <url>` | Full HTTP headers + security header audit | requests |
| `/sub <domain>` | Subdomain enumeration via certificate logs | crt.sh |
| `/reverse <IP>` | Reverse IP / shared hosting lookup | HackerTarget |
| `/myip` | Lookup your own public IP info | ipify + ip-api |
| `/help` | Full command reference | — |
| `/about` | About this bot | — |

**Smart detection:** Drop a plain IP or domain into the chat and the bot auto-detects what you want.

---

## 🏗 Tech Stack

| Component | Library / API |
|-----------|---------------|
| Bot framework | [python-telegram-bot](https://github.com/python-telegram-bot/python-telegram-bot) v21.6 |
| IP intelligence | [ip-api.com](https://ip-api.com) (free, 45 req/min) |
| WHOIS | [python-whois](https://github.com/richardpenman/whois) |
| DNS records | [dnspython](https://github.com/rthalley/dnspython) |
| Phone parsing | [phonenumbers](https://github.com/daviddrysdale/python-phonenumbers) |
| Subdomains | [crt.sh](https://crt.sh) (certificate transparency) |
| Reverse IP | [HackerTarget](https://hackertarget.com/reverse-ip-lookup/) (free tier) |
| HTTP analysis | Python `requests` |

---

## 🚀 Setup & Run

### Prerequisites

- Python 3.11+
- A Telegram Bot Token from [@BotFather](https://t.me/BotFather)

### 1. Clone the repo

```bash
git clone https://github.com/harsh1991mishra/Babaosintbot.git
cd Babaosintbot
```

### 2. Install dependencies

```bash
pip install python-telegram-bot==21.6 python-whois dnspython phonenumbers requests
```

### 3. Set environment variables

```bash
export TELEGRAM_BOT_TOKEN="your_token_here"
```

Or create a `.env` file (and use `python-dotenv`):

```env
TELEGRAM_BOT_TOKEN=your_token_here
```

### 4. Run

```bash
python bot.py
```

---

## 🌐 Deploy on Replit

1. Fork this repo or import it into [Replit](https://replit.com)
2. Add `TELEGRAM_BOT_TOKEN` to Replit Secrets
3. The bot workflow starts automatically

---

## 📁 Project Structure

```
Babaosintbot/
├── bot.py          # Main bot — all OSINT logic and handlers
├── README.md       # This file
├── pyproject.toml  # Python dependencies
└── .gitignore      # Ignores .env and cache files
```

---

## 🔒 Privacy & Ethics

- This bot queries **publicly available data only**
- No user data is stored or logged
- Intended for **educational, defensive security, and research** purposes
- Never use OSINT tools against individuals without consent or legal authority

---

## 👨‍💻 Author

**Harsh Mishra**
- GitHub: [@harsh1991mishra](https://github.com/harsh1991mishra)
- Telegram Bot: [@Babaosintbot](https://t.me/Babaosintbot)

---

## 📄 License

MIT License — free to use, modify, and distribute.
