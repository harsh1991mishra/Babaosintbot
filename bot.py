#!/usr/bin/env python3
"""
Cyber Baba OSINT Bot — @Babaosintbot
Free, open-source OSINT tools delivered via Telegram.
No paid AI — real reconnaissance data only.
"""

import os
import re
import json
import socket
import logging
import asyncio
import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse

import whois
import dns.resolver
import phonenumbers
from phonenumbers import geocoder, carrier, number_type, PhoneNumberType
import requests
from requests.exceptions import RequestException

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.constants import ParseMode, ChatAction
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    filters,
    ContextTypes,
)

# ─────────────────────────── Logging ────────────────────────────
logging.basicConfig(
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger("cyber_baba_osint")

# ─────────────────────────── Config ─────────────────────────────
TELEGRAM_TOKEN = os.environ["TELEGRAM_BOT_TOKEN"]
REQUEST_TIMEOUT = 10   # seconds for HTTP requests

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}

# ─────────────────── Platform Username Check List ────────────────
PLATFORMS = [
    ("GitHub",      "https://github.com/{}",                   200),
    ("GitLab",      "https://gitlab.com/{}",                   200),
    ("Twitter/X",   "https://twitter.com/{}",                  200),
    ("Instagram",   "https://www.instagram.com/{}/",           200),
    ("Reddit",      "https://www.reddit.com/user/{}",          200),
    ("TikTok",      "https://www.tiktok.com/@{}",              200),
    ("LinkedIn",    "https://www.linkedin.com/in/{}/",         200),
    ("Pinterest",   "https://www.pinterest.com/{}/",           200),
    ("Telegram",    "https://t.me/{}",                         200),
    ("YouTube",     "https://www.youtube.com/@{}",             200),
    ("Twitch",      "https://www.twitch.tv/{}",                200),
    ("Steam",       "https://steamcommunity.com/id/{}",        200),
    ("Medium",      "https://medium.com/@{}",                  200),
    ("DevTo",       "https://dev.to/{}",                       200),
    ("Keybase",     "https://keybase.io/{}",                   200),
    ("Pastebin",    "https://pastebin.com/u/{}",               200),
    ("HackerNews",  "https://news.ycombinator.com/user?id={}", 200),
    ("Snapchat",    "https://www.snapchat.com/add/{}",         200),
    ("About.me",    "https://about.me/{}",                     200),
    ("Gravatar",    "https://gravatar.com/{}",                  200),
]

# ─────────────────────── Keyboards ─────────────────────────────
def main_menu() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("🌐 IP Lookup",       callback_data="hint_ip"),
            InlineKeyboardButton("🔍 WHOIS",            callback_data="hint_whois"),
        ],
        [
            InlineKeyboardButton("📡 DNS Records",      callback_data="hint_dns"),
            InlineKeyboardButton("👤 Username Search",  callback_data="hint_user"),
        ],
        [
            InlineKeyboardButton("📱 Phone Info",       callback_data="hint_phone"),
            InlineKeyboardButton("🔗 URL Expand",       callback_data="hint_url"),
        ],
        [
            InlineKeyboardButton("📂 Subdomains",       callback_data="hint_sub"),
            InlineKeyboardButton("🔎 HTTP Headers",     callback_data="hint_headers"),
        ],
        [
            InlineKeyboardButton("🛡 Reverse IP",       callback_data="hint_reverse"),
            InlineKeyboardButton("❓ Help",              callback_data="show_help"),
        ],
    ])

def back_menu() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[
        InlineKeyboardButton("🏠 Main Menu", callback_data="main_menu")
    ]])

# ─────────────────────── Utilities ──────────────────────────────
def safe_md(text: str) -> str:
    """Escape MarkdownV2 special characters."""
    for ch in r"_*[]()~`>#+-=|{}.!\\":
        text = text.replace(ch, f"\\{ch}")
    return text

def resolve_domain(domain: str) -> str | None:
    """Resolve domain to IP, return None on failure."""
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None

def is_valid_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False

def is_private_ip(s: str) -> bool:
    try:
        return ipaddress.ip_address(s).is_private
    except ValueError:
        return False

# ─────────────────────── OSINT Functions ────────────────────────

def osint_ip(target: str) -> str:
    """
    IP geolocation via ip-api.com (free, no key, 45 req/min).
    Accepts IP or domain.
    """
    ip = target
    if not is_valid_ip(target):
        ip = resolve_domain(target)
        if not ip:
            return f"❌ Could not resolve domain: `{target}`"

    if is_private_ip(ip):
        return f"ℹ️ `{ip}` is a *private/local IP address* — not publicly routable."

    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,"
            f"regionName,city,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting,query",
            timeout=REQUEST_TIMEOUT
        )
        d = r.json()
        if d.get("status") != "success":
            return f"❌ Lookup failed: {d.get('message', 'unknown error')}"

        proxy_flag = "⚠️ Yes" if d.get("proxy") else "✅ No"
        hosting    = "⚠️ Yes" if d.get("hosting") else "✅ No"
        mobile     = "📱 Yes" if d.get("mobile") else "🖥 No"

        return (
            f"🌐 *IP Intelligence Report*\n"
            f"{'─'*30}\n"
            f"🔎 *IP:*       `{d.get('query')}`\n"
            f"🏳 *Country:*  {d.get('country')} `{d.get('countryCode')}`\n"
            f"🏙 *Region:*   {d.get('regionName')}\n"
            f"🗺 *City:*     {d.get('city')} {d.get('zip','')}\n"
            f"🕐 *Timezone:* {d.get('timezone')}\n"
            f"📡 *ISP:*      {d.get('isp')}\n"
            f"🏢 *Org:*      {d.get('org')}\n"
            f"🔢 *ASN:*      {d.get('as')}\n"
            f"{'─'*30}\n"
            f"🔒 *VPN/Proxy:* {proxy_flag}\n"
            f"☁️ *Hosting:*   {hosting}\n"
            f"📱 *Mobile:*    {mobile}\n"
            f"🗺 *Coords:*    {d.get('lat')}, {d.get('lon')}\n"
            f"🔗 Maps: https://maps.google.com/?q={d.get('lat')},{d.get('lon')}"
        )
    except Exception as e:
        return f"❌ Error: {e}"


def osint_whois(domain: str) -> str:
    """WHOIS lookup using python-whois."""
    domain = domain.lower().strip().replace("https://","").replace("http://","").split("/")[0]
    try:
        w = whois.whois(domain)
        def fmt(val):
            if val is None:
                return "N/A"
            if isinstance(val, list):
                val = val[0]
            if isinstance(val, datetime):
                return val.strftime("%Y-%m-%d %H:%M UTC")
            return str(val)

        registrar  = fmt(w.registrar)
        created    = fmt(w.creation_date)
        expires    = fmt(w.expiration_date)
        updated    = fmt(w.updated_date)
        nameserver = ", ".join(w.name_servers[:3]) if w.name_servers else "N/A"
        status     = (w.status[0] if isinstance(w.status, list) else str(w.status or "N/A")).split(" ")[0]
        registrant = fmt(w.name or w.org)
        emails     = ", ".join(set(w.emails)) if w.emails else "Hidden (GDPR)"
        country    = fmt(w.country)

        return (
            f"🔍 *WHOIS Report — {safe_md(domain)}*\n"
            f"{'─'*30}\n"
            f"📛 *Registrar:*   {safe_md(registrar)}\n"
            f"👤 *Registrant:*  {safe_md(registrant)}\n"
            f"🌍 *Country:*     {safe_md(country)}\n"
            f"📧 *Emails:*      {safe_md(emails)}\n"
            f"{'─'*30}\n"
            f"📅 *Created:*     {safe_md(created)}\n"
            f"📅 *Expires:*     {safe_md(expires)}\n"
            f"🔄 *Updated:*     {safe_md(updated)}\n"
            f"{'─'*30}\n"
            f"🔢 *Status:*      `{safe_md(status)}`\n"
            f"🖥 *Nameservers:* {safe_md(nameserver)}"
        )
    except Exception as e:
        return f"❌ WHOIS lookup failed: {safe_md(str(e))}"


def osint_dns(domain: str) -> str:
    """DNS record lookup using dnspython."""
    domain = domain.lower().strip().replace("https://","").replace("http://","").split("/")[0]
    results = [f"📡 *DNS Records — {safe_md(domain)}*\n{'─'*30}"]
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5

    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            records = []
            for r in answers:
                txt = r.to_text()
                if rtype == "MX":
                    txt = f"priority={r.preference} → {r.exchange}"
                records.append(txt)
            joined = "\n  ".join(records)
            results.append(f"\n*{rtype}:*\n  `{joined}`")
        except dns.resolver.NoAnswer:
            results.append(f"\n*{rtype}:* _no record_")
        except dns.resolver.NXDOMAIN:
            return f"❌ Domain `{safe_md(domain)}` does not exist \\(NXDOMAIN\\)"
        except Exception:
            results.append(f"\n*{rtype}:* _query failed_")

    return "\n".join(results)


def osint_username(username: str) -> dict:
    """Check username across 20 platforms concurrently."""
    found, not_found, errors = [], [], []

    def check(name, url_template, expected_code):
        url = url_template.format(username)
        try:
            r = requests.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT,
                             allow_redirects=True)
            if r.status_code == expected_code:
                found.append((name, url))
            elif r.status_code == 404:
                not_found.append(name)
            else:
                errors.append(f"{name} (HTTP {r.status_code})")
        except RequestException:
            errors.append(f"{name} (timeout)")

    # Run checks sequentially (Telegram bot is async but requests is sync)
    for name, tmpl, code in PLATFORMS:
        check(name, tmpl, code)

    return {"found": found, "not_found": not_found, "errors": errors}


def osint_phone(number: str) -> str:
    """Parse phone number with phonenumbers library."""
    try:
        parsed = phonenumbers.parse(number, None)
        if not phonenumbers.is_valid_number(parsed):
            return "❌ Invalid phone number. Use international format: `+91XXXXXXXXXX`"

        type_map = {
            PhoneNumberType.MOBILE:           "📱 Mobile",
            PhoneNumberType.FIXED_LINE:       "☎️ Fixed Line",
            PhoneNumberType.FIXED_LINE_OR_MOBILE: "📞 Fixed/Mobile",
            PhoneNumberType.TOLL_FREE:        "🆓 Toll Free",
            PhoneNumberType.PREMIUM_RATE:     "💰 Premium Rate",
            PhoneNumberType.VOIP:             "🌐 VoIP",
            PhoneNumberType.UNKNOWN:          "❓ Unknown",
        }
        ntype    = type_map.get(number_type(parsed), "❓ Unknown")
        region   = geocoder.description_for_number(parsed, "en") or "N/A"
        carr     = carrier.name_for_number(parsed, "en") or "N/A"
        e164     = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        intl     = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        national = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
        country  = phonenumbers.region_code_for_number(parsed)
        possible = phonenumbers.is_possible_number(parsed)

        return (
            f"📱 *Phone Intelligence Report*\n"
            f"{'─'*30}\n"
            f"📞 *Number:*     `{safe_md(e164)}`\n"
            f"🌍 *Country:*    {safe_md(country)}\n"
            f"📍 *Region:*     {safe_md(region)}\n"
            f"📡 *Carrier:*    {safe_md(carr)}\n"
            f"📋 *Type:*       {ntype}\n"
            f"{'─'*30}\n"
            f"🔢 *E\\-164:*     `{safe_md(e164)}`\n"
            f"🌐 *Intl:*       `{safe_md(intl)}`\n"
            f"🏠 *National:*   `{safe_md(national)}`\n"
            f"✅ *Valid:*      {'Yes' if phonenumbers.is_valid_number(parsed) else 'No'}\n"
            f"🔍 *Possible:*   {'Yes' if possible else 'No'}"
        )
    except phonenumbers.NumberParseException as e:
        return f"❌ Could not parse number: {safe_md(str(e))}\n\nUse international format: `\\+91XXXXXXXXXX`"


def osint_url(url: str) -> str:
    """Expand URL and extract header info."""
    if not url.startswith("http"):
        url = "http://" + url
    try:
        r = requests.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT,
                         allow_redirects=True)
        history = r.history
        final   = r.url
        parsed  = urlparse(final)
        status  = r.status_code
        server  = r.headers.get("Server", "N/A")
        content = r.headers.get("Content-Type", "N/A").split(";")[0]
        powered = r.headers.get("X-Powered-By", "N/A")
        length  = r.headers.get("Content-Length", "N/A")
        https   = "🔒 Yes" if parsed.scheme == "https" else "⚠️ No"
        hsts    = "✅ Yes" if "Strict-Transport-Security" in r.headers else "❌ No"

        redirects = ""
        if history:
            chain = " → ".join([safe_md(h.url) for h in history] + [safe_md(final)])
            redirects = f"\n🔄 *Redirect chain:*\n  {chain}"

        return (
            f"🔗 *URL Intelligence*\n"
            f"{'─'*30}\n"
            f"🌐 *Final URL:*    `{safe_md(final)}`\n"
            f"🏠 *Host:*         `{safe_md(parsed.netloc)}`\n"
            f"📂 *Path:*         `{safe_md(parsed.path or '/')}`\n"
            f"📊 *HTTP Status:*  `{status}`\n"
            f"{'─'*30}\n"
            f"🖥 *Server:*       `{safe_md(server)}`\n"
            f"⚙️ *Powered By:*   `{safe_md(powered)}`\n"
            f"📄 *Content Type:* `{safe_md(content)}`\n"
            f"📦 *Size:*         `{safe_md(str(length))} bytes`\n"
            f"🔒 *HTTPS:*        {https}\n"
            f"🛡 *HSTS:*         {hsts}"
            f"{redirects}"
        )
    except Exception as e:
        return f"❌ Error: {safe_md(str(e))}"


def osint_headers(url: str) -> str:
    """Fetch and display full HTTP response headers."""
    if not url.startswith("http"):
        url = "http://" + url
    try:
        r = requests.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT,
                         allow_redirects=True)
        lines = [
            f"🔎 *HTTP Headers — {safe_md(urlparse(url).netloc)}*\n{'─'*30}",
            f"*Status:* `{r.status_code} {r.reason}`\n"
        ]
        security_headers = {
            "Strict-Transport-Security", "Content-Security-Policy",
            "X-Frame-Options", "X-Content-Type-Options",
            "Referrer-Policy", "Permissions-Policy",
            "X-XSS-Protection",
        }
        for k, v in r.headers.items():
            prefix = "🛡 " if k in security_headers else "• "
            v_display = v[:80] + "…" if len(v) > 80 else v
            lines.append(f"{prefix}`{safe_md(k)}:` {safe_md(v_display)}")
        return "\n".join(lines)
    except Exception as e:
        return f"❌ Error fetching headers: {safe_md(str(e))}"


def osint_subdomains(domain: str) -> str:
    """Find subdomains using crt.sh certificate transparency logs."""
    domain = domain.lower().strip().replace("https://","").replace("http://","").split("/")[0]
    try:
        r = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=REQUEST_TIMEOUT + 5,
            headers=HEADERS,
        )
        if r.status_code != 200:
            return f"❌ crt.sh returned HTTP {r.status_code}"

        data   = r.json()
        subs   = set()
        for entry in data:
            name = entry.get("name_value", "")
            for line in name.splitlines():
                line = line.strip().lstrip("*.")
                if domain in line:
                    subs.add(line.lower())

        subs = sorted(subs)
        if not subs:
            return f"🔍 No subdomains found for `{safe_md(domain)}` in certificate logs."

        lines = [
            f"📂 *Subdomains — {safe_md(domain)}*\n"
            f"Found *{len(subs)}* unique subdomains \\(via crt\\.sh\\)\n"
            f"{'─'*30}"
        ]
        for sub in subs[:50]:   # cap at 50
            lines.append(f"• `{safe_md(sub)}`")
        if len(subs) > 50:
            lines.append(f"\n_...and {len(subs)-50} more_")
        return "\n".join(lines)
    except json.JSONDecodeError:
        return "❌ No data returned from crt\\.sh — domain may not have SSL certificates."
    except Exception as e:
        return f"❌ Error: {safe_md(str(e))}"


def osint_reverse_ip(ip: str) -> str:
    """Reverse IP lookup using HackerTarget free API."""
    if not is_valid_ip(ip):
        resolved = resolve_domain(ip)
        if not resolved:
            return f"❌ Could not resolve: `{safe_md(ip)}`"
        ip = resolved

    try:
        r = requests.get(
            f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
            timeout=REQUEST_TIMEOUT,
        )
        text = r.text.strip()
        if "error" in text.lower() or "no record" in text.lower():
            return f"🔍 No reverse DNS records found for `{safe_md(ip)}`"

        hosts = [h.strip() for h in text.splitlines() if h.strip()]
        lines = [
            f"🛡 *Reverse IP Lookup — {safe_md(ip)}*\n"
            f"Found *{len(hosts)}* host\\(s\\)\n"
            f"{'─'*30}"
        ]
        for h in hosts[:40]:
            lines.append(f"• `{safe_md(h)}`")
        if len(hosts) > 40:
            lines.append(f"\n_...and {len(hosts)-40} more_")
        return "\n".join(lines)
    except Exception as e:
        return f"❌ Error: {safe_md(str(e))}"


# ─────────────────────── Command Handlers ────────────────────────
async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    name = update.effective_user.first_name or "Investigator"
    text = (
        f"🕵️ *Namaste {safe_md(name)}\\!*\n\n"
        "*Cyber Baba OSINT Bot* is your free, open\\-source intelligence toolkit\\.\n\n"
        "No AI hallucinations — just *real data* from trusted sources\\.\n\n"
        "👇 *Pick a tool or use a command:*"
    )
    await update.message.reply_text(text, parse_mode=ParseMode.MARKDOWN_V2,
                                    reply_markup=main_menu())


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (
        "🕵️ *Cyber Baba OSINT — Command Reference*\n"
        f"{'─'*32}\n\n"
        "*Reconnaissance:*\n"
        "`/ip <IP or domain>` — Geolocation, ISP, proxy detection\n"
        "`/whois <domain>` — Registrar, dates, registrant\n"
        "`/dns <domain>` — A, AAAA, MX, NS, TXT, CNAME, SOA\n"
        "`/reverse <IP>` — Reverse IP / shared hosting lookup\n"
        "`/sub <domain>` — Subdomain enumeration via crt\\.sh\n\n"
        "*Identity:*\n"
        "`/user <username>` — Check 20\\+ social platforms\n"
        "`/phone <+1234>` — Country, carrier, line type\n\n"
        "*Web Analysis:*\n"
        "`/url <url>` — Unshorten, redirects, HTTPS check\n"
        "`/headers <url>` — Full HTTP headers \\+ security audit\n\n"
        "*General:*\n"
        "`/myip` — Your current public IP info\n"
        "`/about` — About this bot\n"
        "`/help` — This guide\n\n"
        "📡 _All tools use free, public APIs — no API keys required\\._"
    )
    await update.message.reply_text(text, parse_mode=ParseMode.MARKDOWN_V2,
                                    reply_markup=main_menu())


async def cmd_about(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (
        "🕵️ *About Cyber Baba OSINT Bot*\n"
        f"{'─'*30}\n\n"
        "*Handle:* @Babaosintbot\n"
        "*Creator:* Harsh Mishra \\(`harsh1991mishra`\\)\n"
        "*GitHub:* github\\.com/harsh1991mishra/Babaosintbot\n\n"
        "*Tools & Sources:*\n"
        "• 🌐 ip\\-api\\.com — IP geolocation\n"
        "• 🔍 python\\-whois — Domain WHOIS\n"
        "• 📡 dnspython — DNS records\n"
        "• 👤 requests — Username enumeration\n"
        "• 📱 phonenumbers — Phone parsing\n"
        "• 📂 crt\\.sh — Certificate transparency\n"
        "• 🛡 hackertarget\\.com — Reverse IP\n\n"
        "🆓 *100% free\\. No AI\\. No paid APIs\\. Pure OSINT\\.*"
    )
    await update.message.reply_text(text, parse_mode=ParseMode.MARKDOWN_V2,
                                    reply_markup=back_menu())


async def cmd_myip(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await context.bot.send_chat_action(update.effective_chat.id, ChatAction.TYPING)
    try:
        r = requests.get("https://api.ipify.org?format=json", timeout=REQUEST_TIMEOUT)
        public_ip = r.json().get("ip", "unknown")
        result = osint_ip(public_ip)
    except Exception:
        result = "❌ Could not determine your public IP."
    await update.message.reply_text(result, parse_mode=ParseMode.MARKDOWN,
                                    reply_markup=back_menu())


async def cmd_ip(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "Usage: `/ip <IP address or domain>`\nExample: `/ip 8\\.8\\.8\\.8`",
            parse_mode=ParseMode.MARKDOWN_V2)
        return
    target = context.args[0].strip()
    await context.bot.send_chat_action(update.effective_chat.id, ChatAction.TYPING)
    result = await asyncio.get_event_loop().run_in_executor(None, osint_ip, target)
    await update.message.reply_text(result, parse_mode=ParseMode.MARKDOWN,
                                    reply_markup=back_menu())


async def cmd_whois(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "Usage: `/whois <domain>`\nExample: `/whois google\\.com`",
            parse_mode=ParseMode.MARKDOWN_V2)
        return
    domain = context.args[0].strip()
    await context.bot.send_chat_action(update.effective_chat.id, ChatAction.TYPING)
    result = await asyncio.get_event_loop().run_in_executor(None, osint_whois, domain)
    await update.message.reply_text(result, parse_mode=ParseMode.MARKDOWN_V2,
                                    reply_markup=back_menu())


async def cmd_dns(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "Usage: `/dns <domain>`\nExample: `/dns google\\.com`",
            parse_mode=ParseMode.MARKDOWN_V2)
        return
    domain = context.args[0].strip()
    await context.bot.send_chat_action(update.effective_chat.id, ChatAction.TYPING)
    result = await asyncio.get_event_loop().run_in_executor(None, osint_dns, domain)
    await update.message.reply_text(result, parse_mode=ParseMode.MARKDOWN_V2,
                                    reply_markup=back_menu())


async def cmd_username(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "Usage: `/user <username>`\nExample: `/user harsh1991mishra`",
            parse_mode=ParseMode.MARKDOWN_V2)
        return
    username = context.args[0].strip().lstrip("@")
    await context.bot.send_chat_action(update.effective_chat.id, ChatAction.TYPING)
    await update.message.reply_text(
        f"🔍 Scanning *{safe_md(username)}* across {len(PLATFORMS)} platforms\\.\\.\\.",
        parse_mode=ParseMode.MARKDOWN_V2
    )

    loop   = asyncio.get_event_loop()
    data   = await loop.run_in_executor(None, osint_username, username)
    found  = data["found"]
    errors = data["errors"]

    lines = [
        f"👤 *Username Hunt — `{safe_md(username)}`*\n"
        f"{'─'*30}\n"
        f"✅ Found on *{len(found)}* / {len(PLATFORMS)} platforms\n"
    ]
    if found:
        lines.append("\n*🟢 Active profiles:*")
        for name, url in found:
            lines.append(f"• [{safe_md(name)}]({url})")
    if errors:
        lines.append(f"\n_⚠️ {len(errors)} platform\\(s\\) timed out_")

    await update.message.reply_text(
        "\n".join(lines),
        parse_mode=ParseMode.MARKDOWN_V2,
        reply_markup=back_menu(),
        disable_web_page_preview=True,
    )


async def cmd_phone(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "Usage: `/phone <number>`\nExample: `/phone \\+919876543210`",
            parse_mode=ParseMode.MARKDOWN_V2)
        return
    number = " ".join(context.args).strip()
    await context.bot.send_chat_action(update.effective_chat.id, ChatAction.TYPING)
    result = await asyncio.get_event_loop().run_in_executor(None, osint_phone, number)
    await update.message.reply_text(result, parse_mode=ParseMode.MARKDOWN_V2,
                                    reply_markup=back_menu())


async def cmd_url(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "Usage: `/url <url>`\nExample: `/url https://bit\\.ly/example`",
            parse_mode=ParseMode.MARKDOWN_V2)
        return
    url = context.args[0].strip()
    await context.bot.send_chat_action(update.effective_chat.id, ChatAction.TYPING)
    result = await asyncio.get_event_loop().run_in_executor(None, osint_url, url)
    await update.message.reply_text(result, parse_mode=ParseMode.MARKDOWN_V2,
                                    reply_markup=back_menu(), disable_web_page_preview=True)


async def cmd_headers(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "Usage: `/headers <url>`\nExample: `/headers https://example\\.com`",
            parse_mode=ParseMode.MARKDOWN_V2)
        return
    url = context.args[0].strip()
    await context.bot.send_chat_action(update.effective_chat.id, ChatAction.TYPING)
    result = await asyncio.get_event_loop().run_in_executor(None, osint_headers, url)
    # Headers can be long — split if needed
    if len(result) > 4000:
        result = result[:3950] + "\n\n_\\[truncated\\]_"
    await update.message.reply_text(result, parse_mode=ParseMode.MARKDOWN_V2,
                                    reply_markup=back_menu())


async def cmd_sub(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "Usage: `/sub <domain>`\nExample: `/sub google\\.com`",
            parse_mode=ParseMode.MARKDOWN_V2)
        return
    domain = context.args[0].strip()
    await context.bot.send_chat_action(update.effective_chat.id, ChatAction.TYPING)
    await update.message.reply_text(
        f"📂 Querying certificate transparency logs for `{safe_md(domain)}`\\.\\.\\.",
        parse_mode=ParseMode.MARKDOWN_V2
    )
    result = await asyncio.get_event_loop().run_in_executor(None, osint_subdomains, domain)
    if len(result) > 4000:
        result = result[:3950] + "\n\n_\\[truncated\\]_"
    await update.message.reply_text(result, parse_mode=ParseMode.MARKDOWN_V2,
                                    reply_markup=back_menu())


async def cmd_reverse(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "Usage: `/reverse <IP>`\nExample: `/reverse 8\\.8\\.8\\.8`",
            parse_mode=ParseMode.MARKDOWN_V2)
        return
    target = context.args[0].strip()
    await context.bot.send_chat_action(update.effective_chat.id, ChatAction.TYPING)
    result = await asyncio.get_event_loop().run_in_executor(None, osint_reverse_ip, target)
    await update.message.reply_text(result, parse_mode=ParseMode.MARKDOWN_V2,
                                    reply_markup=back_menu())


# ─────────────────────── Callback Handler ────────────────────────
HINTS = {
    "hint_ip":      "🌐 *IP Lookup*\nUsage: `/ip <IP or domain>`\nExample: `/ip 1\\.1\\.1\\.1`",
    "hint_whois":   "🔍 *WHOIS Lookup*\nUsage: `/whois <domain>`\nExample: `/whois github\\.com`",
    "hint_dns":     "📡 *DNS Records*\nUsage: `/dns <domain>`\nExample: `/dns cloudflare\\.com`",
    "hint_user":    "👤 *Username Search*\nUsage: `/user <username>`\nExample: `/user harsh1991mishra`",
    "hint_phone":   "📱 *Phone Info*\nUsage: `/phone <number>`\nExample: `/phone \\+917000000000`",
    "hint_url":     "🔗 *URL Expand*\nUsage: `/url <url>`\nExample: `/url https://bit\\.ly/test`",
    "hint_sub":     "📂 *Subdomain Finder*\nUsage: `/sub <domain>`\nExample: `/sub example\\.com`",
    "hint_headers": "🔎 *HTTP Headers*\nUsage: `/headers <url>`\nExample: `/headers https://example\\.com`",
    "hint_reverse": "🛡 *Reverse IP*\nUsage: `/reverse <IP>`\nExample: `/reverse 104\\.21\\.0\\.1`",
}

async def handle_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data = query.data

    if data == "main_menu":
        await query.edit_message_text(
            "🕵️ *Cyber Baba OSINT — Main Menu*\n\nChoose a tool:",
            parse_mode=ParseMode.MARKDOWN_V2,
            reply_markup=main_menu(),
        )
    elif data == "show_help":
        text = (
            "🕵️ *Available Commands*\n\n"
            "`/ip` `/whois` `/dns` `/reverse` `/sub`\n"
            "`/user` `/phone` `/url` `/headers` `/myip`\n\n"
            "Type `/help` for full details\\."
        )
        await query.edit_message_text(text, parse_mode=ParseMode.MARKDOWN_V2,
                                      reply_markup=back_menu())
    elif data in HINTS:
        await query.edit_message_text(HINTS[data], parse_mode=ParseMode.MARKDOWN_V2,
                                      reply_markup=back_menu())


# ─────────────────────── Unknown Command ─────────────────────────
async def handle_unknown(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "❓ Unknown command\\. Type `/help` to see all available tools\\.",
        parse_mode=ParseMode.MARKDOWN_V2,
        reply_markup=main_menu(),
    )


async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle plain text — try to auto-detect what the user wants."""
    text = update.message.text.strip()
    # Auto-detect IP
    if is_valid_ip(text):
        await context.bot.send_chat_action(update.effective_chat.id, ChatAction.TYPING)
        result = await asyncio.get_event_loop().run_in_executor(None, osint_ip, text)
        await update.message.reply_text(result, parse_mode=ParseMode.MARKDOWN,
                                        reply_markup=back_menu())
        return
    # Auto-detect domain-ish input
    if re.match(r"^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$", text):
        await update.message.reply_text(
            f"🔍 Looks like a domain\\! Try:\n"
            f"`/whois {safe_md(text)}`\n"
            f"`/dns {safe_md(text)}`\n"
            f"`/sub {safe_md(text)}`",
            parse_mode=ParseMode.MARKDOWN_V2,
            reply_markup=main_menu(),
        )
        return
    await update.message.reply_text(
        "🕵️ Use a command to start an OSINT lookup\\. Type `/help` to see all tools\\.",
        parse_mode=ParseMode.MARKDOWN_V2,
        reply_markup=main_menu(),
    )


async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE):
    logger.error("Error: %s", context.error, exc_info=True)


# ─────────────────────────── Main ────────────────────────────────
def main():
    app = Application.builder().token(TELEGRAM_TOKEN).build()

    app.add_handler(CommandHandler("start",   cmd_start))
    app.add_handler(CommandHandler("help",    cmd_help))
    app.add_handler(CommandHandler("about",   cmd_about))
    app.add_handler(CommandHandler("myip",    cmd_myip))
    app.add_handler(CommandHandler("ip",      cmd_ip))
    app.add_handler(CommandHandler("whois",   cmd_whois))
    app.add_handler(CommandHandler("dns",     cmd_dns))
    app.add_handler(CommandHandler("user",    cmd_username))
    app.add_handler(CommandHandler("phone",   cmd_phone))
    app.add_handler(CommandHandler("url",     cmd_url))
    app.add_handler(CommandHandler("headers", cmd_headers))
    app.add_handler(CommandHandler("sub",     cmd_sub))
    app.add_handler(CommandHandler("reverse", cmd_reverse))

    app.add_handler(CallbackQueryHandler(handle_callback))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    app.add_handler(MessageHandler(filters.COMMAND, handle_unknown))

    app.add_error_handler(error_handler)

    logger.info("🚀 Cyber Baba OSINT Bot is live! @Babaosintbot")
    app.run_polling(allowed_updates=Update.ALL_TYPES, drop_pending_updates=True)


if __name__ == "__main__":
    main()
