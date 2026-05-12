#!/usr/bin/env python3
"""
Cyber Baba OSINT Bot — @Babaosintbot
18-tool button-driven intelligence toolkit. 100% free, no paid APIs.

Tools: IP, Shodan, Port Scan, ASN, WHOIS, DNS, Subdomains, Reverse IP,
       Phone, Email Breach, Username (Sherlock), URL, HTTP Headers,
       SSL/TLS, Wayback Machine, MAC Vendor, Google Dorks, Hash Lookup

Deploy: Replit | Heroku | Railway | any VPS
GitHub: github.com/harsh1991mishra/Babaosintbot
"""

import os
import re
import ssl as ssl_lib
import json
import socket
import logging
import asyncio
import subprocess
import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse, quote

import whois
import dns.resolver
import phonenumbers
from phonenumbers import geocoder, carrier, number_type, PhoneNumberType
import requests

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
# Keys are loaded from environment variables — NEVER hardcode secrets.
#
#   Replit  → Secrets tab (lock icon) → Add TELEGRAM_BOT_TOKEN
#   Heroku  → Settings → Config Vars
#   Railway → Project → Variables
#   GitHub  → Settings → Secrets and variables → Actions
#
TELEGRAM_TOKEN  = os.getenv("TELEGRAM_BOT_TOKEN")   # required
REQUEST_TIMEOUT = 12

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )
}

# ────────────────────── Conversation Modes ──────────────────────
(MODE_IP, MODE_WHOIS, MODE_DNS, MODE_USERNAME, MODE_PHONE, MODE_EMAIL,
 MODE_URL, MODE_HEADERS, MODE_SUB, MODE_REVERSE, MODE_PORTSCAN,
 MODE_SHODAN, MODE_WAYBACK, MODE_ASN, MODE_SSL, MODE_MAC,
 MODE_DORK, MODE_HASH) = (
    "ip", "whois", "dns", "username", "phone", "email",
    "url", "headers", "sub", "reverse", "portscan",
    "shodan", "wayback", "asn", "ssl_check", "mac",
    "dork", "hash",
)

TOOL_PROMPTS = {
    # ── Identity & People ────────────────────────────────────────
    "tool_phone":    ("📞 *Phone Lookup — 100% Free*\n\n"
                      "Send a phone number in international format:\n"
                      "_Example:_ `+919876543210`\n\n"
                      "_Source: Google libphonenumber_",            MODE_PHONE),
    "tool_email":    ("📧 *Email Breach Check — 100% Free*\n\n"
                      "Send an email address to check for data breaches:\n"
                      "_Example:_ `someone@gmail.com`\n\n"
                      "_Source: LeakCheck\\.io public API_",        MODE_EMAIL),
    "tool_username": ("👤 *Username Hunt — Sherlock*\n\n"
                      "Send a username to search across 300\\+ platforms:\n"
                      "_Example:_ `harsh1991mishra`\n\n"
                      "_Source: Sherlock open\\-source tool_",      MODE_USERNAME),
    # ── Network & IP ─────────────────────────────────────────────
    "tool_ip":       ("🌐 *IP Geolocation*\n\n"
                      "Send an IP address or domain name:\n"
                      "_Example:_ `8.8.8.8` or `google.com`\n\n"
                      "_Source: ip\\-api\\.com_",                   MODE_IP),
    "tool_shodan":   ("🎯 *Shodan InternetDB*\n\n"
                      "Send an IP to see open ports, CVEs, and tags:\n"
                      "_Example:_ `45.33.32.156`\n\n"
                      "_Source: internetdb\\.shodan\\.io — free, no key_", MODE_SHODAN),
    "tool_portscan": ("🔌 *Port Scanner*\n\n"
                      "Send an IP or domain to scan common ports:\n"
                      "_Example:_ `scanme.nmap.org`\n\n"
                      "_Source: HackerTarget nmap API_",            MODE_PORTSCAN),
    "tool_asn":      ("🌍 *ASN Lookup*\n\n"
                      "Send an IP address to find its AS number and network:\n"
                      "_Example:_ `8.8.8.8`\n\n"
                      "_Source: HackerTarget API_",                 MODE_ASN),
    "tool_reverse":  ("🛡 *Reverse IP Lookup*\n\n"
                      "Send an IP to find all hosted domains:\n"
                      "_Example:_ `93.184.216.34`\n\n"
                      "_Source: HackerTarget API_",                 MODE_REVERSE),
    # ── Domain & Web ─────────────────────────────────────────────
    "tool_whois":    ("🔍 *WHOIS Lookup*\n\n"
                      "Send a domain name:\n"
                      "_Example:_ `github.com`\n\n"
                      "_Source: python\\-whois_",                   MODE_WHOIS),
    "tool_dns":      ("📡 *DNS Records*\n\n"
                      "Send a domain name:\n"
                      "_Example:_ `cloudflare.com`\n\n"
                      "_Source: dnspython_",                        MODE_DNS),
    "tool_sub":      ("📂 *Subdomain Finder*\n\n"
                      "Send a domain name:\n"
                      "_Example:_ `example.com`\n\n"
                      "_Source: crt\\.sh certificate transparency_", MODE_SUB),
    "tool_ssl":      ("🔐 *SSL/TLS Certificate*\n\n"
                      "Send a domain to inspect its certificate:\n"
                      "_Example:_ `google.com`\n\n"
                      "_Source: Python ssl module_",                 MODE_SSL),
    "tool_wayback":  ("🏛 *Wayback Machine*\n\n"
                      "Send a domain or URL to check archive history:\n"
                      "_Example:_ `example.com`\n\n"
                      "_Source: archive\\.org_",                     MODE_WAYBACK),
    "tool_url":      ("🔗 *URL Analysis*\n\n"
                      "Send a URL to analyze redirects and headers:\n"
                      "_Example:_ `https://bit.ly/example`\n\n"
                      "_Source: requests library_",                  MODE_URL),
    "tool_headers":  ("🔎 *HTTP Headers*\n\n"
                      "Send a URL to inspect all response headers:\n"
                      "_Example:_ `https://example.com`\n\n"
                      "_Source: requests library_",                  MODE_HEADERS),
    # ── Intelligence ─────────────────────────────────────────────
    "tool_mac":      ("🏷 *MAC Address Lookup*\n\n"
                      "Send a MAC address to identify its vendor:\n"
                      "_Example:_ `00:1A:2B:3C:4D:5E`\n\n"
                      "_Source: macvendors\\.com free API_",         MODE_MAC),
    "tool_dork":     ("💡 *Google Dork Generator*\n\n"
                      "Send a domain or target name to generate OSINT search queries:\n"
                      "_Example:_ `targetsite.com` or `John Doe`\n\n"
                      "_Source: local generator \\| no API needed_", MODE_DORK),
    "tool_hash":     ("🔑 *Hash Lookup*\n\n"
                      "Send an MD5, SHA1, or SHA256 hash:\n"
                      "_Example:_ `5f4dcc3b5aa765d61d8327deb882cf99`\n\n"
                      "_Source: CIRCL HashLookup \\| Team Cymru MHR_", MODE_HASH),
}

# ─────────────────────── Keyboards ──────────────────────────────
def main_menu() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        # Identity
        [InlineKeyboardButton("📞 Phone Lookup",    callback_data="tool_phone"),
         InlineKeyboardButton("📧 Email Breach",    callback_data="tool_email")],
        [InlineKeyboardButton("👤 Username Hunt",   callback_data="tool_username"),
         InlineKeyboardButton("🏷 MAC Vendor",      callback_data="tool_mac")],
        # Network & IP
        [InlineKeyboardButton("🌐 IP Lookup",       callback_data="tool_ip"),
         InlineKeyboardButton("🎯 Shodan IP",       callback_data="tool_shodan")],
        [InlineKeyboardButton("🔌 Port Scan",       callback_data="tool_portscan"),
         InlineKeyboardButton("🌍 ASN Lookup",      callback_data="tool_asn")],
        [InlineKeyboardButton("🛡 Reverse IP",      callback_data="tool_reverse"),
         InlineKeyboardButton("📡 DNS Records",     callback_data="tool_dns")],
        # Domain & Web
        [InlineKeyboardButton("🔍 WHOIS",           callback_data="tool_whois"),
         InlineKeyboardButton("📂 Subdomains",      callback_data="tool_sub")],
        [InlineKeyboardButton("🔐 SSL/TLS",         callback_data="tool_ssl"),
         InlineKeyboardButton("🏛 Wayback",         callback_data="tool_wayback")],
        [InlineKeyboardButton("🔗 URL Analysis",    callback_data="tool_url"),
         InlineKeyboardButton("🔎 HTTP Headers",    callback_data="tool_headers")],
        # Intelligence
        [InlineKeyboardButton("💡 Google Dorks",    callback_data="tool_dork"),
         InlineKeyboardButton("🔑 Hash Lookup",     callback_data="tool_hash")],
        # Meta
        [InlineKeyboardButton("🖥 My Server IP",    callback_data="cb_myip"),
         InlineKeyboardButton("ℹ️ About",           callback_data="show_about")],
        [InlineKeyboardButton("❓ Help",             callback_data="show_help")],
    ])

def back_menu() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[
        InlineKeyboardButton("🏠 Main Menu", callback_data="main_menu")
    ]])

def cancel_menu() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[
        InlineKeyboardButton("❌ Cancel", callback_data="main_menu")
    ]])

# ─────────────────────── Utilities ──────────────────────────────
def safe_md(text: str) -> str:
    """Escape MarkdownV2 special chars — backslash first."""
    text = str(text).replace("\\", "\\\\")
    for ch in r"_*[]()~`>#+-=|{}.!":
        text = text.replace(ch, f"\\{ch}")
    return text

def clean_domain(raw: str) -> str:
    return raw.lower().strip().replace("https://", "").replace("http://", "").split("/")[0].split("?")[0]

def is_valid_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s.strip())
        return True
    except ValueError:
        return False

def is_private_ip(s: str) -> bool:
    try:
        return ipaddress.ip_address(s.strip()).is_private
    except ValueError:
        return False

def resolve_domain(domain: str):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None

def truncate(text: str, limit: int = 3900) -> str:
    if len(text) > limit:
        return text[:limit] + "\n\n_\\[output truncated\\]_"
    return text

# ═══════════════════════ OSINT FUNCTIONS ════════════════════════

# ─── 1. IP Geolocation ──────────────────────────────────────────
def osint_ip(target: str) -> str:
    """IP geolocation via ip-api.com (free, 45 req/min)."""
    target = target.strip()
    ip = target
    if not is_valid_ip(target):
        ip = resolve_domain(clean_domain(target))
        if not ip:
            return f"❌ Could not resolve: `{safe_md(target)}`"

    if is_private_ip(ip):
        return f"ℹ️ `{safe_md(ip)}` is a *private/local IP* — not publicly routable\\."

    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,"
            f"regionName,city,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting,query",
            timeout=REQUEST_TIMEOUT,
        )
        d = r.json()
        if d.get("status") != "success":
            return f"❌ ip\\-api error: {safe_md(d.get('message', 'unknown'))}"

        proxy   = "⚠️ Yes" if d.get("proxy")   else "✅ No"
        hosting = "⚠️ Yes" if d.get("hosting") else "✅ No"
        mobile  = "📱 Yes" if d.get("mobile")  else "🖥 No"
        lat, lon = d.get("lat", ""), d.get("lon", "")

        return (
            f"🌐 *IP Intelligence — `{safe_md(d.get('query', ip))}`*\n"
            f"{'─'*30}\n"
            f"🏳 *Country:*  {safe_md(d.get('country',''))} `{safe_md(d.get('countryCode',''))}`\n"
            f"🏙 *Region:*   {safe_md(d.get('regionName',''))}\n"
            f"🗺 *City:*     {safe_md(d.get('city',''))} {safe_md(d.get('zip',''))}\n"
            f"🕐 *Timezone:* {safe_md(d.get('timezone',''))}\n"
            f"📡 *ISP:*      {safe_md(d.get('isp',''))}\n"
            f"🏢 *Org:*      {safe_md(d.get('org',''))}\n"
            f"🔢 *ASN:*      {safe_md(d.get('as',''))}\n"
            f"{'─'*30}\n"
            f"🔒 *VPN/Proxy:* {proxy}\n"
            f"☁️ *Hosting:*   {hosting}\n"
            f"📱 *Mobile:*    {mobile}\n"
            f"📍 *Coords:*    {safe_md(str(lat))}\\, {safe_md(str(lon))}\n"
            f"🗺 [Open in Maps](https://maps.google.com/?q={lat},{lon})\n\n"
            f"_Source: ip\\-api\\.com — free_"
        )
    except Exception as e:
        return f"❌ IP lookup error: {safe_md(str(e))}"

# ─── 2. Shodan InternetDB ───────────────────────────────────────
def osint_shodan(target: str) -> str:
    """Shodan InternetDB — open ports, CVEs, tags. Free, no key."""
    target = target.strip()
    ip = target
    if not is_valid_ip(target):
        ip = resolve_domain(clean_domain(target))
        if not ip:
            return f"❌ Could not resolve: `{safe_md(target)}`"
    if is_private_ip(ip):
        return f"ℹ️ `{safe_md(ip)}` is a private IP — Shodan only indexes public IPs\\."

    try:
        r = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=REQUEST_TIMEOUT)
        if r.status_code == 404:
            return (
                f"🎯 *Shodan InternetDB — `{safe_md(ip)}`*\n"
                f"{'─'*30}\n"
                f"🔍 No data indexed for this IP\\.\n\n"
                f"_Source: internetdb\\.shodan\\.io — free_"
            )
        d = r.json()

        ports     = d.get("ports", [])
        tags      = d.get("tags", [])
        vulns     = d.get("vulns", [])
        hostnames = d.get("hostnames", [])
        cpes      = d.get("cpes", [])

        tag_icons = {
            "cdn": "☁️", "cloud": "🌩", "vpn": "🔒", "tor": "🧅",
            "scanner": "🔍", "malware": "☠️", "honeypot": "🍯",
            "compromised": "⚠️", "self-signed": "🔓",
        }

        lines = [f"🎯 *Shodan InternetDB — `{safe_md(ip)}`*\n{'─'*30}"]

        # Ports
        port_str = " | ".join(f"`{p}`" for p in sorted(ports)) if ports else "_none indexed_"
        lines.append(f"\n🔌 *Open Ports:*\n{port_str}")

        # Hostnames
        if hostnames:
            lines.append(f"\n🌐 *Hostnames:* {safe_md(', '.join(hostnames[:4]))}")

        # Tags
        if tags:
            tag_str = "  ".join(f"{tag_icons.get(t.lower(), '🏷')} {safe_md(t)}" for t in tags)
            lines.append(f"\n🏷 *Tags:* {tag_str}")

        # CPEs (software fingerprints)
        if cpes:
            lines.append(f"\n💻 *Software \\(CPE\\):*")
            for c in cpes[:6]:
                lines.append(f"  • `{safe_md(c)}`")

        # CVEs (vulnerabilities)
        if vulns:
            lines.append(f"\n{'─'*30}")
            lines.append(f"⚠️ *Known Vulnerabilities \\({len(vulns)}\\):*")
            for v in sorted(vulns)[:10]:
                cve_link = f"[{safe_md(v)}](https://nvd.nist.gov/vuln/detail/{v})"
                lines.append(f"  • {cve_link}")
            if len(vulns) > 10:
                lines.append(f"  _\\.\\.\\. and {len(vulns)-10} more_")
        else:
            lines.append(f"\n✅ *No known CVEs indexed*")

        lines.append(f"\n_Source: internetdb\\.shodan\\.io — free, no key_")
        return "\n".join(lines)
    except Exception as e:
        return f"❌ Shodan error: {safe_md(str(e))}"

# ─── 3. Port Scanner ────────────────────────────────────────────
def osint_portscan(host: str) -> str:
    """Port scan via HackerTarget nmap API (free, limited)."""
    host = clean_domain(host)
    try:
        r = requests.get(
            f"https://api.hackertarget.com/nmap/?q={host}",
            timeout=45,
        )
        text = r.text.strip()
        if "error" in text.lower() or "API count exceeded" in text:
            return (
                f"⚠️ *Port Scan — {safe_md(host)}*\n\n"
                f"HackerTarget free API limit reached\\. Try again later\\.\n\n"
                f"_Tip: hackertarget\\.com allows 50 scans/day on free tier_"
            )

        lines = [f"🔌 *Port Scan — {safe_md(host)}*\n{'─'*30}"]
        open_ports = []
        service_map = {
            "21": "FTP", "22": "SSH", "23": "Telnet", "25": "SMTP",
            "53": "DNS", "80": "HTTP", "110": "POP3", "143": "IMAP",
            "443": "HTTPS", "3306": "MySQL", "3389": "RDP",
            "5432": "PostgreSQL", "6379": "Redis", "8080": "HTTP-Alt",
            "8443": "HTTPS-Alt", "27017": "MongoDB",
        }
        for line in text.splitlines():
            if "/tcp" in line.lower() and "open" in line.lower():
                port_num = line.split("/")[0].strip()
                service  = service_map.get(port_num, "")
                svc_tag  = f" ({service})" if service else ""
                open_ports.append(f"`{safe_md(line.strip())}`{safe_md(svc_tag)}")

        if open_ports:
            lines.append(f"\n✅ *{len(open_ports)} open port\\(s\\):*")
            lines.extend(f"  • {p}" for p in open_ports)
        else:
            lines.append("\n🔒 No open ports detected \\(host may be firewalled\\)")

        lines.append(f"\n_Source: HackerTarget nmap API — free_")
        return truncate("\n".join(lines))
    except Exception as e:
        return f"❌ Port scan error: {safe_md(str(e))}"

# ─── 4. ASN Lookup ──────────────────────────────────────────────
def osint_asn(target: str) -> str:
    """ASN / BGP lookup via HackerTarget (free)."""
    target = target.strip()
    try:
        r = requests.get(
            f"https://api.hackertarget.com/aslookup/?q={target}",
            timeout=REQUEST_TIMEOUT,
        )
        text = r.text.strip()
        if "error" in text.lower() or "API count" in text:
            return f"⚠️ ASN lookup rate limited\\. Try again later\\."

        lines = [f"🌍 *ASN Lookup — {safe_md(target)}*\n{'─'*30}"]
        for line in text.splitlines():
            if line.strip():
                parts = line.strip().strip('"').split('","')
                if len(parts) >= 4:
                    ip_addr, asn, cidr, org = parts[0], parts[1], parts[2], parts[3]
                    lines.append(f"\n📡 *IP:*      `{safe_md(ip_addr)}`")
                    lines.append(f"🔢 *ASN:*     `AS{safe_md(asn)}`")
                    lines.append(f"🌐 *Network:* `{safe_md(cidr)}`")
                    lines.append(f"🏢 *Owner:*   {safe_md(org)}")
                else:
                    lines.append(f"`{safe_md(line)}`")

        lines.append(f"\n_Source: HackerTarget ASN API — free_")
        return "\n".join(lines)
    except Exception as e:
        return f"❌ ASN error: {safe_md(str(e))}"

# ─── 5. WHOIS ───────────────────────────────────────────────────
def osint_whois(domain: str) -> str:
    domain = clean_domain(domain)
    try:
        w = whois.whois(domain)

        def fmt(val):
            if val is None: return "N/A"
            if isinstance(val, list): val = val[0]
            if isinstance(val, datetime): return val.strftime("%Y-%m-%d %H:%M UTC")
            return str(val)

        registrar  = fmt(w.registrar)
        created    = fmt(w.creation_date)
        expires    = fmt(w.expiration_date)
        updated    = fmt(w.updated_date)
        nameserver = ", ".join(list(w.name_servers)[:3]) if w.name_servers else "N/A"
        status     = (w.status[0] if isinstance(w.status, list) else str(w.status or "N/A")).split(" ")[0]
        registrant = fmt(w.name or w.org)
        emails     = ", ".join(set(w.emails)) if w.emails else "Hidden (GDPR)"
        country    = fmt(w.country)

        # Calculate domain age
        try:
            cd = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            age_days = (datetime.now() - cd.replace(tzinfo=None)).days
            age_str  = f"{age_days // 365}y {(age_days % 365) // 30}m"
        except Exception:
            age_str = "N/A"

        return (
            f"🔍 *WHOIS — {safe_md(domain)}*\n"
            f"{'─'*30}\n"
            f"📛 *Registrar:*   {safe_md(registrar)}\n"
            f"👤 *Registrant:*  {safe_md(registrant)}\n"
            f"🌍 *Country:*     {safe_md(country)}\n"
            f"📧 *Emails:*      {safe_md(emails)}\n"
            f"{'─'*30}\n"
            f"📅 *Created:*     {safe_md(created)} \\({safe_md(age_str)} old\\)\n"
            f"📅 *Expires:*     {safe_md(expires)}\n"
            f"🔄 *Updated:*     {safe_md(updated)}\n"
            f"{'─'*30}\n"
            f"🔢 *Status:*      `{safe_md(status)}`\n"
            f"🖥 *Nameservers:* {safe_md(nameserver)}"
        )
    except Exception as e:
        return f"❌ WHOIS failed: {safe_md(str(e))}"

# ─── 6. DNS Records ─────────────────────────────────────────────
def osint_dns(domain: str) -> str:
    domain   = clean_domain(domain)
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    results  = [f"📡 *DNS Records — {safe_md(domain)}*\n{'─'*30}"]

    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]:
        try:
            answers = resolver.resolve(domain, rtype)
            records = []
            for rec in answers:
                txt = rec.to_text()
                if rtype == "MX":
                    txt = f"priority={rec.preference} → {rec.exchange}"
                records.append(txt)
            results.append(f"\n*{rtype}:*\n  `{safe_md(chr(10).join(records))}`")
        except dns.resolver.NoAnswer:
            results.append(f"\n*{rtype}:* _no record_")
        except dns.resolver.NXDOMAIN:
            return f"❌ Domain `{safe_md(domain)}` does not exist \\(NXDOMAIN\\)"
        except Exception:
            results.append(f"\n*{rtype}:* _query failed_")

    return truncate("\n".join(results))

# ─── 7. Phone (libphonenumber — free) ───────────────────────────
def osint_phone(number: str) -> str:
    """Phone intelligence via Google libphonenumber. Free, no key."""
    number = number.strip()
    if not number.startswith("+"):
        number = "+" + number
    try:
        parsed = phonenumbers.parse(number, None)
    except phonenumbers.NumberParseException as e:
        return (
            f"❌ *Cannot parse:* `{safe_md(number)}`\n\n"
            f"_{safe_md(str(e))}_\n\n"
            f"Use international format: `\\+91XXXXXXXXXX`"
        )

    if not phonenumbers.is_valid_number(parsed):
        return f"❌ Invalid number: `{safe_md(number)}`\n\nUse international format e\\.g\\. `\\+919876543210`"

    type_map = {
        PhoneNumberType.MOBILE:               ("📱", "Mobile"),
        PhoneNumberType.FIXED_LINE:           ("☎️", "Fixed Line"),
        PhoneNumberType.FIXED_LINE_OR_MOBILE: ("📞", "Fixed / Mobile"),
        PhoneNumberType.TOLL_FREE:            ("🆓", "Toll Free"),
        PhoneNumberType.PREMIUM_RATE:         ("💰", "Premium Rate"),
        PhoneNumberType.VOIP:                 ("🌐", "VoIP"),
        PhoneNumberType.PAGER:                ("📟", "Pager"),
        PhoneNumberType.UAN:                  ("🏢", "UAN / Corporate"),
        PhoneNumberType.UNKNOWN:              ("❓", "Unknown"),
    }
    nt_icon, nt_label = type_map.get(number_type(parsed), ("❓", "Unknown"))

    region   = geocoder.description_for_number(parsed, "en") or "N/A"
    carr     = carrier.name_for_number(parsed, "en") or "N/A"
    e164     = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    intl     = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
    national = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
    country  = phonenumbers.region_code_for_number(parsed) or "N/A"
    possible = "✅ Yes" if phonenumbers.is_possible_number(parsed) else "⚠️ Maybe"

    try:
        from phonenumbers import timezone as pn_tz
        tz_list = pn_tz.time_zones_for_number(parsed)
        tz_str  = safe_md(", ".join(tz_list[:2])) if tz_list else "N/A"
    except Exception:
        tz_str = "N/A"

    return (
        f"📞 *Phone Intelligence — `{safe_md(e164)}`*\n"
        f"{'─'*30}\n"
        f"🌍 *Country Code:* `{safe_md(country)}`\n"
        f"📍 *Region:*       {safe_md(region)}\n"
        f"📡 *Carrier:*      {safe_md(carr)}\n"
        f"📋 *Line Type:*    {nt_icon} {safe_md(nt_label)}\n"
        f"🕐 *Timezone:*     {tz_str}\n"
        f"{'─'*30}\n"
        f"🌐 *Intl Format:*  `{safe_md(intl)}`\n"
        f"🏠 *National:*     `{safe_md(national)}`\n"
        f"🔢 *E\\-164:*       `{safe_md(e164)}`\n"
        f"✅ *Valid:*        Yes\n"
        f"🔍 *Possible:*     {possible}\n\n"
        f"_Source: Google libphonenumber — free_"
    )

# ─── 8. Email Breach (LeakCheck — free) ─────────────────────────
def osint_email(email: str) -> str:
    """Email breach check via LeakCheck.io public API. Free, no key."""
    email = email.strip().lower()
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return f"❌ Invalid email format: `{safe_md(email)}`"

    domain = email.split("@")[1]
    mx_ok  = False
    try:
        dns.resolver.resolve(domain, "MX")
        mx_ok = True
    except Exception:
        pass
    mx_line = "✅ Domain has mail server" if mx_ok else "⚠️ No MX record found"

    try:
        r = requests.get(
            "https://leakcheck.io/api/public",
            params={"check": email},
            headers={"User-Agent": "CyberBabaOSINTBot/2.0"},
            timeout=REQUEST_TIMEOUT,
        )
        if r.status_code == 429:
            return "⏳ Rate limited by LeakCheck\\. Please wait a minute and try again\\."
        if r.status_code != 200:
            return f"❌ LeakCheck returned HTTP {r.status_code}\\. Try again later\\."

        data    = r.json()
        found   = data.get("found", 0)
        sources = data.get("sources", [])

        if not data.get("success", False) or found == 0:
            return (
                f"📧 *Email Breach Report — {safe_md(email)}*\n"
                f"{'─'*30}\n"
                f"✅ *Clean!* Not found in any known data breach\\.\n"
                f"🔍 {mx_line}\n\n"
                f"_Source: LeakCheck\\.io public API — free_"
            )

        lines = [
            f"📧 *Email Breach Report — {safe_md(email)}*\n"
            f"{'─'*30}\n"
            f"🚨 Found in *{found}* breach\\(es\\):\n"
            f"🔍 {mx_line}\n"
        ]
        for src in sources[:20]:
            name     = safe_md(src.get("name", "Unknown"))
            date     = src.get("date", "")
            date_str = f" \\({safe_md(date)}\\)" if date else ""
            lines.append(f"• *{name}*{date_str}")

        if found > 20:
            lines.append(f"\n_\\.\\.\\. and {found - 20} more breaches_")
        lines.append(f"\n_Source: LeakCheck\\.io public API — free_")
        return "\n".join(lines)
    except Exception as e:
        return f"❌ Breach check failed: {safe_md(str(e))}"

# ─── 9. Username Hunt (Sherlock — free) ─────────────────────────
def osint_username(username: str) -> str:
    """Username hunt via Sherlock across 300+ platforms. Free, open-source."""
    username = username.strip().lstrip("@")
    try:
        proc = subprocess.run(
            ["sherlock", username, "--timeout", "10", "--print-found", "--no-color"],
            capture_output=True, text=True, timeout=90,
        )
        output = proc.stdout + proc.stderr
        found  = []
        for line in output.splitlines():
            if line.startswith("[+]"):
                parts = line[3:].strip().split(": ", 1)
                if len(parts) == 2:
                    found.append((parts[0].strip(), parts[1].strip()))

        if not found:
            return (
                f"👤 *Username Hunt — `{safe_md(username)}`*\n"
                f"{'─'*30}\n"
                f"🔍 No public profiles found\\.\n\n"
                f"_Checked 300\\+ platforms via Sherlock_"
            )

        lines = [
            f"👤 *Username Hunt — `{safe_md(username)}`*\n"
            f"{'─'*30}\n"
            f"✅ Found on *{len(found)}* platform\\(s\\):\n\n"
            f"*🟢 Active Profiles:*"
        ]
        for platform, url in found[:30]:
            lines.append(f"• [{safe_md(platform)}]({url})")
        if len(found) > 30:
            lines.append(f"\n_\\.\\.\\. and {len(found)-30} more_")
        lines.append(f"\n_Source: Sherlock open\\-source — free_")
        return "\n".join(lines)
    except subprocess.TimeoutExpired:
        return f"⏳ Sherlock timed out for `{safe_md(username)}`\\. Try again\\."
    except FileNotFoundError:
        return "❌ Sherlock not installed\\. Run: `pip install sherlock-project`"
    except Exception as e:
        return f"❌ Sherlock error: {safe_md(str(e))}"

# ─── 10. URL Analysis ───────────────────────────────────────────
def osint_url(url: str) -> str:
    if not url.startswith("http"):
        url = "http://" + url
    try:
        r      = requests.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        final  = r.url
        parsed = urlparse(final)
        server  = r.headers.get("Server", "N/A")
        content = r.headers.get("Content-Type", "N/A").split(";")[0]
        powered = r.headers.get("X-Powered-By", "N/A")
        length  = r.headers.get("Content-Length", "N/A")
        https   = "🔒 Yes" if parsed.scheme == "https" else "⚠️ No"
        hsts    = "✅ Yes" if "Strict-Transport-Security" in r.headers else "❌ No"

        redirect_chain = ""
        if r.history:
            chain = " → ".join([h.url for h in r.history] + [final])
            redirect_chain = f"\n🔄 *Redirect Chain:*\n`{safe_md(chain)}`"

        return (
            f"🔗 *URL Analysis*\n"
            f"{'─'*30}\n"
            f"🌐 *Final URL:*    `{safe_md(final)}`\n"
            f"🏠 *Host:*         `{safe_md(parsed.netloc)}`\n"
            f"📂 *Path:*         `{safe_md(parsed.path or '/')}`\n"
            f"📊 *Status:*       `{r.status_code}`\n"
            f"{'─'*30}\n"
            f"🖥 *Server:*       `{safe_md(server)}`\n"
            f"⚙️ *Powered By:*   `{safe_md(powered)}`\n"
            f"📄 *Content Type:* `{safe_md(content)}`\n"
            f"📦 *Size:*         `{safe_md(str(length))} bytes`\n"
            f"🔒 *HTTPS:*        {https}\n"
            f"🛡 *HSTS:*         {hsts}"
            f"{redirect_chain}"
        )
    except Exception as e:
        return f"❌ URL error: {safe_md(str(e))}"

# ─── 11. HTTP Headers ───────────────────────────────────────────
def osint_headers(url: str) -> str:
    if not url.startswith("http"):
        url = "http://" + url
    try:
        r = requests.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        SECURITY = {
            "Strict-Transport-Security", "Content-Security-Policy",
            "X-Frame-Options", "X-Content-Type-Options",
            "Referrer-Policy", "Permissions-Policy", "X-XSS-Protection",
        }
        lines = [
            f"🔎 *HTTP Headers — {safe_md(urlparse(url).netloc)}*\n{'─'*30}",
            f"*Status:* `{r.status_code} {r.reason}`\n",
        ]
        for k, v in r.headers.items():
            icon  = "🛡 " if k in SECURITY else "• "
            v_show = v[:80] + "…" if len(v) > 80 else v
            lines.append(f"{icon}`{safe_md(k)}:` {safe_md(v_show)}")
        return truncate("\n".join(lines))
    except Exception as e:
        return f"❌ Header fetch failed: {safe_md(str(e))}"

# ─── 12. Subdomains ─────────────────────────────────────────────
def osint_subdomains(domain: str) -> str:
    domain = clean_domain(domain)
    try:
        r = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=REQUEST_TIMEOUT + 5, headers=HEADERS,
        )
        if r.status_code != 200:
            return f"❌ crt\\.sh returned HTTP {r.status_code}"

        subs = set()
        for entry in r.json():
            for line in entry.get("name_value", "").splitlines():
                sub = line.strip().lstrip("*.")
                if domain in sub:
                    subs.add(sub.lower())

        subs = sorted(subs)
        if not subs:
            return f"🔍 No subdomains found for `{safe_md(domain)}` in cert logs\\."

        lines = [
            f"📂 *Subdomains — {safe_md(domain)}*\n"
            f"Found *{len(subs)}* unique subdomains \\(via crt\\.sh\\)\n"
            f"{'─'*30}"
        ]
        for sub in subs[:50]:
            lines.append(f"• `{safe_md(sub)}`")
        if len(subs) > 50:
            lines.append(f"\n_\\.\\.\\. and {len(subs)-50} more_")
        lines.append(f"\n_Source: crt\\.sh certificate transparency — free_")
        return truncate("\n".join(lines))
    except json.JSONDecodeError:
        return "❌ No cert data from crt\\.sh — domain may have no SSL certificates\\."
    except Exception as e:
        return f"❌ Subdomain error: {safe_md(str(e))}"

# ─── 13. Reverse IP ─────────────────────────────────────────────
def osint_reverse_ip(ip: str) -> str:
    if not is_valid_ip(ip):
        resolved = resolve_domain(clean_domain(ip))
        if not resolved:
            return f"❌ Could not resolve: `{safe_md(ip)}`"
        ip = resolved
    try:
        r    = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}", timeout=REQUEST_TIMEOUT)
        text = r.text.strip()
        if "error" in text.lower() or "no record" in text.lower() or "API count" in text:
            return f"🔍 No reverse DNS records for `{safe_md(ip)}`\\."

        hosts = [h.strip() for h in text.splitlines() if h.strip()]
        lines = [
            f"🛡 *Reverse IP — {safe_md(ip)}*\n"
            f"Found *{len(hosts)}* hosted domain\\(s\\)\n"
            f"{'─'*30}"
        ]
        for h in hosts[:40]:
            lines.append(f"• `{safe_md(h)}`")
        if len(hosts) > 40:
            lines.append(f"\n_\\.\\.\\. and {len(hosts)-40} more_")
        lines.append(f"\n_Source: HackerTarget API — free_")
        return "\n".join(lines)
    except Exception as e:
        return f"❌ Reverse IP error: {safe_md(str(e))}"

# ─── 14. SSL/TLS Certificate ────────────────────────────────────
def osint_ssl(domain: str) -> str:
    """SSL/TLS cert check using Python ssl module. No API key needed."""
    domain = clean_domain(domain)
    try:
        ctx = ssl_lib.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert    = ssock.getpeercert()
                version = ssock.version()
                cipher  = ssock.cipher()

        subject  = dict(x[0] for x in cert.get("subject", []))
        issuer   = dict(x[0] for x in cert.get("issuer", []))
        san      = cert.get("subjectAltName", [])
        nb       = cert.get("notBefore", "")
        na       = cert.get("notAfter", "")
        serial   = cert.get("serialNumber", "N/A")

        fmt = "%b %d %H:%M:%S %Y %Z"
        try:
            valid_from = datetime.strptime(nb, fmt)
            valid_to   = datetime.strptime(na, fmt)
            days_left  = (valid_to - datetime.now()).days
            if days_left > 30:
                expiry_icon = "✅"
            elif days_left > 0:
                expiry_icon = "⚠️"
            else:
                expiry_icon = "❌"
            from_str = valid_from.strftime("%Y-%m-%d")
            to_str   = valid_to.strftime("%Y-%m-%d")
        except Exception:
            from_str = nb[:10]
            to_str   = na[:10]
            days_left = "N/A"
            expiry_icon = "❓"

        san_domains = [v for t, v in san if t == "DNS"][:6]
        cipher_str  = f"{cipher[0]} / {cipher[1]}" if cipher else "N/A"

        return (
            f"🔐 *SSL/TLS — {safe_md(domain)}*\n"
            f"{'─'*30}\n"
            f"📛 *Common Name:* `{safe_md(subject.get('commonName', 'N/A'))}`\n"
            f"🏢 *Subject Org:* {safe_md(subject.get('organizationName', 'N/A'))}\n"
            f"{'─'*30}\n"
            f"🏛 *Issuer:*      {safe_md(issuer.get('organizationName', 'N/A'))}\n"
            f"📋 *Issuer CN:*   `{safe_md(issuer.get('commonName', 'N/A'))}`\n"
            f"{'─'*30}\n"
            f"📅 *Valid From:*  `{safe_md(from_str)}`\n"
            f"📅 *Valid To:*    `{safe_md(to_str)}`\n"
            f"{expiry_icon} *Days Left:*   {safe_md(str(days_left))}\n"
            f"🔒 *TLS Version:* `{safe_md(str(version))}`\n"
            f"🔑 *Cipher:*      `{safe_md(cipher_str)}`\n"
            f"🔢 *Serial:*      `{safe_md(str(serial)[:20])}`\n"
            f"{'─'*30}\n"
            f"🌐 *SANs:* {safe_md(', '.join(san_domains)) if san_domains else 'N/A'}\n\n"
            f"_Source: Python ssl module — free_"
        )
    except ssl_lib.SSLCertVerificationError as e:
        return f"⚠️ *SSL Verification Error — {safe_md(domain)}*\n\n{safe_md(str(e))}"
    except ConnectionRefusedError:
        return f"❌ *No HTTPS on port 443* — {safe_md(domain)} refused connection"
    except socket.timeout:
        return f"❌ *Connection timed out* for {safe_md(domain)}"
    except Exception as e:
        return f"❌ SSL check failed: {safe_md(str(e))}"

# ─── 15. Wayback Machine ────────────────────────────────────────
def osint_wayback(url: str) -> str:
    """Check Internet Archive Wayback Machine. Free, no key."""
    url    = url.strip()
    target = clean_domain(url) if not url.startswith("http") else url
    domain = clean_domain(url)

    try:
        r = requests.get(
            f"https://archive.org/wayback/available?url={target}",
            timeout=REQUEST_TIMEOUT,
        )
        snap_data = r.json().get("archived_snapshots", {}).get("closest", {})

        # CDX API for snapshot count
        r2 = requests.get(
            f"https://web.archive.org/cdx/search/cdx?url={target}/*&output=json"
            f"&fl=timestamp&limit=1&fastLatest=true",
            timeout=REQUEST_TIMEOUT,
        )

        lines = [f"🏛 *Wayback Machine — {safe_md(domain)}*\n{'─'*30}"]

        if snap_data:
            ts     = snap_data.get("timestamp", "")
            status = snap_data.get("status", "N/A")
            snap_url = snap_data.get("url", "")
            if len(ts) >= 8:
                snap_date = f"{ts[:4]}\\-{ts[4:6]}\\-{ts[6:8]}"
            else:
                snap_date = safe_md(ts)

            lines.append(f"\n✅ *Archived!*")
            lines.append(f"📅 *Latest Snapshot:* {snap_date}")
            lines.append(f"📊 *HTTP Status:*     `{safe_md(status)}`")
            if snap_url:
                lines.append(f"🔗 [View Snapshot]({snap_url})")
        else:
            lines.append(f"\n❌ *No snapshot found* for this URL")

        lines.append(f"\n🔗 [Browse All Snapshots](https://web.archive.org/web/*/{target})")
        lines.append(f"\n_Source: archive\\.org — free_")
        return "\n".join(lines)
    except Exception as e:
        return f"❌ Wayback error: {safe_md(str(e))}"

# ─── 16. MAC Vendor Lookup ──────────────────────────────────────
def osint_mac(mac: str) -> str:
    """MAC address vendor lookup via macvendors.com (free API)."""
    mac      = mac.strip().upper().replace("-", ":").replace(".", ":")
    mac_clean = re.sub(r"[^0-9A-F]", "", mac)
    if len(mac_clean) < 6:
        return (
            f"❌ Invalid MAC address: `{safe_md(mac)}`\n\n"
            f"Format: `00:1A:2B:3C:4D:5E` or `001A2B3C4D5E`"
        )

    oui       = mac_clean[:6]
    oui_fmt   = f"{oui[0:2]}:{oui[2:4]}:{oui[4:6]}"
    mac_fmt   = ":".join(mac_clean[i:i+2] for i in range(0, min(len(mac_clean), 12), 2))

    try:
        r = requests.get(
            f"https://api.macvendors.com/{oui}",
            headers={"User-Agent": "CyberBabaOSINTBot/2.0"},
            timeout=REQUEST_TIMEOUT,
        )
        if r.status_code == 200:
            vendor = r.text.strip()
        elif r.status_code == 404:
            vendor = "Unknown / Not in registry"
        elif r.status_code == 429:
            return "⏳ Rate limited by macvendors\\.com\\. Wait a moment and try again\\."
        else:
            vendor = f"API error \\(HTTP {r.status_code}\\)"

        return (
            f"🏷 *MAC Address Lookup*\n"
            f"{'─'*30}\n"
            f"📋 *MAC:*      `{safe_md(mac_fmt)}`\n"
            f"🔢 *OUI:*      `{safe_md(oui_fmt)}`\n"
            f"🏢 *Vendor:*   {safe_md(vendor)}\n\n"
            f"_Source: macvendors\\.com — free API_"
        )
    except Exception as e:
        return f"❌ MAC lookup failed: {safe_md(str(e))}"

# ─── 17. Google Dork Generator ──────────────────────────────────
def osint_dork(target: str) -> str:
    """Generate OSINT Google dork queries. No API needed."""
    target    = target.strip()
    is_domain = bool(re.match(r"^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$", target))

    if is_domain:
        dorks = [
            ("🌐 Site search",       f"site:{target}"),
            ("🌳 Subdomains",        f"site:*.{target} -site:www.{target}"),
            ("🔑 Login pages",       f'site:{target} inurl:login OR inurl:admin OR inurl:dashboard OR inurl:portal'),
            ("📁 Open directories",  f'site:{target} intitle:"index of" "parent directory"'),
            ("📄 Sensitive docs",    f"site:{target} filetype:pdf OR filetype:xls OR filetype:docx"),
            ("⚙️ Config files",      f"site:{target} ext:env OR ext:cfg OR ext:conf OR ext:xml OR ext:yml"),
            ("💾 Backup files",      f"site:{target} ext:bak OR ext:sql OR ext:zip OR ext:tar"),
            ("🔌 API endpoints",     f"site:{target} inurl:api OR inurl:v1 OR inurl:v2 OR inurl:swagger"),
            ("📧 Email addresses",   f'site:{target} "@{target}"'),
            ("⚠️ Error messages",    f'site:{target} "sql syntax" OR "stack trace" OR "warning:"'),
            ("🔗 Exposed .git",      f"site:{target} inurl:.git"),
            ("🏛 Cached version",    f"cache:{target}"),
        ]
    else:
        dorks = [
            ("👤 Name search",       f'"{target}"'),
            ("📧 Email hunt",        f'"{target}" "@gmail.com" OR "@yahoo.com" OR "@hotmail.com"'),
            ("💼 LinkedIn",          f'"{target}" site:linkedin.com'),
            ("🐦 Twitter/X",         f'"{target}" site:twitter.com OR site:x.com'),
            ("💻 GitHub",            f'"{target}" site:github.com'),
            ("📘 Facebook",          f'"{target}" site:facebook.com'),
            ("📄 Documents",         f'"{target}" filetype:pdf OR filetype:doc OR filetype:xls'),
            ("📞 Phone numbers",     f'"{target}" "phone" OR "mobile" OR "contact"'),
            ("📍 Location info",     f'"{target}" "address" OR "location" OR "lives in"'),
            ("🗞 News mentions",     f'"{target}" site:news.google.com OR site:reuters.com'),
        ]

    lines = [
        f"💡 *Google Dork Generator — {safe_md(target)}*\n"
        f"{'─'*30}\n"
        f"_Copy any query and paste into Google, Bing, or DuckDuckGo:_\n"
    ]
    for label, dork in dorks:
        lines.append(f"{label}\n`{safe_md(dork)}`\n")

    lines.append(f"_Tip: Combine with `site:pastebin.com` for leaked data_")
    return truncate("\n".join(lines))

# ─── 18. Hash Lookup ────────────────────────────────────────────
def osint_hash(hash_val: str) -> str:
    """Hash lookup via CIRCL HashLookup & Team Cymru MHR. Free, no key."""
    hash_val = hash_val.strip().lower()

    if re.match(r"^[a-f0-9]{32}$", hash_val):
        hash_type, cymru_tld = "md5", "malware.hash.cymru.com"
    elif re.match(r"^[a-f0-9]{40}$", hash_val):
        hash_type, cymru_tld = "sha1", None
    elif re.match(r"^[a-f0-9]{64}$", hash_val):
        hash_type, cymru_tld = "sha256", None
    elif re.match(r"^[a-f0-9]{128}$", hash_val):
        hash_type, cymru_tld = "sha512", None
    else:
        return (
            f"❌ *Unknown hash format*\n\n"
            f"Supported lengths:\n"
            f"• MD5 — 32 chars\n"
            f"• SHA1 — 40 chars\n"
            f"• SHA256 — 64 chars\n"
            f"• SHA512 — 128 chars"
        )

    lines = [
        f"🔑 *Hash Lookup — {hash_type.upper()}*\n"
        f"{'─'*30}\n"
        f"📋 *Hash:* `{safe_md(hash_val[:40])}{'...' if len(hash_val) > 40 else ''}`\n"
        f"🔢 *Type:* {hash_type.upper()}\n"
    ]
    found = False

    # CIRCL HashLookup (free, no key)
    try:
        r = requests.get(
            f"https://hashlookup.circl.lu/lookup/{hash_type}/{hash_val}",
            headers={"Accept": "application/json"},
            timeout=REQUEST_TIMEOUT,
        )
        if r.status_code == 200:
            d = r.json()
            found = True
            lines.append(f"{'─'*30}")
            lines.append(f"✅ *Found in CIRCL database*")
            if "FileName" in d:
                lines.append(f"📄 *File:*    {safe_md(d['FileName'])}")
            if "FileSize" in d:
                lines.append(f"📦 *Size:*    {safe_md(str(d['FileSize']))} bytes")
            if "PackageName" in d:
                lines.append(f"📦 *Package:* {safe_md(str(d['PackageName']))}")
            is_mal = d.get("KnownMalicious")
            if is_mal is not None:
                lines.append(f"☠️ *Malicious:* {'⚠️ YES — CAUTION' if is_mal else '✅ Not flagged'}")
    except Exception:
        pass

    # Team Cymru Malware Hash Registry (MD5 only, via DNS)
    if cymru_tld and not found:
        try:
            reversed_hash = ".".join(reversed(list(hash_val)))
            query         = f"{reversed_hash}.{cymru_tld}"
            answers       = dns.resolver.resolve(query, "TXT")
            for ans in answers:
                txt = ans.to_text().strip('"')
                lines.append(f"{'─'*30}")
                lines.append(f"⚠️ *Team Cymru MHR:* {safe_md(txt)}")
                found = True
        except Exception:
            pass

    if not found:
        lines.append(f"{'─'*30}")
        lines.append(f"🔍 *Not found* in free databases")
        lines.append(f"_Try: [VirusTotal](https://www.virustotal.com/gui/search/{hash_val}) or [Hybrid Analysis](https://hybrid-analysis.com)_")

    lines.append(f"\n_Sources: CIRCL HashLookup \\| Team Cymru MHR — free_")
    return "\n".join(lines)

# ═══════════════════════ CALLBACK HANDLER ═══════════════════════
async def handle_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data  = query.data

    if data == "main_menu":
        context.user_data.pop("mode", None)
        await query.edit_message_text(
            "🕵️ *Cyber Baba OSINT — 18 Free Tools*\n\n👇 Tap any tool to start:",
            parse_mode=ParseMode.MARKDOWN_V2,
            reply_markup=main_menu(),
        )
        return

    if data in TOOL_PROMPTS:
        prompt, mode = TOOL_PROMPTS[data]
        context.user_data["mode"] = mode
        await query.edit_message_text(
            prompt, parse_mode=ParseMode.MARKDOWN_V2, reply_markup=cancel_menu(),
        )
        return

    if data == "cb_myip":
        await query.answer("Checking server IP…")
        try:
            ip = requests.get("https://api.ipify.org?format=json", timeout=REQUEST_TIMEOUT).json().get("ip")
            result = osint_ip(ip)
        except Exception:
            result = "❌ Could not determine the server's public IP\\."
        await query.edit_message_text(result, parse_mode=ParseMode.MARKDOWN_V2, reply_markup=back_menu())
        return

    if data == "show_about":
        await query.edit_message_text(
            "🕵️ *Cyber Baba OSINT Bot — v2\\.0*\n"
            f"{'─'*30}\n\n"
            "*Handle:* @Babaosintbot\n"
            "*Creator:* Harsh Mishra \\(`harsh1991mishra`\\)\n"
            "*GitHub:* [harsh1991mishra/Babaosintbot](https://github.com/harsh1991mishra/Babaosintbot)\n\n"
            "*🆓 18 Tools — 100% Free, Zero Paid APIs:*\n\n"
            "🌐 ip\\-api\\.com • 🎯 Shodan InternetDB\n"
            "🔌 HackerTarget nmap • 🌍 HackerTarget ASN\n"
            "🔍 python\\-whois • 📡 dnspython\n"
            "📂 crt\\.sh • 🛡 HackerTarget reverse\n"
            "📞 Google libphonenumber • 📧 LeakCheck\\.io\n"
            "👤 Sherlock • 🏷 macvendors\\.com\n"
            "🔐 Python ssl • 🏛 archive\\.org\n"
            "🔗 requests • 🔑 CIRCL HashLookup\n"
            "💡 Local dork gen • 🔎 requests headers\n\n"
            "🔐 *Keys via env vars — never hardcoded*\n"
            "📦 *Deploy:* Replit \\| Heroku \\| Railway \\| VPS",
            parse_mode=ParseMode.MARKDOWN_V2,
            reply_markup=back_menu(),
            disable_web_page_preview=True,
        )
        return

    if data == "show_help":
        await query.edit_message_text(
            "❓ *How to Use Cyber Baba*\n"
            f"{'─'*30}\n\n"
            "Tap any button → bot asks for input → get results\\.\n"
            "No commands to memorise\\!\n\n"
            "*🆓 18 Tools — All Free:*\n\n"
            "*Identity & People*\n"
            "  📞 Phone • 📧 Email Breach • 👤 Username • 🏷 MAC\n\n"
            "*Network & IP*\n"
            "  🌐 IP Geo • 🎯 Shodan • 🔌 Port Scan • 🌍 ASN • 🛡 Reverse IP\n\n"
            "*Domain & Web*\n"
            "  🔍 WHOIS • 📡 DNS • 📂 Subdomains • 🔐 SSL • 🏛 Wayback\n"
            "  🔗 URL • 🔎 HTTP Headers\n\n"
            "*Intelligence*\n"
            "  💡 Google Dorks • 🔑 Hash Lookup\n\n"
            "_Tap 🏠 Main Menu anytime to go back\\._",
            parse_mode=ParseMode.MARKDOWN_V2,
            reply_markup=back_menu(),
        )

# ═══════════════════════ TEXT HANDLER ═══════════════════════════
DISPATCH = {
    MODE_IP:       osint_ip,
    MODE_WHOIS:    osint_whois,
    MODE_DNS:      osint_dns,
    MODE_URL:      osint_url,
    MODE_HEADERS:  osint_headers,
    MODE_SUB:      osint_subdomains,
    MODE_REVERSE:  osint_reverse_ip,
    MODE_PORTSCAN: osint_portscan,
    MODE_SHODAN:   osint_shodan,
    MODE_WAYBACK:  osint_wayback,
    MODE_ASN:      osint_asn,
    MODE_SSL:      osint_ssl,
    MODE_MAC:      osint_mac,
    MODE_DORK:     osint_dork,
    MODE_HASH:     osint_hash,
}

WAIT_MSGS = {
    MODE_USERNAME: "🔍 Scanning *{input}* across 300\\+ platforms \\(up to 60s\\)\\.\\.\\.",
    MODE_PORTSCAN: "🔌 Port scanning *{input}*\\.\\.\\. \\(may take 15s\\)",
    MODE_SHODAN:   "🎯 Querying Shodan InternetDB for *{input}*\\.\\.\\.",
    MODE_SSL:      "🔐 Checking SSL certificate for *{input}*\\.\\.\\.",
    MODE_WAYBACK:  "🏛 Checking Wayback Machine for *{input}*\\.\\.\\.",
    MODE_HASH:     "🔑 Looking up hash in CIRCL database\\.\\.\\.",
    MODE_EMAIL:    "📧 Checking *{input}* for data breaches\\.\\.\\.",
    MODE_PHONE:    "📞 Looking up *{input}*\\.\\.\\.",
}

async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text.strip()
    mode = context.user_data.pop("mode", None)
    chat_id = update.effective_chat.id
    await context.bot.send_chat_action(chat_id, ChatAction.TYPING)

    # ── Mode-driven lookup ──────────────────────────────────────
    if mode == MODE_USERNAME:
        wait = WAIT_MSGS[MODE_USERNAME].format(input=safe_md(text))
        await update.message.reply_text(wait, parse_mode=ParseMode.MARKDOWN_V2)
        result = await asyncio.get_event_loop().run_in_executor(None, osint_username, text)
        await update.message.reply_text(result, parse_mode=ParseMode.MARKDOWN_V2,
                                        reply_markup=back_menu(), disable_web_page_preview=True)
        return

    if mode in WAIT_MSGS:
        wait = WAIT_MSGS[mode].format(input=safe_md(text))
        await update.message.reply_text(wait, parse_mode=ParseMode.MARKDOWN_V2)

    if mode in DISPATCH:
        result = await asyncio.get_event_loop().run_in_executor(None, DISPATCH[mode], text)
        await update.message.reply_text(result, parse_mode=ParseMode.MARKDOWN_V2,
                                        reply_markup=back_menu(), disable_web_page_preview=True)
        return

    # ── Smart auto-detect ───────────────────────────────────────
    if is_valid_ip(text):
        result = await asyncio.get_event_loop().run_in_executor(None, osint_ip, text)
        await update.message.reply_text(result, parse_mode=ParseMode.MARKDOWN_V2, reply_markup=back_menu())
        return

    if re.match(r"[^@]+@[^@]+\.[^@]+", text):
        await update.message.reply_text(
            f"📧 Detected email — checking breaches for `{safe_md(text)}`\\.\\.\\.",
            parse_mode=ParseMode.MARKDOWN_V2)
        result = await asyncio.get_event_loop().run_in_executor(None, osint_email, text)
        await update.message.reply_text(result, parse_mode=ParseMode.MARKDOWN_V2,
                                        reply_markup=back_menu(), disable_web_page_preview=True)
        return

    if re.match(r"^\+?\d[\d\s\-]{6,14}\d$", text):
        result = await asyncio.get_event_loop().run_in_executor(None, osint_phone, text)
        await update.message.reply_text(result, parse_mode=ParseMode.MARKDOWN_V2, reply_markup=back_menu())
        return

    if re.match(r"^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128})$", text):
        result = await asyncio.get_event_loop().run_in_executor(None, osint_hash, text)
        await update.message.reply_text(result, parse_mode=ParseMode.MARKDOWN_V2, reply_markup=back_menu())
        return

    if re.match(r"^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$", text):
        await update.message.reply_text(
            f"🔍 Looks like a domain\\! What would you like to check?\n\n"
            f"Tap a tool or try:\n`/whois {safe_md(text)}` \\| `/dns {safe_md(text)}` \\| `/sub {safe_md(text)}`",
            parse_mode=ParseMode.MARKDOWN_V2, reply_markup=main_menu())
        return

    await update.message.reply_text(
        "👇 Tap a tool button to start an OSINT lookup:", reply_markup=main_menu())

# ═══════════════════════ COMMAND HANDLERS ═══════════════════════
async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data.clear()
    name = update.effective_user.first_name or "Investigator"
    await update.message.reply_text(
        f"🕵️ *Namaste {safe_md(name)}\\!*\n\n"
        "*Cyber Baba OSINT Bot* — 18 free intelligence tools\\.\n\n"
        "✅ No paid APIs • No API keys • 100% free\n\n"
        "👇 *Tap any tool to investigate:*",
        parse_mode=ParseMode.MARKDOWN_V2, reply_markup=main_menu(),
    )

async def cmd_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data.clear()
    await update.message.reply_text(
        "🕵️ *Cyber Baba — 18 OSINT Tools*\n\n👇 Choose:",
        parse_mode=ParseMode.MARKDOWN_V2, reply_markup=main_menu(),
    )

def _make_cmd(mode: str, prompt: str):
    """Factory for simple command → mode handlers."""
    async def handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
        if context.args:
            fn     = DISPATCH.get(mode)
            input_ = " ".join(context.args)
            if mode in WAIT_MSGS:
                await update.message.reply_text(
                    WAIT_MSGS[mode].format(input=safe_md(input_)),
                    parse_mode=ParseMode.MARKDOWN_V2)
            await context.bot.send_chat_action(update.effective_chat.id, ChatAction.TYPING)
            result = await asyncio.get_event_loop().run_in_executor(None, fn, input_)
            await update.message.reply_text(
                result, parse_mode=ParseMode.MARKDOWN_V2,
                reply_markup=back_menu(), disable_web_page_preview=True)
        else:
            context.user_data["mode"] = mode
            await update.message.reply_text(prompt, reply_markup=cancel_menu())
    return handler

async def cmd_myip(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await context.bot.send_chat_action(update.effective_chat.id, ChatAction.TYPING)
    try:
        ip     = requests.get("https://api.ipify.org?format=json", timeout=REQUEST_TIMEOUT).json().get("ip")
        result = osint_ip(ip)
    except Exception:
        result = "❌ Could not determine the server's public IP\\."
    await update.message.reply_text(result, parse_mode=ParseMode.MARKDOWN_V2, reply_markup=back_menu())

async def cmd_unknown(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "❓ Unknown command\\. Choose a tool from the menu:",
        parse_mode=ParseMode.MARKDOWN_V2, reply_markup=main_menu(),
    )

async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE):
    logger.error("Unhandled error: %s", context.error, exc_info=True)

# ═══════════════════════════ MAIN ═══════════════════════════════
def main():
    app = Application.builder().token(TELEGRAM_TOKEN).build()

    # Core commands
    app.add_handler(CommandHandler("start",    cmd_start))
    app.add_handler(CommandHandler("menu",     cmd_menu))
    app.add_handler(CommandHandler("myip",     cmd_myip))

    # Tool commands (using factory)
    CMD_MAP = {
        "ip":       (MODE_IP,       "🌐 Send me an IP address or domain:"),
        "whois":    (MODE_WHOIS,    "🔍 Send me a domain name:"),
        "dns":      (MODE_DNS,      "📡 Send me a domain name:"),
        "phone":    (MODE_PHONE,    "📞 Send me a phone number (with +country code):"),
        "email":    (MODE_EMAIL,    "📧 Send me an email address:"),
        "user":     (MODE_USERNAME, "👤 Send me a username to search:"),
        "url":      (MODE_URL,      "🔗 Send me a URL to analyze:"),
        "headers":  (MODE_HEADERS,  "🔎 Send me a URL to inspect headers:"),
        "sub":      (MODE_SUB,      "📂 Send me a domain name:"),
        "reverse":  (MODE_REVERSE,  "🛡 Send me an IP address:"),
        "portscan": (MODE_PORTSCAN, "🔌 Send me an IP or domain to port scan:"),
        "shodan":   (MODE_SHODAN,   "🎯 Send me an IP address:"),
        "asn":      (MODE_ASN,      "🌍 Send me an IP address:"),
        "ssl":      (MODE_SSL,      "🔐 Send me a domain name:"),
        "wayback":  (MODE_WAYBACK,  "🏛 Send me a domain or URL:"),
        "mac":      (MODE_MAC,      "🏷 Send me a MAC address:"),
        "dork":     (MODE_DORK,     "💡 Send me a domain or target name:"),
        "hash":     (MODE_HASH,     "🔑 Send me an MD5 / SHA1 / SHA256 hash:"),
    }
    for cmd, (mode, prompt) in CMD_MAP.items():
        app.add_handler(CommandHandler(cmd, _make_cmd(mode, prompt)))

    app.add_handler(CallbackQueryHandler(handle_callback))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    app.add_handler(MessageHandler(filters.COMMAND, cmd_unknown))
    app.add_error_handler(error_handler)

    logger.info("🚀 Cyber Baba OSINT Bot v2.0 — 18 tools, 100% free — @Babaosintbot")
    app.run_polling(allowed_updates=Update.ALL_TYPES, drop_pending_updates=True)


if __name__ == "__main__":
    main()
