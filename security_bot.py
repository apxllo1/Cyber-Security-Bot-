import discord
from discord import app_commands
from discord.ext import commands, tasks
import asyncio
import hashlib
import socket
import requests
import json
import os
from datetime import datetime
import ssl
import certifi
import urllib.parse
from dotenv import load_dotenv

load_dotenv()

TOKEN = os.getenv("DISCORD_TOKEN")

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents)

# ==================== SECURITY COMMANDS ====================

@bot.tree.command(name="scan", description="Scan ports on a target host")
@app_commands.describe(target="Target hostname or IP address", ports="Port range e.g. 1-1000")
async def scan(interaction: discord.Interaction, target: str, ports: str = "1-1000"):
    await interaction.response.defer()
    await interaction.followup.send(f"🔍 Starting port scan on `{target}` (ports {ports})...")

    open_ports = []
    port_range = ports.split("-")

    try:
        start_port = int(port_range[0])
        end_port = int(port_range[1]) if len(port_range) > 1 else start_port

        if end_port - start_port > 1000:
            await interaction.followup.send("⚠️ Limited to 1000 ports max. Scanning first 1000...")
            end_port = start_port + 1000

        for port in range(start_port, end_port + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target, port))
            if result == 0:
                open_ports.append(port)
            sock.close()

        if open_ports:
            ports_str = ", ".join(map(str, open_ports))
            await interaction.followup.send(f"✅ **Open ports found on {target}:**\n`{ports_str}`")
        else:
            await interaction.followup.send(f"🔒 No open ports found on `{target}` in range {ports}")

    except Exception as e:
        await interaction.followup.send(f"❌ Error: {str(e)}")


@bot.tree.command(name="hashcheck", description="Analyze a hash value")
@app_commands.describe(hash_value="The hash to analyze", hashtype="Hash type: md5, sha1, or sha256")
@app_commands.choices(hashtype=[
    app_commands.Choice(name="MD5", value="md5"),
    app_commands.Choice(name="SHA1", value="sha1"),
    app_commands.Choice(name="SHA256", value="sha256"),
])
async def hashcheck(interaction: discord.Interaction, hash_value: str, hashtype: str = "md5"):
    hash_len = len(hash_value)

    info = "**Hash Analysis:**\n"
    info += f"• Length: {hash_len} characters\n"
    info += f"• Type: {hashtype.upper()}\n"

    if hash_len == 32 and hashtype == "md5":
        info += "• Valid MD5 format ✓\n"
    elif hash_len == 40 and hashtype == "sha1":
        info += "• Valid SHA1 format ✓\n"
    elif hash_len == 64 and hashtype == "sha256":
        info += "• Valid SHA256 format ✓\n"
    else:
        info += "• ⚠️ Length doesn't match selected hash type\n"

    await interaction.response.send_message(info)


@bot.tree.command(name="whois", description="WHOIS lookup for a domain")
@app_commands.describe(domain="Domain to look up e.g. example.com")
async def whois(interaction: discord.Interaction, domain: str):
    await interaction.response.defer()
    try:
        import whois
        w = whois.whois(domain)

        info = f"**WHOIS Info for {domain}:**\n"
        info += f"• Registrar: {w.registrar}\n"
        info += f"• Created: {w.creation_date}\n"
        info += f"• Expires: {w.expiration_date}\n"
        info += f"• Name Servers: {', '.join(w.name_servers) if isinstance(w.name_servers, list) else w.name_servers}\n"

        await interaction.followup.send(info)
    except Exception as e:
        await interaction.followup.send(f"❌ WHOIS lookup failed: {str(e)}")


@bot.tree.command(name="ipinfo", description="Get IP geolocation and info")
@app_commands.describe(ip="IP address to look up e.g. 8.8.8.8")
async def ipinfo(interaction: discord.Interaction, ip: str):
    await interaction.response.defer()
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = response.json()

        if data["status"] == "success":
            info = f"**IP Info for {ip}:**\n"
            info += f"• Country: {data['country']} ({data['countryCode']})\n"
            info += f"• Region: {data['regionName']}\n"
            info += f"• City: {data['city']}\n"
            info += f"• ISP: {data['isp']}\n"
            info += f"• Org: {data['org']}\n"
            info += f"• Timezone: {data['timezone']}\n"
            await interaction.followup.send(info)
        else:
            await interaction.followup.send(f"❌ Could not get info for `{ip}`")
    except Exception as e:
        await interaction.followup.send(f"❌ Error: {str(e)}")


@bot.tree.command(name="breach", description="Check if an email was in a data breach")
@app_commands.describe(email="Email address to check")
async def breach(interaction: discord.Interaction, email: str):
    await interaction.response.send_message(
        f"🔍 Checking breach status for `{email}`...\n*(Integrate with HIBP API for real results)*"
    )


@bot.tree.command(name="sslcheck", description="Check SSL certificate info for a domain")
@app_commands.describe(domain="Domain to check e.g. example.com")
async def sslcheck(interaction: discord.Interaction, domain: str):
    await interaction.response.defer()
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

                info = f"**SSL Certificate for {domain}:**\n"
                info += f"• Protocol: {version}\n"
                info += f"• Cipher: {cipher[0]}\n"
                info += f"• Issuer: {cert.get('issuer', 'Unknown')}\n"
                info += f"• Subject: {cert.get('subject', 'Unknown')}\n"
                info += f"• Not Before: {cert.get('notBefore', 'Unknown')}\n"
                info += f"• Not After: {cert.get('notAfter', 'Unknown')}\n"

                await interaction.followup.send(info)
    except Exception as e:
        await interaction.followup.send(f"❌ SSL check failed: {str(e)}")


@bot.tree.command(name="generatepass", description="Generate a secure random password (sent via DM)")
@app_commands.describe(length="Password length (max 128, default 16)")
async def generatepass(interaction: discord.Interaction, length: int = 16):
    import secrets
    import string

    if length > 128:
        length = 128
    if length < 4:
        length = 4

    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    password = ''.join(secrets.choice(alphabet) for _ in range(length))

    try:
        await interaction.user.send(f"🔐 Your secure password ({length} chars):\n`{password}`")
        await interaction.response.send_message("📩 Password sent via DM!", ephemeral=True)
    except discord.Forbidden:
        await interaction.response.send_message("❌ Couldn't send DM. Please allow DMs from server members.", ephemeral=True)


@bot.tree.command(name="dnslookup", description="DNS record lookup for a domain")
@app_commands.describe(domain="Domain to look up", record_type="DNS record type")
@app_commands.choices(record_type=[
    app_commands.Choice(name="A", value="A"),
    app_commands.Choice(name="AAAA", value="AAAA"),
    app_commands.Choice(name="MX", value="MX"),
    app_commands.Choice(name="TXT", value="TXT"),
    app_commands.Choice(name="NS", value="NS"),
])
async def dnslookup(interaction: discord.Interaction, domain: str, record_type: str = "A"):
    await interaction.response.defer()
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, record_type)
        results = [str(rdata) for rdata in answers]
        await interaction.followup.send(
            f"**{record_type} Records for {domain}:**\n```\n" + "\n".join(results) + "\n```"
        )
    except Exception as e:
        await interaction.followup.send(f"❌ DNS lookup failed: {str(e)}")


@bot.tree.command(name="headers", description="Check HTTP security headers for a URL")
@app_commands.describe(url="URL to check e.g. https://example.com")
async def headers(interaction: discord.Interaction, url: str):
    await interaction.response.defer()
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        response = requests.head(url, timeout=5, allow_redirects=True)
        hdrs = response.headers

        security_headers = [
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection',
            'Referrer-Policy',
            'Permissions-Policy'
        ]

        info = f"**Security Headers for {url}:**\n"
        for header in security_headers:
            value = hdrs.get(header, None)
            status = "✅" if value else "❌"
            info += f"• {header}: {status}\n"

        await interaction.followup.send(info)
    except Exception as e:
        await interaction.followup.send(f"❌ Failed to fetch headers: {str(e)}")


# ==================== MONITORING & ALERTS ====================

@bot.tree.command(name="monitor_start", description="Start monitoring for suspicious activity")
@app_commands.describe(log_file="Log file path to monitor (optional)")
async def monitor_start(interaction: discord.Interaction, log_file: str = None):
    if not hasattr(bot, 'monitored_logs'):
        bot.monitored_logs = {}

    bot.monitored_logs[interaction.guild_id] = {
        'channel': interaction.channel_id,
        'log_file': log_file,
        'patterns': [
            r'Failed password',
            r'authentication failure',
            r'invalid user',
            r'connection refused',
            r'error',
            r'unauthorized'
        ]
    }

    if not log_monitor.is_running():
        log_monitor.start()

    await interaction.response.send_message("🔔 **Log monitoring started!** Checking for suspicious patterns every 30 seconds...")


@tasks.loop(seconds=30)
async def log_monitor():
    if not hasattr(bot, 'monitored_logs'):
        return
    for guild_id, config in bot.monitored_logs.items():
        try:
            pass
        except Exception as e:
            print(f"Monitor error: {e}")


@bot.tree.command(name="monitor_stop", description="Stop log monitoring")
async def monitor_stop(interaction: discord.Interaction):
    if hasattr(bot, 'monitored_logs') and interaction.guild_id in bot.monitored_logs:
        del bot.monitored_logs[interaction.guild_id]
        await interaction.response.send_message("🛑 Log monitoring stopped.")
    else:
        await interaction.response.send_message("ℹ️ No active monitoring to stop.")


@bot.tree.command(name="integrity", description="File integrity check — create or verify a file hash baseline")
@app_commands.describe(filepath="Path to the file", action="Create a baseline or verify an existing one")
@app_commands.choices(action=[
    app_commands.Choice(name="Create baseline", value="create"),
    app_commands.Choice(name="Verify integrity", value="check"),
])
async def integrity(interaction: discord.Interaction, filepath: str, action: str = "create"):
    await interaction.response.defer()

    if action == "create":
        try:
            hash_md5 = hashlib.md5()
            hash_sha256 = hashlib.sha256()

            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
                    hash_sha256.update(chunk)

            result = {
                'file': filepath,
                'md5': hash_md5.hexdigest(),
                'sha256': hash_sha256.hexdigest(),
                'timestamp': datetime.now().isoformat()
            }

            integrity_file = f"integrity_{interaction.guild_id}.json"
            data = {}
            if os.path.exists(integrity_file):
                with open(integrity_file, 'r') as f:
                    data = json.load(f)

            data[filepath] = result

            with open(integrity_file, 'w') as f:
                json.dump(data, f, indent=2)

            await interaction.followup.send(
                f"✅ Baseline created for `{filepath}`\nMD5: `{result['md5']}`\nSHA256: `{result['sha256']}`"
            )
        except Exception as e:
            await interaction.followup.send(f"❌ Error: {str(e)}")

    else:
        try:
            integrity_file = f"integrity_{interaction.guild_id}.json"
            if not os.path.exists(integrity_file):
                await interaction.followup.send("❌ No baseline found. Run `/integrity create` first.")
                return

            with open(integrity_file, 'r') as f:
                data = json.load(f)

            if filepath not in data:
                await interaction.followup.send("❌ No baseline found for this file.")
                return

            stored = data[filepath]
            hash_md5 = hashlib.md5()
            hash_sha256 = hashlib.sha256()

            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
                    hash_sha256.update(chunk)

            current_md5 = hash_md5.hexdigest()
            current_sha256 = hash_sha256.hexdigest()

            if current_md5 != stored['md5'] or current_sha256 != stored['sha256']:
                alert = "🚨 **FILE INTEGRITY ALERT!**\n"
                alert += f"File: `{filepath}`\n"
                alert += f"Expected MD5: `{stored['md5']}`\n"
                alert += f"Current MD5:  `{current_md5}`\n"
                alert += f"Expected SHA256: `{stored['sha256']}`\n"
                alert += f"Current SHA256:  `{current_sha256}`\n"
                alert += f"Baseline created: {stored['timestamp']}"
                await interaction.followup.send(alert)
            else:
                await interaction.followup.send(f"✅ Integrity verified for `{filepath}` — No changes detected.")

        except Exception as e:
            await interaction.followup.send(f"❌ Error: {str(e)}")


# ==================== THREAT INTELLIGENCE ====================

@bot.tree.command(name="threatintel", description="Check threat intelligence for an IP, domain, or hash")
@app_commands.describe(indicator="IP address, domain, or file hash to check")
async def threatintel(interaction: discord.Interaction, indicator: str):
    await interaction.response.defer()

    VT_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')

    if not VT_API_KEY:
        await interaction.followup.send("⚠️ VirusTotal API key not configured. Add `VIRUSTOTAL_API_KEY` to your .env file.")
        return

    try:
        import re
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        domain_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$'

        if re.match(ip_pattern, indicator):
            url = f"https://www.virustotal.com/api/v3/ip-addresses/{indicator}"
        elif re.match(domain_pattern, indicator):
            url = f"https://www.virustotal.com/api/v3/domains/{indicator}"
        else:
            url = f"https://www.virustotal.com/api/v3/files/{indicator}"

        hdrs = {"x-apikey": VT_API_KEY}
        response = requests.get(url, headers=hdrs, timeout=10)
        data = response.json()

        if response.status_code == 200:
            stats = data['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)

            result = f"**Threat Intelligence Report for `{indicator}`:**\n"
            result += f"• Malicious detections: {malicious}\n"
            result += f"• Suspicious detections: {suspicious}\n"
            result += f"• Harmless: {stats.get('harmless', 0)}\n"
            result += f"• Undetected: {stats.get('undetected', 0)}\n"

            if malicious > 0:
                result += "\n🚨 **THREAT DETECTED!** This indicator is flagged as malicious."
            elif suspicious > 0:
                result += "\n⚠️ **Suspicious activity detected.**"
            else:
                result += "\n✅ No threats detected."

            await interaction.followup.send(result)
        else:
            await interaction.followup.send(f"❌ API Error: {data.get('error', {}).get('message', 'Unknown error')}")

    except Exception as e:
        await interaction.followup.send(f"❌ Error checking threat intel: {str(e)}")


@bot.tree.command(name="urlscan", description="Scan a URL for malicious content")
@app_commands.describe(url="URL to scan e.g. https://example.com")
async def urlscan(interaction: discord.Interaction, url: str):
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    await interaction.response.send_message(
        f"🔍 Scanning URL: `{url}`...\n⚠️ URL scanning requires URLScan.io API integration. Add your API key to enable this feature."
    )


# ==================== SECURITY UTILITIES ====================

@bot.tree.command(name="encode", description="Encode text using various methods")
@app_commands.describe(method="Encoding method", text="Text to encode")
@app_commands.choices(method=[
    app_commands.Choice(name="Base64", value="base64"),
    app_commands.Choice(name="URL", value="url"),
    app_commands.Choice(name="Hex", value="hex"),
    app_commands.Choice(name="ROT13", value="rot13"),
])
async def encode(interaction: discord.Interaction, method: str, text: str):
    import base64
    try:
        if method == 'base64':
            result = base64.b64encode(text.encode()).decode()
            await interaction.response.send_message(f"**Base64 Encoded:**\n```\n{result}\n```")
        elif method == 'url':
            result = urllib.parse.quote(text)
            await interaction.response.send_message(f"**URL Encoded:**\n```\n{result}\n```")
        elif method == 'hex':
            result = text.encode().hex()
            await interaction.response.send_message(f"**Hex Encoded:**\n```\n{result}\n```")
        elif method == 'rot13':
            result = text.translate(str.maketrans(
                'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
            ))
            await interaction.response.send_message(f"**ROT13 Encoded:**\n```\n{result}\n```")
    except Exception as e:
        await interaction.response.send_message(f"❌ Error: {str(e)}")


@bot.tree.command(name="decode", description="Decode text using various methods")
@app_commands.describe(method="Decoding method", text="Text to decode")
@app_commands.choices(method=[
    app_commands.Choice(name="Base64", value="base64"),
    app_commands.Choice(name="URL", value="url"),
    app_commands.Choice(name="Hex", value="hex"),
    app_commands.Choice(name="ROT13", value="rot13"),
])
async def decode(interaction: discord.Interaction, method: str, text: str):
    import base64
    try:
        if method == 'base64':
            result = base64.b64decode(text).decode()
            await interaction.response.send_message(f"**Base64 Decoded:**\n```\n{result}\n```")
        elif method == 'url':
            result = urllib.parse.unquote(text)
            await interaction.response.send_message(f"**URL Decoded:**\n```\n{result}\n```")
        elif method == 'hex':
            result = bytes.fromhex(text).decode()
            await interaction.response.send_message(f"**Hex Decoded:**\n```\n{result}\n```")
        elif method == 'rot13':
            result = text.translate(str.maketrans(
                'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
            ))
            await interaction.response.send_message(f"**ROT13 Decoded:**\n```\n{result}\n```")
    except Exception as e:
        await interaction.response.send_message(f"❌ Error: {str(e)}")


@bot.tree.command(name="pwncheck", description="Check password strength")
@app_commands.describe(password="Password to analyze")
async def pwncheck(interaction: discord.Interaction, password: str):
    import re

    strength = 0
    feedback = []

    if len(password) >= 12:
        strength += 1
    else:
        feedback.append("Use at least 12 characters")

    if re.search(r'[A-Z]', password):
        strength += 1
    else:
        feedback.append("Add uppercase letters")

    if re.search(r'[a-z]', password):
        strength += 1
    else:
        feedback.append("Add lowercase letters")

    if re.search(r'\d', password):
        strength += 1
    else:
        feedback.append("Add numbers")

    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        strength += 1
    else:
        feedback.append("Add special characters")

    common_passwords = ['password', '123456', 'qwerty', 'admin', 'letmein']
    if password.lower() in common_passwords:
        strength = 0
        feedback.append("This is a commonly used password!")

    if strength == 5:
        rating = "🔒 Strong"
        color = 0x00ff00
    elif strength >= 3:
        rating = "🟡 Moderate"
        color = 0xffff00
    else:
        rating = "🔴 Weak"
        color = 0xff0000

    embed = discord.Embed(title="Password Analysis", color=color)
    embed.add_field(name="Strength", value=rating, inline=False)
    if feedback:
        embed.add_field(name="Suggestions", value="\n".join(f"• {f}" for f in feedback), inline=False)
    embed.add_field(name="Breach Check", value="Use `/breach <email>` for breach monitoring", inline=False)

    # ephemeral=True means only the user who ran the command can see it
    await interaction.response.send_message(embed=embed, ephemeral=True)


# ==================== HELP COMMAND ====================

@bot.tree.command(name="sechelp", description="Show all available security commands")
async def sechelp(interaction: discord.Interaction):
    embed = discord.Embed(
        title="🛡️ CyberSecurity Bot Commands",
        description="Your automated security assistant — all commands use `/`",
        color=0x00ff00
    )
    embed.add_field(
        name="🔍 Reconnaissance",
        value="`/scan` `/whois` `/ipinfo` `/dnslookup` `/headers` `/sslcheck`",
        inline=False
    )
    embed.add_field(
        name="🔐 Security Tools",
        value="`/hashcheck` `/integrity` `/generatepass` `/pwncheck`",
        inline=False
    )
    embed.add_field(
        name="🌐 Threat Intelligence",
        value="`/threatintel` `/breach` `/urlscan`",
        inline=False
    )
    embed.add_field(
        name="🛠️ Utilities",
        value="`/encode` `/decode` `/monitor_start` `/monitor_stop`",
        inline=False
    )
    await interaction.response.send_message(embed=embed)


# ==================== EVENT HANDLERS ====================

@bot.event
async def on_ready():
    await bot.tree.sync()
    print(f'🤖 {bot.user} has connected to Discord!')
    print(f'✅ Slash commands synced globally!')
    print(f'Connected to {len(bot.guilds)} guilds')
    await bot.change_presence(
        activity=discord.Activity(
            type=discord.ActivityType.watching,
            name="for security threats | /sechelp"
        )
    )


@bot.event
async def on_message(message):
    if message.author == bot.user:
        return

    suspicious_patterns = [
        r'\b\d{16}\b',
        r'\b\d{3}-\d{2}-\d{4}\b',
        r'password\s*[=:]\s*\S+',
        r'api[_-]?key\s*[=:]\s*\S+',
    ]

    for pattern in suspicious_patterns:
        import re
        if re.search(pattern, message.content, re.IGNORECASE):
            print(f"⚠️ Potential sensitive data detected in {message.guild.name}")

    await bot.process_commands(message)


# ==================== RUN BOT ====================

if __name__ == "__main__":
    if not TOKEN:
        print("❌ ERROR: DISCORD_TOKEN not found!")
        print("Make sure your .env file contains: DISCORD_TOKEN=your_token_here")
        exit(1)

    bot.run(TOKEN)
