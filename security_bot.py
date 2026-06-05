import discord
from discord.ext import commands, tasks
import asyncio
import hashlib
import socket
import subprocess
import requests
import json
import os
from datetime import datetime
import ssl
import certifi
import urllib.parse

# Configuration
TOKEN = "YOUR_BOT_TOKEN_HERE"
COMMAND_PREFIX = "!"
ALLOWED_CHANNELS = []  # Add channel IDs to restrict commands, or leave empty for all

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix=COMMAND_PREFIX, intents=intents)

# ==================== SECURITY COMMANDS ====================

@bot.command()
async def scan(ctx, target: str, ports: str = "1-1000"):
    """
    Scan ports on a target. Usage: !scan example.com 1-1000
    """
    await ctx.send(f"🔍 Starting port scan on `{target}` (ports {ports})...")
    
    open_ports = []
    port_range = ports.split("-")
    
    try:
        start_port = int(port_range[0])
        end_port = int(port_range[1]) if len(port_range) > 1 else start_port
        
        # Limit scan range to prevent abuse
        if end_port - start_port > 1000:
            await ctx.send("⚠️ Limited to 1000 ports max. Scanning first 1000...")
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
            await ctx.send(f"✅ **Open ports found on {target}:**\n`{ports_str}`")
        else:
            await ctx.send(f"🔒 No open ports found on `{target}` in range {ports}")
            
    except Exception as e:
        await ctx.send(f"❌ Error: {str(e)}")

@bot.command()
async def hashcheck(ctx, hash_value: str, hashtype: str = "md5"):
    """
    Check hash type and attempt to identify. Usage: !hashcheck <hash> [md5/sha1/sha256]
    """
    hash_len = len(hash_value)
    
    info = f"**Hash Analysis:**\n"
    info += f"• Length: {hash_len} characters\n"
    info += f"• Type: {hashtype.upper()}\n"
    
    # Check against VirusTotal (requires API key)
    # For demo, we'll just analyze the hash
    if hash_len == 32 and hashtype.lower() == "md5":
        info += "• Valid MD5 format ✓\n"
    elif hash_len == 40 and hashtype.lower() == "sha1":
        info += "• Valid SHA1 format ✓\n"
    elif hash_len == 64 and hashtype.lower() == "sha256":
        info += "• Valid SHA256 format ✓\n"
    
    # Check if it's a known hash in your database
    # You could integrate with APIs like VirusTotal, MalwareBazaar, etc.
    
    await ctx.send(info)

@bot.command()
async def whois(ctx, domain: str):
    """
    WHOIS lookup for a domain. Usage: !whois example.com
    """
    try:
        import whois
        w = whois.whois(domain)
        
        info = f"**WHOIS Info for {domain}:**\n"
        info += f"• Registrar: {w.registrar}\n"
        info += f"• Created: {w.creation_date}\n"
        info += f"• Expires: {w.expiration_date}\n"
        info += f"• Name Servers: {', '.join(w.name_servers) if isinstance(w.name_servers, list) else w.name_servers}\n"
        
        await ctx.send(info)
    except Exception as e:
        await ctx.send(f"❌ WHOIS lookup failed: {str(e)}")

@bot.command()
async def ipinfo(ctx, ip: str):
    """
    Get IP geolocation and info. Usage: !ipinfo 8.8.8.8
    """
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
            await ctx.send(info)
        else:
            await ctx.send(f"❌ Could not get info for `{ip}`")
    except Exception as e:
        await ctx.send(f"❌ Error: {str(e)}")

@bot.command()
async def breach(ctx, email: str):
    """
    Check if email was in a data breach (using Have I Been Pwned).
    Requires HIBP API key.
    """
    # Note: This requires an API key from haveibeenpwned.com
    # Demo version - replace with actual API call
    await ctx.send(f"🔍 Checking breach status for `{email}`...\n*(Integrate with HIBP API for real results)*")

@bot.command()
async def sslcheck(ctx, domain: str):
    """
    Check SSL certificate info. Usage: !sslcheck example.com
    """
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
                
                await ctx.send(info)
    except Exception as e:
        await ctx.send(f"❌ SSL check failed: {str(e)}")

@bot.command()
async def generatepass(ctx, length: int = 16):
    """
    Generate secure password. Usage: !generatepass [length]
    """
    import secrets
    import string
    
    if length > 128:
        length = 128
        
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    
    await ctx.author.send(f"🔐 Your secure password ({length} chars):\n`{password}`")
    await ctx.send("📩 Password sent via DM!")

@bot.command()
async def dnslookup(ctx, domain: str, record_type: str = "A"):
    """
    DNS lookup. Usage: !dnslookup example.com [A/AAAA/MX/TXT/NS]
    """
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, record_type)
        
        results = [str(rdata) for rdata in answers]
        await ctx.send(f"**{record_type} Records for {domain}:**\n```\n" + "\n".join(results) + "\n```")
    except Exception as e:
        await ctx.send(f"❌ DNS lookup failed: {str(e)}")

@bot.command()
async def headers(ctx, url: str):
    """
    Check HTTP security headers. Usage: !headers https://example.com
    """
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        response = requests.head(url, timeout=5, allow_redirects=True)
        headers = response.headers
        
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
            value = headers.get(header, "❌ MISSING")
            status = "✅" if value != "❌ MISSING" else "❌"
            info += f"• {header}: {status}\n"
            
        await ctx.send(info)
    except Exception as e:
        await ctx.send(f"❌ Failed to fetch headers: {str(e)}")

# ==================== MONITORING & ALERTS ====================

@bot.command()
async def monitor_start(ctx, log_file: str = None):
    """
    Start monitoring a log file for suspicious activity.
    Usage: !monitor_start /var/log/auth
    """
    await ctx.send("🔔 **Log monitoring started!** Checking for suspicious patterns every 30 seconds...")
    
    # Store monitoring state (in production, use a database)
    if not hasattr(bot, 'monitored_logs'):
        bot.monitored_logs = {}
    
    bot.monitored_logs[ctx.guild.id] = {
        'channel': ctx.channel.id,
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
    
    # Start background task if not running
    if not log_monitor.is_running():
        log_monitor.start()

@tasks.loop(seconds=30)
async def log_monitor():
    """Background task to monitor logs"""
    if not hasattr(bot, 'monitored_logs'):
        return
        
    for guild_id, config in bot.monitored_logs.items():
        try:
            # In production, actually read the log file
            # For demo, we'll simulate detection
            pass
        except Exception as e:
            print(f"Monitor error: {e}")

@bot.command()
async def monitor_stop(ctx):
    """Stop log monitoring"""
    if hasattr(bot, 'monitored_logs') and ctx.guild.id in bot.monitored_logs:
        del bot.monitored_logs[ctx.guild.id]
        await ctx.send("🛑 Log monitoring stopped.")
    else:
        await ctx.send("ℹ️ No active monitoring to stop.")

@bot.command()
async def integrity(ctx, filepath: str = None):
    """
    File integrity check - create or verify hash of a file.
    Usage: !integrity [filepath] or !integrity check [filepath]
    """
    if not filepath:
        await ctx.send("Usage: `!integrity <filepath>` to create baseline\n`!integrity check <filepath>` to verify")
        return
    
    action = "check" if "check" in filepath else "create"
    
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
            
            # Save to integrity database
            integrity_file = f"integrity_{ctx.guild.id}.json"
            data = {}
            if os.path.exists(integrity_file):
                with open(integrity_file, 'r') as f:
                    data = json.load(f)
            
            data[filepath] = result
            
            with open(integrity_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            await ctx.send(f"✅ Baseline created for `{filepath}`\nMD5: `{result['md5']}`\nSHA256: `{result['sha256']}`")
            
        except Exception as e:
            await ctx.send(f"❌ Error: {str(e)}")
    
    else:
        # Verify integrity
        try:
            integrity_file = f"integrity_{ctx.guild.id}.json"
            if not os.path.exists(integrity_file):
                await ctx.send("❌ No baseline found. Run `!integrity <filepath>` first.")
                return
            
            with open(integrity_file, 'r') as f:
                data = json.load(f)
            
            if filepath not in data:
                await ctx.send("❌ No baseline for this file.")
                return
            
            stored = data[filepath]
            
            # Calculate current hash
            hash_md5 = hashlib.md5()
            hash_sha256 = hashlib.sha256()
            
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
                    hash_sha256.update(chunk)
            
            current_md5 = hash_md5.hexdigest()
            current_sha256 = hash_sha256.hexdigest()
            
            if current_md5 != stored['md5'] or current_sha256 != stored['sha256']:
                alert = f"🚨 **FILE INTEGRITY ALERT!**\n"
                alert += f"File: `{filepath}`\n"
                alert += f"Expected MD5: `{stored['md5']}`\n"
                alert += f"Current MD5: `{current_md5}`\n"
                alert += f"Expected SHA256: `{stored['sha256']}`\n"
                alert += f"Current SHA256: `{current_sha256}`\n"
                alert += f"Baseline created: {stored['timestamp']}"
                await ctx.send(alert)
            else:
                await ctx.send(f"✅ Integrity verified for `{filepath}` - No changes detected.")
                
        except Exception as e:
            await ctx.send(f"❌ Error: {str(e)}")

# ==================== THREAT INTELLIGENCE ====================

@bot.command()
async def threatintel(ctx, indicator: str):
    """
    Check threat intelligence for IP/Domain/Hash.
    Usage: !threatintel 8.8.8.8 or !threatintel example.com
    """
    await ctx.send(f"🔍 Checking threat intelligence for `{indicator}`...")
    
    # VirusTotal API integration (requires API key)
    VT_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', 'YOUR_API_KEY')
    
    if VT_API_KEY == 'YOUR_API_KEY':
        await ctx.send("⚠️ VirusTotal API key not configured. Add `VIRUSTOTAL_API_KEY` to your .env file.")
        return
    
    try:
        # Determine indicator type
        import re
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        domain_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$'
        
        if re.match(ip_pattern, indicator):
            url = f"https://www.virustotal.com/api/v3/ip-addresses/{indicator}"
        elif re.match(domain_pattern, indicator):
            url = f"https://www.virustotal.com/api/v3/domains/{indicator}"
        else:
            url = f"https://www.virustotal.com/api/v3/files/{indicator}"
        
        headers = {"x-apikey": VT_API_KEY}
        response = requests.get(url, headers=headers, timeout=10)
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
                result += f"\n🚨 **THREAT DETECTED!** This indicator is flagged as malicious."
            elif suspicious > 0:
                result += f"\n⚠️ **Suspicious activity detected.**"
            else:
                result += f"\n✅ No threats detected."
            
            await ctx.send(result)
        else:
            await ctx.send(f"❌ API Error: {data.get('error', {}).get('message', 'Unknown error')}")
            
    except Exception as e:
        await ctx.send(f"❌ Error checking threat intel: {str(e)}")

@bot.command()
async def urlscan(ctx, url: str):
    """
    Scan a URL for malicious content.
    Usage: !urlscan https://example.com
    """
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    await ctx.send(f"🔍 Scanning URL: `{url}`...")
    
    # URLScan.io or similar API integration
    # This is a placeholder - implement with actual API
    await ctx.send("⚠️ URL scanning requires URLScan.io API integration.\nAdd your API key to enable this feature.")

# ==================== SECURITY UTILITIES ====================

@bot.command()
async def encode(ctx, method: str, *, text: str):
    """
    Encode/decode text. Methods: base64, url, hex, rot13
    Usage: !encode base64 hello world
    """
    import base64
    
    try:
        if method.lower() == 'base64':
            encoded = base64.b64encode(text.encode()).decode()
            await ctx.send(f"**Base64 Encoded:**\n```\n{encoded}\n```")
        
        elif method.lower() == 'url':
            encoded = urllib.parse.quote(text)
            await ctx.send(f"**URL Encoded:**\n```\n{encoded}\n```")
        
        elif method.lower() == 'hex':
            encoded = text.encode().hex()
            await ctx.send(f"**Hex Encoded:**\n```\n{encoded}\n```")
        
        elif method.lower() == 'rot13':
            encoded = text.translate(str.maketrans(
                'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
            ))
            await ctx.send(f"**ROT13 Encoded:**\n```\n{encoded}\n```")
        
        else:
            await ctx.send("Available methods: `base64`, `url`, `hex`, `rot13`")
            
    except Exception as e:
        await ctx.send(f"❌ Error: {str(e)}")

@bot.command()
async def decode(ctx, method: str, *, text: str):
    """
    Decode text. Methods: base64, url, hex, rot13
    Usage: !decode base64 aGVsbG8=
    """
    import base64
    
    try:
        if method.lower() == 'base64':
            decoded = base64.b64decode(text).decode()
            await ctx.send(f"**Base64 Decoded:**\n```\n{decoded}\n```")
        
        elif method.lower() == 'url':
            decoded = urllib.parse.unquote(text)
            await ctx.send(f"**URL Decoded:**\n```\n{decoded}\n```")
        
        elif method.lower() == 'hex':
            decoded = bytes.fromhex(text).decode()
            await ctx.send(f"**Hex Decoded:**\n```\n{decoded}\n```")
        
        elif method.lower() == 'rot13':
            decoded = text.translate(str.maketrans(
                'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
            ))
            await ctx.send(f"**ROT13 Decoded:**\n```\n{decoded}\n```")
        
        else:
            await ctx.send("Available methods: `base64`, `url`, `hex`, `rot13`")
            
    except Exception as e:
        await ctx.send(f"❌ Error: {str(e)}")

@bot.command()
async def pwncheck(ctx, password: str):
    """
    Check password strength and if it's been breached.
    Usage: !pwncheck MyPassword123
    """
    import re
    
    # Strength analysis
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
    
    # Check against common passwords
    common_passwords = ['password', '123456', 'qwerty', 'admin', 'letmein']
    if password.lower() in common_passwords:
        strength = 0
        feedback.append("This is a commonly used password!")
    
    # Calculate score
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
    
    # Note: Real breach checking requires k-anonymity API call to HaveIBeenPwned
    embed.add_field(name="Breach Check", value="Use `!breach <email>` for breach monitoring", inline=False)
    
    await ctx.send(embed=embed)

# ==================== EVENT HANDLERS ====================

@bot.event
async def on_ready():
    print(f'🤖 {bot.user} has connected to Discord!')
    print(f'Connected to {len(bot.guilds)} guilds')
    
    # Set bot status
    await bot.change_presence(
        activity=discord.Activity(
            type=discord.ActivityType.watching,
            name="for security threats | !help"
        )
    )

@bot.event
async def on_message(message):
    # Ignore bot messages
    if message.author == bot.user:
        return
    
    # Check for suspicious patterns in messages (optional)
    suspicious_patterns = [
        r'\b\d{16}\b',  # Credit card numbers
        r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
        r'password\s*[=:]\s*\S+',  # Password leaks
        r'api[_-]?key\s*[=:]\s*\S+',  # API keys
    ]
    
    for pattern in suspicious_patterns:
        import re
        if re.search(pattern, message.content, re.IGNORECASE):
            # Log potential data leak
            print(f"⚠️ Potential sensitive data detected in {message.guild.name}")
            # Could auto-delete or alert admins here
    
    await bot.process_commands(message)

@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.CommandNotFound):
        return  # Ignore unknown commands
    
    elif isinstance(error, commands.MissingPermissions):
        await ctx.send("❌ You don't have permission to use this command.")
    
    elif isinstance(error, commands.CommandOnCooldown):
        await ctx.send(f"⏳ Command on cooldown. Try again in {error.retry_after:.1f}s")
    
    else:
        print(f"Error: {error}")
        await ctx.send(f"❌ An error occurred: {str(error)}")

# ==================== HELP COMMAND ====================

@bot.command()
async def sechelp(ctx):
    """
    Display all available security commands
    """
    embed = discord.Embed(
        title="🛡️ CyberSecurity Bot Commands",
        description="Your automated security assistant",
        color=0x00ff00
    )
    
    embed.add_field(
        name="🔍 Reconnaissance",
        value="""
        `!scan <target> [ports]` - Port scanner
        `!whois <domain>` - WHOIS lookup
        `!ipinfo <ip>` - IP geolocation
        `!dnslookup <domain> [type]` - DNS records
        `!headers <url>` - Check security headers
        `!sslcheck <domain>` - SSL certificate info
        """,
        inline=False
    )
    
    embed.add_field(
        name="🔐 Security Tools",
        value="""
        `!hashcheck <hash> [type]` - Analyze hash
        `!integrity <file>` - File integrity monitoring
        `!generatepass [length]` - Secure password generator
        `!pwncheck <password>` - Password strength check
        """,
        inline=False
    )
    
    embed.add_field(
        name="🌐 Threat Intelligence",
        value="""
        `!threatintel <indicator>` - Check VirusTotal
        `!breach <email>` - Check breach status
        `!urlscan <url>` - Scan URL for threats
        """,
        inline=False
    )
    
    embed.add_field(
        name="🛠️ Utilities",
        value="""
        `!encode <method> <text>` - Encode text
        `!decode <method> <text>` - Decode text
        `!monitor_start [logfile]` - Start log monitoring
        `!monitor_stop` - Stop monitoring
        """,
        inline=False
    )
    
    await ctx.send(embed=embed)

# ==================== RUN BOT ====================

if __name__ == "__main__":
    # Check for required dependencies
    required_modules = ['discord', 'requests']
    missing = []
    
    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            missing.append(module)
    
    if missing:
        print(f"Missing required modules: {', '.join(missing)}")
        print("Install with: pip install " + " ".join(missing))
        exit(1)
    
    bot.run(TOKEN)
