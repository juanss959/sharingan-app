import subprocess
import threading
import json
import os
import re
import requests
import socket as _socket
import sqlite3
import ssl as _ssl
import tempfile
import time
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template, request, jsonify, g
from flask_socketio import SocketIO, emit

app = Flask(__name__)
app.config["SECRET_KEY"] = "sharingan-key"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

DB_PATH = Path(__file__).parent / "sharingan.db"
GO_BIN = Path.home() / "go" / "bin"
SCOOP_SHIMS = Path.home() / "scoop" / "shims"

active_scans = {}


# ── Database ──

def get_db():
    db = sqlite3.connect(str(DB_PATH))
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    return db


def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            status TEXT DEFAULT 'running',
            current_phase INTEGER DEFAULT 0,
            total_phases INTEGER DEFAULT 7,
            started_at TEXT,
            finished_at TEXT
        );
        CREATE TABLE IF NOT EXISTS subdomains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER REFERENCES scans(id),
            subdomain TEXT NOT NULL,
            source TEXT
        );
        CREATE TABLE IF NOT EXISTS alive_hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER REFERENCES scans(id),
            url TEXT NOT NULL,
            status_code INTEGER,
            title TEXT,
            tech TEXT,
            server TEXT,
            content_length INTEGER
        );
        CREATE TABLE IF NOT EXISTS ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER REFERENCES scans(id),
            host TEXT,
            port INTEGER,
            state TEXT,
            service TEXT,
            version TEXT
        );
        CREATE TABLE IF NOT EXISTS vulns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER REFERENCES scans(id),
            template TEXT,
            severity TEXT,
            host TEXT,
            info TEXT,
            matched_at TEXT
        );
        CREATE TABLE IF NOT EXISTS directories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER REFERENCES scans(id),
            host TEXT,
            path TEXT,
            status_code INTEGER,
            content_length INTEGER
        );
        CREATE TABLE IF NOT EXISTS urls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER REFERENCES scans(id),
            url TEXT NOT NULL,
            source TEXT,
            category TEXT
        );
        CREATE TABLE IF NOT EXISTS recon_info (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER REFERENCES scans(id),
            category TEXT NOT NULL,
            key TEXT NOT NULL,
            value TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_sub_scan ON subdomains(scan_id);
        CREATE INDEX IF NOT EXISTS idx_alive_scan ON alive_hosts(scan_id);
        CREATE INDEX IF NOT EXISTS idx_ports_scan ON ports(scan_id);
        CREATE INDEX IF NOT EXISTS idx_vulns_scan ON vulns(scan_id);
        CREATE INDEX IF NOT EXISTS idx_dirs_scan ON directories(scan_id);
        CREATE INDEX IF NOT EXISTS idx_urls_scan ON urls(scan_id);
        CREATE INDEX IF NOT EXISTS idx_recon_scan ON recon_info(scan_id);
    """)
    db.commit()
    db.close()


# ── Helpers ──

def get_env():
    env = os.environ.copy()
    extra = f"{GO_BIN};{SCOOP_SHIMS}"
    env["PATH"] = extra + ";" + env.get("PATH", "")
    env["JAVA_HOME"] = str(Path.home() / "scoop" / "apps" / "temurin21-jdk" / "current")
    return env


def run_cmd(cmd):
    try:
        proc = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            timeout=600, env=get_env(), encoding="utf-8", errors="replace"
        )
        return proc.stdout + proc.stderr
    except Exception as e:
        return f"Error: {e}"


def run_cmd_lines(cmd):
    return [l.strip() for l in run_cmd(cmd).splitlines() if l.strip()]


def run_ps(script):
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.ps1', delete=False, encoding='utf-8') as f:
            f.write(script)
            ps_path = f.name
        proc = subprocess.run(
            ['powershell', '-ExecutionPolicy', 'Bypass', '-File', ps_path],
            capture_output=True, text=True, timeout=60, env=get_env(),
            encoding='utf-8', errors='replace'
        )
        os.unlink(ps_path)
        return proc.stdout
    except Exception as e:
        return f"Error: {e}"


def whois_query(domain):
    try:
        parts = domain.split('.')
        if len(parts) > 2:
            domain = '.'.join(parts[-2:])
        tld = parts[-1] if parts else ''
        whois_servers = {
            'com': 'whois.verisign-grs.com', 'net': 'whois.verisign-grs.com',
            'org': 'whois.pir.org', 'io': 'whois.nic.io', 'co': 'whois.nic.co',
            'dev': 'whois.nic.google', 'app': 'whois.nic.google',
            'me': 'whois.nic.me', 'info': 'whois.afilias.net',
        }
        server = whois_servers.get(tld, f'whois.nic.{tld}')
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((server, 43))
        s.sendall((domain + '\r\n').encode())
        data = b''
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        s.close()
        result = data.decode('utf-8', errors='replace')
        if 'whois.verisign' in server and 'Registrar WHOIS Server:' in result:
            m = re.search(r'Registrar WHOIS Server:\s*(\S+)', result)
            if m:
                s2 = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
                s2.settimeout(10)
                s2.connect((m.group(1), 43))
                s2.sendall((domain + '\r\n').encode())
                data2 = b''
                while True:
                    chunk = s2.recv(4096)
                    if not chunk:
                        break
                    data2 += chunk
                s2.close()
                result = data2.decode('utf-8', errors='replace')
        return result
    except Exception:
        return ''


def get_ssl_info(domain):
    try:
        ctx = _ssl.create_default_context()
        with ctx.wrap_socket(_socket.socket(), server_hostname=domain) as s:
            s.settimeout(10)
            s.connect((domain, 443))
            cert = s.getpeercert()
            info = {}
            subj = dict(x[0] for x in cert.get('subject', ()))
            info['Subject'] = subj.get('commonName', '')
            issuer = dict(x[0] for x in cert.get('issuer', ()))
            info['Issuer'] = issuer.get('organizationName', issuer.get('commonName', ''))
            info['Valido desde'] = cert.get('notBefore', '')
            info['Expira'] = cert.get('notAfter', '')
            info['Version'] = str(cert.get('serialNumber', ''))[:20]
            sans = [v for t, v in cert.get('subjectAltName', ()) if t == 'DNS']
            if sans:
                info['Alt Names'] = ', '.join(sans)
            info['Protocolo'] = s.version() or ''
            return info
    except Exception:
        return {}


def save_info(db, scan_id, category, key, value):
    if value and str(value).strip():
        db.execute("INSERT INTO recon_info (scan_id, category, key, value) VALUES (?, ?, ?, ?)",
                   (scan_id, category, key, str(value).strip()))


def run_fingerprint(db, scan_id, domain):
    # ── WHOIS (Python socket) ──
    whois_out = whois_query(domain)
    whois_fields = {
        "Registrar": r'Registrar:\s*(.+)',
        "Creado": r'Creat(?:ion|ed)\s*Date:\s*(.+)',
        "Expira": r'Expir(?:y|ation)\s*Date:\s*(.+)',
        "Actualizado": r'Updated\s*Date:\s*(.+)',
        "Name Servers": r'Name\s*Server:\s*(.+)',
        "Registrant Org": r'Registrant\s*Organiz?ation:\s*(.+)',
        "Registrant Country": r'Registrant\s*Country:\s*(.+)',
        "DNSSEC": r'DNSSEC:\s*(.+)',
        "Domain Status": r'Domain\s*Status:\s*(\S+)',
    }
    for key, pat in whois_fields.items():
        matches = re.findall(pat, whois_out, re.IGNORECASE)
        if matches:
            if key == "Name Servers":
                ns_list = list(set(m.strip().lower() for m in matches))
                save_info(db, scan_id, "whois", key, ", ".join(ns_list))
            elif key == "Domain Status":
                statuses = list(set(m.strip() for m in matches))
                save_info(db, scan_id, "whois", key, ", ".join(statuses[:5]))
            else:
                save_info(db, scan_id, "whois", key, matches[0].strip())

    # ── DNS Records (PowerShell via temp file) ──
    dns_script = f"""$ErrorActionPreference = 'SilentlyContinue'
$d = '{domain}'
try {{ $r = Resolve-DnsName $d -Type A -EA Stop; $ips = ($r | Where-Object {{ $_.QueryType -eq 'A' -and $_.Name -eq $d }}).IPAddress; if ($ips) {{ "A=" + ($ips -join ", ") }} }} catch {{}}
try {{ $r = Resolve-DnsName $d -Type AAAA -EA Stop; $ips = ($r | Where-Object {{ $_.QueryType -eq 'AAAA' -and $_.Name -eq $d }}).IPAddress; if ($ips) {{ "AAAA=" + ($ips -join ", ") }} }} catch {{}}
try {{ $r = Resolve-DnsName $d -Type MX -EA Stop; "MX=" + (($r | Where-Object {{ $_.NameExchange }}).NameExchange -join ", ") }} catch {{}}
try {{ $r = Resolve-DnsName $d -Type NS -EA Stop; "NS=" + (($r | Where-Object {{ $_.NameHost }}).NameHost -join ", ") }} catch {{}}
try {{ $r = Resolve-DnsName $d -Type TXT -EA Stop; "TXT=" + (($r | Where-Object {{ $_.Strings }}).Strings -join "; ") }} catch {{}}
try {{ $r = Resolve-DnsName $d -Type CNAME -EA Stop; "CNAME=" + (($r | Where-Object {{ $_.NameHost }}).NameHost -join ", ") }} catch {{}}
try {{ $r = Resolve-DnsName $d -Type SOA -EA Stop; $s = $r | Where-Object {{ $_.PrimaryServer }}; if ($s) {{ "SOA=" + $s.PrimaryServer + " (Serial: " + $s.SerialNumber + ")" }} }} catch {{}}
"""
    dns_out = run_ps(dns_script)
    for line in dns_out.splitlines():
        if "=" in line:
            rtype, val = line.split("=", 1)
            rtype = rtype.strip()
            val = val.strip()
            if val and rtype in ("A","AAAA","MX","NS","TXT","CNAME","SOA"):
                save_info(db, scan_id, "dns", rtype, val)

    # ── HTTP Headers + Security + Tech ──
    working_scheme = None
    for scheme in ["https", "http"]:
        headers_out = run_cmd(f'curl -sI -m 10 -L {scheme}://{domain}')
        if "HTTP/" not in headers_out:
            continue
        working_scheme = scheme

        save_info(db, scan_id, "headers", f"Raw ({scheme})", headers_out.strip())

        server = re.search(r'Server:\s*(.+)', headers_out, re.IGNORECASE)
        if server:
            save_info(db, scan_id, "tech", "Server", server.group(1).strip())

        powered = re.search(r'X-Powered-By:\s*(.+)', headers_out, re.IGNORECASE)
        if powered:
            save_info(db, scan_id, "tech", "X-Powered-By", powered.group(1).strip())

        via = re.search(r'Via:\s*(.+)', headers_out, re.IGNORECASE)
        if via:
            save_info(db, scan_id, "tech", "Proxy/CDN (Via)", via.group(1).strip())

        ct = re.search(r'Content-Type:\s*(.+)', headers_out, re.IGNORECASE)
        if ct:
            save_info(db, scan_id, "tech", "Content-Type", ct.group(1).strip())

        set_cookie = re.findall(r'Set-Cookie:\s*(.+)', headers_out, re.IGNORECASE)
        for sc in set_cookie:
            name = sc.split('=')[0].strip()
            flags = []
            if 'httponly' in sc.lower(): flags.append('HttpOnly')
            if 'secure' in sc.lower(): flags.append('Secure')
            if 'samesite' in sc.lower():
                ss = re.search(r'samesite=(\w+)', sc, re.IGNORECASE)
                if ss: flags.append(f'SameSite={ss.group(1)}')
            save_info(db, scan_id, "cookies", name, f"Flags: {', '.join(flags) if flags else 'None'}")

            if 'PHPSESSID' in name or 'PHPSE' in name:
                save_info(db, scan_id, "tech", "Backend", "PHP")
            elif 'JSESSIONID' in name:
                save_info(db, scan_id, "tech", "Backend", "Java")
            elif 'ASP.NET' in name or 'aspnet' in name.lower():
                save_info(db, scan_id, "tech", "Backend", "ASP.NET")
            elif 'connect.sid' in name:
                save_info(db, scan_id, "tech", "Backend", "Node.js (Express)")
            elif 'laravel_session' in name:
                save_info(db, scan_id, "tech", "Backend/Framework", "Laravel (PHP)")
            elif 'django' in name.lower() or 'csrftoken' in name.lower():
                save_info(db, scan_id, "tech", "Backend/Framework", "Django (Python)")
            elif '_rails' in name.lower():
                save_info(db, scan_id, "tech", "Backend/Framework", "Ruby on Rails")
            elif 'wordpress' in name.lower() or 'wp-' in name.lower():
                save_info(db, scan_id, "tech", "CMS", "WordPress")

        sec_headers = {
            "Strict-Transport-Security": "HSTS",
            "Content-Security-Policy": "CSP",
            "X-Frame-Options": "X-Frame-Options",
            "X-Content-Type-Options": "X-Content-Type-Options",
            "Referrer-Policy": "Referrer-Policy",
            "Permissions-Policy": "Permissions-Policy",
            "X-XSS-Protection": "X-XSS-Protection",
            "Access-Control-Allow-Origin": "CORS",
        }
        for header, label in sec_headers.items():
            m = re.search(rf'{header}:\s*(.+)', headers_out, re.IGNORECASE)
            if m:
                save_info(db, scan_id, "security", label, m.group(1).strip())
            else:
                save_info(db, scan_id, "security", label, "MISSING")

        break

    # ── SSL/TLS Certificate (Python) ──
    ssl_info = get_ssl_info(domain)
    for key, val in ssl_info.items():
        if val:
            save_info(db, scan_id, "ssl", key, val)

    # ── robots.txt ──
    base = f"{working_scheme or 'http'}://{domain}"
    robots_out = run_cmd(f'curl -s --max-time 10 {base}/robots.txt')
    if robots_out and 'user-agent' in robots_out.lower() and '<html' not in robots_out.lower():
        save_info(db, scan_id, "files", "robots.txt", robots_out.strip()[:2000])
        disallowed = re.findall(r'Disallow:\s*(.+)', robots_out, re.IGNORECASE)
        if disallowed:
            save_info(db, scan_id, "files", "Disallow paths", "\n".join(d.strip() for d in disallowed))
        sitemaps = re.findall(r'Sitemap:\s*(.+)', robots_out, re.IGNORECASE)
        if sitemaps:
            save_info(db, scan_id, "files", "Sitemaps", "\n".join(s.strip() for s in sitemaps))

    # ── sitemap.xml ──
    sitemap_out = run_cmd(f'curl -s --max-time 10 {base}/sitemap.xml')
    if sitemap_out and '<?xml' in sitemap_out.lower():
        url_count = len(re.findall(r'<loc>', sitemap_out))
        save_info(db, scan_id, "files", "sitemap.xml", f"{url_count} URLs encontradas")

    # ── Tech detection from HTML ──
    html_out = run_cmd(f'curl -s --max-time 10 -L {base}')
    if html_out:
        tech_patterns = {
            "jQuery": r'jquery[.-](\d[\d.]*\d)',
            "Bootstrap": r'bootstrap[.-](\d[\d.]*\d)',
            "React": r'react(?:\.production|\.development)[.-](\d[\d.]*)',
            "Vue.js": r'vue(?:\.min)?\.js.*?(\d+\.\d+)',
            "Angular": r'angular[/@](\d[\d.]*)',
            "WordPress": r'wp-content|wp-includes',
            "Drupal": r'Drupal|drupal\.js',
            "Joomla": r'/media/jui/|/media/system/',
            "Shopify": r'cdn\.shopify\.com',
            "Wix": r'wix\.com|parastorage\.com',
            "Cloudflare": r'cloudflare',
            "Google Analytics": r'google-analytics\.com|gtag|GA_TRACKING',
            "Google Tag Manager": r'googletagmanager\.com',
            "Font Awesome": r'font-awesome|fontawesome',
            "Tailwind CSS": r'tailwindcss',
        }
        for tech, pat in tech_patterns.items():
            m = re.search(pat, html_out, re.IGNORECASE)
            if m:
                ver = m.group(1) if m.lastindex else ""
                save_info(db, scan_id, "tech", tech, ver if ver else "Detected")

        meta_gen = re.search(r'<meta[^>]*name=["\']generator["\'][^>]*content=["\'](.*?)["\']', html_out, re.IGNORECASE)
        if meta_gen:
            save_info(db, scan_id, "tech", "Generator", meta_gen.group(1))

        meta_fw = re.search(r'<meta[^>]*name=["\']framework["\'][^>]*content=["\'](.*?)["\']', html_out, re.IGNORECASE)
        if meta_fw:
            save_info(db, scan_id, "tech", "Framework", meta_fw.group(1))

    # ── Common sensitive paths ──
    sensitive_paths = [
        "/.env", "/.git/HEAD", "/wp-login.php", "/admin", "/administrator",
        "/.htaccess", "/server-status", "/phpinfo.php", "/.well-known/security.txt",
        "/api", "/graphql", "/swagger.json", "/api-docs",
    ]
    for path in sensitive_paths:
        out = run_cmd(f'curl -s -o /dev/null -w "%{{http_code}}" --max-time 5 {base}{path}')
        code = out.strip()
        if code and code not in ["000", "404", "403", "0"]:
            save_info(db, scan_id, "paths", path, f"HTTP {code}")

    # ── JS Secrets Analysis ──
    if html_out:
        js_urls = set()
        for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html_out, re.IGNORECASE):
            src = m.group(1)
            if src.startswith('//'):
                src = (working_scheme or 'https') + ':' + src
            elif src.startswith('/'):
                src = base + src
            elif not src.startswith('http'):
                src = base + '/' + src
            js_urls.add(src)

        for m in re.finditer(r'(?:src|href)\s*=\s*["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', html_out, re.IGNORECASE):
            src = m.group(1)
            if src.startswith('//'):
                src = (working_scheme or 'https') + ':' + src
            elif src.startswith('/'):
                src = base + src
            elif not src.startswith('http'):
                src = base + '/' + src
            js_urls.add(src)

        secret_patterns = {
            "AWS Access Key": r'AKIA[0-9A-Z]{16}',
            "AWS Secret Key": r'(?:aws_secret_access_key|aws.secret.key|secret.?key)\s*[:=]\s*["\']?([0-9a-zA-Z/+=]{40})["\']?',
            "Google API Key": r'AIza[0-9A-Za-z\-_]{35}',
            "Google OAuth": r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
            "Firebase URL": r'https?://[a-z0-9-]+\.firebaseio\.com',
            "Firebase API Key": r'(?:firebase|FIREBASE).{0,30}["\']([A-Za-z0-9_-]{39})["\']',
            "Stripe Publishable": r'pk_(?:live|test)_[0-9a-zA-Z]{24,}',
            "Stripe Secret": r'sk_(?:live|test)_[0-9a-zA-Z]{24,}',
            "Slack Token": r'xox[baprs]-[0-9a-zA-Z\-]{10,}',
            "Slack Webhook": r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+',
            "GitHub Token": r'gh[pousr]_[A-Za-z0-9_]{36,}',
            "Generic API Key": r'(?:api[_-]?key|apikey|api_secret|access_key)\s*[:=]\s*["\']([a-zA-Z0-9\-_]{20,})["\']',
            "Generic Secret": r'(?:secret_key|client_secret|app_secret|private_key|auth_token|access_token)\s*[:=]\s*["\']([^"\']{12,})["\']',
            "Password in Code": r'(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{6,})["\']',
            "Bearer Token": r'[Bb]earer\s+[a-zA-Z0-9\-_.~+/]{20,}',
            "JWT Token": r'eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}',
            "Private Key": r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',
            "S3 Bucket": r'[a-zA-Z0-9.-]+\.s3[.-](?:amazonaws\.com|[a-z0-9-]+\.amazonaws\.com)',
            "Azure Storage": r'[a-zA-Z0-9]+\.blob\.core\.windows\.net',
            "Mailgun API Key": r'key-[0-9a-zA-Z]{32}',
            "Twilio API Key": r'SK[0-9a-fA-F]{32}',
            "SendGrid API Key": r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}',
            "Heroku API Key": r'[hH]eroku.{0,30}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            "Internal Endpoint": r'https?://(?:api\.|internal\.|staging\.|dev\.|admin\.|test\.)[a-zA-Z0-9.-]+\.[a-z]{2,}(?:/[a-zA-Z0-9/._-]*)?',
            "Hardcoded Private IP": r'(?<![0-9])(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?::\d{2,5})(?![0-9])',
            "MapBox Token": r'pk\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
        }
        found_secrets = set()
        js_files_scanned = 0

        for js_url in list(js_urls)[:30]:
            try:
                js_content = run_cmd(f'curl -s --max-time 15 -L "{js_url}"')
                if not js_content or len(js_content) < 20:
                    continue
                js_files_scanned += 1

                for name, pattern in secret_patterns.items():
                    for match in re.finditer(pattern, js_content):
                        secret_val = match.group(0)[:120]
                        dedup_key = f"{name}:{secret_val}"
                        if dedup_key not in found_secrets:
                            found_secrets.add(dedup_key)
                            short_url = js_url.split('?')[0].split('/')[-1] if '/' in js_url else js_url
                            save_info(db, scan_id, "js_secrets", name,
                                      f"{secret_val}  [en {short_url}]")
            except Exception:
                continue

        save_info(db, scan_id, "js_secrets", "JS Files Analizados", str(js_files_scanned))

    db.commit()


# ── Standalone OSINT ──

def run_osint(domain):
    results = {"emails": [], "social": [], "meta": [], "wayback": [], "wayback_total": 0,
               "gdorks": [], "gitdorks": []}

    socketio.emit("osint_status", {"status": "running", "msg": "Descargando pagina..."})

    # Fetch HTML
    html_out = ""
    base = ""
    for scheme in ["https", "http"]:
        try:
            url = f"{scheme}://{domain}"
            resp = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"}, verify=False)
            html_out = resp.text
            base = url
            break
        except Exception:
            continue

    # 1. Email Harvesting
    if html_out:
        socketio.emit("osint_status", {"status": "running", "msg": "Extrayendo emails..."})
        email_pattern = r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
        raw_emails = set(re.findall(email_pattern, html_out))
        skip_ext = {'.png', '.jpg', '.jpeg', '.gif', '.svg', '.css', '.js', '.woff', '.ttf', '.ico'}
        for e in sorted(raw_emails):
            el = e.lower()
            if not any(el.endswith(ext) for ext in skip_ext) and '.' in el.split('@')[1]:
                results["emails"].append(el)

    # 2. Metadata
    if html_out:
        socketio.emit("osint_status", {"status": "running", "msg": "Extrayendo metadata..."})
        meta_patterns = {
            "Meta Description": r'<meta\s+name=["\']description["\']\s+content=["\']([^"\']+)["\']',
            "Meta Author": r'<meta\s+name=["\']author["\']\s+content=["\']([^"\']+)["\']',
            "Meta Generator": r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']',
            "OG Title": r'<meta\s+property=["\']og:title["\']\s+content=["\']([^"\']+)["\']',
            "OG Description": r'<meta\s+property=["\']og:description["\']\s+content=["\']([^"\']+)["\']',
            "OG Image": r'<meta\s+property=["\']og:image["\']\s+content=["\']([^"\']+)["\']',
            "OG Site Name": r'<meta\s+property=["\']og:site_name["\']\s+content=["\']([^"\']+)["\']',
            "Twitter Handle": r'<meta\s+name=["\']twitter:(?:site|creator)["\']\s+content=["\'](@[^"\']+)["\']',
        }
        for name, pat in meta_patterns.items():
            m = re.search(pat, html_out, re.IGNORECASE)
            if m:
                results["meta"].append({"key": name, "value": m.group(1).strip()})

        # Social media links
        social_patterns = {
            "LinkedIn": r'https?://(?:www\.)?linkedin\.com/(?:company|in)/[a-zA-Z0-9\-_.%]+/?',
            "Twitter/X": r'https?://(?:www\.)?(?:twitter\.com|x\.com)/[a-zA-Z0-9_]+/?',
            "GitHub": r'https?://(?:www\.)?github\.com/[a-zA-Z0-9\-]+/?',
            "Facebook": r'https?://(?:www\.)?facebook\.com/[a-zA-Z0-9.\-]+/?',
            "Instagram": r'https?://(?:www\.)?instagram\.com/[a-zA-Z0-9_.]+/?',
            "YouTube": r'https?://(?:www\.)?youtube\.com/(?:c/|channel/|@)[a-zA-Z0-9\-_]+/?',
        }
        found_social = set()
        for name, pat in social_patterns.items():
            for m in re.finditer(pat, html_out, re.IGNORECASE):
                u = m.group(0).rstrip('/')
                if u not in found_social:
                    found_social.add(u)
                    results["social"].append({"platform": name, "url": u})

    # 3. Wayback Machine
    socketio.emit("osint_status", {"status": "running", "msg": "Consultando Wayback Machine..."})
    try:
        wb_url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&limit=50&fl=timestamp,original,statuscode&collapse=urlkey"
        wb_resp = requests.get(wb_url, timeout=15, headers={"User-Agent": "Mozilla/5.0"})
        if wb_resp.status_code == 200:
            wb_data = wb_resp.json()
            results["wayback_total"] = len(wb_data) - 1 if len(wb_data) > 1 else 0
            interesting_ext = {'.php', '.asp', '.aspx', '.jsp', '.env', '.bak', '.old', '.sql', '.xml',
                               '.json', '.yml', '.yaml', '.conf', '.config', '.log', '.txt', '.zip',
                               '.tar', '.gz', '.rar', '.csv', '.xls', '.doc', '.pdf', '.git'}
            interesting_paths = {'admin', 'login', 'dashboard', 'api', 'backup', 'config', 'debug',
                                 'test', 'staging', 'dev', 'internal', 'panel', 'console', 'upload',
                                 'private', 'secret', 'wp-admin', 'phpmyadmin', '.env', '.git'}
            wb_found = set()
            for row in wb_data[1:]:
                ts, url_orig = row[0], row[1]
                url_lower = url_orig.lower()
                is_interesting = any(url_lower.endswith(ext) for ext in interesting_ext)
                is_interesting = is_interesting or any(p in url_lower for p in interesting_paths)
                if is_interesting and url_orig not in wb_found and len(wb_found) < 30:
                    wb_found.add(url_orig)
                    wb_link = f"https://web.archive.org/web/{ts}/{url_orig}"
                    results["wayback"].append({"url": url_orig, "link": wb_link})
    except Exception:
        pass

    # 4. Google Dorks
    socketio.emit("osint_status", {"status": "running", "msg": "Generando Google Dorks..."})
    dorks = [
        ("Archivos Sensibles", f'site:{domain} (filetype:pdf OR filetype:doc OR filetype:xls OR filetype:sql OR filetype:env OR filetype:log OR filetype:bak)'),
        ("Paginas de Login", f'site:{domain} (inurl:login OR inurl:signin OR inurl:auth OR inurl:admin)'),
        ("Directorios Expuestos", f'site:{domain} intitle:"index of"'),
        ("Archivos de Config", f'site:{domain} (filetype:xml OR filetype:json OR filetype:yml OR filetype:conf OR filetype:ini OR filetype:env)'),
        ("Errores y Debug", f'site:{domain} (intext:"error" OR intext:"warning" OR intext:"debug" OR intext:"stack trace")'),
        ("Passwords Expuestos", f'site:{domain} (intext:"password" OR intext:"passwd" OR intext:"credentials" OR filetype:sql)'),
        ("Paneles de Admin", f'site:{domain} (inurl:admin OR inurl:panel OR inurl:dashboard OR inurl:manage OR inurl:console)'),
        ("APIs Expuestas", f'site:{domain} (inurl:api OR inurl:v1 OR inurl:v2 OR inurl:graphql OR inurl:swagger OR inurl:rest)'),
        ("Backups", f'site:{domain} (filetype:bak OR filetype:old OR filetype:backup OR filetype:zip OR filetype:tar OR filetype:gz)'),
        ("Info en Pastebin", f'site:pastebin.com "{domain}"'),
        ("Info en GitHub", f'site:github.com "{domain}" (password OR secret OR api_key OR token)'),
        ("Subdominios Google", f'site:*.{domain} -www'),
        ("Camaras y IoT", f'site:{domain} (inurl:cgi-bin OR inurl:webcam OR inurl:view.shtml)'),
        ("Archivos Git", f'site:{domain} (inurl:.git OR inurl:.svn OR inurl:.env OR inurl:wp-config)'),
        ("S3 Buckets", f'site:s3.amazonaws.com "{domain}"'),
        ("Trello Boards", f'site:trello.com "{domain}"'),
    ]
    for name, query in dorks:
        google_url = f"https://www.google.com/search?q={requests.utils.quote(query)}"
        results["gdorks"].append({"name": name, "query": query, "link": google_url})

    # 5. GitHub Dorks
    github_dorks = [
        ("Passwords", f'"{domain}" password OR passwd OR pwd'),
        ("API Keys", f'"{domain}" api_key OR apikey OR api_secret OR access_key'),
        ("Tokens", f'"{domain}" token OR bearer OR auth_token OR secret_key'),
        ("Configs", f'"{domain}" filename:.env OR filename:.yml OR filename:config'),
        ("AWS Keys", f'"{domain}" AKIA OR aws_secret'),
        ("DB Credentials", f'"{domain}" database OR mysql OR postgres OR mongodb AND password'),
        ("Private Keys", f'"{domain}" "BEGIN RSA PRIVATE KEY" OR "BEGIN EC PRIVATE KEY"'),
    ]
    for name, query in github_dorks:
        gh_url = f"https://github.com/search?q={requests.utils.quote(query)}&type=code"
        results["gitdorks"].append({"name": name, "query": query, "link": gh_url})

    socketio.emit("osint_result", results)
    socketio.emit("osint_status", {"status": "done", "msg": "OSINT completado"})


@socketio.on("start_osint")
def handle_osint(data):
    domain = data.get("domain", "").strip()
    if not domain:
        return
    threading.Thread(target=run_osint, args=(domain,), daemon=True).start()


def update_scan(scan_id, **kwargs):
    db = get_db()
    sets = ", ".join(f"{k} = ?" for k in kwargs)
    vals = list(kwargs.values()) + [scan_id]
    db.execute(f"UPDATE scans SET {sets} WHERE id = ?", vals)
    db.commit()
    db.close()
    socketio.emit("scan_update", {"scan_id": scan_id, **kwargs})


# ── Scan Logic ──

def run_scan(scan_id, domain, phases):
    db = get_db()
    tmpdir = Path.home() / "AppData" / "Local" / "Temp" / f"sharingan-{scan_id}"
    tmpdir.mkdir(parents=True, exist_ok=True)

    try:
        # ── FASE 1: Recon pasivo + fingerprinting + crt.sh ──
        if 1 in phases:
            update_scan(scan_id, current_phase=1, status="running")
            socketio.emit("phase_status", {"scan_id": scan_id, "phase": 1, "status": "running"})

            run_fingerprint(db, scan_id, domain)
            socketio.emit("stats_update", {"scan_id": scan_id, "info": True})

            out = run_cmd(f'curl -s "https://crt.sh/?q=%25.{domain}&output=json"')
            try:
                data = json.loads(out)
                names = sorted(set(
                    n.strip().lower()
                    for entry in data
                    for n in entry.get("name_value", "").split("\n")
                    if domain in n.lower() and "*" not in n
                ))
                for name in names:
                    db.execute("INSERT INTO subdomains (scan_id, subdomain, source) VALUES (?, ?, ?)",
                               (scan_id, name, "crt.sh"))
                db.commit()
            except Exception:
                pass

            socketio.emit("phase_status", {"scan_id": scan_id, "phase": 1, "status": "done"})

        if active_scans.get(scan_id) == "cancelled":
            update_scan(scan_id, status="cancelled")
            return

        # ── FASE 2: Subdominios ──
        if 2 in phases:
            update_scan(scan_id, current_phase=2)
            socketio.emit("phase_status", {"scan_id": scan_id, "phase": 2, "status": "running"})

            sf_file = tmpdir / "subfinder.txt"
            run_cmd(f'subfinder -d {domain} -all -o "{sf_file}" -silent')
            if sf_file.exists():
                for line in sf_file.read_text(encoding="utf-8", errors="replace").splitlines():
                    s = line.strip().lower()
                    if s and domain in s:
                        db.execute("INSERT INTO subdomains (scan_id, subdomain, source) VALUES (?, ?, ?)",
                                   (scan_id, s, "subfinder"))
                db.commit()

            sl_file = tmpdir / "sublist3r.txt"
            run_cmd(f'python -m sublist3r -d {domain} -o "{sl_file}"')
            if sl_file.exists():
                for line in sl_file.read_text(encoding="utf-8", errors="replace").splitlines():
                    s = line.strip().lower()
                    if s and domain in s:
                        db.execute("INSERT INTO subdomains (scan_id, subdomain, source) VALUES (?, ?, ?)",
                                   (scan_id, s, "sublist3r"))
                db.commit()

            af_out = run_cmd(f'assetfinder --subs-only {domain}')
            for line in af_out.splitlines():
                s = line.strip().lower()
                if s and domain in s:
                    db.execute("INSERT INTO subdomains (scan_id, subdomain, source) VALUES (?, ?, ?)",
                               (scan_id, s, "assetfinder"))
            db.commit()

            # Deduplicate
            db.execute("""
                DELETE FROM subdomains WHERE id NOT IN (
                    SELECT MIN(id) FROM subdomains WHERE scan_id = ? GROUP BY subdomain
                ) AND scan_id = ?
            """, (scan_id, scan_id))
            db.commit()

            count = db.execute("SELECT COUNT(*) FROM subdomains WHERE scan_id = ?", (scan_id,)).fetchone()[0]
            socketio.emit("stats_update", {"scan_id": scan_id, "subdomains": count})
            socketio.emit("phase_status", {"scan_id": scan_id, "phase": 2, "status": "done"})

        if active_scans.get(scan_id) == "cancelled":
            update_scan(scan_id, status="cancelled")
            return

        # ── FASE 3: Hosts vivos ──
        if 3 in phases:
            update_scan(scan_id, current_phase=3)
            socketio.emit("phase_status", {"scan_id": scan_id, "phase": 3, "status": "running"})

            subs = [r["subdomain"] for r in db.execute(
                "SELECT DISTINCT subdomain FROM subdomains WHERE scan_id = ?", (scan_id,)).fetchall()]

            if subs:
                subs_file = tmpdir / "subs.txt"
                subs_file.write_text("\n".join(subs), encoding="utf-8")

                httpx_file = tmpdir / "httpx.json"
                run_cmd(f'httpx -l "{subs_file}" -json -o "{httpx_file}" -sc -cl -title -td -server -nc -silent')

                if httpx_file.exists():
                    for line in httpx_file.read_text(encoding="utf-8", errors="replace").splitlines():
                        try:
                            j = json.loads(line)
                            db.execute("""INSERT INTO alive_hosts
                                (scan_id, url, status_code, title, tech, server, content_length)
                                VALUES (?, ?, ?, ?, ?, ?, ?)""", (
                                scan_id,
                                j.get("url", ""),
                                j.get("status_code"),
                                j.get("title", ""),
                                ", ".join(j.get("tech", [])) if isinstance(j.get("tech"), list) else j.get("tech", ""),
                                j.get("webserver", ""),
                                j.get("content_length")
                            ))
                        except Exception:
                            pass
                    db.commit()

            count = db.execute("SELECT COUNT(*) FROM alive_hosts WHERE scan_id = ?", (scan_id,)).fetchone()[0]
            socketio.emit("stats_update", {"scan_id": scan_id, "alive": count})
            socketio.emit("phase_status", {"scan_id": scan_id, "phase": 3, "status": "done"})

        if active_scans.get(scan_id) == "cancelled":
            update_scan(scan_id, status="cancelled")
            return

        # ── FASE 4: Port scanning ──
        if 4 in phases:
            update_scan(scan_id, current_phase=4)
            socketio.emit("phase_status", {"scan_id": scan_id, "phase": 4, "status": "running"})

            hosts = set()
            for r in db.execute("SELECT url FROM alive_hosts WHERE scan_id = ?", (scan_id,)).fetchall():
                h = re.sub(r'https?://', '', r["url"]).split('/')[0].split(':')[0]
                hosts.add(h)

            if hosts:
                hosts_file = tmpdir / "hosts.txt"
                hosts_file.write_text("\n".join(sorted(hosts)), encoding="utf-8")
                nmap_out = run_cmd(f'nmap -sV -T4 --top-ports 100 -iL "{hosts_file}"')

                current_host = ""
                for line in nmap_out.splitlines():
                    m = re.match(r'Nmap scan report for (.+)', line)
                    if m:
                        current_host = m.group(1).split('(')[0].strip()
                        ip_m = re.search(r'\(([^)]+)\)', m.group(1))
                        if ip_m:
                            current_host = m.group(1).split('(')[0].strip()
                    m = re.match(r'(\d+)/(tcp|udp)\s+(open|filtered)\s+(\S+)\s*(.*)', line)
                    if m and current_host:
                        db.execute("""INSERT INTO ports (scan_id, host, port, state, service, version)
                            VALUES (?, ?, ?, ?, ?, ?)""", (
                            scan_id, current_host, int(m.group(1)), m.group(3),
                            m.group(4), m.group(5).strip()
                        ))
                db.commit()

            count = db.execute("SELECT COUNT(*) FROM ports WHERE scan_id = ?", (scan_id,)).fetchone()[0]
            socketio.emit("stats_update", {"scan_id": scan_id, "ports": count})
            socketio.emit("phase_status", {"scan_id": scan_id, "phase": 4, "status": "done"})

        if active_scans.get(scan_id) == "cancelled":
            update_scan(scan_id, status="cancelled")
            return

        # ── FASE 5: Vulnerabilidades ──
        if 5 in phases:
            update_scan(scan_id, current_phase=5)
            socketio.emit("phase_status", {"scan_id": scan_id, "phase": 5, "status": "running"})

            alive = [r["url"] for r in db.execute(
                "SELECT url FROM alive_hosts WHERE scan_id = ?", (scan_id,)).fetchall()]
            if alive:
                alive_file = tmpdir / "alive.txt"
                alive_file.write_text("\n".join(alive), encoding="utf-8")
                nuclei_file = tmpdir / "nuclei.json"
                run_cmd(f'nuclei -l "{alive_file}" -jsonl -o "{nuclei_file}" -es info -rl 30 -nc -silent')

                if nuclei_file.exists():
                    for line in nuclei_file.read_text(encoding="utf-8", errors="replace").splitlines():
                        try:
                            j = json.loads(line)
                            info = j.get("info", {})
                            db.execute("""INSERT INTO vulns
                                (scan_id, template, severity, host, info, matched_at)
                                VALUES (?, ?, ?, ?, ?, ?)""", (
                                scan_id,
                                j.get("template-id", ""),
                                info.get("severity", "unknown"),
                                j.get("host", ""),
                                info.get("name", ""),
                                j.get("matched-at", "")
                            ))
                        except Exception:
                            pass
                    db.commit()

            count = db.execute("SELECT COUNT(*) FROM vulns WHERE scan_id = ?", (scan_id,)).fetchone()[0]
            socketio.emit("stats_update", {"scan_id": scan_id, "vulns": count})
            socketio.emit("phase_status", {"scan_id": scan_id, "phase": 5, "status": "done"})

        if active_scans.get(scan_id) == "cancelled":
            update_scan(scan_id, status="cancelled")
            return

        # ── FASE 6: Directorios ──
        if 6 in phases:
            update_scan(scan_id, current_phase=6)
            socketio.emit("phase_status", {"scan_id": scan_id, "phase": 6, "status": "running"})

            alive = [r["url"] for r in db.execute(
                "SELECT url FROM alive_hosts WHERE scan_id = ?", (scan_id,)).fetchall()]
            for host in alive[:5]:
                safe = re.sub(r'[^\w\-.]', '_', host)
                dir_file = tmpdir / f"dirs-{safe}.txt"
                run_cmd(f'python -m dirsearch -u {host} --format plain -o "{dir_file}" -q')
                if dir_file.exists():
                    for line in dir_file.read_text(encoding="utf-8", errors="replace").splitlines():
                        m = re.match(r'(\d{3})\s+\S+\s+\S+\s+(/.+)', line)
                        if m:
                            db.execute("""INSERT INTO directories (scan_id, host, path, status_code)
                                VALUES (?, ?, ?, ?)""", (scan_id, host, m.group(2).strip(), int(m.group(1))))
                    db.commit()

            count = db.execute("SELECT COUNT(*) FROM directories WHERE scan_id = ?", (scan_id,)).fetchone()[0]
            socketio.emit("stats_update", {"scan_id": scan_id, "dirs": count})
            socketio.emit("phase_status", {"scan_id": scan_id, "phase": 6, "status": "done"})

        if active_scans.get(scan_id) == "cancelled":
            update_scan(scan_id, status="cancelled")
            return

        # ── FASE 7: URLs históricas ──
        if 7 in phases:
            update_scan(scan_id, current_phase=7)
            socketio.emit("phase_status", {"scan_id": scan_id, "phase": 7, "status": "running"})

            param_patterns = ["id=", "redirect=", "url=", "file=", "path=", "q=", "page=",
                              "search=", "token=", "callback=", "next=", "return=", "dest="]
            file_patterns = [".php", ".asp", ".jsp", ".json", ".xml", ".config", ".env",
                             ".bak", ".sql", ".log", ".git", ".zip", ".tar"]

            wb_out = run_cmd(f'waybackurls {domain}')
            gau_out = run_cmd(f'gau {domain}')

            all_urls = set()
            for line in (wb_out + "\n" + gau_out).splitlines():
                u = line.strip()
                if u and u.startswith("http"):
                    all_urls.add(u)

            for url in all_urls:
                cat = "other"
                lower = url.lower()
                for p in param_patterns:
                    if p in lower:
                        cat = "param"
                        break
                if cat == "other":
                    for ext in file_patterns:
                        if ext in lower:
                            cat = "file"
                            break

                source = "waybackurls" if url in wb_out else "gau"
                db.execute("INSERT INTO urls (scan_id, url, source, category) VALUES (?, ?, ?, ?)",
                           (scan_id, url, source, cat))
            db.commit()

            total = len(all_urls)
            params = db.execute("SELECT COUNT(*) FROM urls WHERE scan_id = ? AND category = 'param'", (scan_id,)).fetchone()[0]
            files = db.execute("SELECT COUNT(*) FROM urls WHERE scan_id = ? AND category = 'file'", (scan_id,)).fetchone()[0]
            socketio.emit("stats_update", {"scan_id": scan_id, "urls": total, "params": params, "files": files})
            socketio.emit("phase_status", {"scan_id": scan_id, "phase": 7, "status": "done"})

        # Done
        update_scan(scan_id, status="completed", finished_at=datetime.now().isoformat(), current_phase=7)
        socketio.emit("scan_done", {"scan_id": scan_id})

    except Exception as e:
        update_scan(scan_id, status="error")
        socketio.emit("scan_error", {"scan_id": scan_id, "error": str(e)})
    finally:
        db.close()
        import shutil
        try:
            shutil.rmtree(tmpdir, ignore_errors=True)
        except Exception:
            pass


# ── Routes ──

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/tools")
def tools_status():
    tools = ["subfinder", "sublist3r", "assetfinder", "httpx", "nmap", "nuclei", "ffuf", "dirsearch", "waybackurls", "gau", "whois"]
    cmds = {
        "subfinder": "subfinder -version", "sublist3r": "python -m sublist3r --help",
        "assetfinder": "assetfinder -h", "httpx": "httpx -version", "nmap": "nmap --version",
        "nuclei": "nuclei -version", "ffuf": "ffuf -V", "dirsearch": "python -m dirsearch --help",
        "waybackurls": "waybackurls -h", "gau": "gau --help", "whois": "whois -?",
    }
    results = {}
    for name in tools:
        try:
            r = subprocess.run(cmds[name], shell=True, capture_output=True, text=True, timeout=10, env=get_env())
            results[name] = r.returncode == 0 or len(r.stdout + r.stderr) > 0
        except Exception:
            results[name] = False
    return jsonify(results)


@app.route("/api/scans")
def list_scans():
    db = get_db()
    scans = db.execute("SELECT * FROM scans ORDER BY id DESC").fetchall()
    result = []
    for s in scans:
        row = dict(s)
        row["subdomains"] = db.execute("SELECT COUNT(*) FROM subdomains WHERE scan_id=?", (s["id"],)).fetchone()[0]
        row["alive"] = db.execute("SELECT COUNT(*) FROM alive_hosts WHERE scan_id=?", (s["id"],)).fetchone()[0]
        row["ports"] = db.execute("SELECT COUNT(*) FROM ports WHERE scan_id=?", (s["id"],)).fetchone()[0]
        row["vulns"] = db.execute("SELECT COUNT(*) FROM vulns WHERE scan_id=?", (s["id"],)).fetchone()[0]
        row["dirs"] = db.execute("SELECT COUNT(*) FROM directories WHERE scan_id=?", (s["id"],)).fetchone()[0]
        row["urls"] = db.execute("SELECT COUNT(*) FROM urls WHERE scan_id=?", (s["id"],)).fetchone()[0]
        result.append(row)
    db.close()
    return jsonify(result)


@app.route("/api/scans/<int:scan_id>")
def get_scan(scan_id):
    db = get_db()
    scan = db.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not scan:
        db.close()
        return jsonify({"error": "not found"}), 404
    result = dict(scan)
    result["subdomains"] = [dict(r) for r in db.execute(
        "SELECT subdomain, source FROM subdomains WHERE scan_id=? ORDER BY subdomain", (scan_id,)).fetchall()]
    result["alive_hosts"] = [dict(r) for r in db.execute(
        "SELECT url, status_code, title, tech, server, content_length FROM alive_hosts WHERE scan_id=?", (scan_id,)).fetchall()]
    result["ports"] = [dict(r) for r in db.execute(
        "SELECT host, port, state, service, version FROM ports WHERE scan_id=? ORDER BY port", (scan_id,)).fetchall()]
    result["vulns"] = [dict(r) for r in db.execute(
        "SELECT template, severity, host, info, matched_at FROM vulns WHERE scan_id=? ORDER BY severity", (scan_id,)).fetchall()]
    result["directories"] = [dict(r) for r in db.execute(
        "SELECT host, path, status_code FROM directories WHERE scan_id=? ORDER BY status_code", (scan_id,)).fetchall()]
    result["urls"] = [dict(r) for r in db.execute(
        "SELECT url, source, category FROM urls WHERE scan_id=? ORDER BY category, url", (scan_id,)).fetchall()]
    info_rows = db.execute("SELECT category, key, value FROM recon_info WHERE scan_id=? ORDER BY category, key", (scan_id,)).fetchall()
    recon = {}
    for r in info_rows:
        cat = r["category"]
        if cat not in recon:
            recon[cat] = []
        recon[cat].append({"key": r["key"], "value": r["value"]})
    result["recon_info"] = recon
    db.close()
    return jsonify(result)


@app.route("/api/scans/<int:scan_id>", methods=["DELETE"])
def delete_scan(scan_id):
    db = get_db()
    for table in ["subdomains", "alive_hosts", "ports", "vulns", "directories", "urls", "recon_info"]:
        db.execute(f"DELETE FROM {table} WHERE scan_id=?", (scan_id,))
    db.execute("DELETE FROM scans WHERE id=?", (scan_id,))
    db.commit()
    db.close()
    return jsonify({"ok": True})


@socketio.on("start_scan")
def handle_start(data):
    domain = data.get("domain", "").strip().lower()
    if not domain:
        emit("error", {"message": "Dominio requerido"})
        return
    domain = re.sub(r'^https?://', '', domain).split('/')[0]
    phases = data.get("phases", [1, 2, 3, 4, 5, 6, 7])

    db = get_db()
    cur = db.execute("INSERT INTO scans (domain, status, started_at) VALUES (?, 'running', ?)",
                     (domain, datetime.now().isoformat()))
    scan_id = cur.lastrowid
    db.commit()
    db.close()

    active_scans[scan_id] = "running"
    emit("scan_started", {"scan_id": scan_id, "domain": domain})

    thread = threading.Thread(target=run_scan, args=(scan_id, domain, phases), daemon=True)
    thread.start()


@socketio.on("cancel_scan")
def handle_cancel(data):
    scan_id = data.get("scan_id")
    if scan_id:
        active_scans[scan_id] = "cancelled"
        update_scan(scan_id, status="cancelled")
        emit("scan_cancelled", {"scan_id": scan_id})


if __name__ == "__main__":
    init_db()
    print("\n  Sharingan running at http://localhost:5000\n")
    socketio.run(app, host="0.0.0.0", port=5000, debug=False, allow_unsafe_werkzeug=True)
