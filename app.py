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
app.config["SECRET_KEY"] = os.environ.get("SHARINGAN_SECRET", "sharingan-key")

# El listener se ata a 127.0.0.1 por defecto y solo acepta orígenes locales.
# Antes era 0.0.0.0 + cors="*": cualquiera en la LAN podía disparar los
# handlers (start_fuzzing/start_bypass) y, por la inyección de comandos que
# existía, lograr RCE/SSRF remoto sin auth. Para exponerlo a propósito,
# definir SHARINGAN_BIND=0.0.0.0 y SHARINGAN_ORIGINS con la lista explícita.
BIND_HOST = os.environ.get("SHARINGAN_BIND", "127.0.0.1")
_default_origins = ["http://127.0.0.1:5000", "http://localhost:5000"]
ALLOWED_ORIGINS = [o.strip() for o in os.environ.get("SHARINGAN_ORIGINS", "").split(",") if o.strip()] or _default_origins
socketio = SocketIO(app, cors_allowed_origins=ALLOWED_ORIGINS, async_mode="threading")

DB_PATH = Path(__file__).parent / "sharingan.db"
GO_BIN = Path.home() / "go" / "bin"
SCOOP_SHIMS = Path.home() / "scoop" / "shims"

active_scans = {}
active_fuzz = {}


# ── Database ──

def _norm_host(s):
    """Las 4 representaciones de host (alive_hosts.url completa, ports.host pelado,
    vulns.host crudo de nuclei, directories.host netloc-con-puerto) → un host
    canónico (minúsculas, sin esquema/userinfo/puerto/path, IPv6 sin corchetes,
    sin punto final), o None para basura. Única normalización del codebase: es la
    clave de correlación de assets/findings."""
    if not s:
        return None
    from urllib.parse import urlparse as _up
    s = str(s).strip().lower()
    if not s:
        return None
    try:
        u = _up(s if "://" in s else "//" + s)
        h = u.hostname
    except Exception:
        h = None
    if not h:
        h = s.split("/", 1)[0].rsplit("@", 1)[-1].split(":", 1)[0]
    h = (h or "").rstrip(".")
    return h or None


def get_db():
    db = sqlite3.connect(str(DB_PATH))
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    # norm_host disponible en SQL (vista findings, endpoint de assets).
    db.create_function("norm_host", 1, _norm_host, deterministic=True)
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
            content_length INTEGER,
            words INTEGER,
            lines INTEGER,
            type TEXT,
            redirect TEXT,
            title TEXT,
            server TEXT,
            tech TEXT,
            content_type TEXT,
            interest TEXT,
            source TEXT,
            likely_real INTEGER
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
        CREATE TABLE IF NOT EXISTS assets (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id        INTEGER REFERENCES scans(id),
            canonical_host TEXT NOT NULL,
            ip             TEXT,
            url            TEXT,
            status_code    INTEGER,
            title          TEXT,
            tech           TEXT,
            server         TEXT,
            content_length INTEGER,
            is_wildcard    INTEGER,
            is_internal    INTEGER,
            in_subdomains  INTEGER DEFAULT 0,
            in_alive       INTEGER DEFAULT 0,
            shared_ip      INTEGER DEFAULT 0,
            created_at     TEXT
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_assets_scan_host ON assets(scan_id, canonical_host);
        CREATE INDEX IF NOT EXISTS idx_assets_scan ON assets(scan_id);
    """)

    # ── Migración idempotente para BDs ya existentes ──
    # ALTER TABLE ADD COLUMN es seguro de repetir solo si chequeamos antes.
    def _ensure_cols(table, cols):
        have = {r[1] for r in db.execute(f"PRAGMA table_info({table})").fetchall()}
        for name, decl in cols:
            if name not in have:
                db.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")

    _ensure_cols("directories", [
        ("words", "INTEGER"), ("lines", "INTEGER"), ("type", "TEXT"),
        ("redirect", "TEXT"), ("title", "TEXT"), ("server", "TEXT"),
        ("tech", "TEXT"), ("content_type", "TEXT"), ("interest", "TEXT"),
        ("source", "TEXT"), ("likely_real", "INTEGER"),
        # Motor de validación central: veredicto + evidencia (JSON).
        ("validation_status", "TEXT"), ("evidence", "TEXT"),
    ])
    _ensure_cols("vulns", [("validation_status", "TEXT"), ("evidence", "TEXT")])
    _ensure_cols("scans", [("mode", "TEXT")])
    # #7: resolución DNS + wildcard + scope por IP en subdominios.
    _ensure_cols("subdomains", [
        ("ip", "TEXT"), ("resolved", "INTEGER"),
        ("is_wildcard", "INTEGER"), ("is_internal", "INTEGER"),
    ])

    # #8: reconciliar scans que quedaron 'running' (el proceso murió con su
    # hilo daemon dejando el estado colgado para siempre).
    db.execute("UPDATE scans SET status='interrupted' WHERE status='running'")

    # #9: dedup de vulns. Primero borramos duplicados exactos ya guardados
    # (mismo scan_id/template/host/matched_at), luego un índice ÚNICO evita
    # nuevos duplicados vía INSERT OR IGNORE en FASE 5.
    db.execute("""
        DELETE FROM vulns WHERE id NOT IN (
            SELECT MIN(id) FROM vulns
            GROUP BY scan_id, template, host, matched_at
        )
    """)
    db.execute("""CREATE UNIQUE INDEX IF NOT EXISTS idx_vulns_unique
                  ON vulns(scan_id, template, host, matched_at)""")

    # ── P2: capa de correlación assets ↔ findings ──
    # findings es una VISTA (no tabla): UNION ALL de vulns + directories con el
    # host canonicalizado y el veredicto ya calculado. Refleja cada insert al
    # instante, sin doble-escritura ni backfill. Se crea DESPUÉS de _ensure_cols
    # porque referencia validation_status/evidence (SQLite liga vistas de forma
    # perezosa, pero un SELECT fallaría sin esas columnas).
    db.execute("DROP VIEW IF EXISTS findings")
    db.execute("""CREATE VIEW findings AS
        SELECT v.scan_id AS scan_id, norm_host(v.host) AS canonical_host,
               'vuln' AS finding_type, v.id AS source_id, v.template AS name,
               v.severity AS severity, v.matched_at AS location,
               v.validation_status AS validation_status, v.evidence AS evidence
        FROM vulns v
        UNION ALL
        SELECT d.scan_id, norm_host(d.host), 'dir', d.id, d.path,
               d.interest, d.redirect, d.validation_status, d.evidence
        FROM directories d""")

    # Backfill histórico de assets para todos los scans existentes (idempotente).
    for (sid,) in db.execute("SELECT id FROM scans").fetchall():
        try:
            rebuild_assets(db, sid)
        except Exception:
            pass

    db.commit()
    db.close()


def rebuild_assets(db, scan_id):
    """Reconstruye los assets de un scan: unifica los hosts de las 5 tablas en
    un host canónico (_norm_host), enriquece con la IP de subdomains (el puente)
    y los metadatos de alive_hosts, y hace UPSERT idempotente. Marca shared_ip
    (IP compartida por >1 host = posible CDN). Commitea internamente."""
    db.create_function("norm_host", 1, _norm_host, deterministic=True)
    hosts = set()
    for col, tbl in [("subdomain", "subdomains"), ("url", "alive_hosts"),
                     ("host", "ports"), ("host", "vulns"), ("host", "directories")]:
        for r in db.execute(f"SELECT DISTINCT {col} AS v FROM {tbl} WHERE scan_id=?", (scan_id,)):
            h = _norm_host(r["v"])
            if h:
                hosts.add(h)
    if not hosts:
        db.commit()
        return

    sub = {}
    for r in db.execute("SELECT subdomain, ip, is_wildcard, is_internal FROM subdomains WHERE scan_id=? AND resolved=1", (scan_id,)):
        h = _norm_host(r["subdomain"])
        if h:
            sub.setdefault(h, r)
    alive = {}
    for r in db.execute("SELECT url, status_code, title, tech, server, content_length FROM alive_hosts WHERE scan_id=?", (scan_id,)):
        h = _norm_host(r["url"])
        if h:
            alive.setdefault(h, r)

    now = datetime.now().isoformat()
    for h in hosts:
        s, a = sub.get(h), alive.get(h)
        db.execute("""
            INSERT INTO assets (scan_id, canonical_host, ip, url, status_code, title, tech,
                server, content_length, is_wildcard, is_internal, in_subdomains, in_alive, created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(scan_id, canonical_host) DO UPDATE SET
                ip=COALESCE(excluded.ip, assets.ip),
                url=COALESCE(excluded.url, assets.url),
                status_code=COALESCE(excluded.status_code, assets.status_code),
                title=COALESCE(excluded.title, assets.title),
                tech=COALESCE(excluded.tech, assets.tech),
                server=COALESCE(excluded.server, assets.server),
                content_length=COALESCE(excluded.content_length, assets.content_length),
                is_wildcard=COALESCE(excluded.is_wildcard, assets.is_wildcard),
                is_internal=COALESCE(excluded.is_internal, assets.is_internal),
                in_subdomains=MAX(excluded.in_subdomains, assets.in_subdomains),
                in_alive=MAX(excluded.in_alive, assets.in_alive)
        """, (scan_id, h,
              s["ip"] if s else None,
              a["url"] if a else None,
              a["status_code"] if a else None,
              a["title"] if a else None,
              a["tech"] if a else None,
              a["server"] if a else None,
              a["content_length"] if a else None,
              s["is_wildcard"] if s else None,
              s["is_internal"] if s else None,
              1 if s else 0, 1 if a else 0, now))

    # shared_ip: IPs (comma-joined) vistas en más de un host.
    ip_hosts = {}
    for r in db.execute("SELECT canonical_host, ip FROM assets WHERE scan_id=?", (scan_id,)):
        if not r["ip"]:
            continue
        for part in r["ip"].split(","):
            ip = part.strip()
            if ip:
                ip_hosts.setdefault(ip, set()).add(r["canonical_host"])
    shared = {h for hs in ip_hosts.values() if len(hs) > 1 for h in hs}
    db.execute("UPDATE assets SET shared_ip=0 WHERE scan_id=?", (scan_id,))
    for h in shared:
        db.execute("UPDATE assets SET shared_ip=1 WHERE scan_id=? AND canonical_host=?", (scan_id, h))
    db.commit()


# ── Helpers ──

def get_env():
    env = os.environ.copy()
    extra = f"{GO_BIN};{SCOOP_SHIMS}"
    env["PATH"] = extra + ";" + env.get("PATH", "")
    env["JAVA_HOME"] = str(Path.home() / "scoop" / "apps" / "temurin21-jdk" / "current")
    return env


def run_argv(argv, timeout=600):
    """Ejecuta un binario externo SIN shell (shell=False). ÚNICO ejecutor.

    Las entradas controladas por el usuario/objetivo (domain, url, wordlist,
    host, extensiones) se pasan como elementos discretos de la lista, así que
    los metacaracteres de cmd.exe (`"`, `&`, `|`, `;`, backticks, `$()`) no
    pueden romper la línea de comando ni inyectar procesos. Reemplazó por
    completo a run_cmd(shell=True), eliminado para evitar regresiones de
    inyección de comandos.
    """
    try:
        proc = subprocess.run(
            list(argv), shell=False, capture_output=True, text=True,
            timeout=timeout, env=get_env(), encoding="utf-8", errors="replace"
        )
        return proc.stdout + proc.stderr
    except Exception as e:
        return f"Error: {e}"


def _kill_proc_tree(proc):
    """Mata el proceso y sus hijos. En Windows terminate() no mata el árbol,
    así que usamos taskkill /T."""
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           capture_output=True, timeout=10)
        else:
            proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def run_argv_cancel(argv, scan_id=None, timeout=600):
    """run_argv interrumpible: sondea active_scans[scan_id] cada segundo y mata
    el proceso (y su árbol) si el scan fue cancelado o si vence el timeout.

    Devuelve (salida:str, estado) con estado ∈ {ok, cancelled, timeout, error}.
    La salida va a un archivo temporal (no a un pipe) para que herramientas de
    salida grande — waybackurls/gau — no bloqueen por buffer lleno.
    """
    try:
        outf = tempfile.TemporaryFile(mode="w+b")
    except Exception as e:
        return (f"Error: {e}", "error")
    try:
        proc = subprocess.Popen(list(argv), shell=False, stdout=outf,
                                stderr=subprocess.STDOUT, env=get_env())
    except FileNotFoundError:
        outf.close()
        return (f"Error: binario no encontrado: {argv[0]}", "error")
    except Exception as e:
        outf.close()
        return (f"Error: {e}", "error")

    deadline = time.monotonic() + timeout
    status = "ok"
    while True:
        try:
            proc.wait(timeout=1)
            break
        except subprocess.TimeoutExpired:
            if scan_id is not None and active_scans.get(scan_id) == "cancelled":
                _kill_proc_tree(proc)
                status = "cancelled"
                break
            if time.monotonic() > deadline:
                _kill_proc_tree(proc)
                status = "timeout"
                break

    try:
        outf.seek(0)
        data = outf.read().decode("utf-8", errors="replace")
    except Exception:
        data = ""
    finally:
        try:
            outf.close()
        except Exception:
            pass

    # Distinguir "corrió bien con 0 resultados" de "la herramienta falló".
    if status == "ok" and proc.returncode not in (0, None) and not data.strip():
        status = "error"
    return (data, status)


def run_ps(script, args=None):
    """Ejecuta un script PowerShell desde archivo temporal.

    `args` se pasan como elementos discretos a `-File script.ps1 <args>`
    (ArgumentList), así que los valores del usuario entran como parámetros
    vinculados (param(...)) y NO por interpolación de string — sin inyección.
    """
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.ps1', delete=False, encoding='utf-8') as f:
            f.write(script)
            ps_path = f.name
        cmd = ['powershell', '-ExecutionPolicy', 'Bypass', '-File', ps_path]
        if args:
            cmd += [str(a) for a in args]
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=60, env=get_env(),
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
    dns_script = f"""param([string]$d)
$ErrorActionPreference = 'SilentlyContinue'
try {{ $r = Resolve-DnsName $d -Type A -EA Stop; $ips = ($r | Where-Object {{ $_.QueryType -eq 'A' -and $_.Name -eq $d }}).IPAddress; if ($ips) {{ "A=" + ($ips -join ", ") }} }} catch {{}}
try {{ $r = Resolve-DnsName $d -Type AAAA -EA Stop; $ips = ($r | Where-Object {{ $_.QueryType -eq 'AAAA' -and $_.Name -eq $d }}).IPAddress; if ($ips) {{ "AAAA=" + ($ips -join ", ") }} }} catch {{}}
try {{ $r = Resolve-DnsName $d -Type MX -EA Stop; "MX=" + (($r | Where-Object {{ $_.NameExchange }}).NameExchange -join ", ") }} catch {{}}
try {{ $r = Resolve-DnsName $d -Type NS -EA Stop; "NS=" + (($r | Where-Object {{ $_.NameHost }}).NameHost -join ", ") }} catch {{}}
try {{ $r = Resolve-DnsName $d -Type TXT -EA Stop; "TXT=" + (($r | Where-Object {{ $_.Strings }}).Strings -join "; ") }} catch {{}}
try {{ $r = Resolve-DnsName $d -Type CNAME -EA Stop; "CNAME=" + (($r | Where-Object {{ $_.NameHost }}).NameHost -join ", ") }} catch {{}}
try {{ $r = Resolve-DnsName $d -Type SOA -EA Stop; $s = $r | Where-Object {{ $_.PrimaryServer }}; if ($s) {{ "SOA=" + $s.PrimaryServer + " (Serial: " + $s.SerialNumber + ")" }} }} catch {{}}
"""
    dns_out = run_ps(dns_script, args=["-d", domain])
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
        headers_out = run_argv(["curl", "-sI", "-m", "10", "-L", f"{scheme}://{domain}"])
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
    robots_out = run_argv(["curl", "-s", "--max-time", "10", f"{base}/robots.txt"])
    if robots_out and 'user-agent' in robots_out.lower() and '<html' not in robots_out.lower():
        save_info(db, scan_id, "files", "robots.txt", robots_out.strip()[:2000])
        disallowed = re.findall(r'Disallow:\s*(.+)', robots_out, re.IGNORECASE)
        if disallowed:
            save_info(db, scan_id, "files", "Disallow paths", "\n".join(d.strip() for d in disallowed))
        sitemaps = re.findall(r'Sitemap:\s*(.+)', robots_out, re.IGNORECASE)
        if sitemaps:
            save_info(db, scan_id, "files", "Sitemaps", "\n".join(s.strip() for s in sitemaps))

    # ── sitemap.xml ──
    sitemap_out = run_argv(["curl", "-s", "--max-time", "10", f"{base}/sitemap.xml"])
    if sitemap_out and '<?xml' in sitemap_out.lower():
        url_count = len(re.findall(r'<loc>', sitemap_out))
        save_info(db, scan_id, "files", "sitemap.xml", f"{url_count} URLs encontradas")

    # ── Tech detection from HTML ──
    html_out = run_argv(["curl", "-s", "--max-time", "10", "-L", base])
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
        out = run_argv(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "5", f"{base}{path}"])
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
        # ── Filtro anti-falsos-positivos (etiquetas UI / i18n / placeholders) ──
        FALSE_POSITIVE_VALUES = {
            "password", "passwd", "pwd", "contraseña", "contrasena", "passwort",
            "senha", "mot de passe", "your password", "enter password",
            "new password", "confirm password", "current password", "old password",
            "yourpassword", "mypassword", "placeholder", "example", "changeme",
            "null", "undefined", "none", "true", "false", "string", "value",
            "xxxxxxxx", "********",
        }

        def looks_like_real_secret(secret_name, captured_value):
            """Descarta valores que no parecen credenciales reales (labels, i18n)."""
            if captured_value is None:
                return True  # regex sin grupo de captura (p.ej. AKIA...) ya es especifico
            v = captured_value.strip()
            if not v or v.lower() in FALSE_POSITIVE_VALUES:
                return False
            if secret_name in ("Password in Code", "Generic Secret"):
                classes = sum([
                    any(c.islower() for c in v), any(c.isupper() for c in v),
                    any(c.isdigit() for c in v), any(not c.isalnum() for c in v),
                ])
                # un secreto real mezcla tipos de caracter o es largo; una palabra
                # de un solo tipo como "Password"/"Contraseña" se descarta
                if classes < 2 and len(v) < 16:
                    return False
            return True

        found_secrets = set()
        js_files_scanned = 0

        for js_url in sorted(js_urls)[:30]:
            try:
                # js_url proviene del HTML del target (no del allowlist de dominio):
                # gatear SSRF antes de descargar, y ejecutar sin shell.
                ok, _ = _assert_public_target(js_url)
                if not ok:
                    continue
                js_content = run_argv(["curl", "-s", "--max-time", "15", "-L", js_url])
                if not js_content or len(js_content) < 20:
                    continue
                js_files_scanned += 1

                for name, pattern in secret_patterns.items():
                    for match in re.finditer(pattern, js_content):
                        captured = match.group(1) if match.lastindex else None
                        if not looks_like_real_secret(name, captured):
                            continue
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

def run_osint(domain, sid=None):
    def _se(ev, d):
        socketio.emit(ev, d, room=sid)

    results = {"emails": [], "social": [], "meta": [], "wayback": [], "wayback_total": 0,
               "gdorks": [], "gitdorks": [], "gh_repos": [], "gh_code": [], "gh_gists": []}

    _se("osint_status", {"status": "running", "msg": "Descargando pagina..."})

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
        _se("osint_status", {"status": "running", "msg": "Extrayendo emails..."})
        email_pattern = r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
        raw_emails = set(re.findall(email_pattern, html_out))
        skip_ext = {'.png', '.jpg', '.jpeg', '.gif', '.svg', '.css', '.js', '.woff', '.ttf', '.ico'}
        for e in sorted(raw_emails):
            el = e.lower()
            if not any(el.endswith(ext) for ext in skip_ext) and '.' in el.split('@')[1]:
                results["emails"].append(el)

    # 2. Metadata
    if html_out:
        _se("osint_status", {"status": "running", "msg": "Extrayendo metadata..."})
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
    _se("osint_status", {"status": "running", "msg": "Consultando Wayback Machine..."})
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

    # 4. GitHub Recon (live API search)
    gh_headers = {"Accept": "application/vnd.github.v3+json", "User-Agent": "Sharingan-OSINT"}
    try:
        gh_cmd = str(SCOOP_SHIMS / "gh.exe") if (SCOOP_SHIMS / "gh.exe").exists() else "gh"
        gh_token = subprocess.check_output([gh_cmd, "auth", "token"], stderr=subprocess.DEVNULL, text=True).strip()
        if gh_token:
            gh_headers["Authorization"] = f"token {gh_token}"
    except Exception:
        pass

    # 4a. Repos mentioning the domain
    _se("osint_status", {"status": "running", "msg": "Buscando repositorios en GitHub..."})
    try:
        gh_resp = requests.get(
            f"https://api.github.com/search/repositories?q={requests.utils.quote(domain)}&sort=updated&per_page=15",
            headers=gh_headers, timeout=12)
        if gh_resp.status_code == 200:
            for repo in gh_resp.json().get("items", []):
                results["gh_repos"].append({
                    "name": repo.get("full_name", ""),
                    "url": repo.get("html_url", ""),
                    "description": (repo.get("description") or "")[:150],
                    "stars": repo.get("stargazers_count", 0),
                    "forks": repo.get("forks_count", 0),
                    "language": repo.get("language") or "",
                    "updated": (repo.get("updated_at") or "")[:10],
                    "owner_avatar": repo.get("owner", {}).get("avatar_url", ""),
                })
    except Exception:
        pass

    # 4b. Code search for secrets
    _se("osint_status", {"status": "running", "msg": "Buscando secretos en codigo..."})
    secret_queries = [
        ("API Keys / Tokens", f'"{domain}" password OR api_key OR apikey OR secret OR token OR bearer'),
        ("Config Files", f'"{domain}" filename:.env OR filename:.yml OR filename:.config OR filename:.ini'),
        ("AWS Credentials", f'"{domain}" AKIA OR aws_secret_access_key OR AWS_ACCESS_KEY'),
        ("Private Keys", f'"{domain}" "BEGIN RSA PRIVATE KEY" OR "BEGIN EC PRIVATE KEY" OR "BEGIN OPENSSH"'),
        ("DB Connections", f'"{domain}" mysql:// OR postgres:// OR mongodb:// OR redis://'),
        ("OAuth / JWT", f'"{domain}" client_secret OR client_id OR jwt OR oauth'),
        ("Hardcoded Creds", f'"{domain}" password= OR passwd= OR pwd= OR credentials'),
        ("Internal URLs", f'"{domain}" staging OR internal OR dev OR localhost OR 127.0.0.1'),
    ]
    for label, query in secret_queries:
        try:
            code_resp = requests.get(
                f"https://api.github.com/search/code?q={requests.utils.quote(query)}&per_page=5",
                headers=gh_headers, timeout=10)
            if code_resp.status_code == 200:
                code_data = code_resp.json()
                total = code_data.get("total_count", 0)
                items = []
                for item in code_data.get("items", []):
                    items.append({
                        "file": item.get("name", ""),
                        "path": item.get("path", ""),
                        "repo": item.get("repository", {}).get("full_name", ""),
                        "url": item.get("html_url", ""),
                    })
                if total > 0:
                    results["gh_code"].append({
                        "label": label,
                        "query": query,
                        "total": total,
                        "items": items,
                        "search_url": f"https://github.com/search?q={requests.utils.quote(query)}&type=code",
                    })
            time.sleep(2)
        except Exception:
            pass

    # 4c. Gists mentioning the domain
    _se("osint_status", {"status": "running", "msg": "Buscando en GitHub Gists..."})
    try:
        gist_resp = requests.get(
            f"https://api.github.com/search/code?q={requests.utils.quote(domain)}+in:file+language:text&per_page=10",
            headers=gh_headers, timeout=10)
        if gist_resp.status_code == 200:
            for item in gist_resp.json().get("items", []):
                repo_name = item.get("repository", {}).get("full_name", "")
                if "gist" in repo_name.lower() or "snippet" in repo_name.lower():
                    results["gh_gists"].append({
                        "file": item.get("name", ""),
                        "repo": repo_name,
                        "url": item.get("html_url", ""),
                    })
    except Exception:
        pass

    # 5. Google Dorks
    _se("osint_status", {"status": "running", "msg": "Generando Google Dorks..."})
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

    _se("osint_result", results)
    _se("osint_status", {"status": "done", "msg": "OSINT completado"})


@socketio.on("start_osint")
def handle_osint(data):
    domain = data.get("domain", "").strip()
    if not domain:
        return
    threading.Thread(target=run_osint, args=(domain,), kwargs={"sid": request.sid}, daemon=True).start()


# ── User OSINT (username / email lookup) ──

PLATFORM_CHECKS = [
    {"name": "GitHub", "cat": "dev", "url": "https://api.github.com/users/{}", "icon": "🐙"},
    {"name": "GitLab", "cat": "dev", "url": "https://gitlab.com/api/v4/users?username={}", "icon": "🦊", "json_list": True},
    {"name": "Twitter/X", "cat": "social", "url": "https://x.com/{}", "icon": "🐦"},
    {"name": "Instagram", "cat": "social", "url": "https://www.instagram.com/{}/", "icon": "📸"},
    {"name": "TikTok", "cat": "social", "url": "https://www.tiktok.com/@{}", "icon": "🎵"},
    {"name": "Reddit", "cat": "social", "url": "https://www.reddit.com/user/{}/about.json", "icon": "🤖", "json_check": True},
    {"name": "Pinterest", "cat": "social", "url": "https://www.pinterest.com/{}/", "icon": "📌"},
    {"name": "LinkedIn", "cat": "social", "url": "https://www.linkedin.com/in/{}/", "icon": "💼"},
    {"name": "YouTube", "cat": "social", "url": "https://www.youtube.com/@{}", "icon": "🎬"},
    {"name": "Twitch", "cat": "social", "url": "https://www.twitch.tv/{}", "icon": "🟣"},
    {"name": "Steam", "cat": "gaming", "url": "https://steamcommunity.com/id/{}", "icon": "🎮"},
    {"name": "Spotify", "cat": "social", "url": "https://open.spotify.com/user/{}", "icon": "🎧"},
    {"name": "Medium", "cat": "blog", "url": "https://medium.com/@{}", "icon": "📝"},
    {"name": "Dev.to", "cat": "dev", "url": "https://dev.to/api/users/by_username?url={}", "icon": "👨‍💻", "json_check": True},
    {"name": "Keybase", "cat": "security", "url": "https://keybase.io/_/api/1.0/user/lookup.json?usernames={}", "icon": "🔐", "json_check": True},
    {"name": "HackerOne", "cat": "security", "url": "https://hackerone.com/{}", "icon": "🛡"},
    {"name": "Bugcrowd", "cat": "security", "url": "https://bugcrowd.com/{}", "icon": "🐛"},
    {"name": "Docker Hub", "cat": "dev", "url": "https://hub.docker.com/v2/users/{}/", "icon": "🐳", "json_check": True},
    {"name": "npm", "cat": "dev", "url": "https://www.npmjs.com/~{}", "icon": "📦"},
    {"name": "PyPI", "cat": "dev", "url": "https://pypi.org/user/{}/", "icon": "🐍"},
    {"name": "Gravatar", "cat": "social", "url": "https://en.gravatar.com/{}", "icon": "👤"},
    {"name": "About.me", "cat": "social", "url": "https://about.me/{}", "icon": "🏠"},
    {"name": "Flickr", "cat": "social", "url": "https://www.flickr.com/people/{}/", "icon": "📷"},
    {"name": "SoundCloud", "cat": "social", "url": "https://soundcloud.com/{}", "icon": "🔊"},
    {"name": "Patreon", "cat": "social", "url": "https://www.patreon.com/{}", "icon": "💰"},
    {"name": "Bitbucket", "cat": "dev", "url": "https://bitbucket.org/api/2.0/users/{}", "icon": "🪣", "json_check": True},
    {"name": "Replit", "cat": "dev", "url": "https://replit.com/@{}", "icon": "💻"},
    {"name": "Stack Overflow", "cat": "dev", "url": "https://stackoverflow.com/users/?tab=accounts&SearchOn=DisplayName&Search={}", "icon": "📚"},
    {"name": "Telegram", "cat": "social", "url": "https://t.me/{}", "icon": "✈"},
    {"name": "VK", "cat": "social", "url": "https://vk.com/{}", "icon": "🔵"},
    {"name": "Mastodon (mastodon.social)", "cat": "social", "url": "https://mastodon.social/@{}", "icon": "🐘"},
    {"name": "Fiverr", "cat": "social", "url": "https://www.fiverr.com/{}", "icon": "🟢"},
    {"name": "Scribd", "cat": "social", "url": "https://www.scribd.com/{}", "icon": "📖"},
    {"name": "SlideShare", "cat": "social", "url": "https://www.slideshare.net/{}", "icon": "📊"},
    {"name": "Trello", "cat": "social", "url": "https://trello.com/{}", "icon": "📋"},
]

EMAIL_PLATFORM_CHECKS = [
    {"name": "Gravatar", "cat": "social", "icon": "👤", "method": "gravatar"},
    {"name": "GitHub", "cat": "dev", "icon": "🐙", "method": "github_email"},
    {"name": "Spotify", "cat": "social", "icon": "🎧", "method": "spotify"},
    {"name": "Pinterest", "cat": "social", "icon": "📌", "method": "pinterest"},
    {"name": "Flickr", "cat": "social", "icon": "📷", "method": "flickr"},
    {"name": "Duolingo", "cat": "social", "icon": "🦉", "method": "duolingo"},
    {"name": "Chess.com", "cat": "gaming", "icon": "♟", "method": "chess"},
    {"name": "WordPress", "cat": "blog", "icon": "📝", "method": "wordpress"},
    {"name": "Tumblr", "cat": "blog", "icon": "📘", "method": "tumblr"},
    {"name": "Docker Hub", "cat": "dev", "icon": "🐳", "method": "docker"},
    {"name": "Patreon", "cat": "social", "icon": "💰", "method": "patreon"},
    {"name": "Adobe", "cat": "software", "icon": "🎨", "method": "adobe"},
    {"name": "Samsung", "cat": "software", "icon": "📱", "method": "samsung"},
    {"name": "Atlassian", "cat": "dev", "icon": "🔷", "method": "atlassian"},
    {"name": "GitLab", "cat": "dev", "icon": "🦊", "method": "gitlab"},
    {"name": "Twitter/X", "cat": "social", "icon": "🐦", "method": "twitter"},
    {"name": "Instagram", "cat": "social", "icon": "📸", "method": "instagram"},
    {"name": "Discord", "cat": "social", "icon": "💬", "method": "discord"},
    {"name": "Imgur", "cat": "social", "icon": "🖼", "method": "imgur"},
    {"name": "Strava", "cat": "social", "icon": "🏃", "method": "strava"},
    {"name": "Replit", "cat": "dev", "icon": "💻", "method": "replit"},
    {"name": "Scribd", "cat": "social", "icon": "📖", "method": "scribd"},
    {"name": "Zoom", "cat": "software", "icon": "📹", "method": "zoom"},
    {"name": "Microsoft", "cat": "software", "icon": "🪟", "method": "microsoft"},
    {"name": "Apple", "cat": "software", "icon": "🍎", "method": "apple"},
    {"name": "Amazon", "cat": "shopping", "icon": "📦", "method": "amazon"},
    {"name": "eBay", "cat": "shopping", "icon": "🛒", "method": "ebay"},
    {"name": "Booking.com", "cat": "shopping", "icon": "🏨", "method": "booking"},
]


def _check_email_platform(platform, email, results_list, session):
    import hashlib
    method = platform["method"]
    found = False
    profile_url = ""
    extra_info = {}

    try:
        if method == "gravatar":
            email_hash = hashlib.md5(email.lower().strip().encode()).hexdigest()
            resp = session.get(f"https://en.gravatar.com/{email_hash}.json", timeout=8)
            if resp.status_code == 200:
                found = True
                profile_url = f"https://en.gravatar.com/{email_hash}"
                try:
                    data = resp.json()
                    entry = data.get("entry", [{}])[0]
                    extra_info["name"] = entry.get("displayName", "")
                    extra_info["about"] = entry.get("aboutMe", "")[:100] if entry.get("aboutMe") else ""
                    extra_info["location"] = entry.get("currentLocation", "")
                    if entry.get("photos"):
                        extra_info["avatar"] = entry["photos"][0].get("value", "")
                    if entry.get("accounts"):
                        extra_info["linked_accounts"] = [
                            {"platform": a.get("shortname", ""), "url": a.get("url", "")}
                            for a in entry["accounts"][:5]
                        ]
                except Exception:
                    pass

        elif method == "github_email":
            resp = session.get(f"https://api.github.com/search/users?q={email}+in:email", timeout=8,
                               headers={"Accept": "application/vnd.github.v3+json"})
            if resp.status_code == 200:
                data = resp.json()
                if data.get("total_count", 0) > 0:
                    found = True
                    user = data["items"][0]
                    profile_url = user.get("html_url", "")
                    extra_info["username"] = user.get("login", "")
                    extra_info["avatar"] = user.get("avatar_url", "")

        elif method == "spotify":
            resp = session.get("https://spclient.wg.spotify.com/signup/public/v1/account",
                               params={"validate": "1", "email": email}, timeout=8)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if data.get("status") == 20:
                        found = True
                        profile_url = "https://spotify.com"
                except Exception:
                    pass

        elif method == "pinterest":
            resp = session.get(f"https://www.pinterest.com/_ngjs/resource/EmailExistsResource/get/",
                               params={"source_url": "/", "data": json.dumps({"options": {"email": email}})},
                               timeout=8)
            if resp.status_code == 200:
                try:
                    if "resource_response" in resp.text and "true" in resp.text.lower():
                        found = True
                        profile_url = "https://pinterest.com"
                except Exception:
                    pass

        elif method == "flickr":
            resp = session.get(f"https://www.flickr.com/people/{email.split('@')[0]}/", timeout=8)
            if resp.status_code == 200 and "page not found" not in resp.text.lower():
                found = True
                profile_url = f"https://www.flickr.com/people/{email.split('@')[0]}/"

        elif method == "duolingo":
            resp = session.get(f"https://www.duolingo.com/2017-06-30/users?email={email}", timeout=8)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if data.get("users") and len(data["users"]) > 0:
                        found = True
                        user = data["users"][0]
                        extra_info["username"] = user.get("username", "")
                        profile_url = f"https://www.duolingo.com/profile/{user.get('username', '')}"
                except Exception:
                    pass

        elif method == "chess":
            resp = session.get(f"https://www.chess.com/callback/email/available?email={email}", timeout=8)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if data.get("isEmailAvailable") is False:
                        found = True
                        profile_url = "https://chess.com"
                except Exception:
                    pass

        elif method == "wordpress":
            resp = session.post("https://wordpress.com/wp-login.php?action=lostpassword",
                                data={"user_login": email}, timeout=8, allow_redirects=False)
            if resp.status_code == 302 and "check-your-email" in resp.headers.get("Location", ""):
                found = True
                profile_url = "https://wordpress.com"

        elif method == "tumblr":
            resp = session.post("https://www.tumblr.com/api/v2/register/email_available",
                                json={"email": email}, timeout=8)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if not data.get("response", {}).get("available", True):
                        found = True
                        profile_url = "https://tumblr.com"
                except Exception:
                    pass

        elif method == "docker":
            resp = session.post("https://hub.docker.com/v2/users/signup/",
                                json={"email": email, "username": "x" * 30, "password": "x" * 30},
                                timeout=8)
            if resp.status_code in (200, 400):
                body = resp.text.lower()
                if "already" in body or "registered" in body or "exists" in body or "in use" in body:
                    found = True
                    profile_url = "https://hub.docker.com"

        elif method == "patreon":
            resp = session.post("https://www.patreon.com/api/auth/email-check",
                                json={"data": {"email": email}}, timeout=8)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if data.get("data", {}).get("email_exists"):
                        found = True
                        profile_url = "https://patreon.com"
                except Exception:
                    pass

        elif method == "adobe":
            resp = session.post("https://auth.services.adobe.com/signin/v2/users/accounts",
                                json={"username": email}, timeout=8,
                                headers={"Content-Type": "application/json", "x-ims-clientid": "adobedotcom2"})
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if data and len(data) > 0:
                        found = True
                        profile_url = "https://account.adobe.com"
                        if isinstance(data, list) and data:
                            extra_info["auth_type"] = data[0].get("type", "")
                except Exception:
                    pass

        elif method == "samsung":
            resp = session.post("https://account.samsung.com/accounts/v1/MBR/checkEmailID",
                                json={"emailID": email}, timeout=8)
            if resp.status_code == 200 and "exists" in resp.text.lower():
                found = True
                profile_url = "https://account.samsung.com"

        elif method == "atlassian":
            resp = session.post("https://id.atlassian.com/rest/check-username",
                                json={"username": email}, timeout=8,
                                headers={"Content-Type": "application/json"})
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if data.get("valid"):
                        found = True
                        profile_url = "https://id.atlassian.com"
                except Exception:
                    pass

        elif method == "gitlab":
            resp = session.get(f"https://gitlab.com/api/v4/users?search={email}", timeout=8)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if isinstance(data, list) and len(data) > 0:
                        found = True
                        profile_url = data[0].get("web_url", "https://gitlab.com")
                        extra_info["username"] = data[0].get("username", "")
                except Exception:
                    pass

        elif method == "twitter":
            resp = session.get(f"https://api.twitter.com/i/users/email_available.json?email={email}", timeout=8)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if data.get("taken"):
                        found = True
                        profile_url = "https://x.com"
                except Exception:
                    pass

        elif method == "instagram":
            resp = session.post("https://www.instagram.com/api/v1/web/accounts/web_create_ajax/check_email/",
                                data={"email": email}, timeout=8,
                                headers={"X-Requested-With": "XMLHttpRequest"})
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if data.get("email_is_taken"):
                        found = True
                        profile_url = "https://instagram.com"
                except Exception:
                    pass

        elif method == "discord":
            resp = session.post("https://discord.com/api/v9/auth/register",
                                json={"email": email, "username": "x" * 20, "password": "x" * 20},
                                timeout=8)
            if resp.status_code in (200, 400):
                body = resp.text.lower()
                if "already" in body or "registered" in body or "in use" in body:
                    found = True
                    profile_url = "https://discord.com"

        elif method == "imgur":
            resp = session.get(f"https://imgur.com/signin/ajax_email_check?email={email}", timeout=8)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if data.get("data", {}).get("available") is False:
                        found = True
                        profile_url = "https://imgur.com"
                except Exception:
                    pass

        elif method == "strava":
            resp = session.post("https://www.strava.com/api/v3/email_check",
                                data={"email": email}, timeout=8)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if data.get("exists"):
                        found = True
                        profile_url = "https://strava.com"
                except Exception:
                    pass

        elif method == "replit":
            resp = session.post("https://replit.com/graphql",
                                json={"query": f'query {{ userByEmail(email: "{email}") {{ username }} }}'},
                                timeout=8)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    user = data.get("data", {}).get("userByEmail")
                    if user:
                        found = True
                        extra_info["username"] = user.get("username", "")
                        profile_url = f"https://replit.com/@{user.get('username', '')}"
                except Exception:
                    pass

        elif method == "scribd":
            resp = session.post("https://www.scribd.com/login",
                                data={"login_or_email": email, "login_password": "x" * 10},
                                timeout=8, allow_redirects=False)
            if resp.status_code in (200, 302):
                body = resp.text.lower() if resp.status_code == 200 else ""
                if "incorrect password" in body or "wrong password" in body or resp.status_code == 302:
                    found = True
                    profile_url = "https://scribd.com"

        elif method == "zoom":
            resp = session.post("https://us04web.zoom.us/api/v1/account/check_email",
                                data={"email": email}, timeout=8)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if data.get("existed"):
                        found = True
                        profile_url = "https://zoom.us"
                except Exception:
                    pass

        elif method == "microsoft":
            resp = session.post("https://login.live.com/GetCredentialType.srf",
                                json={"username": email}, timeout=8)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if data.get("IfExistsResult") == 0:
                        found = True
                        profile_url = "https://account.microsoft.com"
                except Exception:
                    pass

        elif method == "apple":
            resp = session.post("https://iforgot.apple.com/password/verify/appleid",
                                json={"id": email}, timeout=8,
                                headers={"Content-Type": "application/json",
                                          "Accept": "application/json"})
            if resp.status_code == 200:
                found = True
                profile_url = "https://appleid.apple.com"

        elif method == "amazon":
            resp = session.post("https://www.amazon.com/ap/signin",
                                data={"email": email, "create": "0"},
                                timeout=8, allow_redirects=False)
            if resp.status_code in (200, 302):
                body = resp.text.lower() if resp.status_code == 200 else ""
                if "password" in body or resp.status_code == 302:
                    found = True
                    profile_url = "https://amazon.com"

        elif method == "ebay":
            resp = session.post("https://signin.ebay.com/ws/eBayISAPI.dll?SignIn",
                                data={"userid": email}, timeout=8, allow_redirects=False)
            if resp.status_code in (200, 302):
                body = resp.text.lower() if resp.status_code == 200 else ""
                if "password" in body or "enter your password" in body:
                    found = True
                    profile_url = "https://ebay.com"

        elif method == "booking":
            resp = session.post("https://account.booking.com/api/identity/email-check",
                                json={"email": email}, timeout=8)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if data.get("matching_credentials"):
                        found = True
                        profile_url = "https://booking.com"
                except Exception:
                    pass

    except Exception:
        pass

    if found:
        result = {
            "platform": platform["name"],
            "url": profile_url or "#",
            "icon": platform["icon"],
            "cat": platform.get("cat", "other"),
        }
        if extra_info:
            result["extra"] = extra_info
        results_list.append(result)


def _check_platform(platform, username, results_list, session):
    url = platform["url"].format(username)
    try:
        resp = session.get(url, timeout=8, allow_redirects=True)
        found = False

        if platform.get("json_list"):
            try:
                data = resp.json()
                found = isinstance(data, list) and len(data) > 0
            except Exception:
                pass
        elif platform.get("json_check"):
            found = resp.status_code == 200
            try:
                resp.json()
            except Exception:
                found = False
        else:
            found = resp.status_code == 200
            if found:
                not_found_signals = [
                    "page not found", "user not found", "this page isn",
                    "doesn't exist", "404", "sorry, this page",
                    "this account doesn", "couldn't find", "no results",
                    "not exist", "pagina no encontrada",
                ]
                body_lower = resp.text[:5000].lower()
                title_match = re.search(r'<title[^>]*>([^<]+)</title>', body_lower)
                check_text = (title_match.group(1) if title_match else "") + body_lower[:2000]
                if any(sig in check_text for sig in not_found_signals):
                    found = False

        if found:
            result = {
                "platform": platform["name"],
                "url": url,
                "icon": platform["icon"],
                "cat": platform.get("cat", "other"),
            }
            if platform["name"] == "GitHub" and resp.status_code == 200:
                try:
                    gh = resp.json()
                    result["extra"] = {
                        "name": gh.get("name", ""),
                        "bio": gh.get("bio", ""),
                        "location": gh.get("location", ""),
                        "company": gh.get("company", ""),
                        "repos": gh.get("public_repos", 0),
                        "followers": gh.get("followers", 0),
                        "avatar": gh.get("avatar_url", ""),
                        "created": gh.get("created_at", "")[:10],
                    }
                except Exception:
                    pass
            results_list.append(result)
    except Exception:
        pass


def run_user_osint(query, mode, sid=None):
    def _se(ev, d):
        socketio.emit(ev, d, room=sid)

    results = {"query": query, "mode": mode, "found": [], "breaches": [], "emails_from_username": [],
               "dorks": [], "total_checked": 0}

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})

    if mode == "username":
        _se("user_osint_status", {"status": "running", "msg": f"Buscando '{query}' en {len(PLATFORM_CHECKS)} plataformas..."})

        threads = []
        found_list = []
        for plat in PLATFORM_CHECKS:
            t = threading.Thread(target=_check_platform, args=(plat, query, found_list, session), daemon=True)
            threads.append(t)
            t.start()

        for i, t in enumerate(threads):
            t.join(timeout=12)
            if (i + 1) % 10 == 0 or i == len(threads) - 1:
                _se("user_osint_status", {
                    "status": "running",
                    "msg": f"Verificadas {i + 1}/{len(PLATFORM_CHECKS)} plataformas... ({len(found_list)} encontradas)"
                })

        results["found"] = sorted(found_list, key=lambda x: x["platform"])
        results["total_checked"] = len(PLATFORM_CHECKS)

        _se("user_osint_status", {"status": "running", "msg": "Generando dorks de usuario..."})
        user_dorks = [
            ("Email en Google", f'"{query}" "@gmail.com" OR "@hotmail.com" OR "@yahoo.com" OR "@outlook.com"'),
            ("Perfiles publicos", f'"{query}" site:linkedin.com OR site:facebook.com OR site:twitter.com OR site:instagram.com'),
            ("Documentos", f'"{query}" filetype:pdf OR filetype:doc OR filetype:xls'),
            ("Foros", f'"{query}" site:reddit.com OR site:stackoverflow.com OR site:quora.com'),
            ("Pastes", f'"{query}" site:pastebin.com OR site:ghostbin.com OR site:paste.ee'),
            ("Leaks / Dumps", f'"{query}" password OR leaked OR dump OR breach'),
            ("CV / Resume", f'"{query}" resume OR curriculum OR "curriculum vitae" filetype:pdf'),
            ("Code Repos", f'"{query}" site:github.com OR site:gitlab.com OR site:bitbucket.org'),
        ]
        for name, q in user_dorks:
            results["dorks"].append({"name": name, "query": q, "link": f"https://www.google.com/search?q={requests.utils.quote(q)}"})

    elif mode == "email":
        _se("user_osint_status", {"status": "running", "msg": f"Analizando email: {query}"})

        email_local = query.split("@")[0] if "@" in query else query
        email_domain = query.split("@")[1] if "@" in query else ""

        _se("user_osint_status", {"status": "running", "msg": f"Verificando email en {len(EMAIL_PLATFORM_CHECKS)} servicios..."})
        threads = []
        found_list = []
        for plat in EMAIL_PLATFORM_CHECKS:
            t = threading.Thread(target=_check_email_platform, args=(plat, query, found_list, session), daemon=True)
            threads.append(t)
            t.start()
        for i, t in enumerate(threads):
            t.join(timeout=15)
            if (i + 1) % 8 == 0 or i == len(threads) - 1:
                _se("user_osint_status", {
                    "status": "running",
                    "msg": f"Verificados {i + 1}/{len(EMAIL_PLATFORM_CHECKS)} servicios... ({len(found_list)} con cuenta)"
                })
        results["found"] = sorted(found_list, key=lambda x: x["platform"])
        results["total_checked"] = len(EMAIL_PLATFORM_CHECKS)

        _se("user_osint_status", {"status": "running", "msg": "Buscando breaches conocidos..."})
        try:
            hibp_resp = session.get(f"https://haveibeenpwned.com/unifiedsearch/{query}", timeout=10,
                                    headers={"User-Agent": "Sharingan-OSINT"})
            if hibp_resp.status_code == 200:
                try:
                    hibp = hibp_resp.json()
                    for b in hibp.get("Breaches", []):
                        results["breaches"].append({
                            "name": b.get("Name", ""),
                            "domain": b.get("Domain", ""),
                            "date": b.get("BreachDate", ""),
                            "count": b.get("PwnCount", 0),
                            "data": ", ".join(b.get("DataClasses", [])[:5]),
                        })
                except Exception:
                    pass
        except Exception:
            pass

        _se("user_osint_status", {"status": "running", "msg": "Generando dorks de email..."})
        email_dorks = [
            ("Menciones del email", f'"{query}"'),
            ("Registros publicos", f'"{query}" site:linkedin.com OR site:facebook.com'),
            ("Documentos con email", f'"{query}" filetype:pdf OR filetype:doc OR filetype:xls'),
            ("Pastes con email", f'"{query}" site:pastebin.com OR site:ghostbin.com'),
            ("Leaks / Breaches", f'"{query}" leaked OR breach OR dump OR password'),
            ("Foros", f'"{query}" site:reddit.com OR site:stackoverflow.com OR site:quora.com'),
            ("Code con email", f'"{query}" site:github.com OR site:gitlab.com'),
            ("Listas publicas", f'"{query}" list OR mailing OR newsletter OR subscriber'),
        ]
        if email_domain:
            email_dorks.append(("Otros emails del dominio", f'"@{email_domain}" -"{query}"'))
        for name, q in email_dorks:
            results["dorks"].append({"name": name, "query": q, "link": f"https://www.google.com/search?q={requests.utils.quote(q)}"})

    _se("user_osint_result", results)
    _se("user_osint_status", {"status": "done", "msg": "Busqueda completada"})


@socketio.on("start_user_osint")
def handle_user_osint(data):
    query = data.get("query", "").strip()
    mode = data.get("mode", "username")
    if not query:
        return
    threading.Thread(target=run_user_osint, args=(query, mode), kwargs={"sid": request.sid}, daemon=True).start()


# ── Standalone Fuzzing ──

BUILTIN_WORDLIST = [
    "admin","administrator","login","wp-admin","wp-login.php","dashboard",
    "panel","console","api","api/v1","api/v2","graphql","swagger","swagger-ui",
    "docs","doc","documentation","help","faq",
    ".env",".git/HEAD",".git/config",".gitignore",".htaccess",".htpasswd",
    "wp-config.php","config.php","configuration.php","settings.php",
    "web.config","robots.txt","sitemap.xml","crossdomain.xml",
    "phpinfo.php","info.php","test.php","server-status","server-info",
    "backup","backups","bak","old","temp","tmp","test",
    "db","database","dump","sql",
    "uploads","upload","files","images","img","media","assets",
    "static","css","js","fonts","includes","inc",
    "cgi-bin","bin","scripts",
    "register","signup","signin","logout","forgot","reset",
    "profile","account","settings","config","setup","install",
    "debug","trace","log","logs","error","errors",
    "rest","swagger.json","api-docs","openapi.json","v1","v2",
    "health","status","ping","users","user","posts","search",
    "phpmyadmin","pma","adminer","wp-content","wp-includes",
    ".well-known","security.txt",
    "vendor","node_modules","package.json","composer.json",
    "xmlrpc.php","readme.html","license.txt","changelog.txt",
    "secret","private","internal","staging","dev","beta",
    "manager","portal","webmail","mail","email","cpanel",
    "shell","cmd","command","exec","run","system",
    "filemanager","editor","ide","terminal",
]


def find_wordlist():
    candidates = [
        Path.home() / "wordlists" / "common.txt",
        Path(r"C:\SecLists\Discovery\Web-Content\common.txt"),
        Path.home() / "SecLists" / "Discovery" / "Web-Content" / "common.txt",
    ]
    try:
        import importlib.util
        spec = importlib.util.find_spec("dirsearch")
        if spec and spec.origin:
            ds_path = Path(spec.origin).parent / "db" / "dicc.txt"
            if ds_path.exists():
                candidates.insert(0, ds_path)
    except Exception:
        pass
    for p in candidates:
        if p.exists():
            return str(p)
    return None


def categorize_path(path, redirect):
    path_lower = path.lower()
    file_exts = ['.php','.asp','.aspx','.jsp','.html','.htm','.js','.css',
                 '.txt','.xml','.json','.yml','.yaml','.env','.bak','.sql',
                 '.log','.zip','.tar','.gz','.config','.ini','.pdf','.doc']
    if any(path_lower.endswith(ext) for ext in file_exts):
        return "file"
    if redirect:
        return "redirect"
    return "directory"


# ─────────────────────────────────────────────────────────────────────────────
#  Inteligencia de fuzzing (SSRF gate, soft-404 baseline, WAF, stack, interés)
# ─────────────────────────────────────────────────────────────────────────────

import hashlib as _hashlib
import ipaddress as _ipaddress
from urllib.parse import urlparse as _urlparse

INTEREST_RANK = {"critical": 0, "high": 1, "medium": 2, "info": 3}

# Rutas/archivos que, si existen, son hallazgos de alto valor en bug bounty.
# El objetivo es que un 200 en /.env no se pierda entre cientos de 200 de /assets.
_HV_CRITICAL = [
    ".env", ".git/config", ".git/head", ".git/", ".svn/", ".hg/",
    "actuator/env", "actuator/heapdump", "actuator/beans", "actuator/configprops",
    ".htpasswd", "id_rsa", ".aws/credentials", "docker-compose.yml",
    "wp-config.php", "config.php", "configuration.php", "settings.py",
]
_HV_HIGH = [
    ".bak", ".sql", ".old", ".backup", "backup", "dump", "phpinfo",
    "web.config", ".htaccess", "server-status", "server-info",
    "actuator", "telescope", "horizon", "_ignition", "elmah.axd", "trace.axd",
    ".git", ".ds_store", "credentials", "secret", ".pem", ".key",
]
_HV_MEDIUM = [
    "admin", "manager", "panel", "console", "dashboard", "phpmyadmin",
    "adminer", "swagger", "openapi", "api-docs", "redoc", "graphql",
    "debug", "install", "setup", "login", "cpanel", "webmail",
]


def classify_interest(path, status, length):
    """Devuelve (severidad, razón) para priorizar hallazgos jugosos.

    Ojo: esto NO se usa para descartar nada; solo para re-ordenar y marcar.
    Un /backup público legítimo saldrá como 'high' pero igual se muestra.
    """
    p = (path or "").lower().lstrip("/")
    if status in (401, 403):
        # Protegido = probablemente vale la pena; marcarlo pero sin inflar severidad.
        base = "medium"
    else:
        base = "info"
    for kw in _HV_CRITICAL:
        if kw in p:
            return "critical", f"recurso sensible expuesto ({kw})"
    for kw in _HV_HIGH:
        if kw in p:
            return "high", f"posible exposición ({kw})"
    for kw in _HV_MEDIUM:
        if kw in p:
            sev = "high" if status and 200 <= status < 300 else "medium"
            return sev, f"superficie administrativa/documentación ({kw})"
    if status in (401, 403):
        return "medium", f"acceso restringido ({status}) — candidato a bypass/auth"
    if status and 500 <= status < 600:
        return "medium", f"error del servidor ({status}) — posible fuga de info"
    return base, ""


# ─────────────────────────────────────────────────────────────────────────────
#  Motor de validación central — taxonomía verificado/probable/FP/no-concluyente
# ─────────────────────────────────────────────────────────────────────────────
# Principio: no confiar ciegamente en la herramienta. Cada hallazgo lleva un
# veredicto + evidencia, para que el analista entienda POR QUÉ se clasificó así.
VALIDATION_RANK = {"verified": 0, "probable": 1, "inconclusive": 2, "false_positive": 3}


def classify_discovery(status, has_distinct_body, httpx_likely_real=None):
    """Veredicto para un hallazgo de descubrimiento (dir/archivo) que YA pasó
    el filtro de catch-all. Señales: status, si tenemos cuerpo distinto del
    baseline (modo nativo), y el veredicto de httpx (likely_real) si existe.
    """
    if httpx_likely_real is True:
        return "verified", "httpx: contenido único, distinto del catch-all"
    if httpx_likely_real is False:
        return "false_positive", "httpx: comparte fingerprint con el catch-all"
    if status is None or status == 0:
        return "inconclusive", "sin respuesta / timeout"
    if 200 <= status < 300:
        if has_distinct_body:
            return "verified", "200 con cuerpo distinto del catch-all calibrado"
        return "probable", "200 (sin cuerpo verificado — confirmar con httpx)"
    if status in (401, 403):
        return "probable", f"recurso protegido ({status}), distinto del catch-all"
    if status in (301, 302, 303, 307, 308):
        return "probable", "redirect distinto del catch-all"
    if 500 <= status < 600:
        return "probable", f"error de servidor ({status})"
    return "inconclusive", f"status {status}"


def classify_vuln(severity, matched_at=None):
    """nuclei/nikto son reportes de herramienta: 'probable' por defecto (no
    re-confirmados). info → inconclusive. La verificación activa (re-request)
    puede elevar a 'verified' en el futuro."""
    sev = (severity or "").lower()
    if sev in ("critical", "high", "medium", "low"):
        return "probable", f"template {sev} reportado por nuclei (sin re-confirmar)"
    return "inconclusive", "severidad info/desconocida"


def validation_badge_rank(v):
    return VALIDATION_RANK.get(v or "probable", 1)


# ── Resolución DNS / wildcard / scope (#7) ──────────────────────────────────
def _in_scope(name, domain):
    """Scope anclado por sufijo: 'name' debe SER el dominio o un subdominio real
    de él. Reemplaza el 'domain in name' (substring) que aceptaba
    'notexample.com' o 'example.com.evil.net' como in-scope."""
    name = (name or "").strip().lower().rstrip(".")
    domain = (domain or "").strip().lower().rstrip(".")
    return bool(name) and (name == domain or name.endswith("." + domain))


def _resolve_host(host):
    """Devuelve el set de IPs (A/AAAA) del host, o set vacío si NXDOMAIN/error."""
    try:
        infos = _socket.getaddrinfo(host, None, proto=_socket.IPPROTO_TCP)
        return {ai[4][0] for ai in infos}
    except Exception:
        return set()


def _ips_internal(ips):
    """True si ALGUNA IP es loopback/privada/link-local/reservada (SSRF)."""
    for a in ips:
        try:
            ip = _ipaddress.ip_address(a)
        except ValueError:
            continue
        if (ip.is_loopback or ip.is_private or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            return True
    return False


def detect_wildcard_dns(domain):
    """Resuelve 3 etiquetas aleatorias inexistentes bajo el dominio. Si resuelven
    (misma IP o no), la zona tiene wildcard DNS → devolvemos el set de IPs
    wildcard para descartar subdominios fantasma. Set vacío = sin wildcard."""
    import random, string
    wildcard_ips = set()
    hits = 0
    for _ in range(3):
        label = "".join(random.choices(string.ascii_lowercase + string.digits, k=20))
        ips = _resolve_host(f"{label}.{domain}")
        if ips:
            hits += 1
            wildcard_ips |= ips
    # Al menos 2 de 3 etiquetas aleatorias resolvieron → es wildcard.
    return wildcard_ips if hits >= 2 else set()


# ── SSRF gate ──────────────────────────────────────────────────────────────
# Evita que el tool se use como proxy SSRF (p.ej. 169.254.169.254, localhost,
# redes internas). Por defecto bloquea destinos privados; para apuntar a un dev
# local a propósito, definir SHARINGAN_ALLOW_PRIVATE=1 o listar hosts en
# SHARINGAN_ALLOW (coma-separado).
def _assert_public_target(url):
    try:
        u = _urlparse(url if "://" in url else "https://" + url)
    except Exception:
        return False, "URL inválida"
    if u.scheme not in ("http", "https"):
        return False, f"esquema no permitido: {u.scheme or '(vacío)'}"
    host = u.hostname
    if not host:
        return False, "sin hostname"
    # Rechazar metacaracteres de control o espacios en el host.
    if any(c.isspace() for c in host) or any(c in host for c in '"\'`\\'):
        return False, "hostname con caracteres inválidos"

    allow_private = os.environ.get("SHARINGAN_ALLOW_PRIVATE", "") == "1"
    allowlist = {h.strip().lower() for h in os.environ.get("SHARINGAN_ALLOW", "").split(",") if h.strip()}
    if host.lower() in allowlist or allow_private:
        return True, ""

    # Resolver TODAS las direcciones (defensa anti DNS-rebinding) y rechazar
    # si alguna es loopback/privada/link-local/reservada.
    try:
        infos = _socket.getaddrinfo(host, u.port or (443 if u.scheme == "https" else 80),
                                    proto=_socket.IPPROTO_TCP)
        addrs = {ai[4][0] for ai in infos}
    except Exception as e:
        return False, f"no resuelve: {e}"
    if not addrs:
        return False, "no resuelve a ninguna IP"
    for a in addrs:
        try:
            ip = _ipaddress.ip_address(a)
        except ValueError:
            return False, f"IP inválida: {a}"
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            return False, (f"{host} resuelve a {a} (interna/reservada). "
                           f"Usá SHARINGAN_ALLOW_PRIVATE=1 para permitirlo.")
    return True, ""


# ── WAF detection (portado de smart_path_fuzzer_v2) ──────────────────────────
WAF_HEADERS = {
    "cloudflare": ["cf-ray", "cf-cache-status"],
    "akamai":     ["x-akamai-transformed", "akamai-origin-hop"],
    "sucuri":     ["x-sucuri-id", "x-sucuri-cache"],
    "incapsula":  ["x-iinfo"],
    "cloudfront": ["x-amz-cf-pop", "x-amz-cf-id"],
}
WAF_BODY_PATTERNS = [
    "access denied", "blocked by cloudflare", "firewall", "security check",
    "ddos protection", "ray id:", "incapsula incident", "attention required",
]


def _waf_cfg(name):
    if name == "cloudflare":
        return {"waf": "cloudflare", "concurrency": 5, "delay": (0.5, 2.0)}
    if name == "akamai":
        return {"waf": "akamai", "concurrency": 3, "delay": (1.0, 3.0)}
    return {"waf": name, "concurrency": 10, "delay": (0.1, 0.5)}


def detect_waf(base_url, session):
    try:
        r = session.get(base_url + "/", timeout=8, allow_redirects=False,
                        headers={"User-Agent": "Mozilla/5.0"}, verify=False)
        hl = {k.lower(): (v or "").lower() for k, v in r.headers.items()}
        bl = r.text[:600].lower()
        for name, hdrs in WAF_HEADERS.items():
            if any(h in hl for h in hdrs):
                return _waf_cfg(name)
        if any(p in bl for p in WAF_BODY_PATTERNS):
            return _waf_cfg("generic")
    except Exception:
        pass
    return {"waf": None, "concurrency": 30, "delay": (0, 0)}


# ── Stack fingerprint (portado de smart_path_fuzzer_v2) ──────────────────────
STACK_SIGNATURES = {
    "spring_boot": {
        "headers": [],
        "body_patterns": ['"timestamp"', '"status"', '"error"', '"path"'],
        "extra_words": [
            "actuator", "actuator/health", "actuator/env", "actuator/beans",
            "actuator/metrics", "actuator/info", "actuator/loggers",
            "actuator/threaddump", "actuator/heapdump", "actuator/mappings",
            "actuator/configprops", "management/health",
        ],
    },
    "django": {
        "headers": [("x-frame-options", "sameorigin")],
        "body_patterns": ["csrf verification failed", "csrfmiddlewaretoken"],
        "extra_words": ["admin/", "admin/login", "api-auth/", "__debug__/", "static/admin/"],
    },
    "laravel": {
        "headers": [("set-cookie", "laravel_session")],
        "body_patterns": ["laravel", "illuminate"],
        "extra_words": ["telescope", "horizon", "nova", "_ignition/health-check",
                        "api/user", "sanctum/csrf-cookie", ".env"],
    },
    "express": {
        "headers": [("x-powered-by", "express")],
        "body_patterns": ["cannot get", "cannot post"],
        "extra_words": ["api/", "api/v1/", "api/v2/"],
    },
    "dotnet": {
        "headers": [("x-powered-by", "asp.net"), ("x-aspnet-version", None)],
        "body_patterns": ["asp.net", "server error in"],
        "extra_words": ["elmah.axd", "trace.axd", "webresource.axd",
                        "app_offline.htm", "web.config", "api/values"],
    },
    "fastapi": {
        "headers": [],
        "body_patterns": ['"detail":', '"detail": "not found"'],
        "extra_words": ["docs", "redoc", "openapi.json"],
    },
    "flask": {
        "headers": [("server", "werkzeug")],
        "body_patterns": ["werkzeug"],
        "extra_words": ["api/", "console"],
    },
}


def fingerprint_stack(base_url, session):
    try:
        r = session.get(base_url + "/___probe_stack___", timeout=8, allow_redirects=False,
                        headers={"User-Agent": "Mozilla/5.0"}, verify=False)
        hl = {k.lower(): (v or "").lower() for k, v in r.headers.items()}
        bl = r.text[:1000].lower()
        for name, sig in STACK_SIGNATURES.items():
            for hdr, val in sig["headers"]:
                if hdr in hl and (val is None or val in hl[hdr]):
                    return name, sig["extra_words"]
            if sum(1 for p in sig["body_patterns"] if p.lower() in bl) >= 2:
                return name, sig["extra_words"]
    except Exception:
        pass
    return None, []


# ── Baseline soft-404 / catch-all ────────────────────────────────────────────
# Reemplaza el "catch_all_size" único por una firma por (profundidad, extensión)
# basada en status + length + md5(body[:512]). Resuelve el bug de calib_status
# (un 404 aleatorio ya no desactiva todo el filtro) y los catch-all dinámicos
# que reflejan el path (cada respuesta cambia de tamaño pero comparte estructura).

def _body_hash(content):
    return _hashlib.md5(content[:512]).hexdigest()


def _rand_token(n):
    import random, string
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _depth_bucket(path):
    return min(path.strip("/").count("/"), 2)


def get_baseline(base_url, session, extensions=None):
    """Sondea rutas inexistentes en varias profundidades y extensiones.

    Devuelve dict: signos[(depth_bucket, ext)] = lista de firmas
    {status, length, body_hash, location}. Cada firma representa una respuesta
    catch-all observada para esa clase de ruta.
    """
    extensions = extensions or []
    signatures = {}

    def probe(path_frag, ext):
        try:
            r = session.get(f"{base_url}/{path_frag}", timeout=8, allow_redirects=False,
                            headers={"User-Agent": "Mozilla/5.0"}, verify=False)
            key = (_depth_bucket(path_frag), ext)
            sig = {
                "status": r.status_code,
                "length": len(r.content),
                "body_hash": _body_hash(r.content),
                "location": r.headers.get("Location", ""),
            }
            signatures.setdefault(key, []).append(sig)
        except Exception:
            pass

    # Tokens de longitud variable a profundidad 1 y 2 (detecta catch-all que
    # reflejan el path y cambian de tamaño según su largo).
    for n in (6, 16, 28):
        probe(_rand_token(n), "")
    for n in (10, 20):
        t = _rand_token(n)
        probe(f"{t}/{_rand_token(8)}", "")
    # Un sondeo por extensión solicitada (el soft-404 de /x.php puede diferir).
    for ext in extensions[:6]:
        probe(f"{_rand_token(14)}.{ext}", ext)

    return signatures


def is_baseline(signatures, path, status, length, body_hash, location):
    """True si (status, length/hash) coincide con un catch-all de SU MISMO status.

    La comparación es por status: si las rutas aleatorias de calibración NO
    devolvieron este status, no hay baseline para él y la respuesta se considera
    real. De ahí emerge la regla de "no filtrar 401/403" en el caso normal
    (un sitio sano responde 404 a lo inexistente, nunca 403), PERO en un target
    que hace 403 a todo (WAF), ese 403 SÍ es el catch-all y se filtra —
    manteniendo solo los 403 cuyo cuerpo difiere del baseline (recurso real
    detrás del WAF). body_hash vacío (ffuf, que no da cuerpo) cae al margen de
    tamaño.
    """
    last = path.rsplit("/", 1)[-1]
    ext = last.rsplit(".", 1)[-1].lower() if "." in last else ""
    candidates = signatures.get((_depth_bucket(path), ext))
    if not candidates:
        candidates = [s for sigs in signatures.values() for s in sigs]
    same_status = [s for s in candidates if s["status"] == status]
    if not same_status:
        return False
    for sig in same_status:
        if status in (301, 302, 303, 307, 308):
            if location and sig["location"] and location == sig["location"]:
                return True
            continue
        if body_hash and body_hash == sig["body_hash"]:
            return True
        if abs(length - sig["length"]) < 32:
            return True
    return False


def _build_native_paths(wordlist_path, extensions, extra_words, max_paths):
    """Construye la lista de rutas para el modo nativo: lee la wordlist real
    (antes se ignoraba), agrega palabras del stack y variantes con extensión."""
    base = []
    if wordlist_path and Path(wordlist_path).exists():
        try:
            for line in Path(wordlist_path).read_text(encoding="utf-8", errors="replace").splitlines():
                w = line.strip()
                if w and not w.startswith("#"):
                    base.append(w.lstrip("/"))
        except Exception:
            base = []
    if not base:
        base = BUILTIN_WORDLIST[:]
    if extra_words:
        base = list(dict.fromkeys(extra_words + base))

    paths = list(dict.fromkeys(base))
    if extensions:
        with_ext = []
        for word in paths[:400]:
            if "." in word.rsplit("/", 1)[-1]:
                continue
            for ext in extensions:
                with_ext.append(f"{word}.{ext}")
        paths = list(dict.fromkeys(paths + with_ext))

    truncated = False
    if len(paths) > max_paths:
        paths = paths[:max_paths]
        truncated = True
    return paths, truncated


def run_fuzzing(url, extensions, threads, wordlist_path,
                scan_id=None, phase=None, headers=None, max_depth=1,
                emit_live=True, db=None, sid=None):
    import random as _random, string as _string, shutil as _shutil, threading as _threading
    from concurrent.futures import ThreadPoolExecutor, as_completed

    MAX_NATIVE_PATHS = 1500
    MAX_RECURSE_DIRS = 25
    REQ_BUDGET = 15000

    def emit(ev, payload):
        # En FASE 6 (emit_live=False) no inundamos el panel standalone.
        # room=sid: solo al cliente que lanzó el fuzz (evita cross-client bleed).
        if emit_live:
            socketio.emit(ev, payload, room=sid)

    sid = _threading.get_ident()
    active_fuzz[sid] = "running"
    results = {"found": [], "total_requests": 0, "method": "", "filtered_count": 0,
               "waf": None, "stack": None, "scan_id": scan_id}

    url = url.rstrip('/')
    extensions = [e for e in (extensions or []) if re.fullmatch(r"[A-Za-z0-9]{1,8}", e)]
    headers = headers or {}
    base_headers = {"User-Agent": "Mozilla/5.0"}
    base_headers.update({k: v for k, v in headers.items() if isinstance(k, str) and isinstance(v, str)})

    emit("fuzz_status", {"status": "running", "msg": "Preparando fuzzing..."})

    use_ffuf = "ffuf" in run_argv(["ffuf", "-V"], timeout=8).lower()

    tmpdir = Path(tempfile.mkdtemp(prefix="sharingan-fuzz-"))

    # Sesión de calibración (reusa conexión para WAF/stack/baseline)
    calib_sess = requests.Session()
    calib_sess.headers.update(base_headers)
    calib_sess.verify = False

    # ── WAF detection → concurrencia adaptativa ──
    emit("fuzz_status", {"status": "running", "msg": "Detectando WAF / stack / catch-all..."})
    waf = detect_waf(url, calib_sess)
    # El clamp SOLO aplica si hay WAF positivamente identificado; un target
    # limpio conserva los hilos del usuario (detect_waf devuelve concurrency=30
    # por defecto y no queremos estrangular sitios sin WAF).
    eff_threads = int(threads) if waf["waf"] is None else min(int(threads), waf["concurrency"])
    delay_cfg = waf["delay"]
    results["waf"] = waf["waf"]

    # ── Stack fingerprint → rutas de alto valor por framework ──
    stack, extra_words = fingerprint_stack(url, calib_sess)
    results["stack"] = stack

    info_bits = []
    if waf["waf"]:
        info_bits.append(f"WAF {waf['waf']} → {eff_threads} hilos")
    if stack:
        info_bits.append(f"Stack {stack} (+{len(extra_words)} rutas)")
    if info_bits:
        emit("fuzz_status", {"status": "running", "msg": " | ".join(info_bits)})

    # Conexión de persistencia (propia del hilo si es standalone)
    own_db = False
    pdb = db
    if pdb is None and scan_id is not None:
        pdb = get_db()
        own_db = True

    def rank_key(x):
        return (INTEREST_RANK.get(x.get("interest", "info"), 3), x.get("status", 0), x.get("path", ""))

    # ───────────────────────── ffuf (shell=False) ─────────────────────────
    if use_ffuf and wordlist_path:
        results["method"] = "ffuf"
        emit("fuzz_status", {"status": "running", "msg": "Ejecutando ffuf..."})

        # Si el stack aportó rutas extra, se escriben a una wordlist combinada.
        wl = wordlist_path
        if extra_words:
            try:
                combined = tmpdir / "wordlist.txt"
                orig = Path(wordlist_path).read_text(encoding="utf-8", errors="replace") if Path(wordlist_path).exists() else ""
                merged = list(dict.fromkeys(extra_words + orig.splitlines()))
                combined.write_text("\n".join(merged), encoding="utf-8")
                wl = str(combined)
            except Exception:
                wl = wordlist_path

        output_file = tmpdir / "ffuf.json"
        argv = ["ffuf", "-u", f"{url}/FUZZ", "-w", wl,
                "-o", str(output_file), "-of", "json",
                "-mc", "all", "-fc", "404",
                "-t", str(eff_threads), "-timeout", "10",
                "-ac", "-s", "-maxtime", "480"]
        if extensions:
            # ffuf espera cada extensión con su punto: ".php,.bak,.env"
            argv += ["-e", "." + ",.".join(extensions)]
        if max_depth and max_depth > 1:
            argv += ["-recursion", "-recursion-depth", str(int(max_depth)),
                     "-recursion-strategy", "greedy"]
        if delay_cfg and delay_cfg[1] > 0:
            argv += ["-p", f"{delay_cfg[0]}-{delay_cfg[1]}"]
        for k, v in base_headers.items():
            if k.lower() == "user-agent":
                continue
            argv += ["-H", f"{k}: {v}"]

        run_argv(argv, timeout=540)

        # Baseline calibrado para el filtrado (ffuf -ac no atrapa catch-all que
        # reflejan el path ni targets que hacen 403 a todo). Comparamos por
        # status + tamaño contra sondas aleatorias.
        ff_baseline = get_baseline(url, calib_sess, extensions)

        if output_file.exists():
            try:
                data = json.loads(output_file.read_text(encoding="utf-8", errors="replace"))
                raw = data.get("results", []) or []
                results["total_requests"] = data.get("numberofRequests", len(raw))

                # Secundario: clusters dominantes por (status, words, lines) —
                # atrapa SPAs 200 que reflejan el path (tamaño varía, estructura no).
                # Umbral conservador para no borrar APIs reales con muchos 200 similares.
                total_raw = len(raw)
                fp_counts = {}
                for r in raw:
                    fp = (r.get("status", 0), r.get("words", 0), r.get("lines", 0))
                    fp_counts[fp] = fp_counts.get(fp, 0) + 1
                catchall_fps = {fp for fp, c in fp_counts.items()
                                if c > 200 or (c > 20 and total_raw and c / total_raw > 0.15)}

                filtered = 0
                for r in raw:
                    path = r.get("input", {}).get("FUZZ", "")
                    status = r.get("status", 0)
                    rlen = r.get("length", 0)
                    redirect = r.get("redirectlocation", "")
                    fp = (status, r.get("words", 0), r.get("lines", 0))
                    # Primario: baseline por status/tamaño. Secundario: cluster dominante.
                    if is_baseline(ff_baseline, path, status, rlen, "", redirect) or fp in catchall_fps:
                        filtered += 1
                        continue
                    sev, reason = classify_interest(path, status, rlen)
                    # ffuf no entrega el cuerpo → no podemos confirmar unicidad
                    # de contenido aquí (has_distinct_body=False → 'probable').
                    vstatus, vreason = classify_discovery(status, has_distinct_body=False)
                    results["found"].append({
                        "url": r.get("url", ""),
                        "status": status, "length": rlen,
                        "words": r.get("words", 0), "lines": r.get("lines", 0),
                        "path": path, "redirect": redirect,
                        "type": categorize_path(path, redirect),
                        "interest": sev, "interest_reason": reason,
                        "validation_status": vstatus, "validation_reason": vreason,
                    })
                results["filtered_count"] = filtered
            except Exception:
                pass

    # ───────────────────────── nativo concurrente ─────────────────────────
    else:
        results["method"] = "python"
        paths, truncated = _build_native_paths(wordlist_path, extensions, extra_words, MAX_NATIVE_PATHS)
        if truncated:
            emit("fuzz_status", {"status": "running",
                 "msg": f"Wordlist recortada a {MAX_NATIVE_PATHS} (modo nativo sin ffuf)"})

        tls = _threading.local()

        def worker_session():
            s = getattr(tls, "s", None)
            if s is None:
                s = requests.Session()
                s.headers.update(base_headers)
                s.verify = False
                a = requests.adapters.HTTPAdapter(pool_connections=eff_threads,
                                                  pool_maxsize=eff_threads, max_retries=0)
                s.mount("http://", a)
                s.mount("https://", a)
                tls.s = s
            return s

        def fetch(base, path):
            s = worker_session()
            if delay_cfg and delay_cfg[1] > 0:
                time.sleep(_random.uniform(delay_cfg[0], delay_cfg[1]))
            try:
                r = s.get(f"{base}/{path}", timeout=(3.05, 5), allow_redirects=False)
                return (base, path, r.status_code, r.content, r.text,
                        r.headers.get("Location", ""))
            except Exception:
                return None

        state = {"done": 0, "req": 0}
        lock = _threading.Lock()
        baselines = {url: get_baseline(url, calib_sess, extensions)}
        bases = [(url, 0)]
        visited_bases = {url}

        while bases:
            if active_fuzz.get(sid) == "cancelled":
                break
            next_bases = []
            # Procesar las bases de esta profundidad, cada una concurrentemente.
            round_total = len(bases) * len(paths)
            for base, depth in bases:
                if active_fuzz.get(sid) == "cancelled" or state["req"] >= REQ_BUDGET:
                    break
                bl = baselines.get(base)
                if bl is None:
                    bl = get_baseline(base, calib_sess, extensions)
                    baselines[base] = bl
                with ThreadPoolExecutor(max_workers=eff_threads) as pool:
                    futs = [pool.submit(fetch, base, p) for p in paths]
                    for fut in as_completed(futs):
                        with lock:
                            state["done"] += 1
                            state["req"] += 1
                            done = state["done"]
                        if done % 50 == 0:
                            emit("fuzz_status", {"status": "running",
                                 "msg": f"Profundidad {depth}: {done} peticiones... "
                                        f"({len(results['found'])} hits)"})
                        res = fut.result()
                        if not res:
                            continue
                        rbase, path, status, content, text, location = res
                        if status == 404:
                            continue
                        bh = _body_hash(content)
                        if is_baseline(bl, path, status, len(content), bh, location):
                            results["filtered_count"] += 1
                            continue
                        hit_url = f"{rbase}/{path}"
                        # Ruta completa relativa al objetivo original (no solo el
                        # segmento hoja) para que /admin/config no se vea como /config
                        # y la clasificación de interés tenga el path completo.
                        full_path = hit_url[len(url):].lstrip("/") if hit_url.startswith(url) else path
                        sev, reason = classify_interest(full_path, status, len(content))
                        # Modo nativo SÍ tiene el cuerpo y ya pasó is_baseline →
                        # un 200 aquí tiene contenido distinto del catch-all.
                        vstatus, vreason = classify_discovery(status, has_distinct_body=True)
                        entry = {
                            "url": hit_url, "status": status,
                            "length": len(content), "words": len(text.split()),
                            "lines": len(text.splitlines()), "path": full_path,
                            "redirect": location, "type": categorize_path(full_path, location),
                            "interest": sev, "interest_reason": reason,
                            "validation_status": vstatus, "validation_reason": vreason,
                        }
                        results["found"].append(entry)
                        emit("fuzz_hit", entry)
                        # ¿Recursar? Solo directorios reales con status jugoso.
                        if (depth + 1 < (max_depth or 1)
                                and status in (200, 301, 302, 403)
                                and entry["type"] in ("directory", "redirect")
                                and len(next_bases) < MAX_RECURSE_DIRS):
                            child = hit_url.rstrip("/")
                            if child not in visited_bases:
                                visited_bases.add(child)
                                next_bases.append((child, depth + 1))
            # Filtrar hijos que resulten ser catch-all (evita dirs fantasma).
            filtered_children = []
            for child, d in next_bases:
                cbl = get_baseline(child, calib_sess, extensions)
                baselines[child] = cbl
                is_ca = any(s["status"] in (200, 201, 204)
                            for sigs in cbl.values() for s in sigs)
                if not is_ca:
                    filtered_children.append((child, d))
            bases = filtered_children
        results["total_requests"] = state["req"]

    # ── Orden por interés, luego status, luego path ──
    results["found"].sort(key=rank_key)

    # ── Persistencia opcional (standalone con scan_id, o FASE 6) ──
    if pdb is not None and scan_id is not None:
        try:
            from urllib.parse import urlparse as _up
            host = _up(url).netloc or url
            src = "fuzz" if phase is None else f"scan-fase{phase}"
            rows = []
            for e in results["found"]:
                ev = json.dumps({
                    "interest": e.get("interest"), "reason": e.get("interest_reason"),
                    "validation_reason": e.get("validation_reason"),
                    "length": e.get("length"), "words": e.get("words"),
                    "lines": e.get("lines"), "type": e.get("type"),
                    "waf": results.get("waf"), "stack": results.get("stack"),
                }, ensure_ascii=False)
                rows.append((scan_id, host, e["path"], e["status"], e["length"], e["words"],
                             e["lines"], e["type"], e["redirect"], "", "", "", "",
                             e.get("interest", "info"), src, None,
                             e.get("validation_status", "probable"), ev))
            pdb.executemany(
                """INSERT INTO directories
                   (scan_id, host, path, status_code, content_length, words, lines,
                    type, redirect, title, server, tech, content_type, interest,
                    source, likely_real, validation_status, evidence)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", rows)
            # Si es un fuzz standalone (no una fase del scan), cerramos su fila
            # scans; antes quedaba en 'running' para siempre.
            if phase is None:
                pdb.execute("UPDATE scans SET status='done', finished_at=? WHERE id=?",
                            (datetime.now().isoformat(), scan_id))
            pdb.commit()
            # P2: correlacionar los dirs recién persistidos en assets.
            try:
                rebuild_assets(pdb, scan_id)
            except Exception:
                pass
        except Exception:
            pass
        finally:
            if own_db:
                try:
                    pdb.close()
                except Exception:
                    pass

    emit("fuzz_result", results)
    filt = results.get("filtered_count", 0)
    hv = sum(1 for e in results["found"] if e.get("interest") in ("critical", "high"))
    done_msg = f"Fuzzing completado: {len(results['found'])} encontrados"
    if hv:
        done_msg += f", {hv} de alto valor"
    if filt:
        done_msg += f" ({filt} descartados como catch-all)"
    emit("fuzz_status", {"status": "done", "msg": done_msg})
    active_fuzz.pop(sid, None)

    try:
        _shutil.rmtree(tmpdir, ignore_errors=True)
    except Exception:
        pass
    return results


# ── 403 Bypass ──

BYPASS_TECHNIQUES = [
    {"name": "Path con slash final", "mod": "path", "suffix": "/"},
    {"name": "Doble slash", "mod": "path", "prefix": "//"},
    {"name": "Path traversal", "mod": "path", "suffix": "/..;/"},
    {"name": "Punto al final", "mod": "path", "suffix": "."},
    {"name": "Espacio URL-encoded", "mod": "path", "suffix": "%20"},
    {"name": "Punto URL-encoded", "mod": "path", "suffix": "%2e"},
    {"name": "Slash URL-encoded", "mod": "path", "prefix_replace": "%2f"},
    {"name": "Case switching", "mod": "case"},
    {"name": "Null byte", "mod": "path", "suffix": "%00"},
    {"name": "Tab URL-encoded", "mod": "path", "suffix": "%09"},
    {"name": "Extension .html", "mod": "path", "suffix": ".html"},
    {"name": "Extension .php", "mod": "path", "suffix": ".php"},
    {"name": "Extension .json", "mod": "path", "suffix": ".json"},
    {"name": "Header X-Original-URL", "mod": "header", "header": "X-Original-URL"},
    {"name": "Header X-Rewrite-URL", "mod": "header", "header": "X-Rewrite-URL"},
    {"name": "Header X-Forwarded-For: 127.0.0.1", "mod": "header_val", "header": "X-Forwarded-For", "value": "127.0.0.1"},
    {"name": "Header X-Forwarded-Host: 127.0.0.1", "mod": "header_val", "header": "X-Forwarded-Host", "value": "127.0.0.1"},
    {"name": "Header X-Custom-IP-Authorization: 127.0.0.1", "mod": "header_val", "header": "X-Custom-IP-Authorization", "value": "127.0.0.1"},
    {"name": "Header X-Real-IP: 127.0.0.1", "mod": "header_val", "header": "X-Real-IP", "value": "127.0.0.1"},
    {"name": "Header X-Host: 127.0.0.1", "mod": "header_val", "header": "X-Host", "value": "127.0.0.1"},
    {"name": "Header X-Forwarded-For: 10.0.0.1", "mod": "header_val", "header": "X-Forwarded-For", "value": "10.0.0.1"},
    {"name": "Metodo POST", "mod": "method", "method": "POST"},
    {"name": "Metodo PUT", "mod": "method", "method": "PUT"},
    {"name": "Metodo PATCH", "mod": "method", "method": "PATCH"},
    {"name": "Metodo OPTIONS", "mod": "method", "method": "OPTIONS"},
    {"name": "Metodo TRACE", "mod": "method", "method": "TRACE"},
    {"name": "Override con X-HTTP-Method-Override: GET", "mod": "header_val", "header": "X-HTTP-Method-Override", "value": "GET"},
    {"name": "Header Referer: mismo sitio", "mod": "referer"},
]


def run_403_bypass(url, headers=None, sid=None):
    def _se(ev, d):
        socketio.emit(ev, d, room=sid)

    _se("bypass_status", {"status": "running", "msg": "Iniciando 403 bypass..."})
    results = []
    total = len(BYPASS_TECHNIQUES)
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
    if headers:
        session.headers.update({k: v for k, v in headers.items() if isinstance(k, str) and isinstance(v, str)})
    session.verify = False

    from urllib.parse import urlparse
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path.rstrip('/')

    original_status = None
    try:
        resp = session.get(url, timeout=10, allow_redirects=False)
        original_status = resp.status_code
        original_length = len(resp.content)
    except Exception:
        original_length = 0

    # Baseline de la home page, para descartar falsos positivos
    # (tecnicas de header que terminan sirviendo la portada en vez del recurso)
    homepage_length = None
    try:
        hp = session.get(base + "/", timeout=10, allow_redirects=True)
        if hp.status_code == 200:
            homepage_length = len(hp.content)
    except Exception:
        pass

    _se("bypass_status", {
        "status": "running",
        "msg": f"Status original: {original_status} | Probando {total} tecnicas..."
    })

    for i, tech in enumerate(BYPASS_TECHNIQUES):
        if (i + 1) % 5 == 0:
            _se("bypass_status", {
                "status": "running",
                "msg": f"Probando {i + 1}/{total}: {tech['name']}..."
            })

        try:
            test_url = url
            headers = {}
            method = "GET"

            if tech["mod"] == "path":
                if tech.get("suffix"):
                    test_url = base + path + tech["suffix"]
                elif tech.get("prefix"):
                    test_url = base + tech["prefix"] + path.lstrip('/')
                elif tech.get("prefix_replace"):
                    test_url = base + path.replace('/', tech["prefix_replace"])
            elif tech["mod"] == "case":
                if path:
                    parts = path.split('/')
                    new_parts = []
                    for p in parts:
                        if p:
                            new_parts.append(p[0].upper() + p[1:] if len(p) > 1 else p.upper())
                        else:
                            new_parts.append(p)
                    test_url = base + '/'.join(new_parts)
            elif tech["mod"] == "header":
                headers[tech["header"]] = path
                test_url = base + "/"
            elif tech["mod"] == "header_val":
                headers[tech["header"]] = tech["value"]
            elif tech["mod"] == "method":
                method = tech["method"]
            elif tech["mod"] == "referer":
                headers["Referer"] = base + "/"

            resp = session.request(method, test_url, headers=headers, timeout=8, allow_redirects=False)
            status = resp.status_code
            length = len(resp.content)
            redirect_to = resp.headers.get("Location", "")

            # ── Deteccion precisa de bypass ──
            # Solo cuenta como bypass real si el recurso estaba protegido (401/403)
            # y ahora responde con contenido real (2xx) que NO es la home page.
            bypassed = False
            note = ""
            if original_status in (401, 403):
                if 200 <= status < 300:
                    is_homepage = (homepage_length is not None and
                                   abs(length - homepage_length) < 50)
                    if is_homepage:
                        note = "Falso positivo: sirvio la home, no el recurso"
                    elif length == 0:
                        note = "200 pero cuerpo vacio"
                    else:
                        bypassed = True
                elif 300 <= status < 400:
                    note = f"Redirect -> {redirect_to[:80]}" if redirect_to else "Redirect (no es acceso)"
                elif status == original_status:
                    note = "Sigue bloqueado"
                elif status == 404:
                    note = "No encontrado"
                else:
                    note = f"Status {status}"

            entry = {
                "technique": tech["name"],
                "url": test_url,
                "method": method,
                "status": status,
                "length": length,
                "bypassed": bypassed,
                "note": note,
                "redirect": redirect_to[:120] if redirect_to else "",
                "headers": headers if headers else None,
                "diff_length": length - original_length if original_length else 0,
            }
            results.append(entry)
            _se("bypass_hit", entry)

        except Exception:
            results.append({
                "technique": tech["name"],
                "url": test_url,
                "method": "GET",
                "status": 0,
                "length": 0,
                "bypassed": False,
                "error": True,
            })

    bypassed_count = sum(1 for r in results if r.get("bypassed"))
    _se("bypass_result", {
        "url": url,
        "original_status": original_status,
        "original_length": original_length,
        "results": results,
        "total": total,
        "bypassed": bypassed_count,
    })
    _se("bypass_status", {
        "status": "done",
        "msg": f"Completado: {bypassed_count}/{total} tecnicas lograron bypass"
    })


def _parse_headers(data):
    """Headers de la UI (texto 'Name: Value' por línea o dict). Solo vienen del
    input del usuario, nunca de contenido escaneado."""
    raw = data.get("headers")
    out = {}
    if isinstance(raw, dict):
        for k, v in raw.items():
            if isinstance(k, str) and isinstance(v, str) and k.strip():
                out[k.strip()] = v.strip()
    elif isinstance(raw, str):
        for line in raw.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                if k.strip():
                    out[k.strip()] = v.strip()
    cookie = (data.get("cookie") or "").strip()
    if cookie:
        out["Cookie"] = cookie
    return out


@socketio.on("start_bypass")
def handle_bypass(data):
    url = (data.get("url") or "").strip()
    if not url:
        return
    if not url.startswith("http"):
        url = "https://" + url
    ok, msg = _assert_public_target(url)
    if not ok:
        socketio.emit("bypass_status", {"status": "done", "msg": f"Objetivo bloqueado: {msg}"})
        return
    headers = _parse_headers(data)
    threading.Thread(target=run_403_bypass, args=(url,), kwargs={"headers": headers, "sid": request.sid}, daemon=True).start()


@socketio.on("start_fuzzing")
def handle_fuzzing(data):
    url = (data.get("url") or "").strip()
    if not url:
        return
    if not url.startswith("http"):
        url = "https://" + url
    ok, msg = _assert_public_target(url)
    if not ok:
        socketio.emit("fuzz_status", {"status": "done", "msg": f"Objetivo bloqueado: {msg}"})
        return
    # Extensiones: allowlist estricta (evita inyección aunque un cliente no-UI mande basura).
    extensions = [e for e in data.get("extensions", [])
                  if isinstance(e, str) and re.fullmatch(r"[A-Za-z0-9]{1,8}", e)]
    try:
        threads = min(max(int(data.get("threads", 40)), 1), 100)
    except (TypeError, ValueError):
        threads = 40
    try:
        max_depth = min(max(int(data.get("max_depth", 1)), 1), 3)
    except (TypeError, ValueError):
        max_depth = 1
    wordlist = (data.get("wordlist") or "").strip()
    if not wordlist or not Path(wordlist).exists():
        wordlist = find_wordlist()
    headers = _parse_headers(data)

    # Persistir resultados: crear una fila scans (mode='fuzz') y pasar su id.
    scan_id = None
    try:
        sdb = get_db()
        cur = sdb.execute(
            "INSERT INTO scans (domain, status, mode, started_at) VALUES (?,?,?,?)",
            (url, "running", "fuzz", datetime.now().isoformat()))
        scan_id = cur.lastrowid
        sdb.commit()
        sdb.close()
    except Exception:
        scan_id = None

    threading.Thread(
        target=run_fuzzing, args=(url, extensions, threads, wordlist),
        kwargs={"scan_id": scan_id, "headers": headers, "max_depth": max_depth, "sid": request.sid},
        daemon=True).start()


@socketio.on("stop_fuzzing")
def handle_stop_fuzzing(data):
    # Marca cancelación; el bucle nativo la chequea por hilo.
    for k in list(active_fuzz.keys()):
        active_fuzz[k] = "cancelled"
    socketio.emit("fuzz_status", {"status": "running", "msg": "Cancelando fuzzing..."})


# ── httpx verification (enriquece resultados del fuzzing) ──

def _httpx_available():
    """Detecta si httpx.exe se puede ejecutar (no bloqueado por Device Guard)."""
    try:
        out = run_argv(["httpx", "-version"], timeout=10).lower()
        if "bloqueado" in out or "device guard" in out or "blocked" in out:
            return False
        return "version" in out or bool(re.search(r"v\d+\.\d+", out))
    except Exception:
        return False


def _verify_url_python(url, session, headers=None):
    """Probe compartido: status, tamaño, title, server, hash de cuerpo.

    allow_redirects=False: NO seguimos redirects — un 302 a un host interno
    (169.254.169.254, localhost) bypasearía el gate SSRF. Además, para verificar
    un recurso descubierto, el status real (301/302) es más informativo que
    seguir hasta el destino.
    """
    try:
        h = {"User-Agent": "Mozilla/5.0"}
        if headers:
            h.update(headers)
        resp = session.get(url, timeout=8, allow_redirects=False,
                           headers=h, verify=False)
        body = resp.text
        title = ""
        m = re.search(r'<title[^>]*>(.*?)</title>', body, re.IGNORECASE | re.DOTALL)
        if m:
            title = re.sub(r'\s+', ' ', m.group(1)).strip()[:120]
        tech = []
        gen = re.search(r'<meta[^>]*name=["\']generator["\'][^>]*content=["\'](.*?)["\']', body, re.IGNORECASE)
        if gen:
            tech.append(gen.group(1)[:40])
        if 'wp-content' in body or 'wp-includes' in body:
            tech.append("WordPress")
        if '/_next/' in body or '__NEXT_DATA__' in body:
            tech.append("Next.js")
        return {
            "url": url,
            "path": re.sub(r'https?://[^/]+', '', url),
            "status": resp.status_code,
            "length": len(resp.content),
            "words": len(body.split()),
            "lines": len(body.splitlines()),
            "title": title,
            "server": resp.headers.get("Server", ""),
            "tech": ", ".join(dict.fromkeys(tech)),
            "content_type": resp.headers.get("Content-Type", "").split(';')[0],
            "location": resp.headers.get("Location", ""),
            "body_hash": _body_hash(resp.content),
        }
    except Exception:
        return None


def run_httpx_verify(urls, headers=None, sid=None):
    def _se(ev, d):
        socketio.emit(ev, d, room=sid)

    enriched = []
    tmpdir = None
    try:
        use_httpx = _httpx_available()

        if use_httpx:
            _se("httpx_status", {"status": "running", "msg": f"Verificando {len(urls)} URLs con httpx..."})
            tmpdir = Path(tempfile.mkdtemp(prefix="sharingan-httpx-"))
            in_file = tmpdir / "urls.txt"
            out_file = tmpdir / "httpx.json"
            in_file.write_text("\n".join(urls), encoding="utf-8")

            argv = ["httpx", "-l", str(in_file), "-json", "-o", str(out_file),
                    "-sc", "-cl", "-title", "-td", "-server", "-location",
                    "-ct", "-nc", "-silent", "-t", "50"]
            if headers:
                for k, v in headers.items():
                    if isinstance(k, str) and isinstance(v, str):
                        argv += ["-H", f"{k}: {v}"]
            run_argv(argv, timeout=540)

            if out_file.exists():
                for line in out_file.read_text(encoding="utf-8", errors="replace").splitlines():
                    try:
                        j = json.loads(line)
                        tech = j.get("tech", [])
                        enriched.append({
                            "url": j.get("url", ""),
                            "path": j.get("path", "") or j.get("input", ""),
                            "status": j.get("status_code", 0),
                            "length": j.get("content_length", 0),
                            "words": j.get("words", 0),
                            "lines": j.get("lines", 0),
                            "title": j.get("title", ""),
                            "server": j.get("webserver", ""),
                            "tech": ", ".join(tech) if isinstance(tech, list) else (tech or ""),
                            "content_type": j.get("content_type", ""),
                            "location": j.get("location", ""),
                        })
                    except Exception:
                        continue
        else:
            # Fallback Python (httpx bloqueado por Device Guard o no disponible)
            _se("httpx_status", {
                "status": "running",
                "msg": f"httpx no disponible (bloqueado) - verificando {len(urls)} URLs con Python..."
            })
            from concurrent.futures import ThreadPoolExecutor, as_completed
            WORKERS = 30
            session = requests.Session()
            session.headers.update({"User-Agent": "Mozilla/5.0"})
            # pool_maxsize == workers: evita "Connection pool is full" y el
            # churn de sockets que colapsaba la concurrencia a ~10.
            _ad = requests.adapters.HTTPAdapter(pool_connections=WORKERS, pool_maxsize=WORKERS, max_retries=0)
            session.mount("http://", _ad)
            session.mount("https://", _ad)
            done = 0
            with ThreadPoolExecutor(max_workers=WORKERS) as pool:
                futures = {pool.submit(_verify_url_python, u, session, headers): u for u in urls}
                for fut in as_completed(futures):
                    done += 1
                    if done % 25 == 0:
                        _se("httpx_status", {
                            "status": "running",
                            "msg": f"Verificadas {done}/{len(urls)} URLs..."
                        })
                    r = fut.result()
                    if r:
                        enriched.append(r)

        # Agrupar por fingerprint de estructura (status, words, lines): una SPA
        # que refleja el path varia en bytes pero mantiene igual estructura.
        # Los que comparten fingerprint con muchos otros son el catch-all.
        fp_counts = {}
        for e in enriched:
            fp = (e["status"], e.get("words", 0), e.get("lines", 0))
            fp_counts[fp] = fp_counts.get(fp, 0) + 1
        for e in enriched:
            fp = (e["status"], e.get("words", 0), e.get("lines", 0))
            e["dup_count"] = fp_counts.get(fp, 1)
            e["likely_real"] = e["dup_count"] <= 3
            # Veredicto de validación central a partir de la señal httpx.
            vstatus, vreason = classify_discovery(
                e.get("status"), has_distinct_body=True,
                httpx_likely_real=e["likely_real"])
            e["validation_status"] = vstatus
            e["validation_reason"] = vreason

        enriched.sort(key=lambda x: (not x["likely_real"], x["status"], x["path"]))
        real_n = sum(1 for e in enriched if e["likely_real"])

        _se("httpx_result", {
            "results": enriched,
            "total": len(enriched),
            "real": real_n,
        })
        _se("httpx_status", {
            "status": "done",
            "msg": f"Verificacion completa: {len(enriched)} verificadas, {real_n} probablemente reales"
        })
    except Exception as e:
        _se("httpx_status", {"status": "done", "msg": f"Error en verificacion: {e}"})
    finally:
        if tmpdir:
            import shutil
            try:
                shutil.rmtree(tmpdir, ignore_errors=True)
            except Exception:
                pass


@socketio.on("start_httpx_verify")
def handle_httpx_verify(data):
    urls = data.get("urls", [])
    # Gate SSRF por URL (misma defensa que fuzzing/bypass).
    clean = []
    for u in urls:
        if u and u.startswith("http"):
            ok, _ = _assert_public_target(u)
            if ok:
                clean.append(u)
    urls = clean[:3000]
    if not urls:
        socketio.emit("httpx_status", {"status": "done", "msg": "No hay URLs válidas para verificar (todas bloqueadas por el filtro SSRF)"})
        return
    headers = _parse_headers(data)
    threading.Thread(target=run_httpx_verify, args=(urls,), kwargs={"headers": headers, "sid": request.sid}, daemon=True).start()


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

            out, _st = run_argv_cancel(["curl", "-s", f"https://crt.sh/?q=%25.{domain}&output=json"],
                                       scan_id=scan_id, timeout=60)
            try:
                data = json.loads(out)
                names = sorted(set(
                    n.strip().lower()
                    for entry in data
                    for n in entry.get("name_value", "").split("\n")
                    if "*" not in n and _in_scope(n, domain)
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

            # Recolección por fuente, con scope anclado por sufijo (#7).
            candidates = {}  # subdominio -> fuente (la primera que lo vio)
            notes = []

            def add_candidates(lines, source):
                for line in lines:
                    s = line.strip().lower().rstrip(".")
                    if s and _in_scope(s, domain):
                        candidates.setdefault(s, source)

            # crt.sh (FASE 1) ya insertó; lo traemos al set para resolver todo junto.
            for r in db.execute("SELECT subdomain, source FROM subdomains WHERE scan_id=?", (scan_id,)).fetchall():
                candidates.setdefault(r["subdomain"], r["source"])
            db.execute("DELETE FROM subdomains WHERE scan_id=?", (scan_id,))

            sf_file = tmpdir / "subfinder.txt"
            _, st = run_argv_cancel(["subfinder", "-d", domain, "-all", "-o", str(sf_file), "-silent"],
                                    scan_id=scan_id, timeout=300)
            if st in ("error", "timeout"):
                notes.append(f"subfinder: {st}")
            if sf_file.exists():
                add_candidates(sf_file.read_text(encoding="utf-8", errors="replace").splitlines(), "subfinder")

            sl_file = tmpdir / "sublist3r.txt"
            _, st = run_argv_cancel(["python", "-m", "sublist3r", "-d", domain, "-o", str(sl_file)],
                                    scan_id=scan_id, timeout=300)
            if st in ("error", "timeout"):
                notes.append(f"sublist3r: {st}")
            if sl_file.exists():
                add_candidates(sl_file.read_text(encoding="utf-8", errors="replace").splitlines(), "sublist3r")

            af_out, st = run_argv_cancel(["assetfinder", "--subs-only", domain], scan_id=scan_id, timeout=120)
            if st in ("error", "timeout"):
                notes.append(f"assetfinder: {st}")
            add_candidates(af_out.splitlines(), "assetfinder")

            # ── #7: wildcard DNS + resolución ──
            wildcard_ips = detect_wildcard_dns(domain)
            if wildcard_ips:
                notes.append(f"wildcard DNS detectado ({len(wildcard_ips)} IP) — fantasmas marcados")
            socketio.emit("phase_status", {"scan_id": scan_id, "phase": 2, "status": "running",
                          "note": f"Resolviendo {len(candidates)} subdominios..."})

            from concurrent.futures import ThreadPoolExecutor as _TPE
            cand_list = list(candidates.keys())
            resolved_map = {}
            if cand_list:
                with _TPE(max_workers=40) as pool:
                    for sub, ips in zip(cand_list, pool.map(_resolve_host, cand_list)):
                        resolved_map[sub] = ips

            rows = []
            n_res = n_wild = 0
            for sub in cand_list:
                ips = resolved_map.get(sub, set())
                resolved = 1 if ips else 0
                is_wild = 1 if (ips and wildcard_ips and ips <= wildcard_ips) else 0
                is_int = 1 if (ips and _ips_internal(ips)) else 0
                if resolved:
                    n_res += 1
                if is_wild:
                    n_wild += 1
                rows.append((scan_id, sub, candidates[sub],
                             ", ".join(sorted(ips))[:200], resolved, is_wild, is_int))
            db.executemany(
                """INSERT INTO subdomains (scan_id, subdomain, source, ip, resolved, is_wildcard, is_internal)
                   VALUES (?,?,?,?,?,?,?)""", rows)
            db.commit()

            count = len(rows)
            socketio.emit("stats_update", {"scan_id": scan_id, "subdomains": count})
            done_note = f"{count} únicos · {n_res} resuelven · {n_wild} wildcard/fantasma"
            if notes:
                done_note += " · " + "; ".join(notes)
            socketio.emit("phase_status", {"scan_id": scan_id, "phase": 2, "status": "done", "note": done_note})

        if active_scans.get(scan_id) == "cancelled":
            update_scan(scan_id, status="cancelled")
            return

        # ── FASE 3: Hosts vivos ──
        if 3 in phases:
            update_scan(scan_id, current_phase=3)
            socketio.emit("phase_status", {"scan_id": scan_id, "phase": 3, "status": "running"})

            # #7: solo hosts que resuelven, NO wildcard, NO internos (SSRF).
            subs = [r["subdomain"] for r in db.execute(
                """SELECT DISTINCT subdomain FROM subdomains
                   WHERE scan_id = ? AND resolved = 1
                     AND (is_wildcard IS NULL OR is_wildcard = 0)
                     AND (is_internal IS NULL OR is_internal = 0)""", (scan_id,)).fetchall()]

            if subs:
                subs_file = tmpdir / "subs.txt"
                subs_file.write_text("\n".join(subs), encoding="utf-8")

                httpx_file = tmpdir / "httpx.json"
                _, st = run_argv_cancel(["httpx", "-l", str(subs_file), "-json", "-o", str(httpx_file),
                          "-sc", "-cl", "-title", "-td", "-server", "-nc", "-silent"],
                          scan_id=scan_id, timeout=600)
                if st in ("error", "timeout"):
                    socketio.emit("phase_status", {"scan_id": scan_id, "phase": 3, "status": "running",
                                  "note": f"httpx: {st}"})

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
                # #7/SSRF: no escanear hosts que resuelven a IP interna.
                ok, _ = _assert_public_target("https://" + h)
                if ok:
                    hosts.add(h)

            if hosts:
                hosts_file = tmpdir / "hosts.txt"
                hosts_file.write_text("\n".join(sorted(hosts)), encoding="utf-8")
                nmap_out, st = run_argv_cancel(["nmap", "-sV", "-T4", "--top-ports", "100", "-iL", str(hosts_file)],
                                               scan_id=scan_id, timeout=600)
                if st in ("error", "timeout"):
                    socketio.emit("phase_status", {"scan_id": scan_id, "phase": 4, "status": "running",
                                  "note": f"nmap: {st}"})

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
                _, st = run_argv_cancel(["nuclei", "-l", str(alive_file), "-jsonl", "-o", str(nuclei_file),
                          "-es", "info", "-rl", "30", "-nc", "-silent"], scan_id=scan_id, timeout=600)
                if st in ("error", "timeout"):
                    socketio.emit("phase_status", {"scan_id": scan_id, "phase": 5, "status": "running",
                                  "note": f"nuclei: {st}"})

                if nuclei_file.exists():
                    for line in nuclei_file.read_text(encoding="utf-8", errors="replace").splitlines():
                        try:
                            j = json.loads(line)
                            info = j.get("info", {})
                            sev = info.get("severity", "unknown")
                            vstatus, vreason = classify_vuln(sev, j.get("matched-at"))
                            # Evidencia completa para triage (antes se descartaba).
                            classification = info.get("classification", {}) or {}
                            ev = json.dumps({
                                "matcher": j.get("matcher-name", ""),
                                "extracted": j.get("extracted-results", []),
                                "cve": classification.get("cve-id", []),
                                "cwe": classification.get("cwe-id", []),
                                "cvss_score": classification.get("cvss-score"),
                                "reference": info.get("reference", []),
                                "description": (info.get("description", "") or "")[:500],
                                "curl": j.get("curl-command", ""),
                                "type": j.get("type", ""),
                                "validation_reason": vreason,
                            }, ensure_ascii=False)
                            db.execute("""INSERT OR IGNORE INTO vulns
                                (scan_id, template, severity, host, info, matched_at,
                                 validation_status, evidence)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""", (
                                scan_id,
                                j.get("template-id", ""),
                                sev,
                                j.get("host", ""),
                                info.get("name", ""),
                                j.get("matched-at", ""),
                                vstatus, ev
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
            wl = find_wordlist()
            for host in alive[:5]:
                if active_scans.get(scan_id) == "cancelled":
                    break
                ok, _ = _assert_public_target(host)
                if not ok:
                    continue
                # Reusa el MISMO motor que el fuzzing interactivo (calibración
                # soft-404, filtro catch-all, clasificación de interés, persistencia)
                # pero en silencio (emit_live=False) para no tocar el panel standalone.
                try:
                    run_fuzzing(host, ["php", "bak", "env", "json"], 40, wl,
                                scan_id=scan_id, phase=6, emit_live=False, db=db)
                except Exception:
                    pass

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

            wb_out, _ = run_argv_cancel(["waybackurls", domain], scan_id=scan_id, timeout=300)
            gau_out, _ = run_argv_cancel(["gau", domain], scan_id=scan_id, timeout=300)

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

        # P2: correlación assets ↔ findings (todas las representaciones de host
        # recién están completas tras FASE 6; reconciliamos una vez al final).
        try:
            rebuild_assets(db, scan_id)
        except Exception:
            pass

        # Done
        update_scan(scan_id, status="completed", finished_at=datetime.now().isoformat(), current_phase=7)
        socketio.emit("scan_done", {"scan_id": scan_id})

    except Exception as e:
        update_scan(scan_id, status="error")
        socketio.emit("scan_error", {"scan_id": scan_id, "error": str(e)})
    finally:
        db.close()
        active_scans.pop(scan_id, None)  # #8: evitar crecimiento ilimitado
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
        "subfinder": ["subfinder", "-version"], "sublist3r": ["python", "-m", "sublist3r", "--help"],
        "assetfinder": ["assetfinder", "-h"], "httpx": ["httpx", "-version"], "nmap": ["nmap", "--version"],
        "nuclei": ["nuclei", "-version"], "ffuf": ["ffuf", "-V"], "dirsearch": ["python", "-m", "dirsearch", "--help"],
        "waybackurls": ["waybackurls", "-h"], "gau": ["gau", "--help"], "whois": ["whois", "-?"],
    }
    results = {}
    for name in tools:
        out = run_argv(cmds[name], timeout=10)
        results[name] = not out.startswith("Error:") and len(out.strip()) > 0
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
        """SELECT subdomain, source, ip, resolved, is_wildcard, is_internal
           FROM subdomains WHERE scan_id=?
           ORDER BY is_wildcard, resolved DESC, subdomain""", (scan_id,)).fetchall()]
    result["alive_hosts"] = [dict(r) for r in db.execute(
        "SELECT url, status_code, title, tech, server, content_length FROM alive_hosts WHERE scan_id=?", (scan_id,)).fetchall()]
    result["ports"] = [dict(r) for r in db.execute(
        "SELECT host, port, state, service, version FROM ports WHERE scan_id=? ORDER BY port", (scan_id,)).fetchall()]
    result["vulns"] = [dict(r) for r in db.execute(
        """SELECT template, severity, host, info, matched_at, validation_status, evidence
           FROM vulns WHERE scan_id=?
           ORDER BY CASE lower(severity) WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                    WHEN 'medium' THEN 2 WHEN 'low' THEN 3 WHEN 'info' THEN 4 ELSE 5 END""",
        (scan_id,)).fetchall()]
    result["directories"] = [dict(r) for r in db.execute(
        """SELECT host, path, status_code, content_length, type, redirect, interest, source,
                  validation_status, evidence
           FROM directories WHERE scan_id=?
           ORDER BY CASE interest WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                    WHEN 'medium' THEN 2 ELSE 3 END, status_code""", (scan_id,)).fetchall()]
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


@app.route("/api/scans/<int:scan_id>/assets")
def get_scan_assets(scan_id):
    """Vista asset-centric: cada host con sus puertos + findings (vulns/dirs)
    correlacionados + el peor veredicto. Endpoint NUEVO; no toca get_scan."""
    db = get_db()
    if not db.execute("SELECT 1 FROM scans WHERE id=?", (scan_id,)).fetchone():
        db.close()
        return jsonify({"error": "not found"}), 404
    out = []
    for a in db.execute("SELECT * FROM assets WHERE scan_id=? ORDER BY canonical_host", (scan_id,)).fetchall():
        a = dict(a)
        h = a["canonical_host"]
        a["ports"] = [dict(r) for r in db.execute(
            "SELECT port, state, service, version FROM ports WHERE scan_id=? AND norm_host(host)=? ORDER BY port",
            (scan_id, h)).fetchall()]
        a["findings"] = [dict(r) for r in db.execute(
            """SELECT finding_type, name, severity, location, validation_status, evidence
               FROM findings WHERE scan_id=? AND canonical_host=?""", (scan_id, h)).fetchall()]
        v = db.execute(
            """SELECT validation_status FROM findings WHERE scan_id=? AND canonical_host=?
               ORDER BY CASE validation_status WHEN 'verified' THEN 0 WHEN 'probable' THEN 1
                        WHEN 'inconclusive' THEN 2 ELSE 3 END LIMIT 1""", (scan_id, h)).fetchone()
        a["verdict"] = v[0] if v else None
        out.append(a)
    db.close()
    return jsonify({"scan_id": scan_id, "assets": out})


# Palabras clave → recomendación (para la sección de recomendaciones del reporte).
_REPORT_RECOS = [
    (("/.env", ".env", "actuator/env", "actuator/heapdump", ".git/config", ".git/head",
      "id_rsa", "credentials", ".aws/credentials", "wp-config"),
     "Remover de inmediato los archivos sensibles expuestos (.env, .git, credenciales, dumps) del webroot y rotar cualquier secreto filtrado."),
    (("admin", "manager", "panel", "phpmyadmin", "adminer", "cpanel", "webmail", "dashboard"),
     "Restringir el acceso a paneles administrativos (IP allowlist / VPN / autenticación fuerte) y no exponerlos a Internet."),
    (("backup", ".bak", ".sql", "dump", ".zip", ".old"),
     "Eliminar respaldos y volcados accesibles públicamente; no dejar artefactos de backup en hosts web."),
    (("swagger", "openapi", "api-docs", "redoc", "graphql"),
     "Revisar documentación de API expuesta en busca de endpoints no documentados y restringirla en producción."),
]


@app.route("/api/scans/<int:scan_id>/report")
def get_scan_report(scan_id):
    """Reporte estructurado del scan: resumen, superficie de ataque (assets),
    hallazgos separados por veredicto, y recomendaciones derivadas. Fuente única
    para la vista de informe y el export JSON. No toca get_scan."""
    db = get_db()
    scan = db.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not scan:
        db.close()
        return jsonify({"error": "not found"}), 404
    scan = dict(scan)

    def count(sql, *a):
        return db.execute(sql, a).fetchone()[0]

    stats = {
        "subdomains": count("SELECT COUNT(*) FROM subdomains WHERE scan_id=?", scan_id),
        "resolved":   count("SELECT COUNT(*) FROM subdomains WHERE scan_id=? AND resolved=1", scan_id),
        "wildcard":   count("SELECT COUNT(*) FROM subdomains WHERE scan_id=? AND is_wildcard=1", scan_id),
        "alive":      count("SELECT COUNT(*) FROM alive_hosts WHERE scan_id=?", scan_id),
        "ports":      count("SELECT COUNT(*) FROM ports WHERE scan_id=? AND state='open'", scan_id),
        "vulns":      count("SELECT COUNT(*) FROM vulns WHERE scan_id=?", scan_id),
        "dirs":       count("SELECT COUNT(*) FROM directories WHERE scan_id=?", scan_id),
        "assets":     count("SELECT COUNT(*) FROM assets WHERE scan_id=?", scan_id),
        "urls":       count("SELECT COUNT(*) FROM urls WHERE scan_id=?", scan_id),
    }

    # Superficie de ataque: assets con puertos (resumen).
    assets = []
    for a in db.execute("""SELECT canonical_host, ip, url, title, tech, server, status_code,
                                  is_wildcard, is_internal, shared_ip
                           FROM assets WHERE scan_id=? ORDER BY canonical_host""", (scan_id,)).fetchall():
        a = dict(a)
        a["ports"] = [dict(r) for r in db.execute(
            "SELECT port, service, version FROM ports WHERE scan_id=? AND norm_host(host)=? AND state='open' ORDER BY port",
            (scan_id, a["canonical_host"])).fetchall()]
        assets.append(a)

    # Hallazgos separados por veredicto (confirmados vs observaciones).
    findings = {"verified": [], "probable": [], "inconclusive": [], "false_positive": []}
    for f in db.execute("""SELECT finding_type, canonical_host, name, severity, location,
                                  validation_status, evidence
                           FROM findings WHERE scan_id=?
                           ORDER BY CASE validation_status WHEN 'verified' THEN 0 WHEN 'probable' THEN 1
                                    WHEN 'inconclusive' THEN 2 ELSE 3 END, canonical_host""", (scan_id,)).fetchall():
        f = dict(f)
        findings.setdefault(f.get("validation_status") or "probable", []).append(f)

    # Recomendaciones derivadas de los nombres de hallazgos.
    corpus = " ".join((f.get("name") or "").lower() + " " + (f.get("location") or "").lower()
                      for grp in findings.values() for f in grp)
    recommendations = [txt for kws, txt in _REPORT_RECOS if any(k in corpus for k in kws)]
    if stats["wildcard"]:
        recommendations.append(f"Hay {stats['wildcard']} subdominios wildcard/fantasma: validar que no oculten servicios reales antes de descartarlos.")
    if not recommendations:
        recommendations.append("No se derivaron recomendaciones automáticas; revisar manualmente los hallazgos marcados como 'probable'.")

    db.close()
    return jsonify({
        "scan": scan,
        "stats": stats,
        "assets": assets,
        "findings": findings,
        "recommendations": recommendations,
    })


@app.route("/api/scans/<int:scan_id>", methods=["DELETE"])
def delete_scan(scan_id):
    db = get_db()
    for table in ["subdomains", "alive_hosts", "ports", "vulns", "directories", "urls", "recon_info", "assets"]:
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
    domain = re.sub(r'^https?://', '', domain).split('/')[0].split(':')[0]
    # ── P0: allowlist estricta de hostname ──
    # El dominio se interpola en comandos y en DNS; restringirlo a
    # [a-z0-9.-] (sin espacios, comillas, &, |, ;, $, backticks) neutraliza
    # de raíz la inyección de comandos y de PowerShell en TODO el scan.
    if not re.fullmatch(r"(?=.{1,253}$)([a-z0-9_-]{1,63}\.)+[a-z]{2,}", domain):
        emit("error", {"message": f"Dominio inválido: {domain}. Usá un hostname (ej: ejemplo.com)."})
        return
    # ── P0: gate SSRF también en el target del scan ──
    ok, msg = _assert_public_target("https://" + domain)
    if not ok:
        emit("error", {"message": f"Objetivo bloqueado: {msg}"})
        return
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
    print(f"\n  Sharingan running at http://{BIND_HOST}:5000  (bind={BIND_HOST})\n")
    socketio.run(app, host=BIND_HOST, port=5000, debug=False, allow_unsafe_werkzeug=True)
