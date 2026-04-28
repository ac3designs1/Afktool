"""
License Server v3 — PostgreSQL (data persists across restarts)
Built on v2 (known-good) + advanced admin panel endpoints
"""
import os, secrets, string, psycopg2, psycopg2.extras, threading, urllib.request, json
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, Response

ADMIN_KEY           = os.environ.get("ADMIN_KEY", "CHANGE_ME")
DATABASE_URL        = os.environ.get("DATABASE_URL", "")
CURRENT_VERSION     = os.environ.get("APP_VERSION", "1.0.0")
DOWNLOAD_URL        = os.environ.get("DOWNLOAD_URL", "")
DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "")
DISCORD_BOT_TOKEN   = os.environ.get("DISCORD_BOT_TOKEN", "")
DISCORD_CHANNEL_ID  = int(os.environ.get("DISCORD_CHANNEL_ID", "0") or 0)

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def db():
    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = True
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""CREATE TABLE IF NOT EXISTS licenses (
        code TEXT PRIMARY KEY, hwid TEXT, activated_at TEXT, created_at TEXT,
        note TEXT, disabled INTEGER DEFAULT 0, expires_at TEXT,
        last_seen TEXT, total_seconds INTEGER DEFAULT 0, app_version TEXT,
        trial_hours REAL, max_sessions INTEGER DEFAULT 1
    )""")
    cur.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS trial_hours REAL")
    cur.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS max_sessions INTEGER DEFAULT 1")
    cur.execute("""CREATE TABLE IF NOT EXISTS broadcast (
        id INTEGER PRIMARY KEY CHECK (id=1), message TEXT, updated_at TEXT
    )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS user_messages (
        id SERIAL PRIMARY KEY, hwid TEXT, message TEXT, created_at TEXT, delivered BOOLEAN DEFAULT FALSE
    )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS activity_logs (
        id SERIAL PRIMARY KEY, hwid TEXT, event_type TEXT, details TEXT, created_at TEXT, ip_address TEXT
    )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS active_sessions (
        hwid TEXT PRIMARY KEY, started_at TEXT, last_seen TEXT
    )""")
    return conn, cur

def _log(cur, hwid, event_type, details, ip=""):
    try:
        cur.execute(
            "INSERT INTO activity_logs(hwid, event_type, details, created_at, ip_address) VALUES(%s,%s,%s,%s,%s)",
            (hwid, event_type, details, datetime.utcnow().isoformat(), ip)
        )
    except Exception:
        pass

def fire_webhook(title, description, color=0x5865F2, fields=None):
    """Non-blocking Discord webhook embed. Silently ignores failures."""
    if not DISCORD_WEBHOOK_URL:
        return
    def _send():
        try:
            embed = {"title": title, "description": description, "color": color,
                     "timestamp": datetime.utcnow().isoformat() + "Z",
                     "fields": fields or []}
            payload = json.dumps({"embeds": [embed]}).encode()
            req = urllib.request.Request(
                DISCORD_WEBHOOK_URL, data=payload,
                headers={"Content-Type": "application/json"}, method="POST")
            urllib.request.urlopen(req, timeout=5)
        except Exception:
            pass
    threading.Thread(target=_send, daemon=True).start()

def gen_code():
    alpha = string.ascii_uppercase + string.digits
    return "FIVEM-" + "-".join("".join(secrets.choice(alpha) for _ in range(4)) for _ in range(4))

def _auth(data): return (data or {}).get("admin_key") == ADMIN_KEY

def _valid_license(hwid):
    conn, cur = db()
    try:
        cur.execute("SELECT * FROM licenses WHERE hwid=%s", (hwid,))
        row = cur.fetchone()
    finally:
        conn.close()
    if not row: return None, "no license"
    if row["disabled"]: return row, "disabled"
    if row["expires_at"]:
        try:
            if datetime.utcnow() > datetime.fromisoformat(row["expires_at"]): return row, "expired"
        except: pass
    return row, None

# ---------------------------------------------------------------------------
# Client endpoints (v2 — unchanged, proven working)
# ---------------------------------------------------------------------------

@app.post("/activate")
def activate():
    data = request.json or {}
    code = (data.get("code") or "").strip().upper()
    hwid = (data.get("hwid") or "").strip().upper()
    if not code or not hwid: return jsonify(ok=False, error="missing code or hwid"), 400
    conn, cur = db()
    try:
        cur.execute("SELECT * FROM licenses WHERE code=%s", (code,))
        row = cur.fetchone()
        if not row: return jsonify(ok=False, error="invalid code"), 404
        if row["disabled"]: return jsonify(ok=False, error="code has been disabled"), 403
        if row["expires_at"]:
            try:
                if datetime.utcnow() > datetime.fromisoformat(row["expires_at"]):
                    return jsonify(ok=False, error="code has expired"), 403
            except: pass
        if row["hwid"] and row["hwid"] != hwid:
            return jsonify(ok=False, error="code already used on another device"), 403
        if not row["hwid"]:
            now = datetime.utcnow()
            # Trial code: set expiry from activation time if not already set
            new_expires = row.get("expires_at")
            if row.get("trial_hours") and not new_expires:
                new_expires = (now + timedelta(hours=float(row["trial_hours"]))).isoformat()
            cur.execute("UPDATE licenses SET hwid=%s, activated_at=%s, expires_at=%s WHERE code=%s",
                        (hwid, now.isoformat(), new_expires, code))
            note = row.get("note") or "—"
            trial_tag = f" · Trial {row['trial_hours']}h" if row.get("trial_hours") else ""
            fire_webhook("🔑 License Activated",
                         f"**User:** {note}{trial_tag}\n**Code:** `{code}`\n**HWID:** `{hwid[:20]}...`",
                         color=0x2ecc71)
        _log(cur, hwid, "ACTIVATE", f"code={code}", request.remote_addr)
    finally:
        conn.close()
    return jsonify(ok=True)

@app.post("/verify")
def verify():
    data = request.json or {}
    hwid = (data.get("hwid") or "").strip().upper()
    ver  = (data.get("version") or "").strip()
    secs = int(data.get("session_seconds", 0))
    ip   = request.remote_addr
    if not hwid: return jsonify(valid=False), 400
    row, err = _valid_license(hwid)
    if err == "disabled":
        conn, cur = db()
        try: _log(cur, hwid, "BLOCKED", "attempted verify while banned", ip)
        finally: conn.close()
        return jsonify(valid=False, error="disabled")
    if err == "expired":
        conn, cur = db()
        try: _log(cur, hwid, "EXPIRED", f"license expired at {row.get('expires_at','?')}", ip)
        finally: conn.close()
        return jsonify(valid=False, error="expired")
    if err or not row:
        return jsonify(valid=False, error=err or "no license")
    conn, cur = db()
    try:
        now_iso = datetime.utcnow().isoformat()
        cur.execute("UPDATE licenses SET last_seen=%s, total_seconds=COALESCE(total_seconds,0)+%s, app_version=%s WHERE hwid=%s",
                    (now_iso, secs, ver or row.get("app_version"), hwid))
        cur.execute("UPDATE active_sessions SET last_seen=%s WHERE hwid=%s", (now_iso, hwid))
        if ver and ver != CURRENT_VERSION:
            _log(cur, hwid, "VERSION_OLD", f"client={ver} server={CURRENT_VERSION}", ip)
        cur.execute("SELECT message, updated_at FROM broadcast WHERE id=1")
        b = cur.fetchone()
        cur.execute("SELECT id, message FROM user_messages WHERE hwid=%s AND delivered=FALSE ORDER BY created_at LIMIT 1", (hwid,))
        um = cur.fetchone()
        if um:
            cur.execute("UPDATE user_messages SET delivered=TRUE WHERE id=%s", (um["id"],))
    finally:
        conn.close()
    return jsonify(valid=True, expires_at=row.get("expires_at"), note=row.get("note"),
                   current_version=CURRENT_VERSION, download_url=DOWNLOAD_URL or None,
                   broadcast=dict(b) if b and b.get("message") else None,
                   user_message=um["message"] if um else None)

@app.post("/generate")
def generate():
    data = request.json or {}
    if not _auth(data): return jsonify(ok=False), 401
    count       = int(data.get("count", 1))
    note        = (data.get("note") or "").strip()
    days        = data.get("expires_days")
    trial_hours = data.get("trial_hours")
    max_sess    = int(data.get("max_sessions", 1) or 1)
    expires = None
    if days:
        try: expires = (datetime.utcnow() + timedelta(days=float(days))).isoformat()
        except: pass
    if trial_hours:
        try: trial_hours = float(trial_hours)
        except: trial_hours = None
    conn, cur = db()
    new = []
    try:
        for _ in range(count):
            c = gen_code()
            cur.execute(
                "INSERT INTO licenses(code, created_at, note, expires_at, trial_hours, max_sessions) VALUES(%s,%s,%s,%s,%s,%s)",
                (c, datetime.utcnow().isoformat(), note, expires, trial_hours, max_sess))
            new.append(c)
    finally:
        conn.close()
    return jsonify(ok=True, codes=new)

@app.post("/list")
def list_codes():
    data = request.json or {}
    if not _auth(data): return jsonify(ok=False), 401
    conn, cur = db()
    try:
        cur.execute("SELECT * FROM licenses ORDER BY created_at DESC")
        rows = [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()
    return jsonify(ok=True, codes=rows, current_version=CURRENT_VERSION)

@app.post("/revoke")
def revoke():
    data = request.json or {}
    if not _auth(data): return jsonify(ok=False), 401
    code = (data.get("code") or "").strip().upper()
    conn, cur = db()
    try:
        cur.execute("SELECT hwid, note FROM licenses WHERE code=%s", (code,))
        row = cur.fetchone()
        cur.execute("DELETE FROM licenses WHERE code=%s", (code,))
        if row and row["hwid"]:
            _log(cur, row["hwid"], "REVOKE", f"code={code} note={row.get('note','')}", request.remote_addr)
    finally:
        conn.close()
    return jsonify(ok=True)

@app.post("/disable")
def toggle_disable():
    data = request.json or {}
    if not _auth(data): return jsonify(ok=False), 401
    code = (data.get("code") or "").strip().upper()
    disabled_val = 1 if data.get("disabled") else 0
    conn, cur = db()
    try:
        cur.execute("UPDATE licenses SET disabled=%s WHERE code=%s", (disabled_val, code))
        cur.execute("SELECT hwid, note FROM licenses WHERE code=%s", (code,))
        row = cur.fetchone()
        if row and row["hwid"]:
            event = "BAN" if disabled_val else "UNBAN"
            _log(cur, row["hwid"], event, f"code={code}", request.remote_addr)
            note = row.get("note") or "—"
            if disabled_val:
                fire_webhook("🚫 User Banned", f"**User:** {note}\n**Code:** `{code}`", color=0xe74c3c)
            else:
                fire_webhook("✅ User Unbanned", f"**User:** {note}\n**Code:** `{code}`", color=0x2ecc71)
    finally:
        conn.close()
    return jsonify(ok=True)

@app.post("/set_expiry")
def set_expiry():
    data = request.json or {}
    if not _auth(data): return jsonify(ok=False), 401
    code = (data.get("code") or "").strip().upper()
    days = data.get("days")
    expires = None
    if days not in (None, "", 0, "0"):
        try: expires = (datetime.utcnow() + timedelta(days=float(days))).isoformat()
        except: pass
    conn, cur = db()
    try:
        cur.execute("SELECT hwid FROM licenses WHERE code=%s", (code,))
        row = cur.fetchone()
        cur.execute("UPDATE licenses SET expires_at=%s WHERE code=%s", (expires, code))
        if row and row["hwid"]:
            label = f"new={expires or 'lifetime'}"
            _log(cur, row["hwid"], "EXPIRY_CHANGED", label, request.remote_addr)
    finally:
        conn.close()
    return jsonify(ok=True)

@app.post("/reset")
def reset_hwid():
    data = request.json or {}
    if not _auth(data): return jsonify(ok=False), 401
    code = (data.get("code") or "").strip().upper()
    conn, cur = db()
    try:
        cur.execute("SELECT hwid FROM licenses WHERE code=%s", (code,))
        row = cur.fetchone()
        if row and row["hwid"]:
            _log(cur, row["hwid"], "HWID_RESET", f"code={code}", request.remote_addr)
        cur.execute("UPDATE licenses SET hwid=NULL, activated_at=NULL WHERE code=%s", (code,))
    finally:
        conn.close()
    return jsonify(ok=True)

@app.post("/send_to_all")
def send_to_all():
    data = request.json or {}
    if not _auth(data): return jsonify(ok=False), 401
    message = (data.get("message") or "").strip()
    if not message: return jsonify(ok=False, error="missing message"), 400
    conn, cur = db()
    count = 0
    try:
        cutoff = (datetime.utcnow() - timedelta(minutes=10)).isoformat()
        cur.execute("SELECT hwid FROM licenses WHERE hwid IS NOT NULL AND last_seen > %s", (cutoff,))
        rows = cur.fetchall()
        for row in rows:
            cur.execute("INSERT INTO user_messages(hwid, message, created_at) VALUES(%s,%s,%s)",
                        (row["hwid"], message, datetime.utcnow().isoformat()))
            count += 1
    finally:
        conn.close()
    return jsonify(ok=True, sent=count)

@app.post("/send_to_user")
def send_to_user():
    data = request.json or {}
    if not _auth(data): return jsonify(ok=False), 401
    hwid = (data.get("hwid") or "").strip().upper()
    message = (data.get("message") or "").strip()
    if not hwid or not message: return jsonify(ok=False, error="missing hwid or message"), 400
    conn, cur = db()
    try:
        cur.execute("INSERT INTO user_messages(hwid, message, created_at) VALUES(%s,%s,%s)",
                    (hwid, message, datetime.utcnow().isoformat()))
        _log(cur, hwid, "MESSAGE", message[:80], request.remote_addr)
    finally:
        conn.close()
    return jsonify(ok=True)

@app.post("/broadcast")
def set_broadcast():
    data = request.json or {}
    if not _auth(data): return jsonify(ok=False), 401
    msg = (data.get("message") or "").strip()
    conn, cur = db()
    try:
        if msg:
            cur.execute("DELETE FROM broadcast WHERE id=1")
            cur.execute("INSERT INTO broadcast(id, message, updated_at) VALUES(1, %s, %s)",
                        (msg, datetime.utcnow().isoformat()))
        else:
            cur.execute("DELETE FROM broadcast WHERE id=1")
    finally:
        conn.close()
    return jsonify(ok=True)

@app.post("/session-start")
def session_start():
    """Client calls this on launch. Enforces max_sessions limit."""
    data = request.json or {}
    hwid = (data.get("hwid") or "").strip().upper()
    ver  = (data.get("version") or "").strip()
    if not hwid: return jsonify(ok=False, error="missing hwid"), 400
    row, err = _valid_license(hwid)
    if err or not row: return jsonify(ok=False, error=err or "no license")
    conn, cur = db()
    try:
        # Check if there's already an active session (heartbeat seen < 2 min ago)
        cutoff = (datetime.utcnow() - timedelta(minutes=2)).isoformat()
        cur.execute("SELECT last_seen FROM active_sessions WHERE hwid=%s", (hwid,))
        existing = cur.fetchone()
        if existing and (existing["last_seen"] or "") > cutoff:
            _log(cur, hwid, "SESSION_BLOCKED", "duplicate session attempt", request.remote_addr)
            return jsonify(ok=False, error="session already active on another instance"), 409
        now = datetime.utcnow().isoformat()
        cur.execute("""
            INSERT INTO active_sessions(hwid, started_at, last_seen) VALUES(%s,%s,%s)
            ON CONFLICT(hwid) DO UPDATE SET started_at=EXCLUDED.started_at, last_seen=EXCLUDED.last_seen
        """, (hwid, now, now))
        _log(cur, hwid, "SESSION_START", f"version={ver}", request.remote_addr)
    finally:
        conn.close()
    return jsonify(ok=True)

@app.post("/session-end")
def session_end():
    """Client calls this on clean shutdown."""
    data = request.json or {}
    hwid = (data.get("hwid") or "").strip().upper()
    ver  = (data.get("version") or "").strip()
    secs = int(data.get("session_seconds", 0))
    if not hwid: return jsonify(ok=False, error="missing hwid"), 400
    conn, cur = db()
    try:
        h = round(secs / 3600, 2)
        cur.execute("DELETE FROM active_sessions WHERE hwid=%s", (hwid,))
        _log(cur, hwid, "SESSION_END", f"duration={h}h version={ver}", request.remote_addr)
    finally:
        conn.close()
    return jsonify(ok=True)

@app.post("/client-event")
def client_event():
    """Generic event endpoint — client can report anything."""
    data = request.json or {}
    hwid    = (data.get("hwid") or "").strip().upper()
    event   = (data.get("event") or "").strip().upper()
    details = (data.get("details") or "").strip()
    if not hwid or not event: return jsonify(ok=False, error="missing hwid or event"), 400
    row, err = _valid_license(hwid)
    if err or not row: return jsonify(ok=False, error=err or "no license")
    conn, cur = db()
    try:
        _log(cur, hwid, event, details[:200], request.remote_addr)
    finally:
        conn.close()
    return jsonify(ok=True)

@app.post("/set_version")
def set_version():
    data = request.json or {}
    if not _auth(data): return jsonify(ok=False), 401
    global CURRENT_VERSION
    CURRENT_VERSION = (data.get("version") or "").strip() or CURRENT_VERSION
    return jsonify(ok=True, current_version=CURRENT_VERSION)

# ---------------------------------------------------------------------------
# Advanced admin endpoints (new — used by the sidebar admin panel)
# ---------------------------------------------------------------------------

@app.post("/admin-system-stats")
def admin_system_stats():
    data = request.json or {}
    if not _auth(data): return jsonify(ok=False), 401
    now = datetime.utcnow()
    conn, cur = db()
    try:
        cur.execute("SELECT COUNT(*) as v FROM licenses WHERE hwid IS NOT NULL")
        total_users = cur.fetchone()["v"]
        cur.execute("SELECT COUNT(*) as v FROM licenses WHERE hwid IS NOT NULL AND disabled=0")
        active_users = cur.fetchone()["v"]
        cur.execute("SELECT COUNT(*) as v FROM licenses WHERE disabled=1")
        banned = cur.fetchone()["v"]
        cur.execute("SELECT COUNT(*) as v FROM licenses WHERE hwid IS NOT NULL AND last_seen > %s",
                    ((now - timedelta(minutes=5)).isoformat(),))
        online = cur.fetchone()["v"]
        cur.execute("SELECT COUNT(*) as v FROM licenses WHERE hwid IS NOT NULL AND last_seen > %s",
                    ((now - timedelta(hours=24)).isoformat(),))
        active_24h = cur.fetchone()["v"]
        cur.execute("SELECT COALESCE(SUM(total_seconds),0) as v FROM licenses WHERE hwid IS NOT NULL")
        total_secs = cur.fetchone()["v"] or 0
        cur.execute("SELECT AVG(total_seconds) as v FROM licenses WHERE hwid IS NOT NULL AND total_seconds > 0")
        avg_row = cur.fetchone()
        avg_secs = float(avg_row["v"]) if avg_row and avg_row["v"] else 0
        cur.execute("SELECT app_version, COUNT(*) as cnt FROM licenses WHERE hwid IS NOT NULL GROUP BY app_version ORDER BY cnt DESC")
        versions = [dict(r) for r in cur.fetchall()]
        cur.execute("SELECT COUNT(*) as v FROM licenses")
        total_codes = cur.fetchone()["v"]
        cur.execute("SELECT COUNT(*) as v FROM licenses WHERE hwid IS NULL")
        unused_codes = cur.fetchone()["v"]
    finally:
        conn.close()
    return jsonify(ok=True,
        users={"total": total_users, "active": active_users, "online": online,
               "active_24h": active_24h, "banned": banned},
        playtime={"total_seconds": total_secs, "avg_seconds": avg_secs, "total_hours": total_secs / 3600},
        versions=versions,
        codes={"total": total_codes, "unused": unused_codes, "used": total_codes - unused_codes}
    )

@app.post("/admin-all-users")
def admin_all_users():
    data = request.json or {}
    if not _auth(data): return jsonify(ok=False), 401
    now_iso = datetime.utcnow().isoformat()
    status = data.get("status")
    search = (data.get("search") or "").strip()
    conn, cur = db()
    try:
        query = "SELECT * FROM licenses WHERE hwid IS NOT NULL"
        params = []
        if status == "active":
            query += " AND disabled=0 AND (expires_at IS NULL OR expires_at > %s)"
            params.append(now_iso)
        elif status == "expired":
            query += " AND expires_at IS NOT NULL AND expires_at <= %s"
            params.append(now_iso)
        elif status == "banned":
            query += " AND disabled=1"
        elif status == "inactive":
            query += " AND last_seen < %s"
            params.append((datetime.utcnow() - timedelta(hours=24)).isoformat())
        if search:
            query += " AND (hwid ILIKE %s OR note ILIKE %s)"
            params += [f"%{search}%", f"%{search}%"]
        query += " ORDER BY last_seen DESC NULLS LAST LIMIT 500"
        cur.execute(query, tuple(params) if params else ())
        users = [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()
    return jsonify(ok=True, users=users)

@app.post("/admin-user-details/<hwid>")
def admin_user_details(hwid):
    data = request.json or {}
    if not _auth(data): return jsonify(ok=False), 401
    hwid = hwid.upper()
    conn, cur = db()
    try:
        cur.execute("SELECT * FROM licenses WHERE hwid=%s", (hwid,))
        user = cur.fetchone()
        if not user:
            return jsonify(ok=False, error="User not found"), 404
        cur.execute("SELECT * FROM activity_logs WHERE hwid=%s ORDER BY created_at DESC LIMIT 50", (hwid,))
        logs = [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()
    return jsonify(ok=True, user=dict(user), activity=logs)

@app.post("/admin-activity-logs")
def admin_activity_logs():
    data = request.json or {}
    if not _auth(data): return jsonify(ok=False), 401
    hwid = (data.get("hwid") or "").strip().upper() or None
    event_type = data.get("event_type") or None
    limit = min(int(data.get("limit", 100)), 500)
    conn, cur = db()
    try:
        query = """
            SELECT a.*, l.note
            FROM activity_logs a
            LEFT JOIN licenses l ON UPPER(l.hwid) = UPPER(a.hwid)
            WHERE 1=1
        """
        params = []
        if hwid:
            query += " AND UPPER(a.hwid)=%s"
            params.append(hwid)
        if event_type:
            query += " AND a.event_type=%s"
            params.append(event_type)
        query += " ORDER BY a.created_at DESC LIMIT %s"
        params.append(limit)
        cur.execute(query, tuple(params))
        logs = [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()
    return jsonify(ok=True, logs=logs)

@app.post("/admin-bulk-ban")
def admin_bulk_ban():
    data = request.json or {}
    if not _auth(data): return jsonify(ok=False), 401
    hwidlist = data.get("hwidlist", [])
    if not hwidlist: return jsonify(ok=False, error="no users"), 400
    conn, cur = db()
    try:
        for hwid in hwidlist:
            cur.execute("UPDATE licenses SET disabled=1 WHERE hwid=%s", (hwid.upper(),))
            _log(cur, hwid.upper(), "BAN", "bulk ban", request.remote_addr)
    finally:
        conn.close()
    return jsonify(ok=True, banned=len(hwidlist))

# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.get("/")
def health():
    return "AntiAFK License Server OK"

# ---------------------------------------------------------------------------
# Admin UI — full sidebar SPA with all features
# ---------------------------------------------------------------------------

ADMIN_HTML = """<!doctype html><html lang='en'><head><meta charset='utf-8'>
<title>AntiAFK Admin</title>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#080c1f;color:#e0e6ff;min-height:100vh;font-size:13px}
/* ---- Login ---- */
.login-wrap{display:flex;align-items:center;justify-content:center;min-height:100vh;background:linear-gradient(135deg,#080c1f 0%,#0f1a3a 100%)}
.login-card{background:#111827;border:1px solid #1e2d4a;border-radius:12px;padding:40px;width:360px;text-align:center}
.login-card h1{color:#e94560;font-size:24px;margin-bottom:6px}
.login-card p{color:#6b7a9a;font-size:12px;margin-bottom:28px}
.login-card input{width:100%;padding:11px 14px;background:#0f1a3a;color:#fff;border:1px solid #1e2d4a;border-radius:7px;font-size:14px;margin-bottom:12px;outline:none;transition:.2s}
.login-card input:focus{border-color:#e94560}
.login-card button{width:100%;padding:12px;background:#e94560;color:#fff;border:none;border-radius:7px;font-size:14px;font-weight:700;cursor:pointer;transition:.2s}
.login-card button:hover{background:#c73652}
/* ---- Layout ---- */
.layout{display:flex;height:100vh;overflow:hidden}
.sidebar{width:220px;background:#0d1225;border-right:1px solid #1a2540;display:flex;flex-direction:column;padding:0;flex-shrink:0}
.sidebar-header{padding:20px 18px 16px;border-bottom:1px solid #1a2540}
.sidebar-header h2{color:#e94560;font-size:16px;font-weight:700}
.sidebar-header p{color:#4a5680;font-size:11px;margin-top:2px}
.sidebar-nav{padding:12px 10px;flex:1;overflow-y:auto}
.nav{display:flex;align-items:center;gap:10px;padding:10px 12px;border-radius:7px;cursor:pointer;color:#6b7a9a;font-size:13px;font-weight:500;transition:.15s;margin-bottom:2px}
.nav:hover{background:#151e38;color:#c0caf5}
.nav.active{background:#1e0a14;color:#e94560}
.nav .icon{font-size:15px;width:18px;text-align:center}
.sidebar-footer{padding:12px 10px;border-top:1px solid #1a2540}
.nav-logout{color:#ff6b81 !important}
.nav-logout:hover{background:#1e0a14 !important}
.main{flex:1;overflow-y:auto;padding:28px 32px;background:#080c1f}
/* ---- Page header ---- */
.page-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:24px}
.page-header h2{font-size:20px;font-weight:700;color:#c0caf5}
/* ---- Stat grid ---- */
.stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:24px}
.stat-card{background:#111827;border:1px solid #1e2d4a;border-radius:10px;padding:18px}
.stat-card .label{color:#4a5680;font-size:10px;text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px}
.stat-card .value{font-size:28px;font-weight:700;color:#e0e6ff}
.stat-card .sub{font-size:10px;color:#4a5680;margin-top:2px}
/* ---- Card ---- */
.card{background:#111827;border:1px solid #1e2d4a;border-radius:10px;padding:20px;margin-bottom:16px}
.card-title{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:#4a5680;margin-bottom:16px}
/* ---- Table ---- */
.table-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;min-width:500px}
th{padding:10px 12px;text-align:left;background:#0d1225;color:#4a5680;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.4px;border-bottom:1px solid #1a2540}
td{padding:10px 12px;border-bottom:1px solid #0f1a3a;font-size:12px;color:#c0caf5}
tr:last-child td{border-bottom:none}
tbody tr:hover td{background:#0f1530}
/* ---- Badges ---- */
.badge{display:inline-flex;align-items:center;padding:3px 9px;border-radius:20px;font-size:10px;font-weight:700;letter-spacing:.3px}
.badge-active{background:#0d2e1a;color:#2ecc71;border:1px solid #1a4d2e}
.badge-banned{background:#2e0d14;color:#ff6b81;border:1px solid #4d1a24}
.badge-expired{background:#2e240d;color:#f1c40f;border:1px solid #4d3d1a}
.badge-unused{background:#151e38;color:#6b7a9a;border:1px solid #1e2d4a}
/* ---- Buttons ---- */
.btn{display:inline-flex;align-items:center;gap:5px;padding:8px 14px;border:none;border-radius:6px;cursor:pointer;font-size:12px;font-weight:600;transition:.15s;white-space:nowrap}
.btn-primary{background:#e94560;color:#fff}.btn-primary:hover{background:#c73652}
.btn-ghost{background:#111827;color:#6b7a9a;border:1px solid #1e2d4a}.btn-ghost:hover{background:#151e38;color:#c0caf5;border-color:#2a3d5e}
.btn-danger{background:#2e0d14;color:#ff6b81;border:1px solid #4d1a24}.btn-danger:hover{background:#3d1020}
.btn-sm{padding:5px 10px;font-size:11px}
/* ---- Inputs ---- */
input,textarea,select{background:#0d1225;color:#e0e6ff;border:1px solid #1e2d4a;border-radius:6px;padding:9px 12px;font-size:12px;font-family:inherit;outline:none;transition:.2s}
input:focus,textarea:focus,select:focus{border-color:#e94560}
select{cursor:pointer}
textarea{resize:vertical}
.input-row{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:12px}
/* ---- Filter pills ---- */
.filter-row{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:14px}
.pill{padding:6px 14px;border-radius:20px;border:1px solid #1e2d4a;background:#0d1225;color:#6b7a9a;font-size:11px;font-weight:600;cursor:pointer;transition:.15s}
.pill:hover{border-color:#2a3d5e;color:#c0caf5}
.pill.active{background:#1e0a14;border-color:#e94560;color:#e94560}
/* ---- Online dot ---- */
.dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:#2ecc71;margin-right:5px;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.5;transform:scale(.8)}}
/* ---- Modal ---- */
.modal-bg{display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:200;align-items:center;justify-content:center;backdrop-filter:blur(2px)}
.modal-bg.show{display:flex}
.modal{background:#111827;border:1px solid #1e2d4a;border-radius:12px;padding:28px;width:92%;max-width:580px;max-height:85vh;overflow-y:auto;position:relative}
.modal h3{color:#e94560;font-size:17px;margin-bottom:20px}
.modal-close{position:absolute;top:16px;right:20px;font-size:20px;cursor:pointer;color:#4a5680;line-height:1}
.modal-close:hover{color:#e0e6ff}
.modal-stat-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:18px}
.modal-stat{background:#0d1225;border:1px solid #1a2540;border-radius:8px;padding:12px}
.modal-stat .label{color:#4a5680;font-size:10px;text-transform:uppercase;margin-bottom:4px}
.modal-stat .value{font-size:20px;font-weight:700}
.info-row{display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid #0f1a3a;font-size:12px}
.info-row:last-child{border:none}
.info-row .lbl{color:#4a5680}
.log-entry{display:grid;grid-template-columns:140px 130px 1fr;gap:8px;padding:6px 0;border-bottom:1px solid #0f1a3a;font-size:11px;align-items:start}
.log-entry:last-child{border:none}
/* ---- Toast ---- */
.toast{position:fixed;bottom:24px;right:24px;background:#1e2d4a;color:#e0e6ff;padding:12px 20px;border-radius:8px;border:1px solid #2a3d5e;opacity:0;transition:opacity .25s;z-index:300;pointer-events:none;font-size:13px}
.toast.show{opacity:1}
.hide{display:none}
.mono{font-family:'Consolas','Monaco',monospace;font-size:11px}
.muted{color:#4a5680}
/* ---- Scrollbar ---- */
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:#080c1f}
::-webkit-scrollbar-thumb{background:#1e2d4a;border-radius:3px}
</style></head><body>

<!-- LOGIN -->
<div id="login-wrap" class="login-wrap">
  <div class="login-card">
    <h1>AntiAFK</h1>
    <p>License Management Console</p>
    <input id="key-input" type="password" placeholder="Enter admin key..." autofocus>
    <button id="login-btn">Sign In</button>
  </div>
</div>

<!-- APP -->
<div id="app" class="layout hide">
  <div class="sidebar">
    <div class="sidebar-header">
      <h2>🚀 AntiAFK</h2>
      <p>Admin Console</p>
    </div>
    <div class="sidebar-nav">
      <div class="nav active" data-tab="overview"><span class="icon">📊</span>Overview</div>
      <div class="nav" data-tab="users"><span class="icon">👥</span>Users</div>
      <div class="nav" data-tab="logs"><span class="icon">📜</span>Activity Logs</div>
      <div class="nav" data-tab="codes"><span class="icon">🎟</span>License Codes</div>
      <div class="nav" data-tab="messages"><span class="icon">💬</span>Messages</div>
      <div class="nav" data-tab="analytics"><span class="icon">📈</span>Analytics</div>
      <div class="nav" data-tab="settings"><span class="icon">⚙️</span>Settings</div>
    </div>
    <div class="sidebar-footer">
      <div class="nav nav-logout" id="logout-btn"><span class="icon">↩</span>Logout</div>
    </div>
  </div>

  <div class="main">

    <!-- OVERVIEW -->
    <div id="tab-overview" class="tab-page">
      <div class="page-header">
        <h2>System Overview</h2>
        <button class="btn btn-ghost btn-sm" id="ov-refresh-btn">↻ Refresh</button>
      </div>
      <div class="stat-grid">
        <div class="stat-card"><div class="label">Total Users</div><div class="value" id="ov-total">—</div></div>
        <div class="stat-card"><div class="label">Active</div><div class="value" id="ov-active">—</div></div>
        <div class="stat-card"><div class="label">Online Now</div><div class="value"><span class="dot"></span><span id="ov-online">—</span></div></div>
        <div class="stat-card"><div class="label">Banned</div><div class="value" id="ov-banned">—</div></div>
        <div class="stat-card"><div class="label">Avg Playtime</div><div class="value" id="ov-avg">—</div></div>
        <div class="stat-card"><div class="label">Total Hours</div><div class="value" id="ov-hours">—</div></div>
      </div>
      <div class="card">
        <div class="card-title">Top 10 Users by Playtime</div>
        <div class="table-wrap">
          <table><thead><tr><th>Status</th><th>Username</th><th>Playtime</th><th>Last Seen</th><th>Version</th></tr></thead>
          <tbody id="ov-top"><tr><td colspan="5" style="text-align:center;color:#4a5680;padding:24px">Loading...</td></tr></tbody></table>
        </div>
      </div>
    </div>

    <!-- USERS -->
    <div id="tab-users" class="tab-page hide">
      <div class="page-header"><h2>User Management</h2></div>
      <div class="card">
        <div class="input-row">
          <input type="text" id="user-search" placeholder="Search by username or HWID..." style="flex:1;min-width:180px">
          <button class="btn btn-primary" id="user-search-btn">Search</button>
        </div>
        <div class="filter-row">
          <div class="pill active" data-filter="all">All</div>
          <div class="pill" data-filter="active">Active</div>
          <div class="pill" data-filter="banned">Banned</div>
          <div class="pill" data-filter="expired">Expired</div>
          <div class="pill" data-filter="inactive">Inactive 24h+</div>
        </div>
        <div class="table-wrap">
          <table><thead><tr><th>Status</th><th>Username / HWID</th><th>Playtime</th><th>Last Seen</th><th>Version</th><th>Actions</th></tr></thead>
          <tbody id="users-tbody"></tbody></table>
        </div>
      </div>
    </div>

    <!-- LOGS -->
    <div id="tab-logs" class="tab-page hide">
      <div class="page-header"><h2>Activity Logs</h2></div>
      <div class="card">
        <div class="input-row">
          <select id="log-user" style="flex:1;min-width:180px">
            <option value="">All Users</option>
          </select>
          <button class="btn btn-ghost btn-sm" id="logs-user-refresh" title="Refresh user list" style="padding:0 10px">↻</button>
          <select id="log-type" style="min-width:180px">
            <option value="">All Events</option>
            <optgroup label="── Session ──">
              <option value="ACTIVATE">Activate</option>
              <option value="SESSION_START">Session Start</option>
              <option value="SESSION_END">Session End</option>
            </optgroup>
            <optgroup label="── In-Game ──">
              <option value="AFK_DETECTED">AFK Detected</option>
              <option value="AFK_HIT">AFK Hit</option>
              <option value="AFK_LOOP_START">AFK Loop Start</option>
              <option value="AFK_LOOP_STOP">AFK Loop Stop</option>
              <option value="GAME_DETECTED">Game Detected</option>
              <option value="GAME_LOST">Game Lost</option>
            </optgroup>
            <optgroup label="── Access ──">
              <option value="BLOCKED">Blocked</option>
              <option value="EXPIRED">License Expired</option>
              <option value="VERSION_OLD">Version Outdated</option>
            </optgroup>
            <optgroup label="── Admin ──">
              <option value="BAN">Ban</option>
              <option value="UNBAN">Unban</option>
              <option value="HWID_RESET">HWID Reset</option>
              <option value="REVOKE">Code Revoked</option>
              <option value="EXPIRY_CHANGED">Expiry Changed</option>
              <option value="MESSAGE">Direct Message</option>
            </optgroup>
          </select>
          <button class="btn btn-primary" id="logs-load-btn">Load Logs</button>
        </div>
        <div class="table-wrap">
          <table><thead><tr><th>Time</th><th>Username</th><th>Event</th><th>Details</th></tr></thead>
          <tbody id="logs-tbody"></tbody></table>
        </div>
      </div>
    </div>

    <!-- CODES -->
    <div id="tab-codes" class="tab-page hide">
      <div class="page-header"><h2>License Codes</h2></div>
      <div class="card">
        <div class="card-title">Generate New Codes</div>
        <div class="input-row">
          <input type="number" id="code-qty" value="1" min="1" max="100" style="width:60px" placeholder="Qty">
          <input type="text" id="code-note" placeholder="Username / note" style="flex:1;min-width:120px">
          <select id="code-expiry" title="Expiry mode">
            <option value="lifetime:">Lifetime</option>
            <optgroup label="── Fixed (from now) ──">
              <option value="days:1">1 Day</option>
              <option value="days:7">7 Days</option>
              <option value="days:30">30 Days</option>
              <option value="days:90">90 Days</option>
              <option value="days:365">1 Year</option>
            </optgroup>
            <optgroup label="── Trial (from activation) ──">
              <option value="trial:1">Trial 1h</option>
              <option value="trial:6">Trial 6h</option>
              <option value="trial:24">Trial 24h</option>
              <option value="trial:72">Trial 3 Days</option>
              <option value="trial:168">Trial 7 Days</option>
            </optgroup>
          </select>
          <button class="btn btn-primary" id="gen-btn">Generate</button>
        </div>
      </div>
      <div class="card">
        <div class="input-row" style="margin-bottom:14px">
          <div class="card-title" style="margin:0;flex:1">All Codes</div>
          <span id="codes-status" class="muted"></span>
          <button class="btn btn-ghost btn-sm" id="codes-refresh-btn">↻ Refresh</button>
        </div>
        <div class="table-wrap">
          <table><thead><tr><th>Status</th><th>Code</th><th>Note</th><th>Expires</th><th>Hours</th><th>Last Seen</th><th>Ver</th><th>Actions</th></tr></thead>
          <tbody id="codes-tbody"></tbody></table>
        </div>
      </div>
    </div>

    <!-- MESSAGES -->
    <div id="tab-messages" class="tab-page hide">
      <div class="page-header"><h2>Messages</h2></div>
      <div class="card">
        <div class="card-title">Broadcast — All Active Users</div>
        <textarea id="broadcast-msg" placeholder="Send a message to all users currently online (seen in last 10 min)..." style="width:100%;height:80px;margin-bottom:12px"></textarea>
        <div class="input-row" style="margin:0">
          <button class="btn btn-primary" id="broadcast-btn">📢 Send to All Active</button>
          <button class="btn btn-ghost" id="broadcast-clear-btn">Clear Broadcast</button>
        </div>
      </div>
      <div class="card">
        <div class="card-title">Direct Message</div>
        <div class="input-row">
          <select id="dm-user-select" style="flex:1;min-width:220px"><option value="">— select a user —</option></select>
          <button class="btn btn-ghost btn-sm" id="dm-refresh-btn">↻</button>
        </div>
        <div class="input-row">
          <input type="text" id="dm-hwid" placeholder="HWID (auto-filled above)" style="flex:1">
        </div>
        <textarea id="dm-msg" placeholder="Your message..." style="width:100%;height:70px;margin-bottom:12px"></textarea>
        <button class="btn btn-primary" id="dm-btn">📩 Send Message</button>
      </div>
    </div>

    <!-- ANALYTICS -->
    <div id="tab-analytics" class="tab-page hide">
      <div class="page-header"><h2>Analytics</h2></div>
      <div class="stat-grid">
        <div class="stat-card"><div class="label">Active (24h)</div><div class="value" id="an-24h">—</div></div>
        <div class="stat-card"><div class="label">Churn Rate</div><div class="value" id="an-churn">—</div><div class="sub">%</div></div>
        <div class="stat-card"><div class="label">Code Usage</div><div class="value" id="an-usage">—</div><div class="sub">%</div></div>
        <div class="stat-card"><div class="label">Unused Codes</div><div class="value" id="an-unused">—</div></div>
      </div>
      <div class="card">
        <div class="card-title">Version Distribution</div>
        <div id="an-versions"><p class="muted">Loading...</p></div>
      </div>
    </div>

    <!-- SETTINGS -->
    <div id="tab-settings" class="tab-page hide">
      <div class="page-header"><h2>Settings</h2></div>
      <div class="card">
        <div class="card-title">Server Version</div>
        <p class="muted" style="margin-bottom:12px;font-size:12px">Set the current app version. Clients running a different version will be flagged as VERSION_OLD in logs.</p>
        <div class="input-row">
          <input type="text" id="set-version-input" placeholder="e.g. 1.2.0" style="flex:1;max-width:200px">
          <button class="btn btn-primary" id="set-version-btn">Update Version</button>
        </div>
        <p style="font-size:12px">Current: <strong id="current-version-display" style="color:#e94560">—</strong></p>
      </div>
      <div class="card">
        <div class="card-title">Database Status</div>
        <div class="info-row"><span class="lbl">Connection</span><span style="color:#2ecc71">● Connected</span></div>
        <div class="info-row"><span class="lbl">Admin Key</span><span style="color:#2ecc71">● Set</span></div>
      </div>
    </div>

  </div>
</div>

<!-- USER MODAL -->
<div id="user-modal" class="modal-bg">
  <div class="modal">
    <span class="modal-close" id="modal-close">&times;</span>
    <div id="modal-body"></div>
  </div>
</div>

<div id="toast" class="toast"></div>

<script>
let KEY = sessionStorage.getItem('akey') || '';
let userFilter = 'all';

// ── Event colours (session + in-game + admin) ──
const EV = {
  SESSION_START:'#2ecc71', SESSION_END:'#27ae60', ACTIVATE:'#4fc3f7',
  AFK_TRIGGERED:'#e67e22', AFK_LOOP_START:'#f39c12', AFK_LOOP_STOP:'#d35400',
  GAME_DETECTED:'#1abc9c', GAME_LOST:'#e74c3c',
  CIRCLE_DETECTED:'#9b59b6', CIRCLE_MISSED:'#8e44ad',
  BLOCKED:'#ff6b81', EXPIRED:'#f1c40f', VERSION_OLD:'#e67e22',
  BAN:'#e74c3c', UNBAN:'#2ecc71', HWID_RESET:'#9b59b6',
  REVOKE:'#e74c3c', EXPIRY_CHANGED:'#e67e22', MESSAGE:'#4fc3f7'
};
function evColor(t){ return EV[t]||'#6b7a9a'; }

// ── Utils ──
function toast(m, dur=2200){
  const t=document.getElementById('toast');
  t.textContent=m; t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'), dur);
}
async function api(path, body){
  try{
    const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    if(!r.ok) return {ok:false,error:'HTTP '+r.status};
    return await r.json();
  }catch(e){ return {ok:false,error:e.message}; }
}
function fmt(i){
  if(!i) return '—';
  return new Date(i.includes('Z')?i:i+'Z').toLocaleString();
}
function fmtD(i){
  if(!i) return '—';
  return new Date(i.includes('Z')?i:i+'Z').toLocaleDateString();
}
function hrs(s){ return s?(s/3600).toFixed(1)+'h':'0h'; }
function timeAgo(iso){
  if(!iso) return '—';
  const s=Math.floor((Date.now()-new Date(iso.includes('Z')?iso:iso+'Z'))/1000);
  if(s<10) return 'just now';
  if(s<60) return s+'s ago';
  if(s<3600) return Math.floor(s/60)+'m ago';
  if(s<86400) return Math.floor(s/3600)+'h ago';
  return Math.floor(s/86400)+'d ago';
}
function isOnline(iso){
  if(!iso) return false;
  return (Date.now()-new Date(iso.includes('Z')?iso:iso+'Z'))<5*60*1000;
}
function isExp(i){ return i&&new Date(i.includes('Z')?i:i+'Z')<new Date(); }
function badge(u){
  if(u.disabled) return '<span class="badge badge-banned">BANNED</span>';
  if(isExp(u.expires_at)) return '<span class="badge badge-expired">EXPIRED</span>';
  if(u.hwid) return '<span class="badge badge-active">ACTIVE</span>';
  return '<span class="badge badge-unused">UNUSED</span>';
}
function evBadge(t){
  return '<span style="color:'+evColor(t)+';font-weight:700;font-size:11px">'+t+'</span>';
}
function empty(cols, msg){
  return '<tr><td colspan="'+cols+'" style="text-align:center;color:#4a5680;padding:28px">'+msg+'</td></tr>';
}

// ── Auth ──
async function doLogin(){
  const k=document.getElementById('key-input').value.trim();
  if(!k) return;
  const r=await api('/list',{admin_key:k});
  if(!r.ok){ toast('Wrong admin key'); return; }
  KEY=k; sessionStorage.setItem('akey',k);
  document.getElementById('login-wrap').classList.add('hide');
  document.getElementById('app').classList.remove('hide');
  renderCodes(r);
  loadOverview();
}
function doLogout(){ sessionStorage.removeItem('akey'); location.reload(); }
if(KEY){
  document.getElementById('login-wrap').classList.add('hide');
  document.getElementById('app').classList.remove('hide');
  loadOverview(); loadCodes();
}
document.getElementById('login-btn').addEventListener('click', doLogin);
document.getElementById('key-input').addEventListener('keypress',e=>{ if(e.key==='Enter') doLogin(); });
document.getElementById('logout-btn').addEventListener('click', doLogout);

// ── Tabs ──
function switchTab(name){
  document.querySelectorAll('.tab-page').forEach(p=>p.classList.add('hide'));
  document.getElementById('tab-'+name).classList.remove('hide');
  document.querySelectorAll('.nav[data-tab]').forEach(n=>n.classList.remove('active'));
  document.querySelector('.nav[data-tab="'+name+'"]').classList.add('active');
  if(name==='overview') loadOverview();
  else if(name==='users') loadUsers();
  else if(name==='logs'){ populateLogUserDropdown(); loadLogs(); }
  else if(name==='codes') loadCodes();
  else if(name==='messages') loadDMUsers();
  else if(name==='analytics') loadAnalytics();
  else if(name==='settings') loadSettings();
}
document.querySelectorAll('.nav[data-tab]').forEach(n=>{
  n.addEventListener('click',()=>switchTab(n.dataset.tab));
});

// ── Overview ──
async function loadOverview(){
  const r=await api('/admin-system-stats',{admin_key:KEY});
  if(!r.ok){ toast('Error loading stats'); return; }
  document.getElementById('ov-total').textContent=r.users.total;
  document.getElementById('ov-active').textContent=r.users.active;
  document.getElementById('ov-online').textContent=r.users.online;
  document.getElementById('ov-banned').textContent=r.users.banned;
  document.getElementById('ov-avg').textContent=(r.playtime.avg_seconds/3600).toFixed(1)+'h';
  document.getElementById('ov-hours').textContent=r.playtime.total_hours.toFixed(0)+'h';
  const tr=await api('/admin-all-users',{admin_key:KEY});
  if(tr.ok){
    document.getElementById('ov-top').innerHTML=tr.users.slice(0,10).map(u=>
      '<tr>'
      +'<td>'+badge(u)+(isOnline(u.last_seen)?' <span class="dot"></span>':'')+'</td>'
      +'<td>'+(u.note||'<span class="muted">—</span>')+'</td>'
      +'<td>'+hrs(u.total_seconds)+'</td>'
      +'<td title="'+fmt(u.last_seen)+'">'+timeAgo(u.last_seen)+'</td>'
      +'<td class="mono">'+(u.app_version||'—')+'</td>'
      +'</tr>'
    ).join('')||empty(5,'No users yet');
  }
}
document.getElementById('ov-refresh-btn').addEventListener('click', loadOverview);

// ── Users ──
async function loadUsers(){
  const search=document.getElementById('user-search').value.trim();
  const r=await api('/admin-all-users',{admin_key:KEY,status:userFilter==='all'?null:userFilter,search});
  if(!r.ok){ toast('Error: '+(r.error||'?')); return; }
  document.getElementById('users-tbody').innerHTML=r.users.map(u=>
    '<tr data-hwid="'+u.hwid+'" data-note="'+(u.note||'')+'">'
    +'<td>'+badge(u)+(isOnline(u.last_seen)?' <span class="dot"></span>':'')+'</td>'
    +'<td>'
      +(u.note?'<strong style="color:#c0caf5">'+u.note+'</strong><br>':'')
      +'<span class="mono muted">'+(u.hwid||'').slice(0,20)+'...</span>'
    +'</td>'
    +'<td>'+hrs(u.total_seconds)+'</td>'
    +'<td title="'+fmt(u.last_seen)+'">'+timeAgo(u.last_seen)+'</td>'
    +'<td class="mono">'+(u.app_version||'—')+'</td>'
    +'<td><button class="btn btn-ghost btn-sm act-view" style="margin-right:4px">Profile</button>'
      +(u.hwid?'<button class="btn btn-ghost btn-sm act-dm">📩 DM</button>':'')+'</td>'
    +'</tr>'
  ).join('')||empty(6,'No users found');
}
document.getElementById('user-search-btn').addEventListener('click', loadUsers);
document.getElementById('user-search').addEventListener('keypress',e=>{ if(e.key==='Enter') loadUsers(); });
document.querySelectorAll('.pill').forEach(p=>{
  p.addEventListener('click',()=>{
    userFilter=p.dataset.filter;
    document.querySelectorAll('.pill').forEach(x=>x.classList.remove('active'));
    p.classList.add('active');
    loadUsers();
  });
});
document.getElementById('users-tbody').addEventListener('click',e=>{
  const row=e.target.closest('tr[data-hwid]');
  if(!row) return;
  if(e.target.classList.contains('act-view')) viewUser(row.dataset.hwid);
  if(e.target.classList.contains('act-dm')) dmUser(row.dataset.hwid, row.dataset.note);
});

// ── Logs ──
async function populateLogUserDropdown(){
  const sel=document.getElementById('log-user');
  const prev=sel.value;
  sel.innerHTML='<option value="">All Users</option>';
  const r=await api('/admin-all-users',{admin_key:KEY});
  if(!r.ok) return;
  r.users.forEach(u=>{
    const opt=document.createElement('option');
    opt.value=u.hwid;
    const name=u.note||u.hwid.slice(0,14)+'...';
    opt.textContent=name+(isOnline(u.last_seen)?' 🟢':'');
    sel.appendChild(opt);
  });
  if(prev) sel.value=prev;
}
async function loadLogs(){
  const hwid=document.getElementById('log-user').value;
  const event_type=document.getElementById('log-type').value;
  const r=await api('/admin-activity-logs',{admin_key:KEY,hwid:hwid||null,event_type:event_type||null});
  if(!r.ok){ toast('Error loading logs'); return; }
  document.getElementById('logs-tbody').innerHTML=r.logs.map(l=>{
    const username=l.note||'<span class="mono muted">'+(l.hwid||'—').slice(0,14)+'...</span>';
    return '<tr>'
      +'<td class="muted" style="font-size:11px;white-space:nowrap">'+fmt(l.created_at)+'</td>'
      +'<td style="font-size:12px">'+username+'</td>'
      +'<td>'+evBadge(l.event_type)+'</td>'
      +'<td style="color:#8892b0;font-size:11px">'+(l.details||'—')+'</td>'
      +'</tr>';
  }).join('')||empty(4,'No logs found');
}
document.getElementById('logs-load-btn').addEventListener('click', loadLogs);
document.getElementById('log-type').addEventListener('change', loadLogs);
document.getElementById('log-user').addEventListener('change', loadLogs);
document.getElementById('logs-user-refresh').addEventListener('click', populateLogUserDropdown);

// ── Codes ──
async function loadCodes(){
  const r=await api('/list',{admin_key:KEY});
  if(!r.ok){ toast('Error loading codes'); return; }
  renderCodes(r);
}
function renderCodes(d){
  const c=d.codes||[];
  const onlineCount=c.filter(x=>isOnline(x.last_seen)).length;
  document.getElementById('codes-status').textContent=
    c.length+' total · '+c.filter(x=>x.hwid).length+' activated · '+onlineCount+' online';
  document.getElementById('codes-tbody').innerHTML=c.map(u=>
    '<tr data-code="'+u.code+'" data-hwid="'+(u.hwid||'')+'" data-note="'+(u.note||'')+'">'
    +'<td>'+badge(u)+(isOnline(u.last_seen)?' <span class="dot"></span>':'')+'</td>'
    +'<td class="mono" style="color:#c0caf5">'+u.code+'</td>'
    +'<td>'+(u.note||'<span class="muted">—</span>')+'</td>'
    +'<td>'+fmtD(u.expires_at)+'</td>'
    +'<td>'+hrs(u.total_seconds)+'</td>'
    +'<td title="'+fmt(u.last_seen)+'">'+timeAgo(u.last_seen)+'</td>'
    +'<td class="mono">'+(u.app_version||'—')+'</td>'
    +'<td style="white-space:nowrap;display:flex;gap:4px;flex-wrap:wrap">'
      +'<button class="btn btn-ghost btn-sm code-copy">Copy</button>'
      +(u.disabled
        ?'<button class="btn btn-ghost btn-sm code-enable">Enable</button>'
        :'<button class="btn btn-ghost btn-sm code-disable">Disable</button>')
      +(u.hwid?'<button class="btn btn-ghost btn-sm code-reset">Reset HWID</button>':'')
      +(u.hwid?'<button class="btn btn-ghost btn-sm code-dm">📩</button>':'')
      +'<button class="btn btn-ghost btn-sm code-expiry">Expiry</button>'
      +'<button class="btn btn-danger btn-sm code-delete">Del</button>'
    +'</td>'
    +'</tr>'
  ).join('')||empty(8,'No codes yet — generate some above');
}
document.getElementById('gen-btn').addEventListener('click', async()=>{
  const qty=parseInt(document.getElementById('code-qty').value)||1;
  const note=document.getElementById('code-note').value.trim();
  const expiry=document.getElementById('code-expiry').value;
  const [expType, expVal]=expiry.split(':');
  const expires_days = expType==='days' ? expVal : null;
  const trial_hours  = expType==='trial' ? expVal : null;
  if(qty<1||qty>100){ toast('Qty must be 1–100'); return; }
  const r=await api('/generate',{admin_key:KEY,count:qty,note,
    expires_days, trial_hours});
  if(!r.ok){ toast('Error: '+(r.error||'?')); return; }
  toast('✓ Generated '+r.codes.length+' code(s)');
  if(r.codes.length===1){ navigator.clipboard.writeText(r.codes[0]); toast('✓ Copied: '+r.codes[0]); }
  document.getElementById('code-note').value='';
  loadCodes();
});
document.getElementById('codes-refresh-btn').addEventListener('click', loadCodes);
document.getElementById('codes-tbody').addEventListener('click', async e=>{
  const row=e.target.closest('tr[data-code]');
  if(!row) return;
  const code=row.dataset.code, hwid=row.dataset.hwid, note=row.dataset.note;
  if(e.target.classList.contains('code-copy')){
    navigator.clipboard.writeText(code); toast('Copied: '+code);
  } else if(e.target.classList.contains('code-disable')){
    await api('/disable',{admin_key:KEY,code,disabled:1}); toast('Disabled'); loadCodes();
  } else if(e.target.classList.contains('code-enable')){
    await api('/disable',{admin_key:KEY,code,disabled:0}); toast('Enabled'); loadCodes();
  } else if(e.target.classList.contains('code-reset')){
    if(confirm('Unbind HWID from '+code+'?')){
      await api('/reset',{admin_key:KEY,code}); toast('HWID unbound'); loadCodes();
    }
  } else if(e.target.classList.contains('code-expiry')){
    const d=prompt('Days until expiry (leave blank for lifetime):');
    if(d===null) return;
    await api('/set_expiry',{admin_key:KEY,code,days:d||null}); toast('Expiry updated'); loadCodes();
  } else if(e.target.classList.contains('code-delete')){
    if(confirm('Permanently delete code '+code+'?')){
      await api('/revoke',{admin_key:KEY,code}); toast('Deleted'); loadCodes();
    }
  } else if(e.target.classList.contains('code-dm')){
    dmUser(hwid, note);
  }
});

// ── Messages ──
async function loadDMUsers(){
  const sel=document.getElementById('dm-user-select');
  const prev=sel.value;
  sel.innerHTML='<option value="">— select a user —</option>';
  const r=await api('/admin-all-users',{admin_key:KEY});
  if(!r.ok){ toast('Could not load users'); return; }
  r.users.forEach(u=>{
    const opt=document.createElement('option');
    opt.value=u.hwid;
    opt.textContent=(u.note?u.note+' · ':'')+u.hwid.slice(0,14)+'...'+(isOnline(u.last_seen)?' 🟢':'');
    if(u.disabled) opt.style.color='#ff6b81';
    sel.appendChild(opt);
  });
  if(prev) sel.value=prev;
}
document.getElementById('dm-user-select').addEventListener('change',function(){
  document.getElementById('dm-hwid').value=this.value;
});
document.getElementById('dm-refresh-btn').addEventListener('click', loadDMUsers);
document.getElementById('broadcast-btn').addEventListener('click', async()=>{
  const msg=document.getElementById('broadcast-msg').value.trim();
  if(!msg){ toast('Enter a message first'); return; }
  const r=await api('/send_to_all',{admin_key:KEY,message:msg});
  if(r.ok){ toast('✓ Sent to '+r.sent+' active user(s)'); document.getElementById('broadcast-msg').value=''; }
  else toast('Error: '+(r.error||'?'));
});
document.getElementById('broadcast-clear-btn').addEventListener('click', async()=>{
  await api('/broadcast',{admin_key:KEY,message:''});
  toast('Broadcast cleared');
  document.getElementById('broadcast-msg').value='';
});
document.getElementById('dm-btn').addEventListener('click', async()=>{
  const hwid=document.getElementById('dm-hwid').value.trim().toUpperCase();
  const msg=document.getElementById('dm-msg').value.trim();
  if(!hwid||!msg){ toast('Select a user and enter a message'); return; }
  const r=await api('/send_to_user',{admin_key:KEY,hwid,message:msg});
  if(r.ok){
    toast('✓ Message queued');
    document.getElementById('dm-hwid').value='';
    document.getElementById('dm-msg').value='';
    document.getElementById('dm-user-select').value='';
  } else toast('Error: '+(r.error||'?'));
});

// ── Analytics ──
async function loadAnalytics(){
  const r=await api('/admin-system-stats',{admin_key:KEY});
  if(!r.ok){ toast('Error'); return; }
  document.getElementById('an-24h').textContent=r.users.active_24h;
  document.getElementById('an-churn').textContent=r.users.active>0
    ?((1-r.users.online/r.users.active)*100).toFixed(1):'0.0';
  document.getElementById('an-usage').textContent=r.codes.total>0
    ?((r.codes.used/r.codes.total)*100).toFixed(1):'0.0';
  document.getElementById('an-unused').textContent=r.codes.unused;
  document.getElementById('an-versions').innerHTML=r.versions.length
    ?r.versions.map(v=>{
      const pct=Math.round((v.cnt/(r.users.total||1))*100);
      return '<div style="margin-bottom:10px">'
        +'<div style="display:flex;justify-content:space-between;margin-bottom:5px">'
        +'<strong style="color:#c0caf5">'+(v.app_version||'Unknown')+'</strong>'
        +'<span class="muted">'+v.cnt+' user(s) · '+pct+'%</span></div>'
        +'<div style="height:5px;border-radius:3px;background:#1a2540">'
        +'<div style="height:100%;border-radius:3px;background:#e94560;width:'+pct+'%"></div></div></div>';
    }).join('')
    :'<p class="muted">No version data yet</p>';
}

// ── Settings ──
async function loadSettings(){
  const r=await api('/list',{admin_key:KEY});
  if(r.ok && r.current_version){
    document.getElementById('current-version-display').textContent=r.current_version;
    document.getElementById('set-version-input').placeholder='e.g. '+r.current_version;
  }
}
document.getElementById('set-version-btn').addEventListener('click', async()=>{
  const v=document.getElementById('set-version-input').value.trim();
  if(!v){ toast('Enter a version string'); return; }
  const r=await api('/set_version',{admin_key:KEY,version:v});
  if(r.ok){
    document.getElementById('current-version-display').textContent=r.current_version;
    toast('✓ Version updated to '+r.current_version);
    document.getElementById('set-version-input').value='';
  } else toast('Error: '+(r.error||'?'));
});

// ── User profile modal ──
async function viewUser(hwid){
  const r=await api('/admin-user-details/'+hwid,{admin_key:KEY});
  if(!r.ok){ toast('User not found'); return; }
  const u=r.user;
  const sessions=r.activity.filter(l=>l.event_type==='SESSION_START').length;
  const afkHits=r.activity.filter(l=>l.event_type==='AFK_TRIGGERED').length;
  const gameDetects=r.activity.filter(l=>l.event_type==='GAME_DETECTED').length;
  let h='<h3>'+(u.note||'User Profile')+'</h3>';
  h+='<div class="modal-stat-grid">'
    +'<div class="modal-stat"><div class="label">Playtime</div><div class="value">'+hrs(u.total_seconds)+'</div></div>'
    +'<div class="modal-stat"><div class="label">Sessions</div><div class="value">'+sessions+'</div></div>'
    +'<div class="modal-stat"><div class="label">AFK Hits</div><div class="value">'+afkHits+'</div></div>'
    +'</div>';
  h+='<div class="info-row"><span class="lbl">Status</span><span>'+(u.disabled?'<span style="color:#ff6b81">BANNED</span>':'<span style="color:#2ecc71">ACTIVE</span>')+'</span></div>';
  h+='<div class="info-row"><span class="lbl">HWID</span><span class="mono muted">'+u.hwid+'</span></div>';
  h+='<div class="info-row"><span class="lbl">Code</span><span class="mono muted">'+u.code+'</span></div>';
  h+='<div class="info-row"><span class="lbl">Activated</span><span>'+fmt(u.activated_at)+'</span></div>';
  h+='<div class="info-row"><span class="lbl">Last Seen</span><span>'+fmt(u.last_seen)+'</span></div>';
  h+='<div class="info-row"><span class="lbl">Expires</span><span>'+(u.expires_at?fmt(u.expires_at):'Never')+'</span></div>';
  h+='<div class="info-row"><span class="lbl">Game Detections</span><span>'+gameDetects+'</span></div>';
  h+='<div style="margin:18px 0 10px;color:#4a5680;font-size:10px;text-transform:uppercase;letter-spacing:.5px">Activity Log (last 50)</div>';
  h+='<div style="max-height:280px;overflow-y:auto">';
  if(r.activity.length){
    r.activity.forEach(l=>{
      h+='<div class="log-entry">'
        +'<span class="muted">'+fmt(l.created_at)+'</span>'
        +evBadge(l.event_type)
        +'<span style="color:#8892b0">'+(l.details||'—')+'</span>'
        +'</div>';
    });
  } else {
    h+='<p class="muted" style="padding:12px 0">No activity logged yet</p>';
  }
  h+='</div>';
  document.getElementById('modal-body').innerHTML=h;
  document.getElementById('user-modal').classList.add('show');
}
function dmUser(hwid, note){
  const msg=prompt('Message to '+(note||hwid.slice(0,12)+'...')+':');
  if(!msg||!msg.trim()) return;
  api('/send_to_user',{admin_key:KEY,hwid,message:msg.trim()})
    .then(r=>{ if(r.ok) toast('✓ Message queued'); else toast('Error: '+(r.error||'?')); });
}
document.getElementById('modal-close').addEventListener('click',()=>{
  document.getElementById('user-modal').classList.remove('show');
});
document.getElementById('user-modal').addEventListener('click',e=>{
  if(e.target===document.getElementById('user-modal'))
    document.getElementById('user-modal').classList.remove('show');
});

// ── Auto-refresh every 30s on active tab ──
setInterval(()=>{
  const t=document.querySelector('.nav.active[data-tab]');
  if(!t) return;
  if(t.dataset.tab==='overview') loadOverview();
  else if(t.dataset.tab==='codes') loadCodes();
}, 30000);
</script></body></html>"""

@app.get("/admin")
def admin_page():
    return Response(ADMIN_HTML, mimetype="text/html")

# ---------------------------------------------------------------------------
# Discord bot (optional — only starts if DISCORD_BOT_TOKEN is set)
# ---------------------------------------------------------------------------

def _start_discord_bot():
    try:
        import asyncio, discord
        from discord.ext import commands as dc_commands
    except ImportError:
        print("[Discord] discord.py not installed — bot disabled")
        return

    # Comma-separated role names that are allowed to use commands, e.g. "Admin,Staff"
    _allowed_roles = [r.strip().lower() for r in os.environ.get("DISCORD_ADMIN_ROLES", "").split(",") if r.strip()]

    intents = discord.Intents.default()
    intents.message_content = True
    intents.members = True
    bot = dc_commands.Bot(command_prefix="!", intents=intents, help_command=None)

    def _allowed(ctx):
        """Return True if author is in an allowed role (or no roles configured)."""
        if not _allowed_roles:
            return True
        author_roles = [r.name.lower() for r in getattr(ctx.author, "roles", [])]
        return any(r in author_roles for r in _allowed_roles)

    def _in_channel(ctx):
        return DISCORD_CHANNEL_ID == 0 or ctx.channel.id == DISCORD_CHANNEL_ID

    async def _guard(ctx):
        """Returns True and silently passes, or sends an error and returns False."""
        if not _in_channel(ctx):
            return False
        if not _allowed(ctx):
            await ctx.send("❌ You don't have permission to use this command.", delete_after=5)
            return False
        return True

    def _resolve_license(cur, target, mentions):
        """
        Resolve a license row from either:
          - A Discord @mention  → match by note (display name)
          - A FIVEM-... code    → match by code
          - A plain name        → match by note
        Returns (code, row) or (None, None).
        """
        if mentions:
            name = mentions[0].display_name
            cur.execute("SELECT * FROM licenses WHERE LOWER(note)=LOWER(%s)", (name,))
        elif target.upper().startswith("FIVEM-"):
            cur.execute("SELECT * FROM licenses WHERE code=%s", (target.upper(),))
        else:
            cur.execute("SELECT * FROM licenses WHERE LOWER(note)=LOWER(%s)", (target,))
        row = cur.fetchone()
        if not row:
            return None, None
        return row.get("code"), row

    async def _dm_code(discord_user, code, exp_str, note):
        """Try to DM the discord user their code. Returns True on success."""
        try:
            embed = discord.Embed(title="🔑 Your License Code", color=0x2ecc71,
                description=(
                    f"Here is your AFK Tool license code:\n\n"
                    f"```\n{code}\n```\n"
                    f"**Expiry:** {exp_str}\n\n"
                    f"Enter this code in the tool to activate it."
                ))
            await discord_user.send(embed=embed)
            return True
        except Exception:
            return False

    @bot.command(name="help")
    async def cmd_help(ctx):
        if not await _guard(ctx): return
        roles_note = f"Allowed roles: `{'`, `'.join(_allowed_roles)}`" if _allowed_roles else "No role restriction set"
        embed = discord.Embed(title="AFK Tool — Bot Commands", color=0x5865F2,
            description=(
                "**Generating**\n"
                "`!gen @user [days]` — Generate a code and DM it\n"
                "`!trial @user <hours>` — Trial code DMed to user\n\n"
                "**Managing**\n"
                "`!ban / !unban / !revoke <@user|code|name>`\n"
                "`!extend <@user|code|name> <days>` — Add days to expiry\n"
                "`!expire <@user|code|name>` — Instantly expire license\n"
                "`!resetHWID <@user|code|name>` — Allow new device\n"
                "`!note <@user|code|name> <new name>` — Rename user\n\n"
                "**Info**\n"
                "`!status` — Server snapshot\n"
                "`!online` — Who's online now\n"
                "`!inactive [days]` — Users not seen in X days\n"
                "`!list [page]` — Paginated license list\n"
                "`!lookup <@user|code|name>` — License details\n"
                "`!stats <@user|code|name>` — Full user profile\n\n"
                "**Messaging**\n"
                "`!msg all <text>` — Broadcast to all online users\n"
                "`!msg <name> <text>` — In-app DM to one user\n"
                "`!dm <name> <text>` — Same as above\n\n"
                f"*{roles_note}*"
            ))
        await ctx.send(embed=embed)

    @bot.command(name="gen")
    async def cmd_gen(ctx, target: str = "", days: str = ""):
        if not await _guard(ctx): return
        if not target: await ctx.send("Usage: `!gen @user [days]` or `!gen <name> [days]`"); return

        # Resolve mention or plain name
        mention_user = ctx.message.mentions[0] if ctx.message.mentions else None
        note = mention_user.display_name if mention_user else target

        conn, cur = db()
        try:
            c = gen_code()
            expires = None
            if days:
                try: expires = (datetime.utcnow() + timedelta(days=float(days))).isoformat()
                except: pass
            cur.execute("INSERT INTO licenses(code, created_at, note, expires_at) VALUES(%s,%s,%s,%s)",
                        (c, datetime.utcnow().isoformat(), note, expires))
        finally:
            conn.close()

        exp_str = f"{days} days" if days else "Lifetime"

        # DM the mentioned user if there was a mention
        dm_status = ""
        if mention_user:
            sent = await _dm_code(mention_user, c, exp_str, note)
            dm_status = f"\n📩 Code DMed to {mention_user.mention}" if sent else f"\n⚠️ Couldn't DM {mention_user.mention} (DMs may be closed)"

        embed = discord.Embed(title="✅ Code Generated", color=0x2ecc71,
            description=f"**Code:** `{c}`\n**User:** {note}\n**Expiry:** {exp_str}{dm_status}")
        await ctx.send(embed=embed)

    @bot.command(name="trial")
    async def cmd_trial(ctx, target: str = "", hours: str = "24"):
        if not await _guard(ctx): return
        if not target: await ctx.send("Usage: `!trial @user <hours>` or `!trial <name> <hours>`"); return

        mention_user = ctx.message.mentions[0] if ctx.message.mentions else None
        note = mention_user.display_name if mention_user else target
        try: h = float(hours)
        except: h = 24.0

        conn, cur = db()
        try:
            c = gen_code()
            cur.execute("INSERT INTO licenses(code, created_at, note, trial_hours) VALUES(%s,%s,%s,%s)",
                        (c, datetime.utcnow().isoformat(), note, h))
        finally:
            conn.close()

        exp_str = f"Trial {h}h (starts on activation)"
        dm_status = ""
        if mention_user:
            sent = await _dm_code(mention_user, c, exp_str, note)
            dm_status = f"\n📩 Code DMed to {mention_user.mention}" if sent else f"\n⚠️ Couldn't DM {mention_user.mention} (DMs may be closed)"

        embed = discord.Embed(title="⏱ Trial Code Generated", color=0xf39c12,
            description=f"**Code:** `{c}`\n**User:** {note}\n**Trial:** {h}h from first activation{dm_status}")
        await ctx.send(embed=embed)

    @bot.command(name="revoke")
    async def cmd_revoke(ctx, target: str = ""):
        if not await _guard(ctx): return
        if not target: await ctx.send("Usage: `!revoke <@user | code | name>`"); return
        conn, cur = db()
        try:
            code, row = _resolve_license(cur, target, ctx.message.mentions)
            if not row:
                await ctx.send(f"❌ No license found for `{target}`"); return
            cur.execute("DELETE FROM licenses WHERE code=%s", (code,))
        finally:
            conn.close()
        await ctx.send(f"🗑 Revoked `{code}` ({row.get('note') or '—'})")

    @bot.command(name="ban")
    async def cmd_ban(ctx, target: str = ""):
        if not await _guard(ctx): return
        if not target: await ctx.send("Usage: `!ban <@user | code | name>`"); return
        conn, cur = db()
        try:
            code, row = _resolve_license(cur, target, ctx.message.mentions)
            if not row:
                await ctx.send(f"❌ No license found for `{target}`"); return
            cur.execute("UPDATE licenses SET disabled=1 WHERE code=%s", (code,))
        finally:
            conn.close()
        await ctx.send(f"🚫 Banned `{code}` ({row.get('note') or '—'})")

    @bot.command(name="unban")
    async def cmd_unban(ctx, target: str = ""):
        if not await _guard(ctx): return
        if not target: await ctx.send("Usage: `!unban <@user | code | name>`"); return
        conn, cur = db()
        try:
            code, row = _resolve_license(cur, target, ctx.message.mentions)
            if not row:
                await ctx.send(f"❌ No license found for `{target}`"); return
            cur.execute("UPDATE licenses SET disabled=0 WHERE code=%s", (code,))
        finally:
            conn.close()
        await ctx.send(f"✅ Unbanned `{code}` ({row.get('note') or '—'})")

    @bot.command(name="lookup")
    async def cmd_lookup(ctx, target: str = ""):
        if not await _guard(ctx): return
        if not target: await ctx.send("Usage: `!lookup <@user | code | name>`"); return
        conn, cur = db()
        try:
            code, row = _resolve_license(cur, target, ctx.message.mentions)
        finally:
            conn.close()
        if not row:
            await ctx.send(f"❌ No license found for `{target}`"); return
        exp = row.get("expires_at")
        if row["disabled"]:          status = "🚫 DISABLED"
        elif exp and datetime.utcnow() > datetime.fromisoformat(exp): status = "⌛ EXPIRED"
        elif row["hwid"]:            status = "✅ ACTIVE"
        else:                        status = "⬜ UNUSED"
        trial_line = f"\n**Trial:** {row['trial_hours']}h from activation" if row.get("trial_hours") else ""
        embed = discord.Embed(title=f"🔍 {row.get('note') or code}", color=0x4fc3f7,
            description=(
                f"**Status:** {status}\n"
                f"**Code:** `{code}`\n"
                f"**HWID:** `{(row.get('hwid') or '—')[:20]}{'...' if row.get('hwid') else ''}`\n"
                f"**Expires:** {exp or 'Lifetime'}{trial_line}\n"
                f"**Hours played:** {round((row.get('total_seconds') or 0)/3600,1)}h"
            ))
        await ctx.send(embed=embed)

    @bot.command(name="online")
    async def cmd_online(ctx):
        if not await _guard(ctx): return
        conn, cur = db()
        try:
            cutoff = (datetime.utcnow() - timedelta(minutes=5)).isoformat()
            cur.execute("SELECT note, hwid, last_seen FROM licenses WHERE last_seen > %s AND hwid IS NOT NULL", (cutoff,))
            rows = cur.fetchall()
        finally:
            conn.close()
        if not rows:
            await ctx.send("No users online right now."); return
        lines = "\n".join(f"• {r.get('note') or r['hwid'][:14]+'...'}" for r in rows)
        embed = discord.Embed(title=f"🟢 {len(rows)} Online", color=0x2ecc71, description=lines)
        await ctx.send(embed=embed)

    @bot.command(name="dm")
    async def cmd_dm(ctx, target: str = "", *, message: str = ""):
        if not await _guard(ctx): return
        if not target or not message: await ctx.send("Usage: `!dm <name> <message>`"); return
        conn, cur = db()
        try:
            cur.execute("SELECT hwid FROM licenses WHERE LOWER(note)=LOWER(%s) OR hwid=UPPER(%s)", (target, target))
            row = cur.fetchone()
            if not row or not row["hwid"]:
                await ctx.send(f"❌ User `{target}` not found in the license database"); return
            cur.execute("INSERT INTO user_messages(hwid, message, created_at) VALUES(%s,%s,%s)",
                        (row["hwid"], message, datetime.utcnow().isoformat()))
        finally:
            conn.close()
        await ctx.send(f"📩 In-app message queued for **{target}** — delivers within 5s")

    # ── !status ────────────────────────────────────────────────────────────────
    @bot.command(name="status")
    async def cmd_status(ctx):
        if not await _guard(ctx): return
        conn, cur = db()
        try:
            cutoff5  = (datetime.utcnow() - timedelta(minutes=5)).isoformat()
            cutoff24 = (datetime.utcnow() - timedelta(hours=24)).isoformat()
            cur.execute("SELECT COUNT(*) as v FROM licenses WHERE hwid IS NOT NULL")
            total = cur.fetchone()["v"]
            cur.execute("SELECT COUNT(*) as v FROM licenses WHERE last_seen > %s AND hwid IS NOT NULL", (cutoff5,))
            online = cur.fetchone()["v"]
            cur.execute("SELECT COUNT(*) as v FROM licenses WHERE hwid IS NULL")
            unused = cur.fetchone()["v"]
            cur.execute("SELECT COUNT(*) as v FROM licenses WHERE disabled=1")
            banned = cur.fetchone()["v"]
            cur.execute("SELECT COUNT(*) as v FROM licenses WHERE last_seen > %s AND hwid IS NOT NULL", (cutoff24,))
            active24 = cur.fetchone()["v"]
            cur.execute("SELECT app_version, COUNT(*) as c FROM licenses WHERE hwid IS NOT NULL AND app_version IS NOT NULL GROUP BY app_version ORDER BY c DESC")
            versions = cur.fetchall()
        finally:
            conn.close()
        ver_lines = "\n".join(f"  v{r['app_version']}: {r['c']} users" for r in versions) or "  —"
        embed = discord.Embed(title="📊 Server Status", color=0x5865F2,
            timestamp=datetime.utcnow())
        embed.add_field(name="Users", value=f"🟢 **{online}** online\n👥 {total} activated\n⬜ {unused} unused\n🚫 {banned} banned", inline=True)
        embed.add_field(name="Activity", value=f"📅 {active24} active (24h)\n🕐 {online} active (5m)", inline=True)
        embed.add_field(name="Versions", value=ver_lines, inline=False)
        await ctx.send(embed=embed)

    # ── !extend ────────────────────────────────────────────────────────────────
    @bot.command(name="extend")
    async def cmd_extend(ctx, target: str = "", days: str = ""):
        if not await _guard(ctx): return
        if not target or not days: await ctx.send("Usage: `!extend <@user | code | name> <days>`"); return
        try: d = float(days)
        except: await ctx.send("❌ Days must be a number"); return
        conn, cur = db()
        try:
            code, row = _resolve_license(cur, target, ctx.message.mentions)
            if not row: await ctx.send(f"❌ No license found for `{target}`"); return
            current = row.get("expires_at")
            base = max(datetime.fromisoformat(current), datetime.utcnow()) if current else datetime.utcnow()
            new_exp = (base + timedelta(days=d)).isoformat()
            cur.execute("UPDATE licenses SET expires_at=%s WHERE code=%s", (new_exp, code))
        finally:
            conn.close()
        name = row.get("note") or code
        await ctx.send(f"📅 Extended **{name}** by {days} days → expires `{new_exp[:10]}`")

    # ── !note ──────────────────────────────────────────────────────────────────
    @bot.command(name="note")
    async def cmd_note(ctx, target: str = "", *, new_note: str = ""):
        if not await _guard(ctx): return
        if not target or not new_note: await ctx.send("Usage: `!note <@user | code | name> <new name>`"); return
        conn, cur = db()
        try:
            code, row = _resolve_license(cur, target, ctx.message.mentions)
            if not row: await ctx.send(f"❌ No license found for `{target}`"); return
            old_note = row.get("note") or "—"
            cur.execute("UPDATE licenses SET note=%s WHERE code=%s", (new_note, code))
        finally:
            conn.close()
        await ctx.send(f"✏️ Renamed `{old_note}` → `{new_note}` (`{code}`)")

    # ── !expire ────────────────────────────────────────────────────────────────
    @bot.command(name="expire")
    async def cmd_expire(ctx, target: str = ""):
        if not await _guard(ctx): return
        if not target: await ctx.send("Usage: `!expire <@user | code | name>`"); return
        conn, cur = db()
        try:
            code, row = _resolve_license(cur, target, ctx.message.mentions)
            if not row: await ctx.send(f"❌ No license found for `{target}`"); return
            cur.execute("UPDATE licenses SET expires_at=%s WHERE code=%s",
                        (datetime.utcnow().isoformat(), code))
        finally:
            conn.close()
        name = row.get("note") or code
        await ctx.send(f"⌛ Expired **{name}**'s license immediately")

    # ── !resetHWID ─────────────────────────────────────────────────────────────
    @bot.command(name="resetHWID")
    async def cmd_reset_hwid(ctx, target: str = ""):
        if not await _guard(ctx): return
        if not target: await ctx.send("Usage: `!resetHWID <@user | code | name>`"); return
        conn, cur = db()
        try:
            code, row = _resolve_license(cur, target, ctx.message.mentions)
            if not row: await ctx.send(f"❌ No license found for `{target}`"); return
            cur.execute("UPDATE licenses SET hwid=NULL, activated_at=NULL WHERE code=%s", (code,))
            if row.get("hwid"):
                cur.execute("DELETE FROM active_sessions WHERE hwid=%s", (row["hwid"],))
                _log(cur, row["hwid"], "HWID_RESET", f"via discord by {ctx.author.name}", "")
        finally:
            conn.close()
        name = row.get("note") or code
        await ctx.send(f"🔄 HWID reset for **{name}** — they can activate on a new device")

    # ── !inactive ──────────────────────────────────────────────────────────────
    @bot.command(name="inactive")
    async def cmd_inactive(ctx, days: str = "7"):
        if not await _guard(ctx): return
        try: d = int(days)
        except: d = 7
        conn, cur = db()
        try:
            cutoff = (datetime.utcnow() - timedelta(days=d)).isoformat()
            cur.execute("""SELECT note, hwid, last_seen FROM licenses
                           WHERE hwid IS NOT NULL AND disabled=0
                           AND (last_seen IS NULL OR last_seen < %s)
                           ORDER BY last_seen ASC NULLS FIRST LIMIT 20""", (cutoff,))
            rows = cur.fetchall()
        finally:
            conn.close()
        if not rows:
            await ctx.send(f"✅ No inactive users found (>{d} days)"); return
        lines = []
        for r in rows:
            name = r.get("note") or (r["hwid"][:14] + "...")
            last = r.get("last_seen")
            ago = f"`{last[:10]}`" if last else "`never`"
            lines.append(f"• **{name}** — last seen {ago}")
        embed = discord.Embed(title=f"😴 Inactive Users (>{d} days)", color=0xe67e22,
            description="\n".join(lines))
        await ctx.send(embed=embed)

    # ── !list ──────────────────────────────────────────────────────────────────
    @bot.command(name="list")
    async def cmd_list(ctx, page: str = "1"):
        if not await _guard(ctx): return
        try: page = max(1, int(page))
        except: page = 1
        per_page = 15
        offset = (page - 1) * per_page
        conn, cur = db()
        try:
            cur.execute("SELECT COUNT(*) as v FROM licenses WHERE hwid IS NOT NULL")
            total = cur.fetchone()["v"]
            cur.execute("""SELECT note, code, disabled, expires_at, last_seen
                           FROM licenses WHERE hwid IS NOT NULL
                           ORDER BY last_seen DESC NULLS LAST
                           LIMIT %s OFFSET %s""", (per_page, offset))
            rows = cur.fetchall()
        finally:
            conn.close()
        cutoff = (datetime.utcnow() - timedelta(minutes=5)).isoformat()
        lines = []
        for r in rows:
            name = r.get("note") or "—"
            exp = r.get("expires_at")
            if r["disabled"]:                        tag = "🚫"
            elif exp and exp < datetime.utcnow().isoformat(): tag = "⌛"
            elif r.get("last_seen", "") > cutoff:   tag = "🟢"
            else:                                    tag = "⚫"
            lines.append(f"{tag} **{name}**")
        pages = max(1, (total + per_page - 1) // per_page)
        embed = discord.Embed(title=f"📋 Active Licenses — Page {page}/{pages}",
            color=0x4fc3f7, description="\n".join(lines) or "No users")
        embed.set_footer(text=f"{total} total activated · !list <page>")
        await ctx.send(embed=embed)

    # ── !stats ─────────────────────────────────────────────────────────────────
    @bot.command(name="stats")
    async def cmd_stats(ctx, target: str = ""):
        if not await _guard(ctx): return
        if not target: await ctx.send("Usage: `!stats <@user | code | name>`"); return
        conn, cur = db()
        try:
            code, row = _resolve_license(cur, target, ctx.message.mentions)
            if not row: await ctx.send(f"❌ No license found for `{target}`"); return
            hwid = row.get("hwid")
            cur.execute("SELECT COUNT(*) as v FROM activity_logs WHERE hwid=%s AND event_type='SESSION_START'", (hwid,))
            sessions = cur.fetchone()["v"]
            cur.execute("SELECT COUNT(*) as v FROM activity_logs WHERE hwid=%s AND event_type='AFK_HIT'", (hwid,))
            hits = cur.fetchone()["v"]
            cur.execute("SELECT COUNT(*) as v FROM activity_logs WHERE hwid=%s AND event_type='AFK_DETECTED'", (hwid,))
            detected = cur.fetchone()["v"]
        finally:
            conn.close()
        name = row.get("note") or code
        hrs = round((row.get("total_seconds") or 0) / 3600, 1)
        exp = row.get("expires_at") or "Lifetime"
        last = (row.get("last_seen") or "never")[:16].replace("T", " ")
        embed = discord.Embed(title=f"📈 {name}", color=0x2ecc71)
        embed.add_field(name="Playtime", value=f"{hrs}h", inline=True)
        embed.add_field(name="Sessions", value=str(sessions), inline=True)
        embed.add_field(name="Circles Hit", value=str(hits), inline=True)
        embed.add_field(name="Circles Detected", value=str(detected), inline=True)
        embed.add_field(name="Last Seen", value=last, inline=True)
        embed.add_field(name="Expires", value=exp[:10] if exp != "Lifetime" else exp, inline=True)
        await ctx.send(embed=embed)

    # ── !msg all ───────────────────────────────────────────────────────────────
    @bot.command(name="msg")
    async def cmd_msg(ctx, target: str = "", *, message: str = ""):
        if not await _guard(ctx): return
        if not target or not message: await ctx.send("Usage: `!msg all <message>` or `!msg <name> <message>`"); return
        conn, cur = db()
        try:
            if target.lower() == "all":
                cutoff = (datetime.utcnow() - timedelta(minutes=10)).isoformat()
                cur.execute("SELECT hwid FROM licenses WHERE hwid IS NOT NULL AND last_seen > %s", (cutoff,))
                rows = cur.fetchall()
                count = 0
                for r in rows:
                    cur.execute("INSERT INTO user_messages(hwid, message, created_at) VALUES(%s,%s,%s)",
                                (r["hwid"], message, datetime.utcnow().isoformat()))
                    count += 1
                await ctx.send(f"📢 Broadcast queued for **{count}** online user(s)")
            else:
                cur.execute("SELECT hwid FROM licenses WHERE LOWER(note)=LOWER(%s) OR hwid=UPPER(%s)", (target, target))
                row = cur.fetchone()
                if not row or not row["hwid"]:
                    await ctx.send(f"❌ User `{target}` not found"); return
                cur.execute("INSERT INTO user_messages(hwid, message, created_at) VALUES(%s,%s,%s)",
                            (row["hwid"], message, datetime.utcnow().isoformat()))
                await ctx.send(f"📩 Message queued for **{target}**")
        finally:
            conn.close()

    # ── Background tasks ───────────────────────────────────────────────────────
    @bot.event
    async def on_ready():
        print(f"[Discord] Logged in as {bot.user}")
        if _allowed_roles:
            print(f"[Discord] Restricted to roles: {', '.join(_allowed_roles)}")
        expiry_check.start()
        activation_watch.start()

    import discord.ext.tasks as tasks

    @tasks.loop(hours=24)
    async def expiry_check():
        """Post in channel if any licenses expire within 3 days."""
        if DISCORD_CHANNEL_ID == 0: return
        ch = bot.get_channel(DISCORD_CHANNEL_ID)
        if not ch: return
        conn, cur = db()
        try:
            soon  = (datetime.utcnow() + timedelta(days=3)).isoformat()
            now   = datetime.utcnow().isoformat()
            cur.execute("""SELECT note, code, expires_at FROM licenses
                           WHERE expires_at IS NOT NULL AND expires_at > %s AND expires_at < %s
                           AND disabled=0 AND hwid IS NOT NULL""", (now, soon))
            rows = cur.fetchall()
        finally:
            conn.close()
        if not rows: return
        lines = []
        for r in rows:
            name = r.get("note") or r["code"]
            exp  = r["expires_at"][:10]
            lines.append(f"• **{name}** — expires `{exp}`")
        embed = discord.Embed(title="⚠️ Licenses Expiring Soon", color=0xf39c12,
            description="\n".join(lines))
        await ch.send(embed=embed)

    _last_activation_check = {"ts": datetime.utcnow().isoformat()}

    @tasks.loop(seconds=30)
    async def activation_watch():
        """Alert when a new activation happens."""
        if DISCORD_CHANNEL_ID == 0: return
        ch = bot.get_channel(DISCORD_CHANNEL_ID)
        if not ch: return
        conn, cur = db()
        try:
            cur.execute("""SELECT a.details, a.created_at, l.note
                           FROM activity_logs a
                           LEFT JOIN licenses l ON UPPER(l.hwid)=UPPER(a.hwid)
                           WHERE a.event_type='ACTIVATE' AND a.created_at > %s
                           ORDER BY a.created_at ASC""", (_last_activation_check["ts"],))
            rows = cur.fetchall()
        finally:
            conn.close()
        for r in rows:
            _last_activation_check["ts"] = r["created_at"]
            name = r.get("note") or "Unknown"
            details = r.get("details") or ""
            embed = discord.Embed(title="🔑 New Activation", color=0x2ecc71,
                description=f"**User:** {name}\n**Details:** {details}")
            await ch.send(embed=embed)

    # ── Update help text ───────────────────────────────────────────────────────
    @bot.event
    async def on_command_error(ctx, error):
        if isinstance(error, dc_commands.CommandNotFound):
            return
        await ctx.send(f"❌ Error: {error}", delete_after=8)

    asyncio.run(bot.start(DISCORD_BOT_TOKEN))

if DISCORD_BOT_TOKEN:
    threading.Thread(target=_start_discord_bot, daemon=True).start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
