"""
License Server v3 — PostgreSQL (data persists across restarts)
Built on v2 (known-good) + advanced admin panel endpoints
"""
import os, secrets, string, psycopg2, psycopg2.extras
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, Response

ADMIN_KEY = os.environ.get("ADMIN_KEY", "CHANGE_ME")
DATABASE_URL = os.environ.get("DATABASE_URL", "")
CURRENT_VERSION = os.environ.get("APP_VERSION", "1.0.0")
DOWNLOAD_URL = os.environ.get("DOWNLOAD_URL", "")

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
        last_seen TEXT, total_seconds INTEGER DEFAULT 0, app_version TEXT
    )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS broadcast (
        id INTEGER PRIMARY KEY CHECK (id=1), message TEXT, updated_at TEXT
    )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS user_messages (
        id SERIAL PRIMARY KEY, hwid TEXT, message TEXT, created_at TEXT, delivered BOOLEAN DEFAULT FALSE
    )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS activity_logs (
        id SERIAL PRIMARY KEY, hwid TEXT, event_type TEXT, details TEXT, created_at TEXT, ip_address TEXT
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
            cur.execute("UPDATE licenses SET hwid=%s, activated_at=%s WHERE code=%s",
                        (hwid, datetime.utcnow().isoformat(), code))
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
    if not hwid: return jsonify(valid=False), 400
    row, err = _valid_license(hwid)
    if err or not row:
        return jsonify(valid=False, error=err or "no license")
    conn, cur = db()
    try:
        cur.execute("UPDATE licenses SET last_seen=%s, total_seconds=COALESCE(total_seconds,0)+%s, app_version=%s WHERE hwid=%s",
                    (datetime.utcnow().isoformat(), secs, ver or row.get("app_version"), hwid))
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
    count = int(data.get("count", 1))
    note  = (data.get("note") or "").strip()
    days  = data.get("expires_days")
    expires = None
    if days:
        try: expires = (datetime.utcnow() + timedelta(days=float(days))).isoformat()
        except: pass
    conn, cur = db()
    new = []
    try:
        for _ in range(count):
            c = gen_code()
            cur.execute("INSERT INTO licenses(code, created_at, note, expires_at) VALUES(%s,%s,%s,%s)",
                        (c, datetime.utcnow().isoformat(), note, expires))
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
    conn, cur = db()
    try:
        cur.execute("DELETE FROM licenses WHERE code=%s", ((data.get("code") or "").strip().upper(),))
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
        cur.execute("SELECT hwid FROM licenses WHERE code=%s", (code,))
        row = cur.fetchone()
        if row and row["hwid"]:
            _log(cur, row["hwid"], "BAN" if disabled_val else "UNBAN", f"code={code}", request.remote_addr)
    finally:
        conn.close()
    return jsonify(ok=True)

@app.post("/set_expiry")
def set_expiry():
    data = request.json or {}
    if not _auth(data): return jsonify(ok=False), 401
    days = data.get("days")
    expires = None
    if days not in (None, "", 0, "0"):
        try: expires = (datetime.utcnow() + timedelta(days=float(days))).isoformat()
        except: pass
    conn, cur = db()
    try:
        cur.execute("UPDATE licenses SET expires_at=%s WHERE code=%s",
                    (expires, (data.get("code") or "").strip().upper()))
    finally:
        conn.close()
    return jsonify(ok=True)

@app.post("/reset")
def reset_hwid():
    data = request.json or {}
    if not _auth(data): return jsonify(ok=False), 401
    conn, cur = db()
    try:
        cur.execute("UPDATE licenses SET hwid=NULL, activated_at=NULL WHERE code=%s",
                    ((data.get("code") or "").strip().upper(),))
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
        query = "SELECT * FROM activity_logs WHERE 1=1"
        params = []
        if hwid:
            query += " AND hwid=%s"
            params.append(hwid)
        if event_type:
            query += " AND event_type=%s"
            params.append(event_type)
        query += " ORDER BY created_at DESC LIMIT %s"
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

ADMIN_HTML = """<!doctype html><html><head><meta charset='utf-8'>
<title>AntiAFK Admin</title><style>
*{box-sizing:border-box;font-family:-apple-system,Segoe UI,sans-serif;margin:0;padding:0}
body{background:#0a0e27;color:#fff;min-height:100vh}
/* Login */
.login-wrap{display:flex;align-items:center;justify-content:center;min-height:100vh}
.login-box{background:#16213e;padding:36px;border-radius:10px;width:340px}
.login-box h1{color:#e94560;font-size:22px;margin-bottom:20px}
.login-box input{width:100%;padding:10px 12px;background:#0f3460;color:#fff;border:1px solid #1a3a5c;border-radius:5px;font-size:14px;margin-bottom:12px}
.login-box button{width:100%;padding:11px;background:#e94560;color:#fff;border:none;border-radius:5px;font-size:14px;font-weight:700;cursor:pointer}
.login-box button:hover{background:#c73652}
/* Layout */
.layout{display:flex;height:100vh}
.sidebar{width:210px;background:#1a1a2e;border-right:1px solid #16213e;display:flex;flex-direction:column;padding:16px 12px;gap:4px;overflow-y:auto;flex-shrink:0}
.sidebar-title{color:#e94560;font-size:17px;font-weight:700;padding:8px 4px 16px}
.nav{padding:10px 12px;border-radius:5px;cursor:pointer;color:#a0a0c0;font-size:13px;transition:.15s}
.nav:hover{background:#1f2a4d;color:#fff}
.nav.active{background:#e94560;color:#fff}
.nav-logout{margin-top:auto;background:#16213e;color:#a0a0c0}
.nav-logout:hover{background:#2a1a2e;color:#ff8899}
.main{flex:1;overflow-y:auto;padding:24px}
/* Cards / stats */
.page-title{font-size:20px;font-weight:700;color:#e94560;margin-bottom:20px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin-bottom:20px}
.stat{background:#16213e;padding:16px;border-radius:8px;border-left:3px solid #e94560}
.stat-label{color:#a0a0c0;font-size:11px;text-transform:uppercase;margin-bottom:6px}
.stat-value{font-size:26px;font-weight:700}
.card{background:#16213e;padding:18px;border-radius:8px;margin-bottom:16px}
.card-title{color:#e94560;font-size:13px;font-weight:700;text-transform:uppercase;margin-bottom:14px}
/* Table */
table{width:100%;border-collapse:collapse}
th,td{padding:10px 12px;text-align:left;border-bottom:1px solid #0f3460;font-size:12px}
th{background:#0f3460;color:#a0a0c0;font-weight:600;text-transform:uppercase;font-size:10px}
tr:hover td{background:#15203a}
/* Badges */
.badge{display:inline-block;padding:3px 9px;border-radius:20px;font-size:10px;font-weight:700}
.badge.active{background:#0d3320;color:#2ecc71}
.badge.banned,.badge.disabled{background:#5a1f2e;color:#ff8899}
.badge.expired{background:#4a3f1f;color:#ffcc00}
.badge.unused{background:#2a2a4e;color:#a0a0c0}
/* Buttons */
.btn{padding:8px 14px;border:none;border-radius:5px;cursor:pointer;font-size:12px;font-weight:600;transition:.15s}
.btn-red{background:#e94560;color:#fff}.btn-red:hover{background:#c73652}
.btn-ghost{background:#0f3460;color:#a0a0c0}.btn-ghost:hover{background:#1a3a5c;color:#fff}
.btn-blue{background:#1a3a5c;color:#4fc3f7}.btn-blue:hover{background:#1f4a72}
/* Inputs */
input[type=text],input[type=number],input[type=password],textarea,select{padding:9px 12px;background:#0f3460;color:#fff;border:1px solid #1a3a5c;border-radius:5px;font-size:12px}
textarea{resize:vertical;font-family:inherit}
select{cursor:pointer}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:12px}
/* Online dot */
.dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:#2ecc71;margin-right:5px;animation:pulse 1.5s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
/* Modal */
.modal-bg{display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:100;align-items:center;justify-content:center}
.modal-bg.show{display:flex}
.modal{background:#1a1a2e;border-radius:10px;padding:24px;width:90%;max-width:560px;max-height:80vh;overflow-y:auto;position:relative}
.modal-close{position:absolute;top:14px;right:18px;font-size:22px;cursor:pointer;color:#a0a0c0}
.modal-close:hover{color:#fff}
/* Toast */
.toast{position:fixed;bottom:24px;right:24px;background:#0f3460;color:#fff;padding:12px 20px;border-radius:7px;opacity:0;transition:opacity .3s;z-index:200;pointer-events:none}
.toast.show{opacity:1}
.hide{display:none}
.mono{font-family:Consolas,monospace;font-size:11px}
.mini{font-size:11px;color:#8b92b3}
</style></head><body>

<!-- LOGIN -->
<div id="login-wrap" class="login-wrap">
  <div class="login-box">
    <h1>🔐 AntiAFK Admin</h1>
    <input id="key-input" type="password" placeholder="Admin Key" autofocus>
    <button id="login-btn">Login</button>
  </div>
</div>

<!-- MAIN LAYOUT -->
<div id="app" class="layout hide">
  <div class="sidebar">
    <div class="sidebar-title">🚀 AntiAFK</div>
    <div class="nav active" data-tab="overview">📊 Overview</div>
    <div class="nav" data-tab="users">👥 Users</div>
    <div class="nav" data-tab="logs">📜 Logs</div>
    <div class="nav" data-tab="codes">🎟 Codes</div>
    <div class="nav" data-tab="messages">💬 Messages</div>
    <div class="nav" data-tab="analytics">📈 Analytics</div>
    <div class="nav nav-logout" id="logout-btn">⬅ Logout</div>
  </div>
  <div class="main">

    <!-- OVERVIEW -->
    <div id="tab-overview" class="tab-page">
      <div class="page-title">📊 System Overview</div>
      <div class="grid">
        <div class="stat"><div class="stat-label">Total Users</div><div class="stat-value" id="ov-total">-</div></div>
        <div class="stat"><div class="stat-label">Active</div><div class="stat-value" id="ov-active">-</div></div>
        <div class="stat"><div class="stat-label">Online Now</div><div class="stat-value"><span class="dot"></span><span id="ov-online">-</span></div></div>
        <div class="stat"><div class="stat-label">Banned</div><div class="stat-value" id="ov-banned">-</div></div>
        <div class="stat"><div class="stat-label">Avg Playtime</div><div class="stat-value" id="ov-avg">-</div></div>
        <div class="stat"><div class="stat-label">Total Hours</div><div class="stat-value" id="ov-hours">-</div></div>
      </div>
      <div class="card">
        <div class="card-title">Top 10 Users by Playtime</div>
        <table><thead><tr><th>Status</th><th>Note</th><th>Playtime</th><th>Last Seen</th><th>Version</th></tr></thead>
        <tbody id="ov-top"></tbody></table>
      </div>
    </div>

    <!-- USERS -->
    <div id="tab-users" class="tab-page hide">
      <div class="page-title">👥 User Management</div>
      <div class="card">
        <div class="row">
          <input type="text" id="user-search" placeholder="Search HWID or note..." style="flex:1;min-width:160px">
          <button class="btn btn-red" id="user-search-btn">Search</button>
        </div>
        <div class="row" style="gap:6px">
          <button class="btn btn-ghost filter-btn active-filter" data-filter="all">All</button>
          <button class="btn btn-ghost filter-btn" data-filter="active">Active</button>
          <button class="btn btn-ghost filter-btn" data-filter="banned">Banned</button>
          <button class="btn btn-ghost filter-btn" data-filter="expired">Expired</button>
          <button class="btn btn-ghost filter-btn" data-filter="inactive">Inactive 24h+</button>
        </div>
      </div>
      <div class="card">
        <table><thead><tr><th>Status</th><th>Note / HWID</th><th>Playtime</th><th>Last Seen</th><th>Ver</th><th></th></tr></thead>
        <tbody id="users-tbody"></tbody></table>
      </div>
    </div>

    <!-- LOGS -->
    <div id="tab-logs" class="tab-page hide">
      <div class="page-title">📜 Activity Logs</div>
      <div class="card">
        <div class="row">
          <input type="text" id="log-hwid" placeholder="Filter by HWID..." style="flex:1">
          <select id="log-type">
            <option value="">All Events</option>
            <option value="ACTIVATE">Activate</option>
            <option value="HEARTBEAT">Heartbeat</option>
            <option value="BAN">Ban</option>
            <option value="UNBAN">Unban</option>
            <option value="MESSAGE">Message</option>
          </select>
          <button class="btn btn-red" id="logs-load-btn">Load</button>
        </div>
      </div>
      <div class="card">
        <table><thead><tr><th>Time</th><th>HWID</th><th>Event</th><th>Details</th></tr></thead>
        <tbody id="logs-tbody"></tbody></table>
      </div>
    </div>

    <!-- CODES -->
    <div id="tab-codes" class="tab-page hide">
      <div class="page-title">🎟 License Codes</div>
      <div class="card">
        <div class="card-title">Generate Codes</div>
        <div class="row">
          <input type="number" id="code-qty" value="1" min="1" max="100" style="width:70px">
          <input type="text" id="code-note" placeholder="Username / note" style="flex:1;min-width:140px">
          <select id="code-expires">
            <option value="">Lifetime</option>
            <option value="1">1 Day</option>
            <option value="7">7 Days</option>
            <option value="30">30 Days</option>
            <option value="90">90 Days</option>
            <option value="365">1 Year</option>
          </select>
          <button class="btn btn-red" id="gen-btn">Generate</button>
        </div>
      </div>
      <div class="card">
        <div class="card-title">All Codes</div>
        <div class="row">
          <button class="btn btn-ghost" id="codes-refresh-btn">↻ Refresh</button>
          <span id="codes-status" class="mini"></span>
        </div>
        <table><thead><tr><th>Status</th><th>Code</th><th>Note</th><th>Expires</th><th>Hours</th><th>Last Seen</th><th>Ver</th><th></th></tr></thead>
        <tbody id="codes-tbody"></tbody></table>
      </div>
    </div>

    <!-- MESSAGES -->
    <div id="tab-messages" class="tab-page hide">
      <div class="page-title">💬 Messages</div>
      <div class="card">
        <div class="card-title">Broadcast to All Active Users</div>
        <textarea id="broadcast-msg" placeholder="Message for all active users (seen in last 10 min)..." style="width:100%;height:80px;margin-bottom:10px"></textarea>
        <div class="row">
          <button class="btn btn-red" id="broadcast-btn">📢 Send to All Active</button>
          <button class="btn btn-ghost" id="broadcast-clear-btn">Clear Broadcast</button>
        </div>
      </div>
      <div class="card">
        <div class="card-title">Direct Message</div>
        <div class="row">
          <input type="text" id="dm-hwid" placeholder="HWID" style="flex:1">
        </div>
        <textarea id="dm-msg" placeholder="Message..." style="width:100%;height:60px;margin-bottom:10px"></textarea>
        <button class="btn btn-red" id="dm-btn">📩 Send DM</button>
      </div>
    </div>

    <!-- ANALYTICS -->
    <div id="tab-analytics" class="tab-page hide">
      <div class="page-title">📈 Analytics</div>
      <div class="grid">
        <div class="stat"><div class="stat-label">24h Active</div><div class="stat-value" id="an-24h">-</div></div>
        <div class="stat"><div class="stat-label">Churn Rate</div><div class="stat-value" id="an-churn">-</div><div class="mini">%</div></div>
        <div class="stat"><div class="stat-label">Code Usage</div><div class="stat-value" id="an-usage">-</div><div class="mini">%</div></div>
        <div class="stat"><div class="stat-label">Unused Codes</div><div class="stat-value" id="an-unused">-</div></div>
      </div>
      <div class="card">
        <div class="card-title">Version Distribution</div>
        <div id="an-versions"></div>
      </div>
    </div>

  </div><!-- .main -->
</div><!-- .layout -->

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

// ---- utils ----
function toast(m, dur=2000){
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
function fmt(i){return i?new Date(i.includes('Z')?i:i+'Z').toLocaleString():'-';}
function fmtD(i){return i?new Date(i.includes('Z')?i:i+'Z').toLocaleDateString():'-';}
function hrs(s){return s?(s/3600).toFixed(1)+'h':'0h';}
function timeAgo(iso){
  if(!iso) return '-';
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
function isExp(i){return i&&new Date(i.includes('Z')?i:i+'Z')<new Date();}
function statusBadge(u){
  if(u.disabled) return '<span class="badge banned">BANNED</span>';
  if(isExp(u.expires_at)) return '<span class="badge expired">EXPIRED</span>';
  if(u.hwid) return '<span class="badge active">ACTIVE</span>';
  return '<span class="badge unused">UNUSED</span>';
}

// ---- auth ----
function showApp(){
  document.getElementById('login-wrap').classList.add('hide');
  document.getElementById('app').classList.remove('hide');
}
function doLogout(){
  sessionStorage.removeItem('akey');
  location.reload();
}
async function doLogin(){
  const k=document.getElementById('key-input').value.trim();
  if(!k) return;
  const r=await api('/list',{admin_key:k});
  if(!r.ok){ alert('Wrong key'); return; }
  KEY=k; sessionStorage.setItem('akey',k);
  showApp();
  renderCodes(r);
  loadOverview();
}
if(KEY){ showApp(); loadOverview(); loadCodes(); }

// ---- tabs ----
function switchTab(name){
  document.querySelectorAll('.tab-page').forEach(p=>p.classList.add('hide'));
  document.getElementById('tab-'+name).classList.remove('hide');
  document.querySelectorAll('.nav[data-tab]').forEach(n=>n.classList.remove('active'));
  document.querySelector('.nav[data-tab="'+name+'"]').classList.add('active');
  if(name==='overview') loadOverview();
  else if(name==='users') loadUsers();
  else if(name==='logs') loadLogs();
  else if(name==='codes') loadCodes();
  else if(name==='analytics') loadAnalytics();
}
document.querySelectorAll('.nav[data-tab]').forEach(n=>{
  n.addEventListener('click',()=>switchTab(n.dataset.tab));
});
document.getElementById('logout-btn').addEventListener('click', doLogout);
document.getElementById('login-btn').addEventListener('click', doLogin);
document.getElementById('key-input').addEventListener('keypress',e=>{if(e.key==='Enter')doLogin();});

// ---- overview ----
async function loadOverview(){
  const r=await api('/admin-system-stats',{admin_key:KEY});
  if(!r.ok){ toast('Stats error: '+(r.error||'?')); return; }
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
      +'<td>'+statusBadge(u)+(isOnline(u.last_seen)?' <span class="dot"></span>':'')+'</td>'
      +'<td>'+(u.note||'—')+'</td>'
      +'<td>'+hrs(u.total_seconds)+'</td>'
      +'<td>'+timeAgo(u.last_seen)+'</td>'
      +'<td class="mono">'+(u.app_version||'—')+'</td>'
      +'</tr>'
    ).join('')||'<tr><td colspan="5" style="text-align:center;color:#a0a0c0;padding:20px">No users yet</td></tr>';
  }
}

// ---- users ----
async function loadUsers(){
  const search=document.getElementById('user-search').value.trim();
  const r=await api('/admin-all-users',{admin_key:KEY,status:userFilter==='all'?null:userFilter,search});
  if(!r.ok){ toast('Error: '+(r.error||'?')); return; }
  document.getElementById('users-tbody').innerHTML=r.users.map(u=>
    '<tr data-hwid="'+u.hwid+'" data-code="'+u.code+'" data-note="'+( u.note||'')+'" data-disabled="'+(u.disabled||0)+'">'
    +'<td>'+statusBadge(u)+(isOnline(u.last_seen)?' <span class="dot"></span>':'')+'</td>'
    +'<td><span class="mono">'+(u.hwid||'—').slice(0,18)+'...</span>'+(u.note?'<br><span class="mini">'+u.note+'</span>':'')+'</td>'
    +'<td>'+hrs(u.total_seconds)+'</td>'
    +'<td title="'+fmt(u.last_seen)+'">'+timeAgo(u.last_seen)+'</td>'
    +'<td class="mono">'+(u.app_version||'—')+'</td>'
    +'<td style="white-space:nowrap">'
      +'<button class="btn btn-ghost act-view" style="margin-right:4px">View</button>'
      +(u.hwid?'<button class="btn btn-ghost act-dm" style="margin-right:4px">📩</button>':'')
    +'</td>'
    +'</tr>'
  ).join('')||'<tr><td colspan="6" style="text-align:center;color:#a0a0c0;padding:20px">No users found</td></tr>';
}
document.getElementById('user-search-btn').addEventListener('click', loadUsers);
document.getElementById('user-search').addEventListener('keypress',e=>{if(e.key==='Enter')loadUsers();});
document.querySelectorAll('.filter-btn').forEach(b=>{
  b.addEventListener('click',()=>{
    userFilter=b.dataset.filter;
    document.querySelectorAll('.filter-btn').forEach(x=>x.classList.remove('active-filter','btn-red'));
    b.classList.add('active-filter','btn-red');
    loadUsers();
  });
});
document.getElementById('users-tbody').addEventListener('click',e=>{
  const row=e.target.closest('tr[data-hwid]');
  if(!row) return;
  const hwid=row.dataset.hwid, note=row.dataset.note;
  if(e.target.classList.contains('act-view')) viewUser(hwid);
  if(e.target.classList.contains('act-dm')) dmUser(hwid, note);
});

// ---- logs ----
async function loadLogs(){
  const hwid=document.getElementById('log-hwid').value.trim();
  const event_type=document.getElementById('log-type').value;
  const r=await api('/admin-activity-logs',{admin_key:KEY,hwid:hwid||null,event_type:event_type||null});
  if(!r.ok){ toast('Error: '+(r.error||'?')); return; }
  document.getElementById('logs-tbody').innerHTML=r.logs.map(l=>
    '<tr>'
    +'<td class="mini">'+fmt(l.created_at)+'</td>'
    +'<td class="mono">'+(l.hwid||'—').slice(0,16)+'...</td>'
    +'<td><span style="color:#4fc3f7">'+l.event_type+'</span></td>'
    +'<td class="mini">'+(l.details||'—')+'</td>'
    +'</tr>'
  ).join('')||'<tr><td colspan="4" style="text-align:center;color:#a0a0c0;padding:20px">No logs found</td></tr>';
}
document.getElementById('logs-load-btn').addEventListener('click', loadLogs);

// ---- codes ----
async function loadCodes(){
  const r=await api('/list',{admin_key:KEY});
  if(!r.ok){ toast('Error loading codes'); return; }
  renderCodes(r);
}
function renderCodes(d){
  const c=d.codes||[];
  const online=c.filter(x=>isOnline(x.last_seen)).length;
  document.getElementById('codes-status').textContent=
    c.length+' total  |  '+c.filter(x=>x.hwid).length+' activated  |  '+online+' online';
  document.getElementById('codes-tbody').innerHTML=c.map(u=>{
    let badge=statusBadge(u);
    return '<tr data-code="'+u.code+'" data-hwid="'+(u.hwid||'')+'" data-note="'+(u.note||'')+'" data-disabled="'+(u.disabled||0)+'">'
      +'<td>'+badge+(isOnline(u.last_seen)?' <span class="dot"></span>':'')+'</td>'
      +'<td class="mono">'+u.code+'</td>'
      +'<td>'+(u.note||'—')+'</td>'
      +'<td>'+fmtD(u.expires_at)+'</td>'
      +'<td>'+hrs(u.total_seconds)+'</td>'
      +'<td title="'+fmt(u.last_seen)+'">'+timeAgo(u.last_seen)+'</td>'
      +'<td class="mono">'+(u.app_version||'—')+'</td>'
      +'<td style="white-space:nowrap;display:flex;gap:4px">'
        +'<button class="btn btn-ghost code-copy">Copy</button>'
        +(u.disabled
          ?'<button class="btn btn-ghost code-enable">Enable</button>'
          :'<button class="btn btn-ghost code-disable">Disable</button>')
        +(u.hwid?'<button class="btn btn-ghost code-reset">Reset</button>':'')
        +(u.hwid?'<button class="btn btn-ghost code-dm">📩</button>':'')
        +'<button class="btn btn-ghost code-expiry">Expiry</button>'
        +'<button class="btn btn-ghost code-delete" style="color:#ff8899">Del</button>'
      +'</td>'
      +'</tr>';
  }).join('')||'<tr><td colspan="8" style="text-align:center;color:#a0a0c0;padding:20px">No codes yet</td></tr>';
}
document.getElementById('gen-btn').addEventListener('click', async()=>{
  const qty=parseInt(document.getElementById('code-qty').value)||1;
  const note=document.getElementById('code-note').value;
  const days=document.getElementById('code-expires').value;
  if(qty<1||qty>100){ toast('Qty 1-100'); return; }
  const r=await api('/generate',{admin_key:KEY,count:qty,note,expires_days:days||null});
  if(!r.ok){ toast('Error: '+(r.error||'?')); return; }
  toast('Generated '+r.codes.length+' code(s)');
  if(r.codes.length===1){ navigator.clipboard.writeText(r.codes[0]); toast('Copied: '+r.codes[0]); }
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
      await api('/reset',{admin_key:KEY,code}); toast('HWID reset'); loadCodes();
    }
  } else if(e.target.classList.contains('code-expiry')){
    const d=prompt('Days until expiry (blank = lifetime):');
    if(d===null) return;
    await api('/set_expiry',{admin_key:KEY,code,days:d||null}); toast('Expiry updated'); loadCodes();
  } else if(e.target.classList.contains('code-delete')){
    if(confirm('Delete '+code+'?')){
      await api('/revoke',{admin_key:KEY,code}); toast('Deleted'); loadCodes();
    }
  } else if(e.target.classList.contains('code-dm')){
    dmUser(hwid, note);
  }
});

// ---- messages ----
document.getElementById('broadcast-btn').addEventListener('click', async()=>{
  const msg=document.getElementById('broadcast-msg').value.trim();
  if(!msg){ toast('Enter a message'); return; }
  const r=await api('/send_to_all',{admin_key:KEY,message:msg});
  if(r.ok){ toast('Sent to '+r.sent+' active user(s)'); document.getElementById('broadcast-msg').value=''; }
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
  if(!hwid||!msg){ toast('Enter HWID and message'); return; }
  const r=await api('/send_to_user',{admin_key:KEY,hwid,message:msg});
  if(r.ok){ toast('Message queued'); document.getElementById('dm-hwid').value=''; document.getElementById('dm-msg').value=''; }
  else toast('Error: '+(r.error||'?'));
});

// ---- analytics ----
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
    ?r.versions.map(v=>'<div style="margin:6px 0;padding:10px;background:#0f3460;border-radius:5px">'
      +'<strong style="color:#4fc3f7">'+(v.app_version||'Unknown')+'</strong>'
      +' — '+v.cnt+' user(s)'
      +'<div style="margin-top:6px;height:6px;border-radius:3px;background:#1a3a5c">'
      +'<div style="height:100%;border-radius:3px;background:#e94560;width:'
      +Math.round(v.cnt/(r.users.total||1)*100)+'%"></div></div></div>').join('')
    :'<p class="mini">No version data yet</p>';
}

// ---- user modal ----
async function viewUser(hwid){
  const r=await api('/admin-user-details/'+hwid,{admin_key:KEY});
  if(!r.ok){ toast('User not found'); return; }
  const u=r.user;
  let html='<h3 style="color:#e94560;margin-bottom:16px">'+(u.note||hwid)+'</h3>';
  html+='<p style="margin-bottom:6px"><strong>HWID:</strong> <span class="mono">'+u.hwid+'</span></p>';
  html+='<p style="margin-bottom:6px"><strong>Code:</strong> <span class="mono">'+u.code+'</span></p>';
  html+='<p style="margin-bottom:6px"><strong>Status:</strong> '+(u.disabled?'<span style="color:#ff8899">BANNED</span>':'<span style="color:#2ecc71">ACTIVE</span>')+'</p>';
  html+='<p style="margin-bottom:6px"><strong>Playtime:</strong> '+hrs(u.total_seconds)+'</p>';
  html+='<p style="margin-bottom:6px"><strong>Last Seen:</strong> '+fmt(u.last_seen)+'</p>';
  html+='<p style="margin-bottom:16px"><strong>Expires:</strong> '+(u.expires_at?fmtD(u.expires_at):'Never')+'</p>';
  html+='<h4 style="color:#a0a0c0;font-size:11px;text-transform:uppercase;margin-bottom:8px">Recent Activity</h4>';
  html+='<div style="max-height:220px;overflow-y:auto">';
  if(r.activity.length){
    r.activity.forEach(l=>{
      html+='<div style="padding:5px 0;border-bottom:1px solid #1a3a5c;font-size:11px">'
        +'<span style="color:#4fc3f7">['+fmt(l.created_at)+']</span> '
        +'<strong>'+l.event_type+'</strong>: '+(l.details||'—')+'</div>';
    });
  } else {
    html+='<p class="mini">No activity logged yet</p>';
  }
  html+='</div>';
  document.getElementById('modal-body').innerHTML=html;
  document.getElementById('user-modal').classList.add('show');
}
function dmUser(hwid, note){
  const msg=prompt('Message to '+(note||hwid.slice(0,12)+'...')+':');
  if(!msg||!msg.trim()) return;
  api('/send_to_user',{admin_key:KEY,hwid,message:msg.trim()})
    .then(r=>{ if(r.ok) toast('Message queued'); else toast('Error: '+(r.error||'?')); });
}
document.getElementById('modal-close').addEventListener('click',()=>{
  document.getElementById('user-modal').classList.remove('show');
});
document.getElementById('user-modal').addEventListener('click',e=>{
  if(e.target===document.getElementById('user-modal'))
    document.getElementById('user-modal').classList.remove('show');
});

// ---- auto-refresh ----
setInterval(()=>{
  const active=document.querySelector('.nav.active');
  if(!active) return;
  const tab=active.dataset.tab;
  if(tab==='overview') loadOverview();
  else if(tab==='codes') loadCodes();
}, 30000);
</script></body></html>"""

@app.get("/admin")
def admin_page():
    return Response(ADMIN_HTML, mimetype="text/html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
