"""
License Server v3 — PostgreSQL + Advanced Admin Panel
Full-featured license management with professional dashboard
"""
import os, secrets, string, psycopg2, psycopg2.extras
from datetime import datetime, timedelta, timezone
from flask import Flask, request, jsonify, Response

ADMIN_KEY = os.environ.get("ADMIN_KEY", "CHANGE_ME")
DATABASE_URL = os.environ.get("DATABASE_URL", "")
CURRENT_VERSION = os.environ.get("APP_VERSION", "1.0.0")
DOWNLOAD_URL = os.environ.get("DOWNLOAD_URL", "")

app = Flask(__name__)

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

def gen_code():
    alpha = string.ascii_uppercase + string.digits
    return "FIVEM-" + "-".join("".join(secrets.choice(alpha) for _ in range(4)) for _ in range(4))

def _auth(data): return (data or {}).get("admin_key") == ADMIN_KEY

def _valid_license(hwid):
    conn, cur = db()
    cur.execute("SELECT * FROM licenses WHERE hwid=%s", (hwid,))
    row = cur.fetchone()
    conn.close()
    if not row: return None, "no license"
    if row["disabled"]: return row, "disabled"
    if row["expires_at"]:
        try:
            if datetime.utcnow() > datetime.fromisoformat(row["expires_at"]): return row, "expired"
        except: pass
    return row, None

@app.post("/activate")
def activate():
    data = request.json or {}
    code = (data.get("code") or "").strip().upper()
    hwid = (data.get("hwid") or "").strip().upper()
    if not code or not hwid: return jsonify(ok=False, error="missing code or hwid"), 400
    conn, cur = db()
    cur.execute("SELECT * FROM licenses WHERE code=%s", (code,))
    row = cur.fetchone()
    if not row: conn.close(); return jsonify(ok=False, error="invalid code"), 404
    if row["disabled"]: conn.close(); return jsonify(ok=False, error="code has been disabled"), 403
    if row["expires_at"]:
        try:
            if datetime.utcnow() > datetime.fromisoformat(row["expires_at"]):
                conn.close(); return jsonify(ok=False, error="code has expired"), 403
        except: pass
    if row["hwid"] and row["hwid"] != hwid:
        conn.close(); return jsonify(ok=False, error="code already used on another device"), 403
    if not row["hwid"]:
        cur.execute("UPDATE licenses SET hwid=%s, activated_at=%s WHERE code=%s",
                    (hwid, datetime.utcnow().isoformat(), code))
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
    cur.execute("UPDATE licenses SET last_seen=%s, total_seconds=COALESCE(total_seconds,0)+%s, app_version=%s WHERE hwid=%s",
                (datetime.utcnow().isoformat(), secs, ver or row.get("app_version"), hwid))
    cur.execute("SELECT message, updated_at FROM broadcast WHERE id=1")
    b = cur.fetchone()
    cur.execute("SELECT id, message FROM user_messages WHERE hwid=%s AND delivered=FALSE ORDER BY created_at LIMIT 1", (hwid,))
    um = cur.fetchone()
    if um:
        cur.execute("UPDATE user_messages SET delivered=TRUE WHERE id=%s", (um["id"],))
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
    conn, cur = db(); new = []
    for _ in range(count):
        c = gen_code()
        cur.execute("INSERT INTO licenses(code, created_at, note, expires_at) VALUES(%s,%s,%s,%s)",
                    (c, datetime.utcnow().isoformat(), note, expires))
        new.append(c)
    conn.close()
    return jsonify(ok=True, codes=new)

@app.post("/list")
def list_codes():
    data = request.json or {}
    if not _auth(data): return jsonify(ok=False), 401
    conn, cur = db()
    cur.execute("SELECT * FROM licenses ORDER BY created_at DESC")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify(ok=True, codes=rows, current_version=CURRENT_VERSION)

@app.post("/revoke")
def revoke():
    data = request.json or {}
    if not _auth(data): return jsonify(ok=False), 401
    conn, cur = db()
    cur.execute("DELETE FROM licenses WHERE code=%s", ((data.get("code") or "").strip().upper(),))
    conn.close()
    return jsonify(ok=True)

@app.post("/disable")
def toggle_disable():
    data = request.json or {}
    if not _auth(data): return jsonify(ok=False), 401
    conn, cur = db()
    cur.execute("UPDATE licenses SET disabled=%s WHERE code=%s",
                (1 if data.get("disabled") else 0, (data.get("code") or "").strip().upper()))
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
    cur.execute("UPDATE licenses SET expires_at=%s WHERE code=%s",
                (expires, (data.get("code") or "").strip().upper()))
    conn.close()
    return jsonify(ok=True)

@app.post("/reset")
def reset_hwid():
    data = request.json or {}
    if not _auth(data): return jsonify(ok=False), 401
    conn, cur = db()
    cur.execute("UPDATE licenses SET hwid=NULL, activated_at=NULL WHERE code=%s",
                ((data.get("code") or "").strip().upper(),))
    conn.close()
    return jsonify(ok=True)

@app.post("/send_to_all")
def send_to_all():
    """Send a message to all currently active users (seen in last 10 minutes)."""
    data = request.json or {}
    if not _auth(data): return jsonify(ok=False), 401
    message = (data.get("message") or "").strip()
    if not message: return jsonify(ok=False, error="missing message"), 400
    conn, cur = db()
    cutoff = (datetime.utcnow().replace(tzinfo=timezone.utc).replace(tzinfo=None) - timedelta(minutes=10)).isoformat()
    cur.execute("SELECT hwid FROM licenses WHERE hwid IS NOT NULL AND last_seen > %s", (cutoff,))
    rows = cur.fetchall()
    count = 0
    for row in rows:
        cur.execute("INSERT INTO user_messages(hwid, message, created_at) VALUES(%s,%s,%s)",
                    (row["hwid"], message, datetime.utcnow().isoformat()))
        count += 1
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
    cur.execute("INSERT INTO user_messages(hwid, message, created_at) VALUES(%s,%s,%s)",
                (hwid, message, datetime.utcnow().isoformat()))
    conn.close()
    return jsonify(ok=True)

@app.post("/broadcast")
def set_broadcast():
    data = request.json or {}
    if not _auth(data): return jsonify(ok=False), 401
    msg = (data.get("message") or "").strip()
    conn, cur = db()
    if msg:
        cur.execute("DELETE FROM broadcast WHERE id=1")
        cur.execute("INSERT INTO broadcast(id, message, updated_at) VALUES(1, %s, %s)",
                    (msg, datetime.utcnow().isoformat()))
    else:
        cur.execute("DELETE FROM broadcast WHERE id=1")
    conn.close()
    return jsonify(ok=True)

@app.post("/set_version")
def set_version():
    data = request.json or {}
    if not _auth(data): return jsonify(ok=False), 401
    global CURRENT_VERSION
    CURRENT_VERSION = (data.get("version") or "").strip() or CURRENT_VERSION
    return jsonify(ok=True, current_version=CURRENT_VERSION)

@app.post("/admin-stats")
def admin_stats():
    """Get overall admin statistics"""
    data = request.json or {}
    if not _auth(data): return jsonify(ok=False), 401
    conn, cur = db()
    cur.execute("SELECT COUNT(*) as total FROM licenses WHERE hwid IS NOT NULL")
    total_users = cur.fetchone()["total"]
    cur.execute("SELECT COUNT(*) as active FROM licenses WHERE hwid IS NOT NULL AND disabled=0")
    active_users = cur.fetchone()["active"]
    cutoff = (datetime.utcnow().replace(tzinfo=timezone.utc).replace(tzinfo=None) - timedelta(minutes=5)).isoformat()
    cur.execute("SELECT COUNT(*) as online FROM licenses WHERE hwid IS NOT NULL AND last_seen > %s", (cutoff,))
    online = cur.fetchone()["online"]
    cur.execute("SELECT COALESCE(SUM(total_seconds), 0) as total FROM licenses WHERE hwid IS NOT NULL")
    total_seconds = cur.fetchone()["total"] or 0
    cur.execute("SELECT hwid, note, total_seconds, last_seen FROM licenses WHERE hwid IS NOT NULL ORDER BY total_seconds DESC LIMIT 5")
    top_users = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify(ok=True, total_users=total_users, active_users=active_users, online=online, 
                   total_seconds=total_seconds, top_users=top_users)

@app.post("/admin-user-stats/<hwid>")
def admin_user_stats(hwid):
    """Get detailed stats for a specific user"""
    data = request.json or {}
    if not _auth(data): return jsonify(ok=False), 401
    hwid = hwid.upper()
    conn, cur = db()
    cur.execute("SELECT * FROM licenses WHERE hwid=%s", (hwid,))
    user = cur.fetchone()
    conn.close()
    if not user: return jsonify(ok=False, error="User not found"), 404
    return jsonify(ok=True, user=dict(user))

@app.post("/admin-all-users")
def admin_all_users():
    """Get all users with optional filtering"""
    data = request.json or {}
    if not _auth(data): return jsonify(ok=False), 401
    conn, cur = db()
    status = data.get("status")
    search = (data.get("search") or "").strip().upper()
    query = "SELECT * FROM licenses WHERE hwid IS NOT NULL"
    params = []
    if status == "active":
        query += " AND disabled=0 AND (expires_at IS NULL OR expires_at > NOW()::text)"
    elif status == "expired":
        query += " AND expires_at IS NOT NULL AND expires_at <= NOW()::text"
    elif status == "disabled":
        query += " AND disabled=1"
    elif status == "inactive":
        cutoff = (datetime.utcnow() - timedelta(hours=24)).isoformat()
        query += f" AND last_seen < %s"
        params.append(cutoff)
    if search:
        query += " AND (hwid ILIKE %s OR note ILIKE %s)"
        params.append(f"%{search}%")
        params.append(f"%{search}%")
    query += " ORDER BY last_seen DESC LIMIT 500"
    cur.execute(query, tuple(params) if params else ())
    users = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify(ok=True, users=users)

@app.post("/admin-bulk-ban")
def admin_bulk_ban():
    """Ban multiple users"""
    data = request.json or {}
    if not _auth(data): return jsonify(ok=False), 401
    hwidlist = data.get("hwidlist", [])
    if not hwidlist: return jsonify(ok=False, error="no users"), 400
    conn, cur = db()
    for hwid in hwidlist:
        cur.execute("UPDATE licenses SET disabled=1 WHERE hwid=%s", (hwid.upper(),))
    conn.close()
    return jsonify(ok=True, banned=len(hwidlist))

@app.post("/admin-user-details/<hwid>")
def admin_user_details(hwid):
    """Get comprehensive user profile"""
    data = request.json or {}
    if not _auth(data): return jsonify(ok=False), 401
    hwid = hwid.upper()
    conn, cur = db()
    cur.execute("SELECT * FROM licenses WHERE hwid=%s", (hwid,))
    user = cur.fetchone()
    if not user:
        conn.close()
        return jsonify(ok=False, error="User not found"), 404
    cur.execute("SELECT * FROM activity_logs WHERE hwid=%s ORDER BY created_at DESC LIMIT 50", (hwid,))
    logs = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify(ok=True, user=dict(user), activity=logs)

@app.post("/admin-activity-logs")
def admin_activity_logs():
    """Get activity logs with filtering"""
    data = request.json or {}
    if not _auth(data): return jsonify(ok=False), 401
    hwid = data.get("hwid")
    event_type = data.get("event_type")
    limit = int(data.get("limit", 100))
    conn, cur = db()
    query = "SELECT * FROM activity_logs WHERE 1=1"
    params = []
    if hwid:
        query += " AND hwid=%s"
        params.append(hwid.upper())
    if event_type:
        query += " AND event_type=%s"
        params.append(event_type)
    query += " ORDER BY created_at DESC LIMIT %s"
    params.append(limit)
    cur.execute(query, tuple(params))
    logs = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify(ok=True, logs=logs)

@app.post("/admin-system-stats")
def admin_system_stats():
    """Get comprehensive system statistics"""
    data = request.json or {}
    if not _auth(data): return jsonify(ok=False), 401
    conn, cur = db()
    cur.execute("SELECT COUNT(*) as total FROM licenses WHERE hwid IS NOT NULL")
    total_users = cur.fetchone()["total"]
    cur.execute("SELECT COUNT(*) as active FROM licenses WHERE hwid IS NOT NULL AND disabled=0")
    active_users = cur.fetchone()["active"]
    cur.execute("SELECT COUNT(*) as banned FROM licenses WHERE disabled=1")
    banned = cur.fetchone()["banned"]
    cutoff5m = (datetime.utcnow().replace(tzinfo=timezone.utc).replace(tzinfo=None) - timedelta(minutes=5)).isoformat()
    cur.execute("SELECT COUNT(*) as online FROM licenses WHERE hwid IS NOT NULL AND last_seen > %s", (cutoff5m,))
    online = cur.fetchone()["online"]
    cutoff24h = (datetime.utcnow() - timedelta(hours=24)).isoformat()
    cur.execute("SELECT COUNT(*) as active24h FROM licenses WHERE hwid IS NOT NULL AND last_seen > %s", (cutoff24h,))
    active_24h = cur.fetchone()["active24h"]
    cur.execute("SELECT COALESCE(SUM(total_seconds), 0) as total FROM licenses WHERE hwid IS NOT NULL")
    total_seconds = cur.fetchone()["total"] or 0
    cur.execute("SELECT AVG(total_seconds) as avg FROM licenses WHERE hwid IS NOT NULL AND total_seconds > 0")
    avg_seconds = cur.fetchone()["avg"] or 0
    cur.execute("SELECT app_version, COUNT(*) as count FROM licenses WHERE hwid IS NOT NULL GROUP BY app_version ORDER BY count DESC")
    versions = [dict(r) for r in cur.fetchall()]
    cur.execute("SELECT COUNT(*) as total FROM licenses")
    total_codes = cur.fetchone()["total"]
    cur.execute("SELECT COUNT(*) as unused FROM licenses WHERE hwid IS NULL")
    unused_codes = cur.fetchone()["unused"]
    conn.close()
    return jsonify(ok=True,
        users={"total": total_users, "active": active_users, "online": online, "active_24h": active_24h, "banned": banned},
        playtime={"total_seconds": total_seconds, "avg_seconds": avg_seconds, "total_hours": total_seconds/3600},
        versions=versions,
        codes={"total": total_codes, "unused": unused_codes, "used": total_codes - unused_codes}
    )

@app.get("/")
def health():
    return "AntiAFK License Server OK"

ADMIN_STATS_HTML = """<!doctype html><html><head><meta charset='utf-8'>
<title>AntiAFK Admin — Stats</title><style>
*{box-sizing:border-box;font-family:-apple-system,Segoe UI,sans-serif}
body{background:#1a1a2e;color:#fff;margin:0;padding:20px}
h1{color:#e94560;margin:0 0 16px}
h2{color:#a0a0c0;margin:20px 0 10px;font-size:13px;text-transform:uppercase}
.card{background:#16213e;padding:14px;border-radius:6px;margin-bottom:14px}
.metric{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px}
.stat{background:#0f3460;padding:12px;border-radius:4px;border-left:3px solid #e94560}
.stat-label{color:#a0a0c0;font-size:11px;text-transform:uppercase}
.stat-value{color:#fff;font-size:24px;font-weight:bold}
table{width:100%;border-collapse:collapse;background:#16213e;border-radius:6px;overflow:hidden}
th,td{padding:8px 10px;text-align:left;border-bottom:1px solid #0f3460;font-size:12px}
th{background:#0f3460;color:#a0a0c0;font-weight:500;text-transform:uppercase;font-size:10px}
.badge{padding:2px 7px;border-radius:10px;font-size:10px;font-weight:bold;background:#0f3460;color:#4fc3f7}
.back{color:#4fc3f7;cursor:pointer;text-decoration:underline}
.hide{display:none}
.toast{position:fixed;bottom:20px;right:20px;background:#0f3460;color:#fff;padding:12px 18px;border-radius:6px;opacity:0;transition:opacity .3s}
.toast.show{opacity:1}
</style></head><body>
<div id='stats' class='hide'>
  <h1>AntiAFK Admin — Statistics</h1>
  <div class='card'>
    <h2>Overview</h2>
    <div class='metric'>
      <div class='stat'>
        <div class='stat-label'>Total Users</div>
        <div class='stat-value' id='totalUsers'>-</div>
      </div>
      <div class='stat'>
        <div class='stat-label'>Active Users</div>
        <div class='stat-value' id='activeUsers'>-</div>
      </div>
      <div class='stat'>
        <div class='stat-label'>Online Now</div>
        <div class='stat-value' id='onlineUsers'>● -</div>
      </div>
      <div class='stat'>
        <div class='stat-label'>Total Playtime</div>
        <div class='stat-value' id='totalPlaytime'>-</div>
      </div>
    </div>
  </div>
  <div class='card'>
    <h2>Top 5 Users by Playtime</h2>
    <table>
      <thead><tr><th>HWID</th><th>Note</th><th>Playtime</th><th>Last Seen</th></tr></thead>
      <tbody id='topUsers'></tbody>
    </table>
  </div>
  <p style='text-align:center;color:#a0a0c0;font-size:12px'><span class='back' onclick='location.href="/admin"'>← Back to Admin Panel</span></p>
</div>
<div id='login'>
  <div style='max-width:400px;margin:100px auto;background:#16213e;padding:30px;border-radius:8px'>
    <h1>AntiAFK Admin Stats</h1>
    <input id='key' type='password' placeholder='Admin Key' autofocus style='width:100%;padding:8px;background:#0f3460;border:none;color:#fff;border-radius:4px;margin-bottom:10px'>
    <button onclick='login()' style='width:100%;padding:8px;background:#e94560;color:#fff;border:none;border-radius:4px;font-weight:bold;cursor:pointer'>Login</button>
  </div>
</div>
<div id='toast' class='toast'></div>
<script>
let KEY = sessionStorage.getItem('stats_key') || '';
if(KEY) { document.getElementById('login').style.display='none'; document.getElementById('stats').classList.remove('hide'); load(); }
async function api(p, b){ const r = await fetch(p, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(b)}); return r.json(); }
function toast(m){ const t = document.getElementById('toast'); t.textContent = m; t.classList.add('show'); setTimeout(() => t.classList.remove('show'), 1800); }
async function login(){
  KEY = document.getElementById('key').value;
  const r = await api('/admin-stats', {admin_key: KEY});
  if(!r.ok) { alert('Wrong key'); return; }
  sessionStorage.setItem('stats_key', KEY);
  document.getElementById('login').style.display = 'none';
  document.getElementById('stats').classList.remove('hide');
  render(r);
}
async function load(){
  const r = await api('/admin-stats', {admin_key: KEY});
  if(!r.ok) { sessionStorage.removeItem('stats_key'); location.reload(); return; }
  render(r);
}
function render(d){
  document.getElementById('totalUsers').textContent = d.total_users;
  document.getElementById('activeUsers').textContent = d.active_users;
  document.getElementById('onlineUsers').textContent = '● ' + d.online;
  const hrs = (d.total_seconds / 3600).toFixed(1);
  document.getElementById('totalPlaytime').textContent = hrs + 'h';
  document.getElementById('topUsers').innerHTML = d.top_users.map(u => 
    '<tr><td style="font-family:monospace;font-size:11px">' + (u.hwid || '-').substring(0,16) + '...</td>' +
    '<td>' + (u.note || '-') + '</td>' +
    '<td>' + (u.total_seconds ? (u.total_seconds / 3600).toFixed(1) + 'h' : '0h') + '</td>' +
    '<td style="font-size:11px">' + (u.last_seen ? new Date(u.last_seen).toLocaleString() : 'Never') + '</td></tr>'
  ).join('');
}
document.getElementById('key').addEventListener('keypress', e => { if(e.key === 'Enter') login(); });
setInterval(() => { if(document.getElementById('stats').style.display !== 'none') load(); }, 30000);
</script></body></html>"""

@app.get("/admin-stats-page")
def admin_stats_page():
    """Admin statistics dashboard"""
    return Response(ADMIN_STATS_HTML, mimetype="text/html")

ADMIN_HTML = """<!doctype html><html><head><meta charset='utf-8'>
<title>AntiAFK Pro Admin Panel</title><style>
* {box-sizing:border-box;font-family:-apple-system,Segoe UI,sans-serif}
body {background:#0a0e27;color:#fff;margin:0;padding:0;min-h:100vh}
.header {background:#1a1a2e;padding:20px;border-bottom:1px solid #16213e;display:flex;align-items:center;justify-content:space-between}
.header h1 {margin:0;color:#e94560;font-size:24px}
.header-right {display:flex;gap:12px;align-items:center}
.logout {padding:8px 16px;background:#16213e;color:#fff;border:none;border-radius:4px;cursor:pointer}
.logout:hover {background:#1f2a4d}
.container {display:flex;min-h:calc(100vh - 70px)}
.sidebar {width:200px;background:#1a1a2e;padding:20px;border-right:1px solid #16213e;overflow-y:auto}
.nav-item {padding:12px;background:#16213e;color:#a0a0c0;border-radius:4px;margin-bottom:8px;cursor:pointer;transition:0.2s}
.nav-item:hover {background:#1f2a4d;color:#fff}
.nav-item.active {background:#e94560;color:#fff}
.main {flex:1;padding:24px;overflow-y:auto}
.tab-content {display:none}
.tab-content.active {display:block}
.card {background:#16213e;padding:20px;border-radius:8px;margin-bottom:16px}
.card h2 {margin-top:0;color:#e94560;font-size:16px;text-transform:uppercase}
.grid {display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:16px}
.stat-card {background:#0f3460;padding:16px;border-radius:6px;border-left:3px solid #e94560}
.stat-label {color:#a0a0c0;font-size:12px;text-transform:uppercase;margin-bottom:8px}
.stat-value {color:#fff;font-size:28px;font-weight:bold}
table {width:100%;border-collapse:collapse;background:#0f3460;border-radius:6px;overflow:hidden;margin-top:12px}
th,td {padding:12px;text-align:left;border-bottom:1px solid #1a3a5c;font-size:12px}
th {background:#1a3a5c;color:#a0a0c0;font-weight:600;text-transform:uppercase;font-size:10px}
tr:hover {background:#15445f}
.badge {display:inline-block;padding:4px 10px;border-radius:20px;font-size:10px;font-weight:bold}
.badge.active {background:#0d3320;color:#2ecc71}
.badge.banned {background:#5a1f2e;color:#ff8899}
.badge.expired {background:#4a3f1f;color:#ffcc00}
.btn {padding:10px 16px;border:none;border-radius:4px;cursor:pointer;font-size:12px;font-weight:600;transition:0.2s}
.btn-primary {background:#e94560;color:#fff}
.btn-primary:hover {background:#c73652}
.btn-secondary {background:#16213e;color:#a0a0c0}
.btn-secondary:hover {background:#1f2a4d}
.search-box {display:flex;gap:8px;margin-bottom:16px}
.search-box input {flex:1;padding:10px;background:#0f3460;color:#fff;border:1px solid #1a3a5c;border-radius:4px;font-size:12px}
.filter-tags {display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap}
.filter-tag {padding:8px 12px;background:#0f3460;color:#4fc3f7;border:1px solid #1a3a5c;border-radius:20px;cursor:pointer;font-size:11px}
.filter-tag:hover {border-color:#4fc3f7}
.modal {display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.7);z-index:1000;align-items:center;justify-content:center}
.modal.show {display:flex}
.modal-content {background:#1a1a2e;padding:24px;border-radius:8px;max-width:600px;width:90%;max-h:80vh;overflow-y:auto}
.modal-close {float:right;cursor:pointer;font-size:24px;color:#a0a0c0}
.toast {position:fixed;bottom:20px;right:20px;background:#0f3460;color:#fff;padding:14px 20px;border-radius:6px;opacity:0;transition:opacity 0.3s;z-index:2000}
.toast.show {opacity:1}
.dot {display:inline-block;width:8px;height:8px;border-radius:50%;background:#2ecc71;margin-right:6px;animation:pulse 1.5s infinite}
@keyframes pulse {0%,100%{opacity:1}50%{opacity:0.3}}
select {padding:10px;background:#0f3460;color:#fff;border:1px solid #1a3a5c;border-radius:4px;font-size:12px;cursor:pointer}
input[type='text'],input[type='number'],textarea {padding:10px;background:#0f3460;color:#fff;border:1px solid #1a3a5c;border-radius:4px;font-size:12px}
input[type='text']::placeholder,textarea::placeholder {color:#4a5568}
textarea {font-family:Consolas,monospace;resize:vertical}
.flex {display:flex;gap:12px;align-items:center;flex-wrap:wrap}
h3 {color:#e94560;margin:16px 0 8px}
.hide {display:none}
</style></head><body>
<div class='header'>
  <h1>🚀 AntiAFK Pro Admin Panel</h1>
  <div class='header-right'>
    <button class='logout' onclick='logout()'>Logout</button>
  </div>
</div>
<div class='container'>
  <div class='sidebar'>
    <div class='nav-item active' onclick='switchTab("overview")' id='nav-overview'>📊 Overview</div>
    <div class='nav-item' onclick='switchTab("users")' id='nav-users'>👥 Users</div>
    <div class='nav-item' onclick='switchTab("logs")' id='nav-logs'>📜 Logs</div>
    <div class='nav-item' onclick='switchTab("profile")' id='nav-profile'>👤 Profile</div>
    <div class='nav-item' onclick='switchTab("analytics")' id='nav-analytics'>📈 Analytics</div>
    <div class='nav-item' onclick='switchTab("codes")' id='nav-codes'>🎟️ Codes</div>
    <div class='nav-item' onclick='switchTab("messages")' id='nav-messages'>💬 Messages</div>
    <div class='nav-item' onclick='switchTab("settings")' id='nav-settings'>⚙️ Settings</div>
  </div>
  <div class='main'>
    <!-- OVERVIEW -->
    <div id='overview-tab' class='tab-content active'>
      <h2 style='color:#e94560;margin:0 0 20px;font-size:20px'>📊 System Overview</h2>
      <div class='grid'>
        <div class='stat-card'><div class='stat-label'>Total Users</div><div class='stat-value' id='stat-total'>-</div></div>
        <div class='stat-card'><div class='stat-label'>Active</div><div class='stat-value' id='stat-active'>-</div></div>
        <div class='stat-card'><div class='stat-label'>Online Now</div><div class='stat-value'><span class='dot'></span><span id='stat-online'>-</span></div></div>
        <div class='stat-card'><div class='stat-label'>Banned</div><div class='stat-value' id='stat-banned'>-</div></div>
        <div class='stat-card'><div class='stat-label'>Avg Playtime</div><div class='stat-value' id='stat-avg'>-</div></div>
        <div class='stat-card'><div class='stat-label'>Total Hours</div><div class='stat-value' id='stat-total-time'>-</div></div>
      </div>
      <div class='card'>
        <h2>Top 10 Users</h2>
        <table><thead><tr><th>Status</th><th>Username</th><th>Playtime</th><th>Last Seen</th><th>Version</th></tr></thead><tbody id='top-users'><tr><td colspan="5" style="text-align:center;color:#a0a0c0">Loading data...</td></tr></tbody></table>
      </div>
    </div>

    <!-- USERS -->
    <div id='users-tab' class='tab-content'>
      <h2 style='color:#e94560;margin:0 0 20px;font-size:20px'>👥 User Management</h2>
      <div class='search-box'>
        <input type='text' id='user-search' placeholder='Search HWID or username...'>
        <button class='btn btn-primary' onclick='loadUsers()'>Search</button>
      </div>
      <div class='filter-tags'>
        <div class='filter-tag' onclick='filterUsers("all")'>All</div>
        <div class='filter-tag' onclick='filterUsers("active")'>Active</div>
        <div class='filter-tag' onclick='filterUsers("banned")'>Banned</div>
        <div class='filter-tag' onclick='filterUsers("expired")'>Expired</div>
        <div class='filter-tag' onclick='filterUsers("inactive")'>Inactive 24h+</div>
      </div>
      <div class='card'>
        <table><thead><tr><th>Status</th><th>Username</th><th>Playtime</th><th>Last Seen</th><th>Actions</th></tr></thead><tbody id='users-table'></tbody></table>
      </div>
    </div>

    <!-- LOGS -->
    <div id='logs-tab' class='tab-content'>
      <h2 style='color:#e94560;margin:0 0 20px;font-size:20px'>📜 Activity Log</h2>
      <div class='card'>
        <input type='text' placeholder='Filter by HWID...' id='log-hwid-filter' style='width:100%;margin-bottom:12px'>
        <select id='log-type-filter' style='width:100%;margin-bottom:12px' onchange='loadLogs()'>
          <option value=''>All Events</option>
          <option value='LOGIN'>Login</option>
          <option value='BAN'>Ban</option>
          <option value='MESSAGE'>Message</option>
        </select>
        <button class='btn btn-primary' style='width:100%' onclick='loadLogs()'>Load Logs</button>
      </div>
      <div class='card'>
        <table><thead><tr><th>Time</th><th>HWID</th><th>Event</th><th>Details</th></tr></thead><tbody id='logs-table'></tbody></table>
      </div>
    </div>

    <!-- PROFILE -->
    <div id='profile-tab' class='tab-content'>
      <h2 style='color:#e94560;margin:0 0 20px;font-size:20px'>👤 User Profile</h2>
      <div class='card'>
        <input type='text' placeholder='Enter HWID...' id='profile-hwid' style='width:100%;margin-bottom:12px;padding:10px'>
        <button class='btn btn-primary' style='width:100%' onclick='loadUserProfile()'>Load Profile</button>
      </div>
      <div id='profile-content'></div>
    </div>

    <!-- ANALYTICS -->
    <div id='analytics-tab' class='tab-content'>
      <h2 style='color:#e94560;margin:0 0 20px;font-size:20px'>📈 Analytics</h2>
      <div class='grid'>
        <div class='stat-card'><div class='stat-label'>24h Active</div><div class='stat-value' id='stat-24h'>-</div></div>
        <div class='stat-card'><div class='stat-label'>Churn Rate</div><div class='stat-value' id='stat-churn'>-</div><div style='color:#a0a0c0;font-size:10px'>%</div></div>
        <div class='stat-card'><div class='stat-label'>Code Usage</div><div class='stat-value' id='stat-code-usage'>-</div><div style='color:#a0a0c0;font-size:10px'>%</div></div>
      </div>
      <div class='card'>
        <h3>Version Distribution</h3>
        <div id='version-list'></div>
      </div>
    </div>

    <!-- CODES -->
    <div id='codes-tab' class='tab-content'>
      <h2 style='color:#e94560;margin:0 0 20px;font-size:20px'>🎟️ License Codes</h2>
      <div class='card'>
        <h3>Generate Codes</h3>
        <div class='flex'>
          <input type='number' id='code-qty' value='1' min='1' max='100' placeholder='Qty' style='width:80px'>
          <input type='text' id='code-note' placeholder='Username/Note' style='flex:1;min-width:150px'>
          <select id='code-expires' style='width:120px'>
            <option value=''>Lifetime</option><option value='1'>1 Day</option><option value='7'>7 Days</option>
            <option value='30'>30 Days</option><option value='90'>90 Days</option>
          </select>
          <button class='btn btn-primary' onclick='generateCodes()'>Generate</button>
        </div>
      </div>
    </div>

    <!-- MESSAGES -->
    <div id='messages-tab' class='tab-content'>
      <h2 style='color:#e94560;margin:0 0 20px;font-size:20px'>💬 Messages</h2>
      <div class='card'>
        <h3>Broadcast</h3>
        <textarea placeholder='Message...' id='broadcast-msg' style='width:100%;height:80px;margin-bottom:12px'></textarea>
        <button class='btn btn-primary' style='width:100%' onclick='sendBroadcast()'>Send to All Active</button>
      </div>
      <div class='card'>
        <h3>Direct Message</h3>
        <div class='flex' style='margin-bottom:12px'>
          <input type='text' id='dm-hwid' placeholder='HWID' style='flex:1;min-width:150px;'>
        </div>
        <textarea placeholder='Message...' id='dm-msg' style='width:100%;height:60px;margin-bottom:12px'></textarea>
        <button class='btn btn-primary' style='width:100%' onclick='sendDM()'>Send DM</button>
      </div>
    </div>

    <!-- SETTINGS -->
    <div id='settings-tab' class='tab-content'>
      <h2 style='color:#e94560;margin:0 0 20px;font-size:20px'>⚙️ Settings</h2>
      <div class='card'>
        <h3>Server Information</h3>
        <table><tr><td style='border:0;background:0;padding:8px 0'>Server Version</td><td style='border:0;background:0;padding:8px 0' id='setting-version'>v1.0.0</td></tr>
        <tr><td style='border:0;background:0;padding:8px 0'>Database Status</td><td style='border:0;background:0;padding:8px 0'><span style='color:#2ecc71'>● Connected</span></td></tr></table>
      </div>
    </div>
  </div>
</div>

<div id='user-modal' class='modal'>
  <div class='modal-content'>
    <span class='modal-close' onclick='closeModal()'>&times;</span>
    <div id='modal-body'></div>
  </div>
</div>

<div id='toast' class='toast'></div>

<script>
let KEY = sessionStorage.getItem('akey') || '';
let currentFilter = 'all';

if (!KEY) {
  const key = prompt('Enter ADMIN_KEY:');
  if (key) { KEY = key; sessionStorage.setItem('akey', key); }
  else { location.href = '/'; return; }
}

async function api(p, b) {
  try {
    const r = await fetch(p, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(b)});
    if (!r.ok) {
      console.error(`API error at ${p}: ${r.status}`);
      return {ok: false, error: `HTTP ${r.status}`};
    }
    const data = await r.json();
    return data;
  } catch(e) {
    console.error(`Fetch error at ${p}:`, e);
    return {ok: false, error: e.message};
  }
}

function toast(m) {
  const t = document.getElementById('toast');
  t.textContent = m;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 2000);
}

function logout() {
  sessionStorage.removeItem('akey');
  location.reload();
}

function switchTab(tab) {
  document.querySelectorAll('.tab-content').forEach(e => e.classList.remove('active'));
  document.getElementById(tab + '-tab').classList.add('active');
  document.querySelectorAll('.nav-item').forEach(e => e.classList.remove('active'));
  document.getElementById('nav-' + tab).classList.add('active');
  if (tab === 'overview') loadOverview();
  else if (tab === 'users') loadUsers();
  else if (tab === 'logs') loadLogs();
  else if (tab === 'analytics') loadAnalytics();
}

async function loadOverview() {
  const r = await api('/admin-system-stats', {admin_key: KEY});
  if (!r.ok) {
    console.error('API error:', r);
    toast('Error loading stats: ' + (r.error || 'Unknown error'));
    return;
  }
  document.getElementById('stat-total').textContent = r.users.total;
  document.getElementById('stat-active').textContent = r.users.active;
  document.getElementById('stat-online').textContent = r.users.online;
  document.getElementById('stat-banned').textContent = r.users.banned;
  document.getElementById('stat-avg').textContent = (r.playtime.avg_seconds / 3600).toFixed(1) + 'h';
  document.getElementById('stat-total-time').textContent = (r.playtime.total_hours).toFixed(0) + 'h';

  const topR = await api('/admin-all-users', {admin_key: KEY});
  if (topR.ok) {
    let html = '';
    topR.users.slice(0, 10).forEach(u => {
      html += '<tr><td><span class="badge ' + (u.disabled ? 'banned' : 'active') + '">' + (u.disabled ? 'BANNED' : 'ACTIVE') + '</span></td>';
      html += '<td>' + (u.note || 'N/A') + '</td>';
      html += '<td>' + ((u.total_seconds || 0) / 3600).toFixed(1) + 'h</td>';
      html += '<td>' + (u.last_seen ? new Date(u.last_seen).toLocaleString() : 'Never') + '</td>';
      html += '<td>' + (u.app_version || '-') + '</td></tr>';
    });
    document.getElementById('top-users').innerHTML = html || '<tr><td colspan="5" style="text-align:center;color:#a0a0c0">No users yet</td></tr>';
  } else {
    console.error('Failed to load users:', topR);
  }
}

async function loadUsers() {
  const search = (document.getElementById('user-search').value || '').toUpperCase();
  const r = await api('/admin-all-users', {admin_key: KEY, status: currentFilter === 'all' ? null : currentFilter, search});
  if (!r.ok) return;
  let html = '';
  r.users.forEach(u => {
    html += '<tr>';
    html += '<td><span class="badge ' + (u.disabled ? 'banned' : 'active') + '">' + (u.disabled ? 'BANNED' : 'ACTIVE') + '</span></td>';
    html += '<td>' + (u.note || 'N/A') + '</td>';
    html += '<td>' + ((u.total_seconds || 0) / 3600).toFixed(1) + 'h</td>';
    html += '<td>' + (u.last_seen ? new Date(u.last_seen).toLocaleString() : 'Never') + '</td>';
    html += '<td><button class="btn btn-secondary" style="font-size:11px;padding:6px 12px" onclick="viewUserProfile(\'' + u.hwid + '\')">View</button></td>';
    html += '</tr>';
  });
  document.getElementById('users-table').innerHTML = html || '<tr><td colspan="5" style="text-align:center;color:#a0a0c0">No users found</td></tr>';
}

function filterUsers(f) {
  currentFilter = f;
  loadUsers();
}

async function loadLogs() {
  const hwid = document.getElementById('log-hwid-filter').value;
  const type = document.getElementById('log-type-filter').value;
  const r = await api('/admin-activity-logs', {admin_key: KEY, hwid, event_type: type});
  if (!r.ok) return;
  let html = '';
  r.logs.slice(0, 100).forEach(log => {
    html += '<tr>';
    html += '<td>' + (log.created_at ? new Date(log.created_at).toLocaleString() : '-') + '</td>';
    html += '<td style="font-family:monospace;font-size:10px">' + (log.hwid || '-').substring(0, 16) + '...</td>';
    html += '<td><span style="color:#4fc3f7">' + log.event_type + '</span></td>';
    html += '<td>' + (log.details || '-') + '</td></tr>';
  });
  document.getElementById('logs-table').innerHTML = html || '<tr><td colspan="4" style="text-align:center;color:#a0a0c0">No logs found</td></tr>';
}

async function viewUserProfile(hwid) {
  const r = await api('/admin-user-details/' + hwid, {admin_key: KEY});
  if (!r.ok) { alert('User not found'); return; }
  let html = '<h3 style="color:#e94560;margin-top:0">' + (r.user.note || hwid) + '</h3>';
  html += '<p><strong>HWID:</strong> ' + r.user.hwid + '</p>';
  html += '<p><strong>Status:</strong> ' + (r.user.disabled ? '<span style="color:#ff8899">BANNED</span>' : '<span style="color:#2ecc71">ACTIVE</span>') + '</p>';
  html += '<p><strong>Playtime:</strong> ' + ((r.user.total_seconds || 0) / 3600).toFixed(1) + 'h</p>';
  html += '<p><strong>Last Seen:</strong> ' + (r.user.last_seen ? new Date(r.user.last_seen).toLocaleString() : 'Never') + '</p>';
  html += '<p><strong>Code:</strong> ' + r.user.code + '</p>';
  html += '<h4 style="color:#a0a0c0">Activity (Last 50)</h4>';
  html += '<ul style="list-style:none;padding:0;max-height:300px;overflow-y:auto">';
  r.activity.forEach(log => {
    html += '<li style="padding:4px 0;border-bottom:1px solid #1a3a5c;font-size:10px">';
    html += '<span style="color:#4fc3f7">[' + new Date(log.created_at).toLocaleString() + ']</span> ';
    html += '<strong>' + log.event_type + '</strong>: ' + (log.details || '-') + '</li>';
  });
  html += '</ul>';
  document.getElementById('modal-body').innerHTML = html;
  document.getElementById('user-modal').classList.add('show');
}

function loadUserProfile() {
  const hwid = document.getElementById('profile-hwid').value;
  if (!hwid) { toast('Enter HWID'); return; }
  viewUserProfile(hwid);
  document.getElementById('profile-hwid').value = '';
}

function closeModal() {
  document.getElementById('user-modal').classList.remove('show');
}

async function loadAnalytics() {
  const r = await api('/admin-system-stats', {admin_key: KEY});
  if (!r.ok) return;
  document.getElementById('stat-24h').textContent = r.users.active_24h;
  document.getElementById('stat-churn').textContent = ((1 - r.users.online / r.users.active) * 100).toFixed(1);
  document.getElementById('stat-code-usage').textContent = r.codes.total > 0 ? ((1 - r.codes.unused / r.codes.total) * 100).toFixed(1) : '0';
  let vhtml = '';
  r.versions.forEach(v => {
    vhtml += '<div style="margin:8px 0;padding:8px;background:#0f3460;border-radius:4px">' +
      '<strong style="color:#4fc3f7">' + v.app_version + '</strong>: ' + v.count + ' users</div>';
  });
  document.getElementById('version-list').innerHTML = vhtml;
}

async function sendBroadcast() {
  const msg = document.getElementById('broadcast-msg').value;
  if (!msg) { toast('Enter message'); return; }
  const r = await api('/send_to_all', {admin_key: KEY, message: msg});
  if (r.ok) {
    toast('Sent to ' + r.sent + ' users');
    document.getElementById('broadcast-msg').value = '';
  } else {
    toast('Error: ' + (r.error || 'Unknown'));
  }
}

async function sendDM() {
  const hwid = document.getElementById('dm-hwid').value;
  const msg = document.getElementById('dm-msg').value;
  if (!hwid || !msg) { toast('Enter HWID and message'); return; }
  const r = await api('/send_to_user', {admin_key: KEY, hwid, message: msg});
  if (r.ok) {
    toast('Message sent');
    document.getElementById('dm-hwid').value = '';
    document.getElementById('dm-msg').value = '';
  } else {
    toast('Error: ' + (r.error || 'Unknown'));
  }
}

async function generateCodes() {
  const qty = parseInt(document.getElementById('code-qty').value);
  const note = document.getElementById('code-note').value;
  const expires = document.getElementById('code-expires').value;
  if (qty < 1 || qty > 100) { toast('Qty must be 1-100'); return; }
  const r = await api('/generate', {admin_key: KEY, count: qty, note, expires_days: expires || null});
  if (r.ok) {
    toast('Generated ' + r.codes.length + ' codes');
    const codes = r.codes.join('\\n');
    const blob = new Blob([codes], {type:'text/plain'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'codes-' + new Date().getTime() + '.txt';
    a.click();
    document.getElementById('code-qty').value = '1';
    document.getElementById('code-note').value = '';
  } else {
    toast('Error: ' + (r.error || 'Unknown'));
  }
}

// Load overview on start
console.log('Admin panel loaded, fetching data...');
loadOverview().catch(e => {
  console.error('Failed to load overview:', e);
  document.getElementById('top-users').innerHTML = '<tr><td colspan="5" style="text-align:center;color:#ff8899">Failed to load data. Check database connection.</td></tr>';
});
setInterval(loadOverview, 30000);
</script></body></html>"""

@app.get("/admin")
def admin_page():
    return Response(ADMIN_HTML, mimetype="text/html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
