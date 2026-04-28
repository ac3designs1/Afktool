"""
License Server v2 — PostgreSQL (data persists across restarts)
"""
import os, secrets, string, psycopg2, psycopg2.extras
from datetime import datetime, timedelta
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
    # Check for a pending personal message
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
    # Active = has hwid and was seen in last 10 minutes
    from datetime import timezone
    cutoff = (datetime.utcnow().replace(tzinfo=timezone.utc)
              .replace(tzinfo=None) - timedelta(minutes=10)).isoformat()
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
    # Online = seen in last 5 minutes
    from datetime import timezone
    cutoff = (datetime.utcnow().replace(tzinfo=timezone.utc).replace(tzinfo=None) - timedelta(minutes=5)).isoformat()
    cur.execute("SELECT COUNT(*) as online FROM licenses WHERE hwid IS NOT NULL AND last_seen > %s", (cutoff,))
    online = cur.fetchone()["online"]
    # Total playtime
    cur.execute("SELECT COALESCE(SUM(total_seconds), 0) as total FROM licenses WHERE hwid IS NOT NULL")
    total_seconds = cur.fetchone()["total"] or 0
    # Top 5 users by playtime
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
    """Admin statistics dashboard (requires auth in JS)"""
    return Response(ADMIN_STATS_HTML, mimetype="text/html")

ADMIN_HTML = """<!doctype html><html><head><meta charset='utf-8'>
<title>AntiAFK Admin</title><style>
*{box-sizing:border-box;font-family:-apple-system,Segoe UI,sans-serif}
body{background:#1a1a2e;color:#fff;margin:0;padding:20px}
h1{color:#e94560;margin:0 0 16px}
h3{color:#a0a0c0;margin:16px 0 6px;font-size:11px;text-transform:uppercase}
input,button,textarea{background:#16213e;color:#fff;border:none;padding:9px 12px;border-radius:4px;font-size:13px}
input,textarea{font-family:Consolas,monospace}
button{background:#e94560;cursor:pointer;font-weight:bold}
button:hover{background:#c73652}
button.ghost{background:#16213e}
button.ghost:hover{background:#1f2a4d}
.card{background:#16213e;padding:14px;border-radius:6px;margin-bottom:14px}
.bar{display:flex;gap:6px;align-items:center;flex-wrap:wrap}
.status{color:#a0a0c0;font-size:12px;margin-left:auto}
table{width:100%;border-collapse:collapse;background:#16213e;border-radius:6px;overflow:hidden}
th,td{padding:8px 10px;text-align:left;border-bottom:1px solid #0f3460;font-size:12px}
th{background:#0f3460;color:#a0a0c0;font-weight:500;text-transform:uppercase;font-size:10px}
td.code{font-family:Consolas,monospace}
.badge{padding:2px 7px;border-radius:10px;font-size:10px;font-weight:bold}
.badge.active{background:#0f3460;color:#4fc3f7}
.badge.unused{background:#2a2a4e;color:#a0a0c0}
.badge.disabled{background:#5a1f2e;color:#ff8899}
.badge.online{background:#0d3320;color:#2ecc71}
.dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:#2ecc71;margin-right:4px;animation:pulse 1.5s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.3}}
.login{max-width:400px;margin:100px auto;background:#16213e;padding:30px;border-radius:8px}
.login input{width:100%;margin-bottom:10px}
.login button{width:100%}
.hide{display:none}
.toast{position:fixed;bottom:20px;right:20px;background:#0f3460;color:#fff;padding:12px 18px;border-radius:6px;opacity:0;transition:opacity .3s}
.toast.show{opacity:1}
.copy{cursor:pointer;color:#4fc3f7;font-size:11px;margin-left:6px}
.mini{font-size:11px;color:#8b92b3}
</style></head><body>
<div id='login' class='login'>
 <h1>AntiAFK Admin</h1>
 <input id='key' type='password' placeholder='Admin Key' autofocus>
 <button onclick='login()'>Login</button>
</div>
<div id='panel' class='hide'>
 <h1>AntiAFK License Admin <span class='mini' id='version'></span></h1>
 <div style='display:flex;align-items:center;margin-bottom:16px'>
  <h1 style='margin:0;flex:1'>AntiAFK License Admin <span class='mini' id='version'></span></h1>
  <button class='ghost' onclick="window.open('/admin-stats-page','_blank')" style='background:#1a3a5c;padding:6px 12px;font-size:11px;cursor:pointer'>📊 View Stats</button>
 </div>
 <div class='card'>
  <h3>Generate Codes</h3>
  <div class='bar'>
   <input id='qty' type='number' value='1' min='1' max='100' style='width:60px'>
   <input id='note' type='text' placeholder='note / username' style='flex:1;min-width:140px'>
   <select id='expires' style='background:#16213e;color:#fff;border:none;padding:8px;border-radius:4px'>
    <option value=''>lifetime</option><option value='1'>1 day</option><option value='7'>7 days</option>
    <option value='30'>30 days</option><option value='90'>90 days</option><option value='365'>1 year</option>
   </select>
   <button onclick='gen()'>Generate</button>
   <button class='ghost' onclick='load()'>Refresh</button>
   <span class='status' id='status'>-</span>
  </div>
 </div>
 <div class='card'>
  <h3>Broadcast message to all users (leave empty to clear)</h3>
  <div class='bar'>
   <input id='bmsg' type='text' placeholder='Announcement text...' style='flex:1'>
   <button onclick='setBroadcast()'>Send</button>
   <button class='ghost' onclick='clearBroadcast()'>Clear</button>
   <button class='ghost' onclick='sendToAll()'>📩 Message All Active</button>
  </div>
 </div>
 <table>
  <thead><tr><th>Status</th><th>Code</th><th>Note</th><th>Expires</th><th>Hours</th><th>Last Seen</th><th>Ver</th><th></th></tr></thead>
  <tbody id='tbody'></tbody>
 </table>
</div>
<div id='toast' class='toast'></div>
<script>
let KEY=sessionStorage.getItem('akey')||'';
if(KEY){document.getElementById('login').classList.add('hide');document.getElementById('panel').classList.remove('hide');load();}
function toast(m){const t=document.getElementById('toast');t.textContent=m;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),1800);}
async function api(p,b){const r=await fetch(p,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)});return r.json();}
async function login(){KEY=document.getElementById('key').value;const r=await api('/list',{admin_key:KEY});if(!r.ok){alert('Wrong key');return;}sessionStorage.setItem('akey',KEY);document.getElementById('login').classList.add('hide');document.getElementById('panel').classList.remove('hide');render(r);}
async function load(){const r=await api('/list',{admin_key:KEY});if(!r.ok){sessionStorage.removeItem('akey');location.reload();return;}render(r);}
async function gen(){const q=parseInt(document.getElementById('qty').value)||1;const n=document.getElementById('note').value;const e=document.getElementById('expires').value;const r=await api('/generate',{admin_key:KEY,count:q,note:n,expires_days:e||null});if(r.ok){document.getElementById('note').value='';toast('Generated '+r.codes.length);if(r.codes.length===1)copy(r.codes[0]);load();}}
async function disable(c,on){await api('/disable',{admin_key:KEY,code:c,disabled:on?1:0});toast(on?'Disabled':'Enabled');load();}
async function revoke(c){if(!confirm('Delete '+c+'?'))return;await api('/revoke',{admin_key:KEY,code:c});toast('Revoked');load();}
async function reset(c){if(!confirm('Unbind HWID from '+c+'?'))return;await api('/reset',{admin_key:KEY,code:c});toast('Reset');load();}
async function setExpiry(c){const d=prompt('Days until expiry (empty=lifetime):');if(d===null)return;await api('/set_expiry',{admin_key:KEY,code:c,days:d||null});toast('Updated');load();}
async function setBroadcast(){const m=document.getElementById('bmsg').value;await api('/broadcast',{admin_key:KEY,message:m});toast(m?'Broadcast sent':'Broadcast cleared');document.getElementById('bmsg').value='';}
async function clearBroadcast(){await api('/broadcast',{admin_key:KEY,message:''});toast('Broadcast cleared');document.getElementById('bmsg').value='';}
async function sendToAll(){
 const m=prompt('Message to ALL active users (online in last 10 min):');
 if(!m||!m.trim())return;
 if(!confirm('Send to all active users?'))return;
 const r=await api('/send_to_all',{admin_key:KEY,message:m.trim()});
 if(r.ok) toast('Sent to '+r.sent+' active user(s)');
 else toast('Failed: '+(r.error||'unknown'));
}async function sendDM(hwid, note){
 const m=prompt('Message to '+(note||hwid.slice(0,8)+'...')+':');
 if(!m||!m.trim())return;
 const r=await api('/send_to_user',{admin_key:KEY,hwid:hwid,message:m.trim()});
 if(r.ok) toast('Sent to '+( note||'user')+' — delivers within 5s');
 else toast('Failed: '+(r.error||'unknown'));
}function copy(t){navigator.clipboard.writeText(t);toast('Copied: '+t);}
function fmt(i){if(!i)return'-';return new Date(i).toLocaleString();}
function fmtD(i){if(!i)return'-';return new Date(i).toLocaleDateString();}
function hrs(s){return s?(s/3600).toFixed(1)+'h':'-';}
function trunc(s){if(!s)return'';return s.length>14?s.slice(0,14)+'...':s;}
function isOnline(last_seen){ 
  if(!last_seen) return false; 
  const t = new Date(last_seen.includes('Z') ? last_seen : last_seen + 'Z');
  return (new Date() - t) < 5*60*1000; // 5 min window
}
function timeAgo(iso){
  if(!iso) return '-';
  const t = new Date(iso.includes('Z') ? iso : iso + 'Z');
  const secs = Math.floor((new Date()-t)/1000);
  if(secs < 10) return 'just now';
  if(secs < 60) return secs+'s ago';
  if(secs < 3600) return Math.floor(secs/60)+'m ago';
  if(secs < 86400) return Math.floor(secs/3600)+'h ago';
  return Math.floor(secs/86400)+'d ago';
}
function isExp(i){if(!i)return false;return new Date(i)<new Date();}
function render(d){
 document.getElementById('version').textContent='Server v'+(d.current_version||'?');
 const c=d.codes;
 const onlineCount = c.filter(x=>isOnline(x.last_seen)).length;
 document.getElementById('status').textContent=c.length+' total, '+c.filter(x=>x.hwid).length+' active, '+(onlineCount?'<span style="color:#2ecc71">●</span> '+onlineCount+' online now':'0 online');
 document.getElementById('status').innerHTML=c.length+' total &nbsp;|&nbsp; '+c.filter(x=>x.hwid).length+' activated &nbsp;|&nbsp; <span style="color:#2ecc71">● '+onlineCount+' online now</span>';
 document.getElementById('tbody').innerHTML=c.map(x=>{
  let st='UNUSED',cl='unused';
  if(x.disabled){st='DISABLED';cl='disabled';}
  else if(x.expires_at&&isExp(x.expires_at)){st='EXPIRED';cl='expired';}
  else if(x.hwid){st='ACTIVE';cl='active';}
  const online = isOnline(x.last_seen);
  return'<tr style="'+(online?'background:rgba(46,204,113,0.04)':'')+'">'
   +'<td><span class="badge '+cl+'">'+st+'</span>'+(online?' <span class="dot"></span>':'')+' </td>'+
   '<td class="code">'+x.code+' <span class="copy" onclick="copy(\\''+x.code+'\\')">copy</span>'+(x.note?'<br><span class="mini">'+x.note+'</span>':'')+'</td>'+
   '<td class="mini">'+(x.hwid?trunc(x.hwid):'-')+'</td>'+
   '<td class="mini"><a href="#" onclick="setExpiry(\\''+x.code+'\\');return false">'+fmtD(x.expires_at)+'</a></td>'+
   '<td>'+hrs(x.total_seconds)+'</td><td class="mini" title="'+fmt(x.last_seen)+'">'+timeAgo(x.last_seen)+'</td><td class="mini">'+(x.app_version||'-')+'</td>'+
   '<td>'+(x.disabled?'<button class="ghost" onclick="disable(\\''+x.code+'\\',false)">Enable</button>':'<button class="ghost" onclick="disable(\\''+x.code+'\\',true)">Disable</button>')+' '+
   (x.hwid?'<button class="ghost" onclick="reset(\\''+x.code+'\\')">Reset</button> ':'')+
   (x.hwid?'<button class="ghost" onclick="sendDM(\\''+x.hwid+'\\',\\''+( x.note||'')+'\\')" style="background:#1a3a5c">📩 DM</button> ':'')+
   '<button class="ghost" onclick="revoke(\\''+x.code+'\\')">Delete</button></td></tr>';
 }).join('');
}
document.getElementById('key').addEventListener('keypress',e=>{if(e.key==='Enter')login();});
// Auto-refresh every 30s to keep online status current
setInterval(()=>{ if(document.getElementById('panel').style.display!=='none' && !document.getElementById('panel').classList.contains('hide')) load(); }, 30000);
</script></body></html>"""

@app.get("/admin")
def admin_page():
    return Response(ADMIN_HTML, mimetype="text/html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
