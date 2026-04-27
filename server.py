"""
License Server - v2 with admin features: disable, broadcast, expiry, analytics, version.
"""
import os, sqlite3, secrets, string
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, Response

ADMIN_KEY = os.environ.get("ADMIN_KEY", "CHANGE_ME")
DB = os.environ.get("DB_PATH", "licenses.db")
CURRENT_VERSION = os.environ.get("APP_VERSION", "1.0.0")

app = Flask(__name__)

def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    conn.execute("""CREATE TABLE IF NOT EXISTS licenses (
        code TEXT PRIMARY KEY, hwid TEXT, activated_at TEXT, created_at TEXT,
        note TEXT, disabled INTEGER DEFAULT 0, expires_at TEXT,
        last_seen TEXT, total_seconds INTEGER DEFAULT 0, app_version TEXT
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS broadcast (
        id INTEGER PRIMARY KEY CHECK (id=1), message TEXT, updated_at TEXT
    )""")
    # migrations for older DBs
    for col, typ in [("note","TEXT"),("disabled","INTEGER DEFAULT 0"),
                     ("expires_at","TEXT"),("last_seen","TEXT"),
                     ("total_seconds","INTEGER DEFAULT 0"),("app_version","TEXT")]:
        try: conn.execute(f"ALTER TABLE licenses ADD COLUMN {col} {typ}")
        except: pass
    return conn

def gen_code():
    alpha = string.ascii_uppercase + string.digits
    return "FIVEM-" + "-".join("".join(secrets.choice(alpha) for _ in range(4)) for _ in range(4))

def _auth(data): return (data or {}).get("admin_key") == ADMIN_KEY

def _valid_license_row(hwid):
    conn = db()
    row = conn.execute("SELECT * FROM licenses WHERE hwid=?", (hwid,)).fetchone()
    conn.close()
    if not row: return None, "no license"
    if row["disabled"]: return row, "disabled"
    if row["expires_at"]:
        try:
            exp = datetime.fromisoformat(row["expires_at"])
            if datetime.utcnow() > exp: return row, "expired"
        except: pass
    return row, None

@app.post("/activate")
def activate():
    data = request.json or {}
    code = (data.get("code") or "").strip().upper()
    hwid = (data.get("hwid") or "").strip().upper()
    if not code or not hwid: return jsonify(ok=False, error="missing code or hwid"), 400
    conn = db()
    row = conn.execute("SELECT * FROM licenses WHERE code=?", (code,)).fetchone()
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
        conn.execute("UPDATE licenses SET hwid=?, activated_at=? WHERE code=?",
                    (hwid, datetime.utcnow().isoformat(), code))
        conn.commit()
    conn.close()
    return jsonify(ok=True)

@app.post("/verify")
def verify():
    data = request.json or {}
    hwid = (data.get("hwid") or "").strip().upper()
    ver  = (data.get("version") or "").strip()
    session_seconds = int(data.get("session_seconds", 0))
    if not hwid: return jsonify(valid=False), 400
    row, err = _valid_license_row(hwid)
    if err or not row:
        return jsonify(valid=False, error=err or "no license")
    # Update analytics
    conn = db()
    conn.execute("""UPDATE licenses SET last_seen=?, total_seconds=COALESCE(total_seconds,0)+?, app_version=? WHERE hwid=?""",
                (datetime.utcnow().isoformat(), session_seconds, ver or row["app_version"], hwid))
    # Broadcast
    b = conn.execute("SELECT message, updated_at FROM broadcast WHERE id=1").fetchone()
    conn.commit(); conn.close()
    resp = {
        "valid": True,
        "expires_at": row["expires_at"],
        "note": row["note"],
        "current_version": CURRENT_VERSION,
        "broadcast": dict(b) if b and b["message"] else None,
    }
    return jsonify(resp)

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
    conn = db(); new = []
    for _ in range(count):
        c = gen_code()
        conn.execute("INSERT INTO licenses(code, created_at, note, expires_at) VALUES(?,?,?,?)",
                    (c, datetime.utcnow().isoformat(), note, expires))
        new.append(c)
    conn.commit(); conn.close()
    return jsonify(ok=True, codes=new)

@app.post("/list")
def list_codes():
    data = request.json or {}
    if not _auth(data): return jsonify(ok=False), 401
    conn = db()
    rows = [dict(r) for r in conn.execute("SELECT * FROM licenses ORDER BY created_at DESC").fetchall()]
    conn.close()
    return jsonify(ok=True, codes=rows, current_version=CURRENT_VERSION)

@app.post("/revoke")
def revoke():
    data = request.json or {}
    if not _auth(data): return jsonify(ok=False), 401
    conn = db()
    conn.execute("DELETE FROM licenses WHERE code=?", ((data.get("code") or "").strip().upper(),))
    conn.commit(); conn.close()
    return jsonify(ok=True)

@app.post("/disable")
def toggle_disable():
    data = request.json or {}
    if not _auth(data): return jsonify(ok=False), 401
    code = (data.get("code") or "").strip().upper()
    disabled = 1 if data.get("disabled") else 0
    conn = db()
    conn.execute("UPDATE licenses SET disabled=? WHERE code=?", (disabled, code))
    conn.commit(); conn.close()
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
    conn = db()
    conn.execute("UPDATE licenses SET expires_at=? WHERE code=?", (expires, code))
    conn.commit(); conn.close()
    return jsonify(ok=True)

@app.post("/reset")
def reset_hwid():
    data = request.json or {}
    if not _auth(data): return jsonify(ok=False), 401
    conn = db()
    conn.execute("UPDATE licenses SET hwid=NULL, activated_at=NULL WHERE code=?",
                ((data.get("code") or "").strip().upper(),))
    conn.commit(); conn.close()
    return jsonify(ok=True)

@app.post("/broadcast")
def set_broadcast():
    data = request.json or {}
    if not _auth(data): return jsonify(ok=False), 401
    msg = (data.get("message") or "").strip()
    conn = db()
    if msg:
        conn.execute("INSERT OR REPLACE INTO broadcast(id, message, updated_at) VALUES(1, ?, ?)",
                    (msg, datetime.utcnow().isoformat()))
    else:
        conn.execute("DELETE FROM broadcast WHERE id=1")
    conn.commit(); conn.close()
    return jsonify(ok=True)

@app.post("/set_version")
def set_version():
    """Updates the server-advertised latest version. (Requires redeploy env var OR this stores in-memory only — use env var for permanent.)"""
    data = request.json or {}
    if not _auth(data): return jsonify(ok=False), 401
    global CURRENT_VERSION
    CURRENT_VERSION = (data.get("version") or "").strip() or CURRENT_VERSION
    return jsonify(ok=True, current_version=CURRENT_VERSION)

@app.get("/")
def health():
    return "AntiAFK License Server OK"

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
.badge.expired{background:#4a3800;color:#ffcc66}
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

 <div class='card'>
  <h3>Generate Codes</h3>
  <div class='bar'>
   <input id='qty' type='number' value='1' min='1' max='100' style='width:60px'>
   <input id='note' type='text' placeholder='note / username' style='flex:1;min-width:140px'>
   <select id='expires' style='background:#16213e;color:#fff;border:none;padding:8px;border-radius:4px'>
    <option value=''>lifetime</option>
    <option value='1'>1 day</option>
    <option value='7'>7 days</option>
    <option value='30'>30 days</option>
    <option value='90'>90 days</option>
    <option value='365'>1 year</option>
   </select>
   <button onclick='gen()'>Generate</button>
   <button class='ghost' onclick='load()'>Refresh</button>
   <span class='status' id='status'>-</span>
  </div>
 </div>

 <div class='card'>
  <h3>Broadcast message to all users (leave empty to clear)</h3>
  <div class='bar'>
   <input id='bmsg' type='text' placeholder='Server maintenance 3pm EST' style='flex:1'>
   <button onclick='setBroadcast()'>Send</button>
  </div>
 </div>

 <table>
  <thead><tr><th>Status</th><th>Code</th><th>Note</th><th>Expires</th><th>Hours</th><th>Last Seen</th><th>Ver</th><th></th></tr></thead>
  <tbody id='tbody'></tbody>
 </table>
</div>

<div id='toast' class='toast'></div>

<script>
let KEY = sessionStorage.getItem('akey') || '';
if (KEY) { document.getElementById('login').classList.add('hide'); document.getElementById('panel').classList.remove('hide'); load(); }

function toast(m){ const t=document.getElementById('toast'); t.textContent=m; t.classList.add('show'); setTimeout(()=>t.classList.remove('show'),1800); }

async function api(path, body){
 const r = await fetch(path, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)});
 return r.json();
}
async function login(){
 KEY = document.getElementById('key').value;
 const r = await api('/list', {admin_key:KEY});
 if (!r.ok){ alert('Wrong key'); return; }
 sessionStorage.setItem('akey', KEY);
 document.getElementById('login').classList.add('hide');
 document.getElementById('panel').classList.remove('hide');
 render(r);
}
async function load(){
 const r = await api('/list', {admin_key:KEY});
 if (!r.ok){ sessionStorage.removeItem('akey'); location.reload(); return; }
 render(r);
}
async function gen(){
 const qty = parseInt(document.getElementById('qty').value)||1;
 const note = document.getElementById('note').value;
 const exp = document.getElementById('expires').value;
 const r = await api('/generate', {admin_key:KEY, count:qty, note:note, expires_days:exp||null});
 if (r.ok){
  document.getElementById('note').value='';
  toast('Generated ' + r.codes.length + ' code(s)');
  if (r.codes.length === 1) copy(r.codes[0]);
  load();
 }
}
async function disable(code, on){
 await api('/disable', {admin_key:KEY, code:code, disabled:on?1:0});
 toast(on?'Disabled':'Enabled'); load();
}
async function revoke(code){
 if (!confirm('Delete '+code+' permanently?')) return;
 await api('/revoke', {admin_key:KEY, code:code}); toast('Revoked'); load();
}
async function reset(code){
 if (!confirm('Unbind HWID from '+code+'?')) return;
 await api('/reset', {admin_key:KEY, code:code}); toast('Reset'); load();
}
async function setExpiry(code){
 const d = prompt('Days from now until expiry (empty = lifetime):');
 if (d === null) return;
 await api('/set_expiry', {admin_key:KEY, code:code, days:d||null});
 toast('Expiry updated'); load();
}
async function setBroadcast(){
 const msg = document.getElementById('bmsg').value;
 await api('/broadcast', {admin_key:KEY, message:msg});
 toast(msg?'Broadcast sent':'Broadcast cleared');
 document.getElementById('bmsg').value = '';
}
function copy(t){ navigator.clipboard.writeText(t); toast('Copied: '+t); }
function fmt(iso){ if(!iso) return '-'; return new Date(iso).toLocaleString(); }
function fmtDate(iso){ if(!iso) return '-'; return new Date(iso).toLocaleDateString(); }
function hrs(s){ return s?(s/3600).toFixed(1)+'h':'-'; }
function trunc(s){ if(!s) return ''; return s.length>14? s.slice(0,14)+'...':s; }
function isExpired(iso){ if(!iso) return false; return new Date(iso) < new Date(); }

function render(data){
 document.getElementById('version').textContent = 'Server v' + (data.current_version||'?');
 const codes = data.codes;
 document.getElementById('status').textContent = codes.length + ' total, ' + codes.filter(c=>c.hwid).length + ' active';
 const tb = document.getElementById('tbody');
 tb.innerHTML = codes.map(c => {
  let statusBadge = 'UNUSED', cls='unused';
  if (c.disabled) { statusBadge='DISABLED'; cls='disabled'; }
  else if (c.expires_at && isExpired(c.expires_at)) { statusBadge='EXPIRED'; cls='expired'; }
  else if (c.hwid) { statusBadge='ACTIVE'; cls='active'; }
  return '<tr>' +
   '<td><span class="badge '+cls+'">'+statusBadge+'</span></td>' +
   '<td class="code">'+c.code+' <span class="copy" onclick="copy(\\''+c.code+'\\')">copy</span>'+
   (c.note?'<br><span class="mini">'+c.note+'</span>':'')+'</td>' +
   '<td class="mini">'+(c.hwid?trunc(c.hwid):'-')+'</td>' +
   '<td class="mini"><a href="#" onclick="setExpiry(\\''+c.code+'\\');return false">'+fmtDate(c.expires_at)+'</a></td>' +
   '<td>'+hrs(c.total_seconds)+'</td>' +
   '<td class="mini">'+fmt(c.last_seen)+'</td>' +
   '<td class="mini">'+(c.app_version||'-')+'</td>' +
   '<td>' +
     (c.disabled ?
       '<button class="ghost" onclick="disable(\\''+c.code+'\\',false)">Enable</button>' :
       '<button class="ghost" onclick="disable(\\''+c.code+'\\',true)">Disable</button>') + ' ' +
     (c.hwid?'<button class="ghost" onclick="reset(\\''+c.code+'\\')">Reset</button> ':'') +
     '<button class="ghost" onclick="revoke(\\''+c.code+'\\')">Delete</button>' +
   '</td>' +
   '</tr>';
 }).join('');
}
document.getElementById('key').addEventListener('keypress', e=>{ if(e.key==='Enter') login(); });
</script>
</body></html>"""

@app.get("/admin")
def admin_page():
    return Response(ADMIN_HTML, mimetype="text/html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
