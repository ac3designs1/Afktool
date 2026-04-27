"""
License Server - Flask + SQLite (with web admin panel)
"""
import os, sqlite3, secrets, string
from datetime import datetime
from flask import Flask, request, jsonify, Response

ADMIN_KEY = os.environ.get("ADMIN_KEY", "CHANGE_ME")
DB = os.environ.get("DB_PATH", "licenses.db")

app = Flask(__name__)

def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    conn.execute("""CREATE TABLE IF NOT EXISTS licenses (
        code TEXT PRIMARY KEY,
        hwid TEXT,
        activated_at TEXT,
        created_at TEXT,
        note TEXT
    )""")
    try: conn.execute("ALTER TABLE licenses ADD COLUMN note TEXT")
    except: pass
    return conn

def gen_code():
    alphabet = string.ascii_uppercase + string.digits
    parts = ["".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(4)]
    return "FIVEM-" + "-".join(parts)

@app.post("/activate")
def activate():
    data = request.json or {}
    code = (data.get("code") or "").strip().upper()
    hwid = (data.get("hwid") or "").strip().upper()
    if not code or not hwid:
        return jsonify(ok=False, error="missing code or hwid"), 400
    conn = db()
    row = conn.execute("SELECT * FROM licenses WHERE code=?", (code,)).fetchone()
    if not row:
        return jsonify(ok=False, error="invalid code"), 404
    if row["hwid"] and row["hwid"] != hwid:
        return jsonify(ok=False, error="code already used on another device"), 403
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
    if not hwid:
        return jsonify(valid=False), 400
    conn = db()
    row = conn.execute("SELECT code FROM licenses WHERE hwid=?", (hwid,)).fetchone()
    conn.close()
    return jsonify(valid=bool(row))

def _auth(data):
    return (data or {}).get("admin_key") == ADMIN_KEY

@app.post("/generate")
def generate():
    data = request.json or {}
    if not _auth(data): return jsonify(ok=False), 401
    count = int(data.get("count", 1))
    note  = (data.get("note") or "").strip()
    conn = db(); new = []
    for _ in range(count):
        c = gen_code()
        conn.execute("INSERT INTO licenses(code, created_at, note) VALUES(?,?,?)",
                    (c, datetime.utcnow().isoformat(), note))
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
    return jsonify(ok=True, codes=rows)

@app.post("/revoke")
def revoke():
    data = request.json or {}
    if not _auth(data): return jsonify(ok=False), 401
    code = (data.get("code") or "").strip().upper()
    conn = db()
    conn.execute("DELETE FROM licenses WHERE code=?", (code,))
    conn.commit(); conn.close()
    return jsonify(ok=True)

@app.post("/reset")
def reset_hwid():
    """Unbind a code's HWID so it can be re-activated."""
    data = request.json or {}
    if not _auth(data): return jsonify(ok=False), 401
    code = (data.get("code") or "").strip().upper()
    conn = db()
    conn.execute("UPDATE licenses SET hwid=NULL, activated_at=NULL WHERE code=?", (code,))
    conn.commit(); conn.close()
    return jsonify(ok=True)

@app.get("/")
def health():
    return "AntiAFK License Server OK"

# ── Admin web panel ────────────────────────────────────────────────────────────
ADMIN_HTML = """<!doctype html><html><head><meta charset='utf-8'>
<title>AntiAFK Admin</title><style>
*{box-sizing:border-box;font-family:-apple-system,Segoe UI,sans-serif}
body{background:#1a1a2e;color:#fff;margin:0;padding:20px}
h1{color:#e94560;margin:0 0 20px}
input,button{background:#16213e;color:#fff;border:none;padding:10px 14px;border-radius:4px;font-size:14px}
input{font-family:Consolas,monospace}
button{background:#e94560;cursor:pointer;font-weight:bold}
button:hover{background:#c73652}
button.ghost{background:#16213e}
button.ghost:hover{background:#1f2a4d}
.bar{display:flex;gap:8px;align-items:center;margin-bottom:20px;flex-wrap:wrap}
.status{color:#a0a0c0;font-size:13px;margin-left:auto}
table{width:100%;border-collapse:collapse;background:#16213e;border-radius:6px;overflow:hidden}
th,td{padding:10px 12px;text-align:left;border-bottom:1px solid #0f3460;font-size:13px}
th{background:#0f3460;color:#a0a0c0;font-weight:500;text-transform:uppercase;font-size:11px}
td.code{font-family:Consolas,monospace;color:#fff}
td.hwid{font-family:Consolas,monospace;color:#a0a0c0;font-size:11px}
.badge{padding:3px 8px;border-radius:10px;font-size:11px;font-weight:bold}
.badge.active{background:#0f3460;color:#4fc3f7}
.badge.unused{background:#2a2a4e;color:#a0a0c0}
.login{max-width:400px;margin:100px auto;background:#16213e;padding:30px;border-radius:8px}
.login input{width:100%;margin-bottom:10px}
.login button{width:100%}
.hide{display:none}
.toast{position:fixed;bottom:20px;right:20px;background:#0f3460;color:#fff;padding:12px 18px;border-radius:6px;opacity:0;transition:opacity .3s}
.toast.show{opacity:1}
.copy{cursor:pointer;color:#4fc3f7;font-size:11px;margin-left:6px}
.copy:hover{text-decoration:underline}
</style></head><body>

<div id='login' class='login'>
 <h1>AntiAFK Admin</h1>
 <input id='key' type='password' placeholder='Admin Key' autofocus>
 <button onclick='login()'>Login</button>
</div>

<div id='panel' class='hide'>
 <h1>AntiAFK License Admin</h1>
 <div class='bar'>
  <input id='qty' type='number' value='1' min='1' max='100' style='width:70px'>
  <input id='note' type='text' placeholder='note (optional, e.g. username)' style='flex:1;min-width:200px'>
  <button onclick='gen()'>Generate Code</button>
  <button class='ghost' onclick='load()'>Refresh</button>
  <span class='status' id='status'>-</span>
 </div>
 <table>
  <thead><tr><th>Status</th><th>Code</th><th>Note</th><th>HWID</th><th>Activated</th><th>Created</th><th></th></tr></thead>
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
 render(r.codes);
}

async function load(){
 const r = await api('/list', {admin_key:KEY});
 if (!r.ok){ sessionStorage.removeItem('akey'); location.reload(); return; }
 render(r.codes);
}

async function gen(){
 const qty = parseInt(document.getElementById('qty').value)||1;
 const note = document.getElementById('note').value;
 const r = await api('/generate', {admin_key:KEY, count:qty, note:note});
 if (r.ok){
  document.getElementById('note').value='';
  toast('Generated ' + r.codes.length + ' code(s)');
  if (r.codes.length === 1) copy(r.codes[0]);
  load();
 }
}

async function revoke(code){
 if (!confirm('Delete '+code+' permanently?')) return;
 const r = await api('/revoke', {admin_key:KEY, code:code});
 if (r.ok){ toast('Revoked'); load(); }
}

async function reset(code){
 if (!confirm('Unbind HWID from '+code+'? The code will become reusable.')) return;
 const r = await api('/reset', {admin_key:KEY, code:code});
 if (r.ok){ toast('HWID reset'); load(); }
}

function copy(text){
 navigator.clipboard.writeText(text);
 toast('Copied: '+text);
}

function fmt(iso){ if(!iso) return '-'; return new Date(iso).toLocaleString(); }
function trunc(s){ if(!s) return ''; return s.length>16? s.slice(0,16)+'...':s; }

function render(codes){
 document.getElementById('status').textContent = codes.length + ' total, ' + codes.filter(c=>c.hwid).length + ' active';
 const tb = document.getElementById('tbody');
 tb.innerHTML = codes.map(c =>
   '<tr>' +
   '<td><span class="badge '+(c.hwid?'active':'unused')+'">'+(c.hwid?'ACTIVE':'UNUSED')+'</span></td>' +
   '<td class="code">'+c.code+' <span class="copy" onclick="copy(\\''+c.code+'\\')">copy</span></td>' +
   '<td>'+(c.note||'')+'</td>' +
   '<td class="hwid">'+trunc(c.hwid||'')+'</td>' +
   '<td>'+fmt(c.activated_at)+'</td>' +
   '<td>'+fmt(c.created_at)+'</td>' +
   '<td>' +
     (c.hwid?'<button class="ghost" onclick="reset(\\''+c.code+'\\')">Reset</button> ':'') +
     '<button class="ghost" onclick="revoke(\\''+c.code+'\\')">Delete</button>' +
   '</td>' +
   '</tr>'
 ).join('');
}

document.getElementById('key').addEventListener('keypress', e=>{ if(e.key==='Enter') login(); });
</script>
</body></html>"""

@app.get("/admin")
def admin_page():
    return Response(ADMIN_HTML, mimetype="text/html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
