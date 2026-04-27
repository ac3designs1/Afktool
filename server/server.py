"""
License Server — Flask + SQLite
Deploy free on Render.com / PythonAnywhere / your own VPS.

Endpoints:
  POST /activate  { code, hwid }        -> binds code to HWID (first time only)
  POST /verify    { hwid }              -> returns {valid: bool}
  POST /generate  { admin_key, count }  -> create new unused codes
  POST /list      { admin_key }         -> list all codes + status
  POST /revoke    { admin_key, code }   -> delete a code

Codes format: FIVEM-XXXX-XXXX-XXXX (16 random chars in groups of 4)
"""
import os, sqlite3, secrets, string, hmac, hashlib
from datetime import datetime
from flask import Flask, request, jsonify

ADMIN_KEY = os.environ.get("ADMIN_KEY", "CHANGE_ME_TO_A_SECRET_STRING")
DB = os.environ.get("DB_PATH", "licenses.db")

app = Flask(__name__)

def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    conn.execute("""CREATE TABLE IF NOT EXISTS licenses (
        code TEXT PRIMARY KEY,
        hwid TEXT,
        activated_at TEXT,
        created_at TEXT
    )""")
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

@app.post("/generate")
def generate():
    data = request.json or {}
    if data.get("admin_key") != ADMIN_KEY:
        return jsonify(ok=False), 401
    count = int(data.get("count", 1))
    conn = db()
    new = []
    for _ in range(count):
        c = gen_code()
        conn.execute("INSERT INTO licenses(code, created_at) VALUES(?,?)",
                    (c, datetime.utcnow().isoformat()))
        new.append(c)
    conn.commit(); conn.close()
    return jsonify(ok=True, codes=new)

@app.post("/list")
def list_codes():
    data = request.json or {}
    if data.get("admin_key") != ADMIN_KEY:
        return jsonify(ok=False), 401
    conn = db()
    rows = [dict(r) for r in conn.execute("SELECT * FROM licenses ORDER BY created_at DESC").fetchall()]
    conn.close()
    return jsonify(ok=True, codes=rows)

@app.post("/revoke")
def revoke():
    data = request.json or {}
    if data.get("admin_key") != ADMIN_KEY:
        return jsonify(ok=False), 401
    code = (data.get("code") or "").strip().upper()
    conn = db()
    conn.execute("DELETE FROM licenses WHERE code=?", (code,))
    conn.commit(); conn.close()
    return jsonify(ok=True)

@app.get("/")
def health():
    return "AntiAFK License Server OK"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
