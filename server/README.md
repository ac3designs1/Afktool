# Deploy to Render.com (FREE)

1. Push this `server/` folder to a new GitHub repo
2. Go to https://render.com → New → Web Service
3. Connect your GitHub repo
4. Settings:
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `gunicorn server:app`
   - Environment Variables:
     - `ADMIN_KEY` = some long secret string (YOU keep this private)
5. Deploy — you'll get a URL like `https://your-app.onrender.com`
6. Paste that URL into:
   - `AntiAFK.py` → `SERVER_URL` constant
   - `admin.py`   → `SERVER_URL` constant
7. Run `admin.py`, paste your ADMIN_KEY, click "Generate Code"
8. Give generated codes to your users — they enter the code, it binds to their PC

That's it. SQLite database persists in Render's disk between deploys.
