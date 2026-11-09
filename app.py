# language: Python 3, file: app.py, runtime: Flask 3
import re, os, sqlite3, requests, hashlib
from datetime import datetime, date, timezone
from flask import Flask, render_template, request, session, redirect, url_for, abort
from authlib.integrations.flask_client import OAuth

# ========= CONFIG =========
API_TOKEN  = "57786|5Q7RcOMfGEjJ914GDTsiYt1UxFsNUcADaBrJclNZed1c29c7"
BASE       = "https://api.tsoftedge.com/api/v1"
CHANNEL    = "https://t.me/r77cr"
ADMIN_TG   = "lifas_py"
DAILY_FREE = 3
DB         = "otp.db"

# <-- سر الجلسة (عدلناه عشان ما يطردك برا)
SECRET     = "super_secret_key_123456_otp_web"
ADMIN_PASS = "admin123" # باسورد لوحة الإدارة

# مفاتيح جوجل
GOOGLE_CLIENT_ID = "483195823539-qprmui1ck50j51r205becmca7ge1eq5l.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "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"
# ==========================

HEADERS = {
    "User-Agent": "okhttp/5.5.0",
    "Accept": "application/json",
    "x-security-upgrade-capable": "1",
    "authorization": f"Bearer {API_TOKEN}",
}

app = Flask(__name__)
app.secret_key = SECRET
app.config['SESSION_COOKIE_SECURE'] = True      # حماية إضافية للكوكيز
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'   # منع حظر الكوكيز في جوجل

# ========= GOOGLE OAUTH SETUP =========
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

# ========= DB =========
def db():
    c = sqlite3.connect(DB, check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    c = db()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        google_id TEXT UNIQUE,
        name TEXT,
        password TEXT,
        is_complete INTEGER DEFAULT 0,
        daily_date TEXT,
        daily_count INTEGER DEFAULT 0,
        created_at TEXT
    );
    """)
    c.commit(); c.close()

def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def get_user():
    if "user_id" not in session:
        return None
    c = db()
    row = c.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    c.close()
    return row

def daily_info(user_id):
    c = db()
    row = c.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    today = date.today().isoformat()
    if row["daily_date"] != today:
        c.execute("UPDATE users SET daily_date=?, daily_count=0 WHERE id=?", (today, user_id))
        c.commit()
        used = 0
    else:
        used = row["daily_count"]
    c.close()
    return used, DAILY_FREE, used >= DAILY_FREE

def consume(user_id):
    used, mx, blocked = daily_info(user_id)
    if blocked: return False
    c = db()
    c.execute("UPDATE users SET daily_count=daily_count+1 WHERE id=?", (user_id,))
    c.commit(); c.close()
    return True

# ========= API & OTP =========
def api_numbers(page=1, country="United States"):
    r = requests.get(f"{BASE}/public-numbers", params={"country_name": country, "per_page": "50", "page": str(page)}, headers=HEADERS, timeout=15)
    r.raise_for_status(); return r.json()

def api_messages(num_id, page=1):
    r = requests.get(f"{BASE}/public-numbers/{num_id}/messages", params={"per_page": "50", "page": str(page)}, headers=HEADERS, timeout=15)
    r.raise_for_status(); return r.json()

CODE_PATS = (r'code\s*(?:is|:)\s*(\d{4,8})', r'pin\s*[:]\s*(\d{4,8})', r'passcode[^\d]{0,20}(\d{4,8})', r'\b(\d{4,8})\b')
SKIP = ("reply stop","opt out","aws4_request","x-amz-","do not reply","unsubscribe","msg&data","msg & data")

def extract_otp(body):
    low = body.lower()
    if any(w in low for w in SKIP): return None
    for pat in CODE_PATS:
        m = re.search(pat, low)
        if m: return m.group(1)
    return None

# ========= AUTH ROUTES =========
@app.route("/login")
def login():
    return render_template("login.html", mode="login")

@app.route("/auth/google")
def auth_google():
    # هذا السطر يجبر الموقع يستخدم HTTPS دايماً على PythonAnywhere
    scheme = "https" if "pythonanywhere" in request.host else request.scheme
    redirect_uri = url_for('authorize_google', _external=True, _scheme=scheme)
    return google.authorize_redirect(redirect_uri)

@app.route("/auth/google/callback")
def authorize_google():
    try:
        token = google.authorize_access_token()
        user_info = token.get('userinfo')
        
        if not user_info:
            return redirect(url_for("login"))
            
        google_id = user_info.get("sub")
        email = user_info.get("email")
        
        c = db()
        row = c.execute("SELECT * FROM users WHERE google_id=? OR email=?", (google_id, email)).fetchone()
        
        if not row:
            c.execute("INSERT INTO users (email, google_id, created_at) VALUES (?,?,?)",
                      (email, google_id, datetime.now(timezone.utc).isoformat()))
            c.commit()
            row = c.execute("SELECT * FROM users WHERE google_id=?", (google_id,)).fetchone()
        
        c.close()
        
        # حفظ الجلسة بالشكل الصحيح
        session.permanent = True
        session["user_id"] = row["id"]
        
        if row["is_complete"] == 0:
            return redirect(url_for("complete_profile"))
            
        return redirect(url_for("index"))
    except Exception as e:
        print(f"Google Auth Error: {e}")
        return redirect(url_for("login"))

@app.route("/complete-profile", methods=["GET", "POST"])
def complete_profile():
    u = get_user()
    if not u: return redirect(url_for("login"))
    if u["is_complete"] == 1: return redirect(url_for("index"))
    
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        pw = request.form.get("password", "")
        
        if not re.search(r"[A-Z]", pw) or not re.search(r"\d", pw) or not re.search(r"[^a-zA-Z0-9]", pw) or len(pw) < 6:
            return render_template("login.html", error="الباسورد يجب أن يكون 6 أحرف عالأقل، ويحتوي على حرف كبير، رقم، ورمز خاص.", mode="complete")
        
        c = db()
        c.execute("UPDATE users SET name=?, password=?, is_complete=1 WHERE id=?", (name, hash_pw(pw), u["id"]))
        c.commit(); c.close()
        return redirect(url_for("index"))
        
    return render_template("login.html", mode="complete", user=u)

@app.route("/logout")
def logout():
    session.pop("user_id", None)
    return redirect(url_for("login"))

# ========= MAIN ROUTES =========
@app.route("/")
def index():
    u = get_user()
    if not u: return redirect(url_for("login"))
    if u["is_complete"] == 0: return redirect(url_for("complete_profile"))
    return render_template("index.html", user=u)

@app.route("/numbers")
def numbers():
    u = get_user()
    if not u: return redirect(url_for("login"))
    page = int(request.args.get("page", 1))
    used, mx, blocked = daily_info(u["id"])
    try:
        j = api_numbers(page=page)
    except Exception as e:
        return render_template("numbers.html", error=str(e), rows=[], page=page, last=1, total=0, used=used, mx=mx, blocked=blocked, admin=ADMIN_TG, user=u)
    rows = j.get("data", [])[:10]
    return render_template("numbers.html", rows=rows, page=page, last=j.get("meta", {}).get("last_page", 1), total=j.get("meta", {}).get("total", 0), used=used, mx=mx, blocked=blocked, admin=ADMIN_TG, error=None, user=u)

@app.route("/messages/<int:num_id>")
def messages(num_id):
    u = get_user()
    if not u: return redirect(url_for("login"))
    page = int(request.args.get("page", 1))
    phone = request.args.get("phone", "")
    is_refresh = request.args.get("refresh", "0") == "1"
    
    if not is_refresh:
        if not consume(u["id"]):
            return render_template("messages.html", blocked=True, phone=phone, mx=DAILY_FREE, admin=ADMIN_TG, channel=CHANNEL, rows=[], page=1, last=1, total=0, error=None, user=u)
    else:
        used, mx, blocked = daily_info(u["id"])
        if blocked:
            return render_template("messages.html", blocked=True, phone=phone, mx=DAILY_FREE, admin=ADMIN_TG, channel=CHANNEL, rows=[], page=1, last=1, total=0, error=None, user=u)

    try:
        j = api_messages(num_id, page=page)
    except Exception as e:
        return render_template("messages.html", error=str(e), phone=phone, blocked=False, mx=DAILY_FREE, admin=ADMIN_TG, channel=CHANNEL, rows=[], page=page, last=1, total=0, num_id=num_id, user=u)

    msgs = [{"body": m["body"], "otp": extract_otp(m["body"]), "time": m["received_at"]} for m in j.get("data", [])[:20]]
    used, mx, _ = daily_info(u["id"])
    
    return render_template("messages.html", blocked=False, error=None, phone=phone, rows=msgs, page=page, last=j.get("meta", {}).get("last_page", 1), total=j.get("meta", {}).get("total", 0), used=used, mx=mx, admin=ADMIN_TG, channel=CHANNEL, num_id=num_id, user=u)

# ========= ADMIN ROUTE =========
@app.route("/admin", methods=["GET", "POST"])
def admin():
    if request.method == "POST":
        pw = request.form.get("pw", "")
        if pw == ADMIN_PASS:
            session["is_admin"] = True
    if not session.get("is_admin"):
        return '''
        <body style="background:#0d1117;color:white;font-family:sans-serif;text-align:center;padding:50px;">
        <h2>Admin Login</h2>
        <form method="POST"><input type="password" name="pw" placeholder="Password" style="padding:10px;border-radius:5px;border:none;"><button type="submit" style="padding:10px 20px;background:#0891b2;color:white;border:none;border-radius:5px;cursor:pointer;">Enter</button></form>
        </body>'''
    c = db()
    users = c.execute("SELECT * FROM users ORDER BY id DESC").fetchall()
    c.close()
    return render_template("admin.html", users=users)

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port)
