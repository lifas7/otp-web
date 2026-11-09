# language: Python 3, file: app.py, runtime: Flask 3
import re, os, sqlite3, requests, hashlib, json
from datetime import datetime, date, timezone
from flask import Flask, render_template, request, session, redirect, url_for, abort

# ========= CONFIG =========
BASE       = "https://api.tsoftedge.com/api/v1"
API_TOKEN  = "57786|5Q7RcOMfGEjJ914GDTsiYt1UxFsNUcADaBrJclNZed1c29c7"
CHANNEL    = "https://t.me/r77cr"
ADMIN_TG   = "lifas_py"
DAILY_FREE = 3
DB         = "otp.db"
SECRET     = "super_secret_key_123456_otp_web"
ADMIN_PASS = "admin123"
# ==========================

HEADERS = {
    "User-Agent": "okhttp/5.5.0",
    "Accept": "application/json",
    "x-security-upgrade-capable": "1",
    "authorization": f"Bearer {API_TOKEN}",
}

app = Flask(__name__)
app.secret_key = SECRET

# ========= OTP (TSOFTEDGE REGISTER) =========
def send_registration_otp(email):
    url = f"{BASE}/auth/register/send-otp"
    payload = {"email": email, "full_name": "OTP User"}
    headers = {
        'User-Agent': "okhttp/5.5.0",
        'Accept': "application/json",
        'Accept-Encoding': "gzip",
        'accept-language': "en",
        'x-security-upgrade-capable': "1",
        'content-type': "application/json; charset=UTF-8"
    }
    try:
        r = requests.post(url, data=json.dumps(payload), headers=headers, timeout=15)
        return r.status_code in (200, 201)
    except:
        return False

def verify_registration(email, otp_code, password):
    url = f"{BASE}/auth/register"
    payload = {
        "country": "Iraq",
        "device_name": "android-app",
        "email": email,
        "full_name": "OTP User",
        "otp": otp_code,
        "password": password,
        "password_confirmation": password
    }
    headers = {
        'User-Agent': "okhttp/5.5.0",
        'Accept': "application/json",
        'Accept-Encoding': "gzip",
        'accept-language': "en",
        'x-security-upgrade-capable': "1",
        'content-type': "application/json; charset=UTF-8"
    }
    try:
        r = requests.post(url, data=json.dumps(payload), headers=headers, timeout=15)
        return r.status_code in (200, 201)
    except:
        return False

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
        name TEXT,
        email TEXT UNIQUE,
        password TEXT,
        is_verified INTEGER DEFAULT 0,
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

# ========= API SMS (FOR NUMBERS) =========
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
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        pw = request.form.get("password", "")
        c = db()
        row = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        c.close()
        if row and row["password"] == hash_pw(pw):
            if row["is_verified"] == 0:
                # إذا الحساب غير مفعل، نرسله لصفحة التحقق ونرسل له كود جديد
                send_registration_otp(email)
                session["verify_email"] = email
                return redirect(url_for("verify"))
            
            session["user_id"] = row["id"]
            return redirect(url_for("index"))
        return render_template("login.html", error="الإيميل أو الباسورد غلط", mode="login")
    return render_template("login.html", mode="login")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        pw = request.form.get("password", "")
        
        if not re.search(r"[A-Z]", pw) or not re.search(r"\d", pw) or not re.search(r"[^a-zA-Z0-9]", pw) or len(pw) < 6:
            return render_template("login.html", error="الباسورد يجب أن يكون 6 أحرف عالأقل، ويحتوي على حرف كبير، رقم، ورمز خاص.", mode="register")

        c = db()
        row = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        
        if row:
            if row["is_verified"] == 1:
                return render_template("login.html", error="هذا الإيميل مسجل ومفعل مسبقاً، يرجى تسجيل الدخول.", mode="register")
            else:
                # إذا الإيميل مسجل بس غير مفعل، نحدث بياناته ونعيد إرسال الكود
                c.execute("UPDATE users SET name=?, password=? WHERE email=?", (name, hash_pw(pw), email))
                c.commit()
                send_registration_otp(email)
                session["verify_email"] = email
                return redirect(url_for("verify"))
        
        try:
            c.execute("INSERT INTO users (name, email, password, created_at) VALUES (?,?,?,?)",
                      (name, email, hash_pw(pw), datetime.now(timezone.utc).isoformat()))
            c.commit()
            
            send_registration_otp(email)
            session["verify_email"] = email
            return redirect(url_for("verify"))
        except sqlite3.IntegrityError:
            return render_template("login.html", error="حدث خطأ غير متوقع، حاول مرة أخرى.", mode="register")
        finally:
            c.close()
    return render_template("login.html", mode="register")

@app.route("/verify", methods=["GET", "POST"])
def verify():
    email = session.get("verify_email")
    if not email: return redirect(url_for("login"))
    
    if request.method == "POST":
        code = request.form.get("code", "").strip()
        
        c = db()
        row = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        
        if verify_registration(email, code, "Aa12345678@"): # الباسورد هنا ثابت للـ API
            c.execute("UPDATE users SET is_verified=1 WHERE email=?", (email,))
            c.commit()
            session.pop("verify_email", None)
            session["user_id"] = row["id"]
            c.close()
            return redirect(url_for("index"))
        else:
            c.close()
            return render_template("login.html", error="كود التحقق غلط أو منتهي، تأكد من الإيميل وحاول مرة ثانية.", mode="verify", email=email)
            
    return render_template("login.html", mode="verify", email=email)

@app.route("/resend-otp")
def resend_otp():
    email = session.get("verify_email")
    if email:
        send_registration_otp(email)
    return redirect(url_for("verify"))

@app.route("/logout")
def logout():
    session.pop("user_id", None)
    return redirect(url_for("login"))

# ========= MAIN ROUTES =========
@app.route("/")
def index():
    u = get_user()
    if not u: return redirect(url_for("login"))
    if u["is_verified"] == 0: 
        session["verify_email"] = u["email"]
        return redirect(url_for("verify"))
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

application = app
init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port)
