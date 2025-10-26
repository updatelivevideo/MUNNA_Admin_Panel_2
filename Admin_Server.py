# server.py
from flask import Flask, request, jsonify, session, redirect, url_for, render_template_string
import os, sqlite3, secrets, base64, datetime, math
from functools import wraps

# ---------------- Config ----------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change_me")
DB = os.environ.get("DB_PATH", "users.db")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "admin")

# ---------------- DB init ----------------
def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        activation_key TEXT,
        status TEXT,
        machine_id TEXT,
        expiry_date TEXT
    )''')
    conn.commit()
    conn.close()

init_db()

# ---------------- Helpers ----------------
def db_conn():
    conn = sqlite3.connect(DB)
    return conn

def login_required_json(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return wrapper

def login_required_page(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return wrapper

# ---------------- Templates ----------------
DASHBOARD_PAGE = """
<!doctype html>
<html data-bs-theme="dark">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>MUNNA All Bot Admin Panel</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body{padding:1rem;background:#0b1220;color:#e6eef6}
    .card{background:#0f1724;border:1px solid #213041}
    table thead {background:#e9ecef;color:#0b1220}
  </style>
</head>
<body>
<div class="container">
  <div class="d-flex justify-content-between align-items-center mb-3">
    <h4>⚙️ MUNNA All Bot Admin Panel</h4>
    <div>
      <button class="btn btn-sm btn-outline-light me-2" id="refreshBtn">Refresh</button>
      <button class="btn btn-sm btn-danger" id="logoutBtn">Logout</button>
    </div>
  </div>

  <div class="card p-3 mb-3">
    <form id="addForm" class="row g-2">
      <div class="col-sm-2"><input class="form-control form-control-sm" name="username" placeholder="Username" required></div>
      <div class="col-sm-2"><input class="form-control form-control-sm" name="password" placeholder="Password (opt)"></div>
      <div class="col-sm-3"><input class="form-control form-control-sm" name="activation_key" placeholder="Activation Key (opt)"></div>
      <div class="col-sm-3"><input class="form-control form-control-sm" type="date" name="expiry_date" placeholder="Expiry"></div>
      <div class="col-sm-2"><button class="btn btn-success btn-sm w-100" type="submit">➕ Add</button></div>
    </form>
  </div>

  <div class="d-flex mb-2 gap-2">
    <input id="searchInput" class="form-control form-control-sm w-25" placeholder="🔍 search username...">
    <select id="perPage" class="form-select form-select-sm w-auto">
      <option value="5">5 / page</option>
      <option value="8" selected>8 / page</option>
      <option value="15">15 / page</option>
      <option value="30">30 / page</option>
    </select>
    <button class="btn btn-outline-info btn-sm" id="clearAllBtn">🧹 Clear All Machines</button>
  </div>

  <div class="table-responsive card p-2">
    <table class="table table-dark table-striped mb-0">
      <thead class="table-light">
        <tr>
          <th>Username</th>
          <th>Activation Key</th>
          <th>Status</th>
          <th>Machine ID</th>
          <th>Expiry</th>
          <th>Days Left</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody id="userTable"></tbody>
    </table>
  </div>

  <nav class="mt-3">
    <ul class="pagination pagination-sm" id="pagination"></ul>
  </nav>
</div>

<script>
const autoRefreshInterval = 5000;
let currentPage = 1;

async function apiFetch(path, method='GET', data=null){
  const opts = {method, headers:{}};
  if(data){
    opts.headers['Content-Type']='application/json';
    opts.body = JSON.stringify(data);
  }
  const res = await fetch(path, opts);
  if(res.status === 401){
    alert('Session expired. Redirecting to login.');
    window.location.href = '/login';
    throw new Error('Unauthorized');
  }
  return res.json();
}

async function loadUsers(page=1){
  currentPage = page;
  const per_page = document.getElementById('perPage').value;
  const search = document.getElementById('searchInput').value.trim();
  const url = `/api/users?page=${page}&per_page=${per_page}&search=${encodeURIComponent(search)}`;
  try{
    const data = await apiFetch(url);
    if(data.status === 'ok'){
      renderTable(data.data.users);
      renderPagination(data.data.total_pages, data.data.current_page);
    }
  }catch(e){console.error(e);}
}

function renderTable(users){
  const tbody = document.getElementById('userTable');
  tbody.innerHTML = '';
  for(const u of users){
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${u.username}</td>
      <td>${u.activation_key}</td>
      <td><span class="badge ${u.status==='ENABLED'?'bg-success':'bg-warning text-dark'}">${u.status}</span></td>
      <td>${u.machine_id}</td>
      <td>${u.expiry_date}</td>
      <td>${u.days_left}</td>
      <td>
        <button class="btn btn-sm btn-${u.status==='ENABLED'?'warning':'success'} me-1" onclick="toggleUser('${u.username}')">${u.status==='ENABLED'?'Disable':'Enable'}</button>
        <button class="btn btn-sm btn-info me-1" onclick="renewLicense('${u.username}')">Renew</button>
        <button class="btn btn-sm btn-primary me-1" onclick="editExpiry('${u.username}', '${u.expiry_date}')">Edit Expiry</button>
        <button class="btn btn-sm btn-secondary me-1" onclick="clearMachine('${u.username}')">Clear</button>
        <button class="btn btn-sm btn-danger" onclick="deleteUser('${u.username}')">Delete</button>
      </td>`;
    tbody.appendChild(tr);
  }
}

function renderPagination(totalPages, current){
  const ul = document.getElementById('pagination');
  ul.innerHTML = '';
  for(let i=1;i<=totalPages;i++){
    const li = document.createElement('li');
    li.className = 'page-item' + (i===current?' active':'');
    li.innerHTML = `<a class="page-link" href="#" onclick="loadUsers(${i});return false;">${i}</a>`;
    ul.appendChild(li);
  }
}

document.getElementById('addForm').addEventListener('submit', async (e)=>{
  e.preventDefault();
  const fd = new FormData(e.target);
  const body = Object.fromEntries(fd.entries());
  const res = await apiFetch('/api/add_user', 'POST', body);
  alert(res.message || JSON.stringify(res));
  await loadUsers(currentPage);
  e.target.reset();
});

document.getElementById('searchInput').addEventListener('input', ()=> loadUsers(1));
document.getElementById('perPage').addEventListener('change', ()=> loadUsers(1));
document.getElementById('refreshBtn').addEventListener('click', ()=> loadUsers(currentPage));
document.getElementById('logoutBtn').addEventListener('click', async ()=>{
  await apiFetch('/logout', 'POST');
  window.location.href = '/login';
});
document.getElementById('clearAllBtn').addEventListener('click', async ()=>{
  if(!confirm('Clear all machine IDs?')) return;
  const res = await apiFetch('/api/clear_all_machines', 'POST');
  alert(res.message);
  loadUsers(currentPage);
});

// Actions
async function toggleUser(username){
  const res = await apiFetch('/api/toggle_user', 'POST', {username});
  alert(res.message); loadUsers(currentPage);
}
async function renewLicense(username){
  const res = await apiFetch('/api/renew_license', 'POST', {username});
  alert(res.message); loadUsers(currentPage);
}
async function editExpiry(username, currentDate){
  const newDate = prompt(`Enter new expiry date for ${username} (YYYY-MM-DD):`, currentDate);
  if(!newDate) return;
  const res = await apiFetch('/api/update_expiry', 'POST', {username, new_expiry: newDate});
  alert(res.message);
  loadUsers(currentPage);
}
async function clearMachine(username){
  if(!confirm('Clear machine for '+username+'?')) return;
  const res = await apiFetch('/api/clear_machine', 'POST', {username});
  alert(res.message); loadUsers(currentPage);
}
async function deleteUser(username){
  if(!confirm('Delete '+username+'?')) return;
  const res = await apiFetch('/api/delete_user', 'POST', {username});
  alert(res.message); loadUsers(currentPage);
}

let autoRefresh = setInterval(()=> loadUsers(currentPage), autoRefreshInterval);
loadUsers(1);
</script>
</body>
</html>
"""

LOGIN_PAGE = """
<!doctype html>
<html data-bs-theme="dark">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Admin Login</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-dark text-light d-flex align-items-center justify-content-center vh-100">
  <div class="card p-4 bg-secondary" style="width:360px;">
    <h4 class="text-center mb-3">🔐 Admin Login</h4>
    <form id="loginForm" method="post" action="/login">
      <div class="mb-2"><input required class="form-control" name="username" placeholder="Username"></div>
      <div class="mb-3"><input required class="form-control" type="password" name="password" placeholder="Password"></div>
      <div><button class="btn btn-primary w-100" type="submit">Login</button></div>
    </form>
  </div>
</body>
</html>
"""

# ---------------- Routes ----------------
@app.route("/login", methods=["GET","POST"])
def login_page():
    if request.method == "GET":
        return render_template_string(LOGIN_PAGE)
    u = request.form.get("username")
    p = request.form.get("password")
    if u == ADMIN_USER and p == ADMIN_PASS:
        session["logged_in"] = True
        return redirect(url_for("dashboard"))
    return "Invalid credentials", 401

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"status":"ok","message":"Logged out"})

@app.route("/")
@login_required_page
def dashboard():
    return render_template_string(DASHBOARD_PAGE)

# ---------------- JSON API ----------------
@app.route("/api/users")
@login_required_json
def api_users():
    search = request.args.get("search","").strip()
    page = int(request.args.get("page",1))
    per_page = int(request.args.get("per_page",8))
    offset = (page-1)*per_page
    conn=db_conn(); c=conn.cursor()
    if search:
        like=f"%{search}%"
        c.execute("SELECT COUNT(*) FROM users WHERE username LIKE ?",(like,))
        total=c.fetchone()[0]
        c.execute("SELECT username,activation_key,status,machine_id,expiry_date FROM users WHERE username LIKE ? ORDER BY id DESC LIMIT ? OFFSET ?",(like,per_page,offset))
    else:
        c.execute("SELECT COUNT(*) FROM users"); total=c.fetchone()[0]
        c.execute("SELECT username,activation_key,status,machine_id,expiry_date FROM users ORDER BY id DESC LIMIT ? OFFSET ?",(per_page,offset))
    rows=c.fetchall(); conn.close()
    total_pages=max(1,math.ceil(total/per_page))
    today=datetime.date.today(); users=[]
    for (u,k,s,m,e) in rows:
        try:
            expiry=datetime.date.fromisoformat(e)
            days_left=(expiry-today).days
        except Exception:
            days_left=None
        users.append({"username":u,"activation_key":k,"status":s,"machine_id":m,"expiry_date":e,"days_left":days_left})
    return jsonify({"status":"ok","data":{"users":users,"total_pages":total_pages,"current_page":page}})

@app.route("/api/add_user", methods=["POST"])
@login_required_json
def api_add_user():
    data=request.get_json() or request.form.to_dict()
    username=data.get("username"); password=data.get("password","")
    activation_key=data.get("activation_key") or secrets.token_urlsafe(8)
    expiry=data.get("expiry_date") or (datetime.date.today()+datetime.timedelta(days=30)).isoformat()
    if not username: return jsonify({"status":"error","message":"username required"}),400
    conn=db_conn(); c=conn.cursor()
    try:
        c.execute("INSERT INTO users(username,password,activation_key,status,machine_id,expiry_date) VALUES (?,?,?,?,?,?)",
            (username,password,activation_key,"ENABLED","-",expiry))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close(); return jsonify({"status":"error","message":"User exists"}),400
    conn.close(); return jsonify({"status":"ok","message":"User added"})

@app.route("/api/update_expiry", methods=["POST"])
@login_required_json
def api_update_expiry():
    data=request.get_json() or {}
    username=data.get("username"); new_expiry=data.get("new_expiry")
    if not username or not new_expiry:
        return jsonify({"status":"error","message":"Missing username or date"}),400
    try:
        _=datetime.date.fromisoformat(new_expiry)
    except Exception:
        return jsonify({"status":"error","message":"Invalid date format (use YYYY-MM-DD)"}),400
    conn=db_conn(); c=conn.cursor()
    c.execute("UPDATE users SET expiry_date=? WHERE username=?",(new_expiry,username))
    conn.commit(); conn.close()
    return jsonify({"status":"ok","message":f"Expiry updated for {username} → {new_expiry}"})

@app.route("/api/toggle_user", methods=["POST"])
@login_required_json
def api_toggle_user():
    d=request.get_json() or {}; u=d.get("username")
    conn=db_conn(); c=conn.cursor()
    c.execute("SELECT status FROM users WHERE username=?",(u,))
    row=c.fetchone()
    if not row: conn.close(); return jsonify({"status":"error","message":"User not found"}),404
    new="DISABLED" if row[0]=="ENABLED" else "ENABLED"
    c.execute("UPDATE users SET status=? WHERE username=?",(new,u)); conn.commit(); conn.close()
    return jsonify({"status":"ok","message":f"{u} {new}"})

@app.route("/api/renew_license", methods=["POST"])
@login_required_json
def api_renew_license():
    d=request.get_json() or {}; u=d.get("username")
    conn=db_conn(); c=conn.cursor()
    c.execute("SELECT expiry_date FROM users WHERE username=?",(u,))
    row=c.fetchone()
    if not row: conn.close(); return jsonify({"status":"error","message":"User not found"}),404
    try: cur=datetime.date.fromisoformat(row[0])
    except: cur=datetime.date.today()
    new=cur+datetime.timedelta(days=30)
    c.execute("UPDATE users SET expiry_date=? WHERE username=?",(new.isoformat(),u))
    conn.commit(); conn.close()
    return jsonify({"status":"ok","message":f"Renewed till {new}"})

@app.route("/api/clear_machine", methods=["POST"])
@login_required_json
def api_clear_machine():
    d=request.get_json() or {}; u=d.get("username")
    conn=db_conn(); c=conn.cursor()
    c.execute("UPDATE users SET machine_id='-' WHERE username=?",(u,))
    conn.commit(); conn.close()
    return jsonify({"status":"ok","message":f"Cleared {u}"})

@app.route("/api/clear_all_machines", methods=["POST"])
@login_required_json
def api_clear_all():
    conn=db_conn(); c=conn.cursor()
    c.execute("UPDATE users SET machine_id='-'")
    conn.commit(); conn.close()
    return jsonify({"status":"ok","message":"All cleared"})

@app.route("/api/delete_user", methods=["POST"])
@login_required_json
def api_delete_user():
    d=request.get_json() or {}; u=d.get("username")
    conn=db_conn(); c=conn.cursor()
    c.execute("DELETE FROM users WHERE username=?",(u,))
    conn.commit(); conn.close()
    return jsonify({"status":"ok","message":f"Deleted {u}"})

@app.route("/api/ck", methods=["POST"])
def api_ck():
    data = request.get_json() or {}
    username = data.get("usrname")
    machine_id = data.get("key")
    license_key = data.get("license")

    # Basic validation
    if not username or not machine_id or not license_key:
        print(f"[❌] Missing fields from client → {data}")
        return jsonify({"error": "Missing fields"}), 400

    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT activation_key, status, machine_id, expiry_date FROM users WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()

    if not row:
        print(f"[❌] {username}: user not found")
        return jsonify({"error": "User not found"}), 404

    db_license, status, db_machine, expiry_date = row

    # Expiry check
    today = datetime.date.today()
    try:
        expiry = datetime.date.fromisoformat(expiry_date)
        days_left = (expiry - today).days
    except Exception:
        days_left = None

    if days_left is not None and days_left < 0:
        print(f"[⏳] {username}: license expired on {expiry_date}")
        return jsonify({"error": "License expired", "days_left": 0}), 403

    # Status check
    if status != "ENABLED":
        print(f"[🚫] {username}: user disabled")
        return jsonify({"error": "User disabled"}), 403

    # Machine check
    if db_machine in ("-", "", None):
        conn = db_conn()
        c = conn.cursor()
        c.execute("UPDATE users SET machine_id=? WHERE username=?", (machine_id, username))
        conn.commit()
        conn.close()
        db_machine = machine_id
        print(f"[🖥️] {username}: first activation → machine_id saved = {machine_id}")

    elif db_machine != machine_id:
        print(f"[⚠️] {username}: machine mismatch! stored={db_machine}, tried={machine_id}")
        return jsonify({"error": "Machine mismatch"}), 403

    # License key check
    if db_license == license_key and db_machine == machine_id:
        print(f"[✅] {username}: license verified successfully ({days_left} days left)")
        return jsonify({
            "status": "ok",
            "key": base64.b64encode(machine_id.encode()).decode(),
            "key1": base64.b64encode(license_key.encode()).decode(),
            "key0": base64.b64encode(username.encode()).decode(),
            "days_left": days_left
        })

    print(f"[❌] {username}: invalid license key (expected={db_license}, got={license_key})")
    return jsonify({"error": "Invalid license"}), 403


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)
