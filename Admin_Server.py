# server.py / Admin_Server.py
from flask import Flask, request, jsonify, session, redirect, url_for, render_template_string
import os, sqlite3, secrets, base64, datetime, math
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

# ---------------- Config ----------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change_me")

DB = os.environ.get("DB_PATH", "users.db")

# Bootstrap SUPER_ADMIN credentials (used only to create the first SUPER_ADMIN in DB)
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "admin")

# ---------------- DB init ----------------
def _add_column_if_missing(c: sqlite3.Cursor, table: str, column: str, col_type: str):
    c.execute(f"PRAGMA table_info({table})")
    cols = {r[1] for r in c.fetchall()}
    if column not in cols:
        c.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")


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

    # Admin accounts (SUPER_ADMIN or SUB_ADMIN)
    c.execute('''CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        max_users INTEGER,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL
    )''')

    # Which SUB_ADMIN can manage which users
    c.execute('''CREATE TABLE IF NOT EXISTS admin_user_access (
        admin_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        UNIQUE(admin_id, user_id)
    )''')

    # Migrations: keep ownership info even if sub-admin is deleted
    _add_column_if_missing(c, "users", "created_by_admin_id", "INTEGER")
    _add_column_if_missing(c, "users", "created_by_username", "TEXT")
    _add_column_if_missing(c, "users", "created_by_role", "TEXT")

    conn.commit()
    conn.close()


def db_conn():
    # check_same_thread=False helps when gunicorn uses multiple threads
    return sqlite3.connect(DB, check_same_thread=False)


def ensure_super_admin():
    """Ensure there is at least one SUPER_ADMIN in DB.

    Uses ADMIN_USER/ADMIN_PASS from env only for bootstrapping.
    """
    u = (ADMIN_USER or "admin").strip()
    p = ADMIN_PASS or "admin"
    now = datetime.datetime.utcnow().isoformat()

    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT id FROM admins WHERE role='SUPER_ADMIN' LIMIT 1")
    exists = c.fetchone()
    if not exists:
        c.execute(
            "INSERT INTO admins(username,password_hash,role,max_users,is_active,created_at) VALUES (?,?,?,?,?,?)",
            (u, generate_password_hash(p), "SUPER_ADMIN", None, 1, now)
        )
        conn.commit()
    conn.close()


init_db()
ensure_super_admin()

# ---------------- Helpers ----------------
def is_super_admin() -> bool:
    return session.get("role") == "SUPER_ADMIN"


@app.before_request
def _validate_admin_session():
    # If an admin gets disabled/deleted after login, invalidate the session.
    if not session.get("logged_in"):
        return None

    admin_id = session.get("admin_id")
    if not admin_id:
        session.clear()
        return None

    # allow login/logout endpoints to work even if session is half-broken
    if request.path in ("/login", "/logout"):
        return None

    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT is_active, role, username, COALESCE(max_users,0) FROM admins WHERE id=?", (admin_id,))
    row = c.fetchone()
    conn.close()

    if not row:
        session.clear()
        if request.path.startswith("/api/"):
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        return redirect(url_for("login_page"))

    is_active, role, username, max_users = row
    if not int(is_active):
        session.clear()
        if request.path.startswith("/api/"):
            return jsonify({"status": "error", "message": "Admin disabled"}), 403
        return redirect(url_for("login_page"))

    # Keep session values in sync (quota/role changes reflect without re-login)
    session["role"] = role
    session["admin_username"] = username
    session["max_users"] = int(max_users or 0)
    return None


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


def require_super_admin_json():
    if not session.get("logged_in") or not is_super_admin():
        return jsonify({"status": "error", "message": "Forbidden"}), 403
    return None


def can_manage_user(username: str) -> bool:
    """Return True if current logged-in admin can manage this user."""
    if not username:
        return False
    if is_super_admin():
        return True

    admin_id = session.get("admin_id")
    if not admin_id:
        return False

    conn = db_conn()
    c = conn.cursor()
    c.execute(
        """
        SELECT 1
        FROM users u
        JOIN admin_user_access aua ON aua.user_id = u.id
        WHERE aua.admin_id=? AND u.username=?
        LIMIT 1
        """,
        (admin_id, username)
    )
    ok = c.fetchone() is not None
    conn.close()
    return ok


def subadmin_has_quota() -> bool:
    """For SUB_ADMIN: returns True if they can add one more user (count < max_users)."""
    if is_super_admin():
        return True
    max_users = int(session.get("max_users") or 0)
    if max_users <= 0:
        return False

    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM admin_user_access WHERE admin_id=?", (session["admin_id"],))
    cnt = c.fetchone()[0]
    conn.close()
    return cnt < max_users


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
    <div>
      <h4 class="mb-0">⚙️ MUNNA All Bot Admin Panel</h4>
      <div class="small text-secondary">Logged in as: <span class="text-light">{{ admin_username }}</span> <span class="badge bg-info text-dark">{{ role }}</span></div>
    </div>
    <div>
      <button class="btn btn-sm btn-outline-light me-2" id="refreshBtn">Refresh</button>
      <button class="btn btn-sm btn-danger" id="logoutBtn">Logout</button>
    </div>
  </div>

  {% if is_super %}
  <div class="card p-3 mb-3">
    <div class="d-flex align-items-center justify-content-between">
      <h6 class="mb-2">👥 Sub Admin Management</h6>
      <button class="btn btn-sm btn-outline-info" id="subadminRefreshBtn">Refresh Sub Admins</button>
    </div>

    <div class="row g-2 mt-1">
      <div class="col-md-4">
        <div class="card p-2">
          <div class="small text-secondary mb-2">Create Sub Admin</div>
          <form id="createSubadminForm" class="row g-2">
            <div class="col-12"><input class="form-control form-control-sm" name="username" placeholder="Sub-admin username" required></div>
            <div class="col-12"><input class="form-control form-control-sm" name="password" placeholder="Password" type="password" required></div>
            <div class="col-12"><input class="form-control form-control-sm" name="max_users" placeholder="Max users" value="10" type="number" min="1" required></div>
            <div class="col-12"><button class="btn btn-sm btn-success w-100" type="submit">Create</button></div>
          </form>
        </div>
      </div>

      <div class="col-md-4">
        <div class="card p-2">
          <div class="small text-secondary mb-2">Assign User → Sub Admin</div>
          <form id="assignUserForm" class="row g-2">
            <div class="col-12">
              <select class="form-select form-select-sm" name="subadmin" id="assignSubadminSelect" required>
                <option value="">Select sub-admin...</option>
              </select>
            </div>
            <div class="col-12"><input class="form-control form-control-sm" name="username" id="assignUsernameInput" placeholder="User username" list="userSuggestList" required></div>
            <div class="col-12"><button class="btn btn-sm btn-primary w-100" type="submit">Assign</button></div>
          </form>
        </div>
      </div>

      <div class="col-md-4">
        <div class="card p-2">
          <div class="small text-secondary mb-2">Unassign User</div>
          <form id="unassignUserForm" class="row g-2">
            <div class="col-12">
              <select class="form-select form-select-sm" name="subadmin" id="unassignSubadminSelect" required>
                <option value="">Select sub-admin...</option>
              </select>
            </div>
            <div class="col-12"><input class="form-control form-control-sm" name="username" id="unassignUsernameInput" placeholder="User username" list="userSuggestList" required></div>
            <div class="col-12"><button class="btn btn-sm btn-warning w-100" type="submit">Unassign</button></div>
          </form>
        </div>
      </div>
    </div>

    <datalist id="userSuggestList"></datalist>

    <div class="card p-2 mt-3">
      <div class="d-flex align-items-center justify-content-between">
        <div class="small text-secondary">Assigned Users (Selected Sub-admin)</div>
        <button class="btn btn-sm btn-outline-info" id="subadminUsersRefreshBtn">Refresh List</button>
      </div>
      <div class="row g-2 mt-2 align-items-center">
        <div class="col-md-4">
          <select class="form-select form-select-sm" id="subadminUsersSelect">
            <option value="">Select sub-admin...</option>
          </select>
        </div>
        <div class="col-md-8 small text-secondary" id="assignedUsersMeta"></div>
      </div>
      <div class="table-responsive mt-2">
        <table class="table table-dark table-striped mb-0">
          <thead class="table-light">
            <tr>
              <th>User</th>
              <th>Status</th>
              <th>Expiry</th>
              <th>Created?</th>
            </tr>
          </thead>
          <tbody id="assignedUsersTable"></tbody>
        </table>
      </div>
    </div>

    <div class="table-responsive mt-3">
      <table class="table table-dark table-striped mb-0">
        <thead class="table-light">
          <tr>
            <th>Sub Admin</th>
            <th>Quota</th>
            <th>Assigned</th>
            <th>Created Users</th>
            <th>Active</th>
            <th>Created</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody id="subadminTable"></tbody>
      </table>
    </div>
  </div>
  {% endif %}

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
          {% if is_super %}
          <th>Created By</th>
          <th>Assigned Subadmins</th>
          {% endif %}
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
const IS_SUPER = {{ 'true' if is_super else 'false' }};
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

function populateSubadminSelects(rows){
  const names = (rows || []).map(r => r.username);
  const selectIds = ['assignSubadminSelect', 'unassignSubadminSelect', 'subadminUsersSelect'];
  for(const id of selectIds){
    const sel = document.getElementById(id);
    if(!sel) continue;
    const cur = sel.value;
    sel.innerHTML = '<option value="">Select sub-admin...</option>' + names.map(n => `<option value="${n}">${n}</option>`).join('');
    if(cur && names.includes(cur)) sel.value = cur;
  }
}

async function refreshUserSuggestions(q){
  if(!IS_SUPER) return;
  const dl = document.getElementById('userSuggestList');
  if(!dl) return;
  if(!q || q.length < 1){
    dl.innerHTML = '';
    return;
  }
  try{
    const res = await apiFetch(`/api/admin/user_suggestions?search=${encodeURIComponent(q)}`);
    const arr = res.data || [];
    dl.innerHTML = arr.map(u => `<option value="${u}"></option>`).join('');
  }catch(e){
    console.error(e);
  }
}

let _userSuggestTimer = null;
function queueUserSuggest(q){
  clearTimeout(_userSuggestTimer);
  _userSuggestTimer = setTimeout(()=> refreshUserSuggestions(q), 200);
}

async function loadSubadminUsers(){
  const sel = document.getElementById('subadminUsersSelect');
  const tbody = document.getElementById('assignedUsersTable');
  const meta = document.getElementById('assignedUsersMeta');
  if(!sel || !tbody || !meta) return;

  const subadmin = (sel.value || '').trim();
  if(!subadmin){
    tbody.innerHTML = '';
    meta.textContent = 'Select a sub-admin to see assigned users.';
    return;
  }

  try{
    const res = await apiFetch(`/api/admin/subadmin_users?subadmin=${encodeURIComponent(subadmin)}`);
    if(res.status !== 'ok'){
      meta.textContent = res.message || 'Failed to load assigned users';
      tbody.innerHTML = '';
      return;
    }
    const users = (res.data && res.data.users) ? res.data.users : [];
    meta.textContent = `Total: ${users.length}`;
    tbody.innerHTML = '';
    for(const u of users){
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${u.username}</td>
        <td><span class="badge ${u.status==='ENABLED'?'bg-success':'bg-warning text-dark'}">${u.status}</span></td>
        <td>${u.expiry_date || ''}</td>
        <td>${u.is_created ? '<span class="badge bg-info text-dark">CREATED</span>' : '<span class="badge bg-secondary">ASSIGNED</span>'}</td>
      `;
      tbody.appendChild(tr);
    }
  }catch(e){
    console.error(e);
  }
}

function viewAssignedUsers(username){
  const sel = document.getElementById('subadminUsersSelect');
  if(!sel) return;
  sel.value = username;
  loadSubadminUsers();
}

async function toggleSubadmin(username, is_active){
  if(!IS_SUPER) return;
  const res = await apiFetch('/api/admin/toggle_subadmin', 'POST', {username, is_active});
  alert(res.message || JSON.stringify(res));
  await loadSubadmins();
}

async function promptQuota(username, current){
  if(!IS_SUPER) return;
  const v = prompt(`Set quota (max users) for ${username}:`, String(current ?? 10));
  if(!v) return;
  const max_users = parseInt(v);
  if(!max_users || max_users <= 0){
    alert('Invalid quota');
    return;
  }
  const res = await apiFetch('/api/admin/update_subadmin_quota', 'POST', {username, max_users});
  alert(res.message || JSON.stringify(res));
  await loadSubadmins();
}

async function deleteSubadmin(username){
  if(!IS_SUPER) return;
  if(!confirm(`Delete sub-admin ${username}? Their created users will be DISABLED.`)) return;
  const res = await apiFetch('/api/admin/delete_subadmin', 'POST', {username});
  alert(res.message || JSON.stringify(res));
  await loadSubadmins();
  await loadUsers(1);
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
    const createdBy = (u.created_by && (u.created_by.username || u.created_by.role))
      ? `${u.created_by.username || ''}${u.created_by.role ? ' ('+u.created_by.role+')' : ''}`
      : '';
    const assigned = (u.assigned_subadmins || []).join(', ');

    tr.innerHTML = `
      <td>${u.username}</td>
      ${IS_SUPER ? `<td>${createdBy}</td><td>${assigned}</td>` : ''}
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

const assignUsernameInput = document.getElementById('assignUsernameInput');
if(assignUsernameInput){
  assignUsernameInput.addEventListener('input', (e)=> queueUserSuggest(e.target.value));
}
const unassignUsernameInput = document.getElementById('unassignUsernameInput');
if(unassignUsernameInput){
  unassignUsernameInput.addEventListener('input', (e)=> queueUserSuggest(e.target.value));
}
const subadminUsersSelect = document.getElementById('subadminUsersSelect');
if(subadminUsersSelect){
  subadminUsersSelect.addEventListener('change', ()=> loadSubadminUsers());
}
const subadminUsersRefreshBtn = document.getElementById('subadminUsersRefreshBtn');
if(subadminUsersRefreshBtn){
  subadminUsersRefreshBtn.addEventListener('click', ()=> loadSubadminUsers());
}

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

async function loadSubadmins(){
  const tbody = document.getElementById('subadminTable');
  if(!tbody) return;
  try{
    const res = await apiFetch('/api/admin/subadmins');
    if(res.status !== 'ok'){
      tbody.innerHTML = `<tr><td colspan="7">${res.message || 'Failed to load sub-admins'}</td></tr>`;
      return;
    }
    const rows = res.data || [];
    tbody.innerHTML = '';

    // populate dropdowns
    populateSubadminSelects(rows);

    for(const a of rows){
      const tr = document.createElement('tr');
      const activeBadge = a.is_active ? '<span class="badge bg-success">YES</span>' : '<span class="badge bg-secondary">NO</span>';
      const toggleBtn = `<button class="btn btn-sm ${a.is_active?'btn-warning':'btn-success'} me-1" onclick="toggleSubadmin('${a.username}', ${a.is_active?0:1})">${a.is_active?'Disable':'Enable'}</button>`;
      const quotaBtn = `<button class="btn btn-sm btn-info me-1" onclick="promptQuota('${a.username}', ${a.max_users})">Quota</button>`;
      const viewBtn = `<button class="btn btn-sm btn-secondary me-1" onclick="viewAssignedUsers('${a.username}')">Users</button>`;
      const delBtn = `<button class="btn btn-sm btn-danger" onclick="deleteSubadmin('${a.username}')">Delete</button>`;

      tr.innerHTML = `
        <td>${a.username}</td>
        <td>${a.max_users}</td>
        <td>${a.assigned_count}</td>
        <td>${a.created_count ?? 0}</td>
        <td>${activeBadge}</td>
        <td>${a.created_at || ''}</td>
        <td>${toggleBtn}${quotaBtn}${viewBtn}${delBtn}</td>
      `;
      tbody.appendChild(tr);
    }

    // keep assigned-users panel updated
    loadSubadminUsers();
  }catch(e){ console.error(e); }
}

const createForm = document.getElementById('createSubadminForm');
if(createForm){
  createForm.addEventListener('submit', async (e)=>{
    e.preventDefault();
    const fd = new FormData(e.target);
    const body = Object.fromEntries(fd.entries());
    body.max_users = parseInt(body.max_users || '10');
    const res = await apiFetch('/api/admin/create_subadmin', 'POST', body);
    alert(res.message || JSON.stringify(res));
    await loadSubadmins();
    e.target.reset();
  });
}

const assignForm = document.getElementById('assignUserForm');
if(assignForm){
  assignForm.addEventListener('submit', async (e)=>{
    e.preventDefault();
    const fd = new FormData(e.target);
    const body = Object.fromEntries(fd.entries());
    const res = await apiFetch('/api/admin/assign_user', 'POST', body);
    alert(res.message || JSON.stringify(res));
    await loadSubadmins();
    e.target.reset();
  });
}

const unassignForm = document.getElementById('unassignUserForm');
if(unassignForm){
  unassignForm.addEventListener('submit', async (e)=>{
    e.preventDefault();
    const fd = new FormData(e.target);
    const body = Object.fromEntries(fd.entries());
    const res = await apiFetch('/api/admin/unassign_user', 'POST', body);
    alert(res.message || JSON.stringify(res));
    await loadSubadmins();
    e.target.reset();
  });
}

const subadminRefreshBtn = document.getElementById('subadminRefreshBtn');
if(subadminRefreshBtn){
  subadminRefreshBtn.addEventListener('click', ()=> loadSubadmins());
}

let autoRefresh = setInterval(()=> loadUsers(currentPage), autoRefreshInterval);
let autoRefreshSuper = null;
if(IS_SUPER){
  autoRefreshSuper = setInterval(()=>{
    loadSubadmins();
    loadSubadminUsers();
  }, autoRefreshInterval);
}

loadUsers(1);
loadSubadmins();
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
@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "GET":
        return render_template_string(LOGIN_PAGE)

    u = (request.form.get("username") or "").strip()
    p = request.form.get("password") or ""

    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT id, password_hash, role, is_active, COALESCE(max_users, 0) FROM admins WHERE username=?", (u,))
    row = c.fetchone()
    conn.close()

    if not row:
        return "Invalid credentials", 401

    admin_id, pw_hash, role, is_active, max_users = row

    if not int(is_active):
        return "Admin disabled", 403

    if not check_password_hash(pw_hash, p):
        return "Invalid credentials", 401

    session.clear()
    session["logged_in"] = True
    session["admin_id"] = int(admin_id)
    session["admin_username"] = u
    session["role"] = role
    session["max_users"] = int(max_users or 0)

    return redirect(url_for("dashboard"))


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"status": "ok", "message": "Logged out"})


@app.route("/")
@login_required_page
def dashboard():
    return render_template_string(
        DASHBOARD_PAGE,
        is_super=is_super_admin(),
        role=session.get("role") or "",
        admin_username=session.get("admin_username") or "",
    )


# ---------------- JSON API ----------------
@app.route("/api/users")
@login_required_json
def api_users():
    search = request.args.get("search", "").strip()
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 8))
    offset = (page - 1) * per_page

    conn = db_conn()
    c = conn.cursor()

    if is_super_admin():
        if search:
            like = f"%{search}%"
            c.execute("SELECT COUNT(*) FROM users WHERE username LIKE ?", (like,))
            total = c.fetchone()[0]
            c.execute(
                """
                SELECT id, username, activation_key, status, machine_id, expiry_date,
                       COALESCE(created_by_username,''), COALESCE(created_by_role,'')
                FROM users
                WHERE username LIKE ?
                ORDER BY id DESC
                LIMIT ? OFFSET ?
                """,
                (like, per_page, offset),
            )
        else:
            c.execute("SELECT COUNT(*) FROM users")
            total = c.fetchone()[0]
            c.execute(
                """
                SELECT id, username, activation_key, status, machine_id, expiry_date,
                       COALESCE(created_by_username,''), COALESCE(created_by_role,'')
                FROM users
                ORDER BY id DESC
                LIMIT ? OFFSET ?
                """,
                (per_page, offset),
            )
    else:
        admin_id = session["admin_id"]
        if search:
            like = f"%{search}%"
            c.execute(
                """
                SELECT COUNT(*)
                FROM users u
                JOIN admin_user_access aua ON aua.user_id=u.id
                WHERE aua.admin_id=? AND u.username LIKE ?
                """,
                (admin_id, like),
            )
            total = c.fetchone()[0]
            c.execute(
                """
                SELECT u.id, u.username, u.activation_key, u.status, u.machine_id, u.expiry_date,
                       COALESCE(u.created_by_username,''), COALESCE(u.created_by_role,'')
                FROM users u
                JOIN admin_user_access aua ON aua.user_id=u.id
                WHERE aua.admin_id=? AND u.username LIKE ?
                ORDER BY u.id DESC
                LIMIT ? OFFSET ?
                """,
                (admin_id, like, per_page, offset),
            )
        else:
            c.execute(
                """
                SELECT COUNT(*)
                FROM users u
                JOIN admin_user_access aua ON aua.user_id=u.id
                WHERE aua.admin_id=?
                """,
                (admin_id,),
            )
            total = c.fetchone()[0]
            c.execute(
                """
                SELECT u.id, u.username, u.activation_key, u.status, u.machine_id, u.expiry_date,
                       COALESCE(u.created_by_username,''), COALESCE(u.created_by_role,'')
                FROM users u
                JOIN admin_user_access aua ON aua.user_id=u.id
                WHERE aua.admin_id=?
                ORDER BY u.id DESC
                LIMIT ? OFFSET ?
                """,
                (admin_id, per_page, offset),
            )

    rows = c.fetchall()
    conn.close()

    # For SUPER_ADMIN: build mapping user_id -> [subadmins]
    assigned_map = {}
    if is_super_admin() and rows:
        user_ids = [r[0] for r in rows]
        placeholders = ",".join(["?"] * len(user_ids))
        conn2 = db_conn()
        c2 = conn2.cursor()
        c2.execute(
            f"""
            SELECT aua.user_id, a.username
            FROM admin_user_access aua
            JOIN admins a ON a.id = aua.admin_id
            WHERE aua.user_id IN ({placeholders}) AND a.role='SUB_ADMIN'
            ORDER BY a.username
            """,
            user_ids,
        )
        for user_id, a_username in c2.fetchall():
            assigned_map.setdefault(int(user_id), []).append(a_username)
        conn2.close()

    total_pages = max(1, math.ceil(total / per_page))
    today = datetime.date.today()
    users = []
    for (user_id, u, k, s, m, e, created_by_username, created_by_role) in rows:
        try:
            expiry = datetime.date.fromisoformat(e)
            days_left = (expiry - today).days
        except Exception:
            days_left = None

        item = {
            "username": u,
            "activation_key": k,
            "status": s,
            "machine_id": m,
            "expiry_date": e,
            "days_left": days_left,
            "created_by": {
                "username": created_by_username or "",
                "role": created_by_role or "",
            },
        }
        if is_super_admin():
            item["assigned_subadmins"] = assigned_map.get(int(user_id), [])
        users.append(item)

    return jsonify({"status": "ok", "data": {"users": users, "total_pages": total_pages, "current_page": page}})


@app.route("/api/add_user", methods=["POST"])
@login_required_json
def api_add_user():
    if not is_super_admin() and not subadmin_has_quota():
        return jsonify({"status": "error", "message": "User limit reached"}), 403

    data = request.get_json() or request.form.to_dict()
    username = (data.get("username") or "").strip()
    password = data.get("password", "")
    activation_key = data.get("activation_key") or secrets.token_urlsafe(8)
    expiry = data.get("expiry_date") or (datetime.date.today() + datetime.timedelta(days=30)).isoformat()

    if not username:
        return jsonify({"status": "error", "message": "username required"}), 400

    conn = db_conn()
    c = conn.cursor()
    try:
        c.execute(
            """
            INSERT INTO users(
              username,password,activation_key,status,machine_id,expiry_date,
              created_by_admin_id,created_by_username,created_by_role
            ) VALUES (?,?,?,?,?,?,?,?,?)
            """,
            (
                username,
                password,
                activation_key,
                "ENABLED",
                "-",
                expiry,
                int(session.get("admin_id") or 0) or None,
                session.get("admin_username"),
                session.get("role"),
            ),
        )
        user_id = c.lastrowid

        # If SUB_ADMIN created a user, auto-assign it to them
        if not is_super_admin():
            c.execute(
                "INSERT OR IGNORE INTO admin_user_access(admin_id,user_id) VALUES (?,?)",
                (session["admin_id"], user_id),
            )

        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"status": "error", "message": "User exists"}), 400

    conn.close()
    return jsonify({"status": "ok", "message": "User added"})


@app.route("/api/update_expiry", methods=["POST"])
@login_required_json
def api_update_expiry():
    data = request.get_json() or {}
    username = (data.get("username") or "").strip()
    new_expiry = (data.get("new_expiry") or "").strip()

    if not username or not new_expiry:
        return jsonify({"status": "error", "message": "Missing username or date"}), 400

    if not can_manage_user(username):
        return jsonify({"status": "error", "message": "Forbidden"}), 403

    try:
        _ = datetime.date.fromisoformat(new_expiry)
    except Exception:
        return jsonify({"status": "error", "message": "Invalid date format (use YYYY-MM-DD)"}), 400

    conn = db_conn()
    c = conn.cursor()
    c.execute("UPDATE users SET expiry_date=? WHERE username=?", (new_expiry, username))
    conn.commit()
    conn.close()

    return jsonify({"status": "ok", "message": f"Expiry updated for {username} → {new_expiry}"})


@app.route("/api/toggle_user", methods=["POST"])
@login_required_json
def api_toggle_user():
    d = request.get_json() or {}
    u = (d.get("username") or "").strip()

    if not can_manage_user(u):
        return jsonify({"status": "error", "message": "Forbidden"}), 403

    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT status FROM users WHERE username=?", (u,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({"status": "error", "message": "User not found"}), 404

    new = "DISABLED" if row[0] == "ENABLED" else "ENABLED"
    c.execute("UPDATE users SET status=? WHERE username=?", (new, u))
    conn.commit()
    conn.close()

    return jsonify({"status": "ok", "message": f"{u} {new}"})


@app.route("/api/renew_license", methods=["POST"])
@login_required_json
def api_renew_license():
    d = request.get_json() or {}
    u = (d.get("username") or "").strip()

    if not can_manage_user(u):
        return jsonify({"status": "error", "message": "Forbidden"}), 403

    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT expiry_date FROM users WHERE username=?", (u,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({"status": "error", "message": "User not found"}), 404

    try:
        cur = datetime.date.fromisoformat(row[0])
    except Exception:
        cur = datetime.date.today()

    new = cur + datetime.timedelta(days=30)
    c.execute("UPDATE users SET expiry_date=? WHERE username=?", (new.isoformat(), u))
    conn.commit()
    conn.close()

    return jsonify({"status": "ok", "message": f"Renewed till {new}"})


@app.route("/api/clear_machine", methods=["POST"])
@login_required_json
def api_clear_machine():
    d = request.get_json() or {}
    u = (d.get("username") or "").strip()

    if not can_manage_user(u):
        return jsonify({"status": "error", "message": "Forbidden"}), 403

    conn = db_conn()
    c = conn.cursor()
    c.execute("UPDATE users SET machine_id='-' WHERE username=?", (u,))
    conn.commit()
    conn.close()

    return jsonify({"status": "ok", "message": f"Cleared {u}"})


@app.route("/api/clear_all_machines", methods=["POST"])
@login_required_json
def api_clear_all():
    conn = db_conn()
    c = conn.cursor()

    if is_super_admin():
        c.execute("UPDATE users SET machine_id='-'")
    else:
        # Only clear machines for users assigned to this sub-admin
        c.execute(
            """
            UPDATE users
            SET machine_id='-'
            WHERE id IN (
              SELECT u.id
              FROM users u
              JOIN admin_user_access aua ON aua.user_id=u.id
              WHERE aua.admin_id=?
            )
            """,
            (session["admin_id"],),
        )

    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "message": "All cleared" if is_super_admin() else "Assigned users cleared"})


@app.route("/api/delete_user", methods=["POST"])
@login_required_json
def api_delete_user():
    d = request.get_json() or {}
    u = (d.get("username") or "").strip()

    if not can_manage_user(u):
        return jsonify({"status": "error", "message": "Forbidden"}), 403

    conn = db_conn()
    c = conn.cursor()

    # delete mapping first
    c.execute("SELECT id FROM users WHERE username=?", (u,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({"status": "error", "message": "User not found"}), 404

    user_id = row[0]
    c.execute("DELETE FROM admin_user_access WHERE user_id=?", (user_id,))
    c.execute("DELETE FROM users WHERE id=?", (user_id,))

    conn.commit()
    conn.close()

    return jsonify({"status": "ok", "message": f"Deleted {u}"})


# ---------------- Sub-admin management (API only; SUPER_ADMIN only) ----------------
@app.route("/api/admin/create_subadmin", methods=["POST"])
@login_required_json
def api_create_subadmin():
    guard = require_super_admin_json()
    if guard:
        return guard

    d = request.get_json() or {}
    username = (d.get("username") or "").strip()
    password = d.get("password") or ""
    max_users = int(d.get("max_users") or 10)

    if not username or not password:
        return jsonify({"status": "error", "message": "username/password required"}), 400
    if max_users <= 0:
        return jsonify({"status": "error", "message": "max_users must be > 0"}), 400

    conn = db_conn()
    c = conn.cursor()
    try:
        c.execute(
            "INSERT INTO admins(username,password_hash,role,max_users,is_active,created_at) VALUES (?,?,?,?,?,?)",
            (
                username,
                generate_password_hash(password),
                "SUB_ADMIN",
                max_users,
                1,
                datetime.datetime.utcnow().isoformat(),
            ),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"status": "error", "message": "Sub-admin exists"}), 400

    conn.close()
    return jsonify({"status": "ok", "message": "Sub-admin created"})


@app.route("/api/admin/assign_user", methods=["POST"])
@login_required_json
def api_assign_user():
    guard = require_super_admin_json()
    if guard:
        return guard

    d = request.get_json() or {}
    subadmin = (d.get("subadmin") or "").strip()
    username = (d.get("username") or "").strip()

    if not subadmin or not username:
        return jsonify({"status": "error", "message": "subadmin/username required"}), 400

    conn = db_conn()
    c = conn.cursor()

    c.execute(
        "SELECT id, COALESCE(max_users,0) FROM admins WHERE username=? AND role='SUB_ADMIN' AND is_active=1",
        (subadmin,),
    )
    a = c.fetchone()
    if not a:
        conn.close()
        return jsonify({"status": "error", "message": "Sub-admin not found"}), 404
    admin_id, max_users = a

    c.execute("SELECT id FROM users WHERE username=?", (username,))
    u = c.fetchone()
    if not u:
        conn.close()
        return jsonify({"status": "error", "message": "User not found"}), 404
    user_id = u[0]

    # quota check
    c.execute("SELECT COUNT(*) FROM admin_user_access WHERE admin_id=?", (admin_id,))
    cnt = c.fetchone()[0]
    if int(max_users or 0) > 0 and cnt >= int(max_users or 0):
        conn.close()
        return jsonify({"status": "error", "message": "Sub-admin quota full"}), 403

    c.execute(
        "INSERT OR IGNORE INTO admin_user_access(admin_id,user_id) VALUES (?,?)",
        (admin_id, user_id),
    )

    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "message": "Assigned"})


@app.route("/api/admin/unassign_user", methods=["POST"])
@login_required_json
def api_unassign_user():
    guard = require_super_admin_json()
    if guard:
        return guard

    d = request.get_json() or {}
    subadmin = (d.get("subadmin") or "").strip()
    username = (d.get("username") or "").strip()

    if not subadmin or not username:
        return jsonify({"status": "error", "message": "subadmin/username required"}), 400

    conn = db_conn()
    c = conn.cursor()

    c.execute("SELECT id FROM admins WHERE username=? AND role='SUB_ADMIN'", (subadmin,))
    a = c.fetchone()
    if not a:
        conn.close()
        return jsonify({"status": "error", "message": "Sub-admin not found"}), 404
    admin_id = a[0]

    c.execute("SELECT id FROM users WHERE username=?", (username,))
    u = c.fetchone()
    if not u:
        conn.close()
        return jsonify({"status": "error", "message": "User not found"}), 404
    user_id = u[0]

    c.execute("DELETE FROM admin_user_access WHERE admin_id=? AND user_id=?", (admin_id, user_id))

    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "message": "Unassigned"})


@app.route("/api/admin/subadmins", methods=["GET"])
@login_required_json
def api_list_subadmins():
    guard = require_super_admin_json()
    if guard:
        return guard

    conn = db_conn()
    c = conn.cursor()
    c.execute(
        """
        SELECT a.username,
               COALESCE(a.max_users,0) AS max_users,
               a.is_active,
               a.created_at,
               (SELECT COUNT(*) FROM admin_user_access aua WHERE aua.admin_id=a.id) AS assigned_count,
               (SELECT COUNT(*) FROM users u WHERE u.created_by_admin_id=a.id) AS created_count
        FROM admins a
        WHERE a.role='SUB_ADMIN'
        ORDER BY a.id DESC
        """
    )
    rows = c.fetchall()
    conn.close()

    data = []
    for (u, max_users, is_active, created_at, assigned_count, created_count) in rows:
        data.append({
            "username": u,
            "max_users": int(max_users or 0),
            "assigned_count": int(assigned_count or 0),
            "created_count": int(created_count or 0),
            "is_active": bool(int(is_active)),
            "created_at": created_at,
        })

    return jsonify({"status": "ok", "data": data})


@app.route("/api/admin/user_suggestions", methods=["GET"])
@login_required_json
def api_user_suggestions():
    guard = require_super_admin_json()
    if guard:
        return guard

    q = (request.args.get("search") or "").strip()
    if not q:
        return jsonify({"status": "ok", "data": []})

    like = f"%{q}%"
    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT username FROM users WHERE username LIKE ? ORDER BY username LIMIT 20", (like,))
    rows = [r[0] for r in c.fetchall()]
    conn.close()
    return jsonify({"status": "ok", "data": rows})


@app.route("/api/admin/subadmin_users", methods=["GET"])
@login_required_json
def api_subadmin_users():
    guard = require_super_admin_json()
    if guard:
        return guard

    subadmin = (request.args.get("subadmin") or "").strip()
    if not subadmin:
        return jsonify({"status": "error", "message": "subadmin required"}), 400

    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT id FROM admins WHERE username=? AND role='SUB_ADMIN'", (subadmin,))
    a = c.fetchone()
    if not a:
        conn.close()
        return jsonify({"status": "error", "message": "Sub-admin not found"}), 404
    admin_id = int(a[0])

    c.execute(
        """
        SELECT u.username, u.status, u.expiry_date,
               COALESCE(u.created_by_username,''), COALESCE(u.created_by_role,''),
               CASE WHEN u.created_by_admin_id=? THEN 1 ELSE 0 END AS is_created
        FROM users u
        JOIN admin_user_access aua ON aua.user_id = u.id
        WHERE aua.admin_id=?
        ORDER BY u.id DESC
        LIMIT 500
        """,
        (admin_id, admin_id),
    )
    rows = c.fetchall()
    conn.close()

    data = []
    for (username, status, expiry_date, cbu, cbr, is_created) in rows:
        data.append({
            "username": username,
            "status": status,
            "expiry_date": expiry_date,
            "created_by": {"username": cbu, "role": cbr},
            "is_created": bool(int(is_created)),
        })

    return jsonify({"status": "ok", "data": {"subadmin": subadmin, "users": data}})


@app.route("/api/admin/toggle_subadmin", methods=["POST"])
@login_required_json
def api_toggle_subadmin():
    guard = require_super_admin_json()
    if guard:
        return guard

    d = request.get_json() or {}
    username = (d.get("username") or "").strip()
    if not username:
        return jsonify({"status": "error", "message": "username required"}), 400

    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT id, is_active FROM admins WHERE username=? AND role='SUB_ADMIN'", (username,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({"status": "error", "message": "Sub-admin not found"}), 404

    admin_id, is_active = row
    if "is_active" in d:
        new_active = 1 if int(d.get("is_active") or 0) else 0
    else:
        new_active = 0 if int(is_active) else 1

    c.execute("UPDATE admins SET is_active=? WHERE id=?", (new_active, admin_id))

    # Auto-disable/enable users created by this sub-admin
    user_status = "ENABLED" if int(new_active) else "DISABLED"
    c.execute("UPDATE users SET status=? WHERE created_by_admin_id=?", (user_status, int(admin_id)))

    conn.commit()
    conn.close()

    return jsonify({"status": "ok", "message": f"{username} {'ENABLED' if new_active else 'DISABLED'} (users: {user_status})"})


@app.route("/api/admin/update_subadmin_quota", methods=["POST"])
@login_required_json
def api_update_subadmin_quota():
    guard = require_super_admin_json()
    if guard:
        return guard

    d = request.get_json() or {}
    username = (d.get("username") or "").strip()
    max_users = d.get("max_users")
    if not username or max_users is None:
        return jsonify({"status": "error", "message": "username/max_users required"}), 400

    try:
        max_users = int(max_users)
    except Exception:
        return jsonify({"status": "error", "message": "max_users must be int"}), 400
    if max_users <= 0:
        return jsonify({"status": "error", "message": "max_users must be > 0"}), 400

    conn = db_conn()
    c = conn.cursor()
    c.execute("UPDATE admins SET max_users=? WHERE username=? AND role='SUB_ADMIN'", (max_users, username))
    if c.rowcount <= 0:
        conn.close()
        return jsonify({"status": "error", "message": "Sub-admin not found"}), 404
    conn.commit()
    conn.close()

    return jsonify({"status": "ok", "message": f"Quota updated for {username} → {max_users}"})


@app.route("/api/admin/delete_subadmin", methods=["POST"])
@login_required_json
def api_delete_subadmin():
    guard = require_super_admin_json()
    if guard:
        return guard

    d = request.get_json() or {}
    username = (d.get("username") or "").strip()
    if not username:
        return jsonify({"status": "error", "message": "username required"}), 400

    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT id FROM admins WHERE username=? AND role='SUB_ADMIN'", (username,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({"status": "error", "message": "Sub-admin not found"}), 404
    admin_id = int(row[0])

    # Disable all users CREATED by this sub-admin (so license check stops working)
    c.execute("UPDATE users SET status='DISABLED' WHERE created_by_admin_id=?", (admin_id,))
    # Remove management mappings for this sub-admin
    c.execute("DELETE FROM admin_user_access WHERE admin_id=?", (admin_id,))
    # Finally delete the sub-admin account
    c.execute("DELETE FROM admins WHERE id=?", (admin_id,))

    conn.commit()
    conn.close()

    return jsonify({"status": "ok", "message": f"Deleted sub-admin {username} and disabled their created users"})


# ---------------- Client license check API ----------------
@app.route("/api/ck", methods=["POST"])
def api_ck():
    data = request.get_json() or {}
    username = data.get("usrname")
    machine_id = data.get("key")
    license_key = data.get("license")

    # Basic validation
    if not username or not machine_id or not license_key:
        return jsonify({"error": "Missing fields"}), 400

    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT activation_key, status, machine_id, expiry_date FROM users WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()

    if not row:
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
        return jsonify({"error": "License expired", "days_left": 0}), 403

    # Status check
    if status != "ENABLED":
        return jsonify({"error": "User disabled"}), 403

    # Machine check
    if db_machine in ("-", "", None):
        conn = db_conn()
        c = conn.cursor()
        c.execute("UPDATE users SET machine_id=? WHERE username=?", (machine_id, username))
        conn.commit()
        conn.close()
        db_machine = machine_id

    elif db_machine != machine_id:
        return jsonify({"error": "Machine mismatch"}), 403

    # License key check
    if db_license == license_key and db_machine == machine_id:
        return jsonify(
            {
                "status": "ok",
                "key": base64.b64encode(machine_id.encode()).decode(),
                "key1": base64.b64encode(license_key.encode()).decode(),
                "key0": base64.b64encode(username.encode()).decode(),
                "days_left": days_left,
            }
        )

    return jsonify({"error": "Invalid license"}), 403


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)
