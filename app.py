import os, json, uuid, shutil, subprocess, threading, time, hashlib, secrets, string, signal, sys, socket, re
import urllib.request, urllib.error
from flask import Flask, request, jsonify, send_from_directory, session, redirect, url_for, Response, send_file
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__, static_folder='static', template_folder='templates')

# ─── PATHS ───────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
UPLOADS_DIR = os.path.join(BASE_DIR, 'uploads')
PROJECTS_DIR= os.path.join(BASE_DIR, 'projects')
DATA_FILE   = os.path.join(BASE_DIR, 'data', 'db.json')
SECRET_KEY_FILE = os.path.join(BASE_DIR, 'data', 'secret.key')
for d in [UPLOADS_DIR, PROJECTS_DIR, os.path.join(BASE_DIR,'data')]:
    os.makedirs(d, exist_ok=True)

# A key generated fresh on every process start would silently invalidate
# every logged-in session on any restart (deploy, crash-restart, systemd
# reload) — the opposite of what persistent "remember me" sessions need.
# Generate it once and reuse it forever after.
if os.path.exists(SECRET_KEY_FILE):
    with open(SECRET_KEY_FILE, 'r') as f:
        app.secret_key = f.read().strip()
else:
    app.secret_key = secrets.token_hex(32)
    with open(SECRET_KEY_FILE, 'w') as f:
        f.write(app.secret_key)
    os.chmod(SECRET_KEY_FILE, 0o600)

# "Remember me" — sessions survive browser restarts for up to 30 days
# instead of expiring the moment the browser closes.
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# ─── DB ──────────────────────────────────────────────
def load_db():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE) as f:
            return json.load(f)
    default = {
        "users": [
            {"username":"DeV Sk7 and skinz","password":hashpw("sk7andskins"),"role":"dev","file_limit":9999,"days":99999,"created_at":time.time(),"files":[]},
            {"username":"admin","password":hashpw("admin123"),"role":"admin","file_limit":50,"days":365,"created_at":time.time(),"files":[]},
        ],
        "projects": {},
        "port_counter": 9000
    }
    save_db(default)
    return default

def save_db(db):
    with open(DATA_FILE,'w') as f:
        json.dump(db, f, indent=2, ensure_ascii=False)

def hashpw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

DB = load_db()

# ─── RUNNING PROCESSES ───────────────────────────────
PROCESSES = {}   # project_id -> {"proc": Popen, "port": int, "log": [...], "status": str}

# ─── AUTH HELPERS ────────────────────────────────────
def get_user(username):
    return next((u for u in DB['users'] if u['username']==username), None)

def current_user():
    if 'username' not in session: return None
    return get_user(session['username'])

def login_required(f):
    @wraps(f)
    def wrapper(*a,**kw):
        if not current_user():
            return jsonify({"error":"unauthorized"}), 401
        return f(*a,**kw)
    return wrapper

def role_required(*roles):
    def dec(f):
        @wraps(f)
        def wrapper(*a,**kw):
            u = current_user()
            if not u or u['role'] not in roles:
                return jsonify({"error":"forbidden"}), 403
            return f(*a,**kw)
        return wrapper
    return dec

def file_limit_ok(user, extra=1):
    return len(user.get('files',[])) + extra <= user['file_limit']

def gen_password(length=12):
    chars = string.ascii_letters + string.digits + '@#$%'
    return ''.join(secrets.choice(chars) for _ in range(length))

PORT_MIN, PORT_MAX = 9000, 9999

def port_in_use(port):
    """Real OS-level check — catches ports held by leftover/external processes,
    not just ones this panel thinks it allocated."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.3)
        return s.connect_ex(('127.0.0.1', port)) == 0

def next_port():
    used = {p['port'] for p in DB['projects'].values()}
    start = DB.get('port_counter', PORT_MIN)
    for i in range(PORT_MAX - PORT_MIN + 1):
        candidate = PORT_MIN + ((start - PORT_MIN + i) % (PORT_MAX - PORT_MIN + 1))
        if candidate in used or port_in_use(candidate):
            continue
        DB['port_counter'] = candidate + 1
        save_db(DB)
        return candidate
    raise RuntimeError("لا توجد منافذ متاحة (9000-9999 كلها مستخدمة)")

# ─── SERVE FRONTEND ──────────────────────────────────
@app.route('/')
def index():
    return send_from_directory('templates','index.html')

@app.route('/static/<path:path>')
def static_files(path):
    return send_from_directory('static', path)

@app.route('/health')
def panel_health():
    return jsonify({"ok": True, "time": time.time()})

# ─── REVERSE PROXY — makes every hosted project reachable through this
# same origin/port, so it works behind Cloudflare Tunnel / nginx / ngrok /
# any single-port reverse proxy (raw "hostname:9002" links only work when
# hitting the VPS directly, which is why they broke for you before) ───
_PROXY_DROP_HEADERS = {'content-length', 'transfer-encoding', 'connection', 'keep-alive',
                        'proxy-authenticate', 'proxy-authorization', 'te', 'trailer',
                        'upgrade', 'host'}

def _probe_project(port, timeout=1.5):
    """Real HTTP probe against the project's local port. Any HTTP response
    (even a 404/500) means the app is up and listening — that's still a
    'reachable' server, just one whose route returned an error."""
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{port}/", method='GET')
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return True, resp.status
    except urllib.error.HTTPError as e:
        return True, e.code
    except Exception:
        return False, None

# ─── PROXY-LEVEL METRICS — real per-project request count + network bytes.
# Genuine per-process network accounting isn't possible without per-project
# network namespaces (which this no-Docker architecture doesn't have) or
# eBPF; but since /app/<id>/ is the actual path real traffic takes to reach
# a hosted project, counting at the proxy gives accurate numbers for that
# traffic (direct-port access, if someone bypasses the proxy, isn't counted
# — documented in the dashboard). ───
PROXY_STATS = {}

def _requests_per_sec(pid):
    s = PROXY_STATS.get(pid)
    if not s:
        return 0.0
    now_t = time.time()
    prev_count, prev_t = s.get('_rate_sample', (s['requests'], now_t))
    dt = now_t - prev_t
    rate = (s['requests'] - prev_count) / dt if dt > 0 else 0.0
    s['_rate_sample'] = (s['requests'], now_t)
    return round(max(0.0, rate), 2)

@app.route('/app/<pid>', defaults={'subpath': ''}, methods=['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'])
@app.route('/app/<pid>/', defaults={'subpath': ''}, methods=['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'])
@app.route('/app/<pid>/<path:subpath>', methods=['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'])
def proxy_project(pid, subpath):
    proj = DB['projects'].get(pid)
    if not proj:
        return jsonify({"error": "مشروع غير موجود"}), 404
    info = PROCESSES.get(pid, {})
    if info.get('status') != 'running':
        return jsonify({"error": "السيرفر متوقف حالياً — شغّله من لوحة التحكم"}), 503

    # NOTE on WebSockets: this is a synchronous HTTP proxy (urllib-based), so it
    # cannot tunnel a raw `Connection: Upgrade` WebSocket handshake — that needs
    # an async server (gevent/eventlet/ASGI) sitting in front. SSE and chunked/
    # long-polling responses DO work below because we stream the body instead
    # of buffering it. For WebSocket apps (socket.io etc.), hit the project's
    # direct port instead of this /app/ path until that's added.
    if request.headers.get('Upgrade', '').lower() == 'websocket':
        return jsonify({"error": "WebSocket غير مدعوم عبر هذا الرابط حالياً — استخدم بورت المشروع المباشر"}), 501

    body = request.get_data() or None
    stats = PROXY_STATS.setdefault(pid, {'requests': 0, 'bytes_in': 0, 'bytes_out': 0})
    stats['requests'] += 1
    stats['bytes_in'] += len(body) if body else 0

    target = f"http://127.0.0.1:{proj['port']}/{subpath}"
    if request.query_string:
        target += '?' + request.query_string.decode()
    fwd_headers = {k: v for k, v in request.headers.items() if k.lower() not in _PROXY_DROP_HEADERS}
    try:
        req = urllib.request.Request(target, data=body, headers=fwd_headers, method=request.method)
        upstream = urllib.request.urlopen(req, timeout=90)
    except urllib.error.HTTPError as e:
        resp_headers = [(k, v) for k, v in e.headers.items() if k.lower() not in _PROXY_DROP_HEADERS]
        err_body = e.read()
        stats['bytes_out'] += len(err_body)
        return (err_body, e.code, resp_headers)
    except Exception as e:
        return jsonify({"error": f"تعذر الوصول للمشروع محلياً: {e}"}), 502

    resp_headers = [(k, v) for k, v in upstream.getheaders() if k.lower() not in _PROXY_DROP_HEADERS]

    def stream():
        try:
            while True:
                chunk = upstream.read(8192)
                if not chunk:
                    break
                stats['bytes_out'] += len(chunk)
                yield chunk
        finally:
            upstream.close()

    return Response(stream(), status=upstream.status, headers=resp_headers)


# ─── AUTH ROUTES ─────────────────────────────────────
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json or {}
    u = get_user(data.get('username',''))
    if not u or u['password'] != hashpw(data.get('password','')):
        return jsonify({"error":"بيانات خاطئة"}), 401
    # check expiry
    expires = datetime.fromtimestamp(u['created_at']) + timedelta(days=u['days'])
    if datetime.now() > expires and u['role'] not in ('dev',):
        return jsonify({"error":"الحساب منتهي الصلاحية"}), 403
    session['username'] = u['username']
    session.permanent = True
    return jsonify({"ok":True,"role":u['role'],"username":u['username'],"file_limit":u['file_limit']})

@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({"ok":True})

@app.route('/api/me')
def api_me():
    u = current_user()
    if not u: return jsonify({"error":"unauth"}),401
    expires = datetime.fromtimestamp(u['created_at']) + timedelta(days=u['days'])
    return jsonify({"username":u['username'],"role":u['role'],"file_limit":u['file_limit'],"files_used":len(u.get('files',[])),"expires":expires.strftime('%Y-%m-%d')})

# ─── UPLOAD & DEPLOY ─────────────────────────────────
ALLOWED_EXTENSIONS = {
    'py','js','ts','html','css','json','txt','md','sh','env','yaml','yml',
    'php','rb','go','rs','java','cpp','c','h','xml','csv','sql','zip','tar',
    'gz','png','jpg','jpeg','gif','svg','pdf','mp4','mp3','woff','woff2','ttf'
}

def allowed(filename):
    return '.' in filename and filename.rsplit('.',1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/api/upload', methods=['POST'])
@login_required
def api_upload():
    u = current_user()
    files = request.files.getlist('files')
    if not files: return jsonify({"error":"لا توجد ملفات"}),400

    uploaded = []
    errors   = []
    for f in files:
        if not allowed(f.filename):
            errors.append(f"{f.filename}: نوع غير مدعوم")
            continue
        if len(u.get('files',[])) >= u['file_limit']:
            errors.append(f"{f.filename}: تجاوزت الحد الأقصى ({u['file_limit']})")
            break
        filename = secure_filename(f.filename)
        user_dir = os.path.join(UPLOADS_DIR, u['username'])
        os.makedirs(user_dir, exist_ok=True)
        dest = os.path.join(user_dir, filename)
        f.save(dest)
        size = os.path.getsize(dest)
        record = {"name":filename,"size":size,"date":datetime.now().strftime('%Y-%m-%d %H:%M'),"path":dest}
        if 'files' not in u: u['files']=[]
        u['files'].append(record)
        uploaded.append(record)

    save_db(DB)
    return jsonify({"uploaded":uploaded,"errors":errors,"total_files":len(u.get('files',[]))})

@app.route('/api/files', methods=['GET'])
@login_required
def api_files():
    u = current_user()
    return jsonify({"files":u.get('files',[]),"limit":u['file_limit']})

@app.route('/api/files/<filename>', methods=['DELETE'])
@login_required
def api_delete_file(filename):
    u = current_user()
    files = u.get('files',[])
    record = next((f for f in files if f['name']==filename),None)
    if not record: return jsonify({"error":"ملف غير موجود"}),404
    try: os.remove(record['path'])
    except: pass
    u['files'] = [f for f in files if f['name']!=filename]
    save_db(DB)
    return jsonify({"ok":True})

# ─── PROJECTS / SERVERS (native subprocess engine — no Docker) ──
# Every hosted project runs as a plain OS process, isolated by its own
# folder + (for python) its own venv, supervised by a watchdog thread
# that restarts it if it dies — this is what gives 24/7 uptime without
# needing container isolation.

BIMO_RUNNER = '''import sys, os, runpy
try:
    from flask import Flask
    _orig = Flask.run
    def _patched(self, host=None, port=None, **kw):
        _orig(self, host="0.0.0.0", port=int(os.environ.get("PORT", {port})), **kw)
    Flask.run = _patched
except ImportError:
    pass
try:
    from fastapi import FastAPI
    import uvicorn
    _orig_run = uvicorn.run
    def _uvicorn_patched(app, host=None, port=None, **kw):
        _orig_run(app, host="0.0.0.0", port=int(os.environ.get("PORT", {port})), **kw)
    uvicorn.run = _uvicorn_patched
except ImportError:
    pass
sys.argv = [sys.argv[1]] + sys.argv[2:]
runpy.run_path(sys.argv[0], run_name="__main__")
'''

def now():
    return datetime.now().strftime('%H:%M:%S')

def parse_env(env_vars):
    out = {}
    for line in (env_vars or '').split('\n'):
        line = line.strip()
        if line and '=' in line and not line.startswith('#'):
            k, v = line.split('=', 1)
            out[k.strip()] = v.strip()
    return out

# ─── AUTO-DETECT project type, entry file, and framework ────
# This is what lets people upload a raw folder/zip and have it "just work"
# without manually picking type/main_file — similar to how Railway/Render
# inspect the repo to pick a builder.
_PY_ENTRY_CANDIDATES = ['main.py', 'app.py', 'bot.py', 'run.py', 'server.py', 'wsgi.py', 'asgi.py']
_NODE_ENTRY_CANDIDATES = ['index.js', 'server.js', 'app.js', 'main.js']
_PHP_ENTRY_CANDIDATES = ['index.php', 'app.php', 'server.php']

def _walk_top_levels(proj_dir, max_depth=2):
    """Files within the first couple of levels — deep enough to catch e.g.
    src/main.py, shallow enough to ignore vendored/node_modules noise."""
    for root, dirs, files in os.walk(proj_dir):
        depth = root[len(proj_dir):].count(os.sep)
        dirs[:] = [d for d in dirs if d not in ('venv', 'node_modules', '.git', '__pycache__', 'vendor')]
        if depth >= max_depth:
            dirs[:] = []
        for f in files:
            yield os.path.join(root, f)

_FLASK_APP_RE = re.compile(r'^\s*(\w+)\s*=\s*Flask\(', re.MULTILINE)
_FASTAPI_APP_RE = re.compile(r'^\s*(\w+)\s*=\s*FastAPI\(', re.MULTILINE)

def detect_python_web_framework(proj_dir, main_file):
    """Confidently detect Flask/FastAPI + the app variable name by reading the
    actual entry file — this is what lets the Runtime Manager pick a real
    production server (gunicorn/uvicorn) with the correct '<module>:<var>'
    import string, instead of guessing. Returns (framework, app_var) or
    (None, None) if we can't be confident (in which case the dev-server
    fallback path is used — safer than guessing wrong)."""
    path = os.path.join(proj_dir, main_file)
    try:
        with open(path, 'r', errors='ignore') as f:
            text = f.read()
    except OSError:
        return None, None
    m = _FASTAPI_APP_RE.search(text)
    if m:
        return 'fastapi', m.group(1)
    m = _FLASK_APP_RE.search(text)
    if m:
        return 'flask', m.group(1)
    return None, None

def _module_name_for(main_file):
    """'app.py' -> 'app', 'src/main.py' -> 'src.main' (for gunicorn/uvicorn import strings)."""
    rel = main_file[:-3] if main_file.endswith('.py') else main_file
    return rel.replace('/', '.').replace('\\', '.')

def calc_worker_count(mem_limit_mb=None, min_workers=1, max_workers=4, mb_per_worker=200):
    """CPU- and memory-aware worker count for gunicorn/uvicorn/pm2 — enough
    to use available cores under load, capped so we don't oversubscribe a
    small VPS or spawn more workers than the project's own memory cap can
    actually hold (each worker is a full process)."""
    mem_limit_mb = mem_limit_mb or PROJECT_MEM_LIMIT_MB
    cpu = os.cpu_count() or 1
    by_cpu = max(1, min(max_workers, cpu))
    by_mem = max(1, mem_limit_mb // mb_per_worker)
    return max(min_workers, min(by_cpu, by_mem))

def detect_project(proj_dir):
    """Returns {'type', 'main_file', 'framework'}. Best-effort — falls back to
    python/main.py (existing default) when nothing matches, and the deploy
    log always states what was detected so the user can correct it."""
    entries = os.listdir(proj_dir)
    lower = {e.lower(): e for e in entries}

    # Go
    if 'go.mod' in lower:
        return {'type': 'go', 'main_file': 'main.go', 'framework': None}

    # Django (must win over generic python before generic entry search)
    if 'manage.py' in lower:
        return {'type': 'python', 'main_file': 'manage.py', 'framework': 'django'}

    # Node
    if 'package.json' in lower:
        main_file = None
        try:
            with open(os.path.join(proj_dir, lower['package.json'])) as f:
                pkg = json.load(f)
            cand = pkg.get('main') or (pkg.get('scripts', {}).get('start', '').replace('node ', '').strip() or None)
            if cand and os.path.exists(os.path.join(proj_dir, cand)):
                main_file = cand
        except Exception:
            pass
        if not main_file:
            for c in _NODE_ENTRY_CANDIDATES:
                if c in lower:
                    main_file = lower[c]; break
        return {'type': 'node', 'main_file': main_file or 'index.js', 'framework': None}

    # PHP
    php_files = [e for e in entries if e.lower().endswith('.php')]
    if 'composer.json' in lower or php_files:
        main_file = next((lower[c] for c in _PHP_ENTRY_CANDIDATES if c in lower), None) or (php_files[0] if php_files else 'index.php')
        return {'type': 'php', 'main_file': main_file, 'framework': None}

    # Python
    py_files = [e for e in entries if e.lower().endswith('.py')]
    if 'requirements.txt' in lower or py_files:
        main_file = next((lower[c] for c in _PY_ENTRY_CANDIDATES if c in lower), None)
        if not main_file and py_files:
            main_file = py_files[0]
        main_file = main_file or 'main.py'
        framework = detect_python_web_framework(proj_dir, main_file)[0]
        return {'type': 'python', 'main_file': main_file, 'framework': framework}

    # Node — standalone .js file(s) with no package.json (bots/scripts often
    # ship like this). Checked after Python so a project with both types of
    # files (rare) still prefers the more common all-in-one-file Python case.
    js_files = [e for e in entries if e.lower().endswith('.js')]
    if js_files:
        main_file = next((lower[c] for c in _NODE_ENTRY_CANDIDATES if c in lower), None) or js_files[0]
        return {'type': 'node', 'main_file': main_file, 'framework': None}

    # Static site
    if 'index.html' in lower or any(e.lower().endswith('.html') for e in entries):
        return {'type': 'static', 'main_file': 'index.html', 'framework': None}

    return {'type': 'python', 'main_file': 'main.py', 'framework': None}

# Common third-party import name -> pip package name, for projects that
# forgot (or never had) a requirements.txt. Only used when requirements.txt
# is missing — never overrides one the user actually provided.
_IMPORT_TO_PIP = {
    'flask': 'flask', 'fastapi': 'fastapi', 'uvicorn': 'uvicorn', 'django': 'django',
    'requests': 'requests', 'bs4': 'beautifulsoup4', 'PIL': 'pillow', 'cv2': 'opencv-python-headless',
    'numpy': 'numpy', 'pandas': 'pandas', 'yaml': 'pyyaml', 'dotenv': 'python-dotenv',
    'telebot': 'pyTelegramBotAPI', 'telegram': 'python-telegram-bot', 'aiogram': 'aiogram',
    'discord': 'discord.py', 'pymongo': 'pymongo', 'psycopg2': 'psycopg2-binary',
    'redis': 'redis', 'sqlalchemy': 'sqlalchemy', 'jinja2': 'jinja2', 'gunicorn': 'gunicorn',
    'aiohttp': 'aiohttp', 'httpx': 'httpx', 'pydantic': 'pydantic', 'websockets': 'websockets',
    'selenium': 'selenium', 'openai': 'openai', 'anthropic': 'anthropic', 'jwt': 'pyjwt',
    'dateutil': 'python-dateutil', 'bcrypt': 'bcrypt', 'passlib': 'passlib', 'lxml': 'lxml',
}
_IMPORT_RE = re.compile(r'^\s*(?:import|from)\s+([a-zA-Z0-9_]+)', re.MULTILINE)

def guess_requirements(proj_dir):
    """Scan .py files for top-level imports and propose pip packages for the
    non-stdlib ones we recognize. Best effort — written to requirements.txt
    ONLY when the project didn't already ship one."""
    stdlib = getattr(sys, 'stdlib_module_names', set())
    found = set()
    for path in _walk_top_levels(proj_dir):
        if not path.endswith('.py') or os.path.basename(path) == '_bimo_run.py':
            continue
        try:
            with open(path, 'r', errors='ignore') as f:
                text = f.read()
        except OSError:
            continue
        for m in _IMPORT_RE.finditer(text):
            mod = m.group(1)
            if mod in stdlib or mod in ('__future__',):
                continue
            pkg = _IMPORT_TO_PIP.get(mod)
            if pkg:
                found.add(pkg)
    return sorted(found)

def venv_python(proj_dir):
    return os.path.join(proj_dir, 'venv', 'bin', 'python3')

def build_env(proj_dir, proj_type, port, env_vars):
    env = os.environ.copy()
    env['PORT'] = str(port)
    env.update(parse_env(env_vars))
    if proj_type == 'python':
        vbin = os.path.join(proj_dir, 'venv', 'bin')
        env['PATH'] = vbin + os.pathsep + env.get('PATH', '')
        env['VIRTUAL_ENV'] = os.path.join(proj_dir, 'venv')
    return env

def resolve_cmd(proj_dir, proj_type, main_file, port, start_cmd=None, framework=None):
    """Build the argv list used to launch the project. A custom start_cmd
    (advanced users) always wins; otherwise pick the best production runtime
    for what was detected, with a safe dev-server fallback whenever the
    production server isn't actually installed/available."""
    if start_cmd:
        return ['/bin/sh', '-c', start_cmd]
    if proj_type == 'python' and framework == 'django':
        return [venv_python(proj_dir), 'manage.py', 'runserver', f'0.0.0.0:{port}', '--noreload']

    main_file = main_file or {'python': 'main.py', 'node': 'index.js', 'php': 'index.php', 'go': 'main.go'}.get(proj_type, 'main.py')

    if proj_type == 'python' and framework in ('flask', 'fastapi'):
        _, app_var = detect_python_web_framework(proj_dir, main_file)
        if app_var:
            module = _module_name_for(main_file)
            workers = calc_worker_count()
            if framework == 'flask':
                gunicorn = os.path.join(proj_dir, 'venv', 'bin', 'gunicorn')
                if os.path.exists(gunicorn):
                    return [gunicorn, '--workers', str(workers), '--bind', f'0.0.0.0:{port}',
                            '--timeout', '120', '--access-logfile', '-', '--error-logfile', '-',
                            f'{module}:{app_var}']
            elif framework == 'fastapi':
                uvicorn = os.path.join(proj_dir, 'venv', 'bin', 'uvicorn')
                if os.path.exists(uvicorn):
                    return [uvicorn, f'{module}:{app_var}', '--host', '0.0.0.0', '--port', str(port),
                            '--workers', str(workers)]
        # app var not confidently detected, or the production server failed to
        # install — fall through to the dev-server wrapper below rather than
        # risk launching gunicorn/uvicorn with a wrong/missing import string.

    if proj_type == 'python':
        return [venv_python(proj_dir), os.path.join(proj_dir, '_bimo_run.py'), main_file]

    if proj_type == 'node':
        pm2 = shutil.which('pm2-runtime')
        if pm2:
            workers = calc_worker_count(max_workers=4)
            return [pm2, 'start', main_file, '-i', str(workers)]
        return ['node', main_file]

    if proj_type == 'php':
        return ['php', '-S', f'0.0.0.0:{port}', main_file]
    if proj_type == 'static':
        return [sys.executable, '-m', 'http.server', str(port), '--directory', proj_dir, '--bind', '0.0.0.0']
    if proj_type == 'go':
        return [os.path.join(proj_dir, '_sk7_go_bin')]
    return [venv_python(proj_dir), os.path.join(proj_dir, '_bimo_run.py'), main_file]

_DANGEROUS_CMD_PATTERNS = [
    (re.compile(r'\brm\s+(-\w*r\w*f\w*|-\w*f\w*r\w*)\s+/(\s|$)'), 'حذف جذر النظام'),
    (re.compile(r'\bmkfs\b'), 'تهيئة قرص'),
    (re.compile(r'\bdd\s+.*of=/dev/(sd|nvme|vd)'), 'كتابة مباشرة على قرص النظام'),
    (re.compile(r':\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:'), 'fork bomb'),
    (re.compile(r'\b(shutdown|reboot|poweroff|halt)\b'), 'إيقاف/إعادة تشغيل السيرفر'),
    (re.compile(r'\biptables\s+.*-F\b'), 'مسح قواعد الجدار الناري'),
    (re.compile(r'>\s*/dev/sd[a-z]'), 'الكتابة فوق قرص النظام'),
    (re.compile(r'\bchmod\s+-R\s+777\s+/(\s|$)'), 'تغيير صلاحيات جذر النظام'),
    (re.compile(r'\bcat\s+/etc/(shadow|sudoers)\b'), 'قراءة ملفات نظام حساسة'),
]

def is_dangerous_command(cmd):
    for pattern, why in _DANGEROUS_CMD_PATTERNS:
        if pattern.search(cmd):
            return True, why
    return False, None

def analyze_project_error(pid):
    """Rule-based diagnosis over the project's actual process output — not a
    magic AI black box, but a transparent set of checks for the failure modes
    that actually take down real deployments, each with an honest explanation
    and (where it's safe to act automatically) a concrete one-click fix."""
    proj = DB['projects'].get(pid)
    info = PROCESSES.get(pid, {})
    log_path = info.get('log_file') or (proj and os.path.join(proj.get('dir', ''), 'run.log'))
    text = ''
    if log_path and os.path.exists(log_path):
        try:
            with open(log_path, 'r', errors='replace') as f:
                text = f.read()[-8000:]
        except OSError:
            pass
    if not text:
        text = '\n'.join(info.get('log', [])[-40:])

    mp = detect_missing_package(pid)
    if mp:
        return {"category": "missing_package", "title": f"مكتبة ناقصة: {mp['package']}",
                "explanation": f"الكود يستورد '{mp['package']}' لكنها غير مثبتة بالبيئة الحالية.",
                "fix_hint": "اضغط 'تثبيت تلقائي' — رح تُثبَّت المكتبة ويُعاد تشغيل المشروع تلقائياً.",
                "auto_fixable": True, "fix_action": "install_package", "fix_payload": mp}

    if re.search(r'Address already in use|EADDRINUSE|OSError: \[Errno 98\]', text):
        return {"category": "port_conflict", "title": "المنفذ مستخدم من عملية ثانية",
                "explanation": "البورت المخصص لمشروعك محجوز حالياً من عملية أخرى على نفس السيرفر.",
                "fix_hint": "اضغط 'تخصيص بورت جديد' — رح ناخذ بورت فاضي فعلياً ونعيد التشغيل عليه.",
                "auto_fixable": True, "fix_action": "reassign_port", "fix_payload": {}}

    m = re.search(r"can't open file '([^']+)': \[Errno 2\]|No such file or directory: '([^']+\.(?:py|js|php))'", text)
    if m:
        bad_file = m.group(1) or m.group(2)
        return {"category": "wrong_entry_file", "title": f"ملف التشغيل غير موجود: {bad_file}",
                "explanation": "ملف التشغيل المحدد للمشروع غير موجود فعلياً بمجلده.",
                "fix_hint": "اضغط 'إعادة اكتشاف الملف' — رح نفحص المجلد من جديد ونحدد الملف الصحيح تلقائياً.",
                "auto_fixable": True, "fix_action": "redetect_entry", "fix_payload": {}}

    m = re.search(r"KeyError: '([A-Z][A-Z0-9_]{2,})'", text)
    if m:
        var = m.group(1)
        return {"category": "missing_env", "title": f"متغير بيئة ناقص: {var}",
                "explanation": f"الكود يتوقع متغير بيئة باسم {var} وهو غير موجود ضمن Environment Variables.",
                "fix_hint": "أضف القيمة من تبويب Environment Variables بتفاصيل المشروع ثم أعد التشغيل — القيمة نفسها ما نقدر نخمّنها لك.",
                "auto_fixable": False, "fix_action": None, "fix_payload": {"var": var}}

    m = re.search(r"SyntaxError: (.+)", text)
    if m:
        return {"category": "syntax_error", "title": "خطأ صياغة بالكود (SyntaxError)",
                "explanation": m.group(1).strip(),
                "fix_hint": "افتح الملف من File Manager وصحّح الخطأ يدوياً — هذا النوع ما نقدر نصلحه تلقائياً بأمان.",
                "auto_fixable": False, "fix_action": None, "fix_payload": {}}

    if re.search(r"ERROR: No matching distribution found|npm ERR!|ERROR: Could not find a version", text):
        return {"category": "dependency_failed", "title": "فشل تثبيت إحدى المكتبات",
                "explanation": "تعذر تثبيت مكتبة مطلوبة أثناء البناء — قد يكون الاسم خاطئ أو لا يوجد إنترنت على السيرفر.",
                "fix_hint": "راجع سجل البناء أعلاه، وتأكد من اسم المكتبة بـ requirements.txt أو package.json.",
                "auto_fixable": False, "fix_action": None, "fix_payload": {}}

    if re.search(r"Permission denied", text):
        return {"category": "permission_denied", "title": "صلاحيات غير كافية",
                "explanation": "العملية حاولت الوصول لملف أو منفذ بدون صلاحية كافية.",
                "fix_hint": "من التيرمنل: جرّب chmod +x على الملف المطلوب، وتأكد إن أي بورت مخصص فوق 1024.",
                "auto_fixable": False, "fix_action": None, "fix_payload": {}}

    return {"category": "unknown", "title": "ما لقينا سبب واضح تلقائياً",
            "explanation": "راجع آخر أسطر السجل بالأسفل يدوياً — الأخطاء غير المعروفة تحتاج نظر بشري.",
            "fix_hint": None, "auto_fixable": False, "fix_action": None, "fix_payload": {},
            "raw_tail": text[-1500:]}

def install_package_for_project(pid, proj, package):
    """Shared by the terminal's quick-install button and the error-analyzer's
    one-click fix — installs with the right tool for the project's type."""
    proj_dir = proj.get('dir')
    proj_type = proj['type']
    if proj_type == 'python':
        pip = os.path.join(proj_dir, 'venv', 'bin', 'pip')
        if not os.path.exists(pip):
            return False, "لم يتم إنشاء بيئة Python بعد — انتظر انتهاء أول تشغيل"
        cmd = [pip, 'install', '-q', '--no-cache-dir', package]
    elif proj_type == 'node':
        cmd = ['npm', 'install', package]
    else:
        return False, "التثبيت التلقائي متاح فقط لمشاريع Python وNode حالياً"
    r = subprocess.run(cmd, cwd=proj_dir, capture_output=True, text=True, timeout=180)
    out = ((r.stdout or '') + (r.stderr or ''))[-4000:]
    ok = r.returncode == 0
    PROCESSES.setdefault(pid, {}).setdefault('log', []).append(
        f"[{now()}] {'📦 ثبّتنا' if ok else '❌ فشل تثبيت'} {package}")
    return ok, out

def reassign_project_port(pid, proj):
    kill_process(pid)
    new_port = next_port()
    old_port = proj['port']
    proj['port'] = new_port
    save_db(DB)
    PROCESSES.setdefault(pid, {}).setdefault('log', []).append(
        f"[{now()}] 🔀 تغيير المنفذ من {old_port} إلى {new_port} (كان مستخدَم)")
    if proj['type'] == 'python' and not proj.get('start_cmd'):
        try:
            with open(os.path.join(proj['dir'], '_bimo_run.py'), 'w') as f:
                f.write(BIMO_RUNNER.format(port=new_port))
        except OSError:
            pass
    PROCESSES[pid]['desired'] = 'running'
    start_process(pid, proj['dir'], new_port, proj['type'], proj.get('main_file'),
                  proj.get('env', ''), proj.get('start_cmd'), proj.get('framework'))
    return True, f"تم التبديل للبورت {new_port}"

def redetect_entry_file(pid, proj):
    detected = detect_project(proj['dir'])
    if detected['type'] != proj['type']:
        # Don't silently change type (bigger decision) — just report it needs manual attention.
        return False, f"الملفات تبدو من نوع مختلف ({detected['type']}) — راجع المشروع يدوياً"
    proj['main_file'] = detected['main_file']
    proj['framework'] = detected['framework']
    save_db(DB)
    PROCESSES.setdefault(pid, {}).setdefault('log', []).append(
        f"[{now()}] 🔍 أعدنا اكتشاف ملف التشغيل: {detected['main_file']}")
    PROCESSES[pid]['desired'] = 'running'
    kill_process(pid)
    start_process(pid, proj['dir'], proj['port'], proj['type'], proj['main_file'],
                  proj.get('env', ''), proj.get('start_cmd'), proj.get('framework'))
    return True, f"ملف التشغيل الجديد: {detected['main_file']}"

@app.route('/api/projects/<pid>/diagnose')
@login_required
def api_diagnose(pid):
    proj, err = _fm_authorize(pid)
    if err: return err
    return jsonify(analyze_project_error(pid))

@app.route('/api/projects/<pid>/autofix', methods=['POST'])
@login_required
def api_autofix(pid):
    proj, err = _fm_authorize(pid)
    if err: return err
    diag = analyze_project_error(pid)
    action = diag.get('fix_action')
    if not diag.get('auto_fixable') or not action:
        return jsonify({"error": "هذا النوع من الأخطاء ما إله إصلاح تلقائي آمن"}), 400
    if action == 'install_package':
        ok, out = install_package_for_project(pid, proj, diag['fix_payload']['package'])
        if ok:
            kill_process(pid)
            start_process(pid, proj['dir'], proj['port'], proj['type'], proj.get('main_file'),
                          proj.get('env', ''), proj.get('start_cmd'), proj.get('framework'))
        return jsonify({"ok": ok, "detail": out})
    if action == 'reassign_port':
        ok, detail = reassign_project_port(pid, proj)
        return jsonify({"ok": ok, "detail": detail})
    if action == 'redetect_entry':
        ok, detail = redetect_entry_file(pid, proj)
        return jsonify({"ok": ok, "detail": detail})
    return jsonify({"error": "إجراء غير معروف"}), 400

# ─── BACKUP / RESTORE — download a project's source + config as a zip,
# and recreate a project from one of those zips later ───
_BACKUP_EXCLUDE_DIRS = {'venv', 'node_modules', '__pycache__', '.git'}
_BACKUP_EXCLUDE_FILES = {'run.log', '_bimo_run.py', '_sk7_go_bin'}

@app.route('/api/projects/<pid>/backup')
@login_required
def api_backup(pid):
    proj, err = _fm_authorize(pid)
    if err: return err
    import zipfile, io
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        meta = {"name": proj['name'], "type": proj['type'], "framework": proj.get('framework'),
                "main_file": proj.get('main_file'), "env": proj.get('env', ''),
                "start_cmd": proj.get('start_cmd')}
        zf.writestr('sk7_meta.json', json.dumps(meta, ensure_ascii=False, indent=2))
        for root, dirs, files in os.walk(proj['dir']):
            dirs[:] = [d for d in dirs if d not in _BACKUP_EXCLUDE_DIRS]
            for f in files:
                if f in _BACKUP_EXCLUDE_FILES:
                    continue
                full = os.path.join(root, f)
                arcname = os.path.relpath(full, proj['dir'])
                zf.write(full, arcname)
    buf.seek(0)
    return send_file(buf, as_attachment=True, download_name=f"{proj['name']}-backup.zip", mimetype='application/zip')

@app.route('/api/projects/restore', methods=['POST'])
@login_required
def api_restore():
    u = current_user()
    f = request.files.get('backup')
    if not f or not f.filename:
        return jsonify({"error": "ارفع ملف نسخة احتياطية (.zip)"}), 400
    quota_err = _check_deploy_quota(u)
    if quota_err:
        return jsonify({"error": quota_err}), 400
    disk_err = _check_disk_space()
    if disk_err:
        return jsonify({"error": disk_err}), 507

    import zipfile
    project_id = str(uuid.uuid4())[:8]
    proj_dir = os.path.join(PROJECTS_DIR, project_id)
    os.makedirs(proj_dir, exist_ok=True)
    tmp_zip = os.path.join('/tmp', f'sk7-restore-{project_id}.zip')
    f.save(tmp_zip)
    try:
        if not zipfile.is_zipfile(tmp_zip):
            raise ValueError("ملف الزيب غير صالح")
        with zipfile.ZipFile(tmp_zip) as zf:
            base = os.path.realpath(proj_dir)
            for n in zf.namelist():
                target = os.path.realpath(os.path.join(base, n))
                if not (target == base or target.startswith(base + os.sep)):
                    raise ValueError(f"مسار غير آمن داخل الأرشيف: {n}")
            zf.extractall(proj_dir)
    except Exception as e:
        shutil.rmtree(proj_dir, ignore_errors=True)
        return jsonify({"error": f"فشلت الاستعادة: {e}"}), 400
    finally:
        try: os.remove(tmp_zip)
        except OSError: pass

    meta_path = os.path.join(proj_dir, 'sk7_meta.json')
    meta = {}
    if os.path.exists(meta_path):
        try:
            with open(meta_path) as mf:
                meta = json.load(mf)
        except (OSError, json.JSONDecodeError):
            pass
        os.remove(meta_path)

    project_name = meta.get('name') or f"restored-{project_id}"
    proj_type = meta.get('type') or 'auto'
    main_file = meta.get('main_file') or ''
    env_vars = meta.get('env') or ''
    start_cmd = meta.get('start_cmd')

    init_log = [f"[{now()}] ♻️ استعادة من نسخة احتياطية..."]
    proj_type, main_file, framework, port = _finalize_and_launch_deploy(
        u, project_id, proj_dir, project_name, proj_type, main_file, env_vars, start_cmd, init_log)

    return jsonify({"ok": True, "project_id": project_id, "port": port, "name": project_name})

_PKG_PATTERNS = [
    (re.compile(r"ModuleNotFoundError: No module named '([\w\-.]+)'"), 'pip'),
    (re.compile(r"ImportError: No module named ([\w\-.]+)"), 'pip'),
    (re.compile(r"Cannot find module '([\w\-@/.]+)'"), 'npm'),
    (re.compile(r"sh: \d+: (\S+): not found"), 'apt'),
    (re.compile(r"(?:php|Fatal error): .*?require\(.*?'([\w\-/.]+)'"), None),
]

def detect_missing_package(pid):
    """Scan a project's actual process output (run.log) for a missing-dependency
    signature so the UI can surface 'مكتبة ناقصة: X' with a one-click install
    instead of a raw traceback."""
    info = PROCESSES.get(pid, {})
    log_path = info.get('log_file')
    text = ''
    if log_path and os.path.exists(log_path):
        try:
            with open(log_path, 'r', errors='replace') as f:
                text = f.read()[-6000:]
        except OSError:
            pass
    if not text:
        text = '\n'.join(info.get('log', [])[-40:])
    for pattern, kind in _PKG_PATTERNS:
        m = pattern.search(text)
        if m and kind:
            return {"package": m.group(1), "installer": kind}
    return None

def _append_log(pid, msg):
    info = PROCESSES.get(pid)
    if info is not None:
        info.setdefault('log', []).append(f"[{now()}] {msg}")

def kill_process(pid):
    """Terminate the whole process group for a project (kills child procs too, e.g. npm->node)."""
    info = PROCESSES.get(pid)
    if not info or not info.get('proc'):
        return
    proc = info['proc']
    if proc.poll() is not None:
        return
    try:
        pgid = os.getpgid(proc.pid)
        os.killpg(pgid, signal.SIGTERM)
        for _ in range(20):
            if proc.poll() is not None:
                break
            time.sleep(0.25)
        if proc.poll() is None:
            os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    _cleanup_cgroup(pid)

PROJECT_MEM_LIMIT_MB = int(os.environ.get('SK7_PROJECT_MEM_MB', 768))
PROJECT_CPU_CORES = float(os.environ.get('SK7_PROJECT_CPU_CORES', 1.0))
PROJECT_DISK_QUOTA_MB = int(os.environ.get('SK7_PROJECT_DISK_QUOTA_MB', 2048))

# NOTE: there used to be a per-process RLIMIT_AS (address-space) memory cap
# applied via preexec_fn here. It's removed on purpose. Empirical testing
# while fixing the "RuntimeError: can't start new thread" bug showed
# RLIMIT_AS causes exactly that failure for any threaded process (venv
# Python + RLIMIT_AS=768MB alone reproduces it with zero cgroup involvement)
# — RLIMIT_AS counts *reserved virtual address space*, not real memory, and
# thread creation needs to mmap a new stack; Python reserves enough virtual
# space at startup that a few hundred MB ceiling gets hit by thread creation
# long before real memory usage is anywhere near the cap. Memory limiting
# now comes exclusively from cgroups (memory.max), which was verified safe
# for threaded processes in the same testing. When cgroups aren't available
# there is currently no hard per-project memory ceiling — the watchdog
# restart loop and the OS's own OOM killer are the safety net instead.

# ─── CGROUPS — real per-project resource isolation (memory + CPU) that's
# actually scoped to one project, unlike the rlimit approach above. Supports
# both cgroup v2 (unified, the default on modern Ubuntu/Debian) and cgroup v1
# (older distros), with a clean no-op fallback if neither is available or
# writable (e.g. inside some restricted containers). Deliberately does NOT
# touch the pids controller — see _apply_cgroup_limits docstring. CPU is
# limited via cpu.max/cfs_quota, which *throttles* over-budget processes
# rather than killing them or blocking thread creation, so it doesn't carry
# the same risk that pids-limiting did; this was verified in testing
# (a CPU-bound thread-heavy process stays responsive, just slower, once
# throttled — no RuntimeError). ───
_CGROUP_MODE = None
_CGROUP_ROOT = '/sys/fs/cgroup'

def _detect_cgroups():
    global _CGROUP_MODE
    try:
        if os.path.exists(os.path.join(_CGROUP_ROOT, 'cgroup.controllers')) and os.access(_CGROUP_ROOT, os.W_OK):
            _CGROUP_MODE = 'v2'
        elif os.path.isdir(os.path.join(_CGROUP_ROOT, 'memory')) and os.path.isdir(os.path.join(_CGROUP_ROOT, 'pids')) \
                and os.access(os.path.join(_CGROUP_ROOT, 'memory'), os.W_OK):
            _CGROUP_MODE = 'v1'
        else:
            _CGROUP_MODE = None
    except OSError:
        _CGROUP_MODE = None
_detect_cgroups()

def _apply_cgroup_limits(pid_key, os_pid):
    """Assign a hosted project's OS process to its own cgroup with real
    memory and CPU caps scoped to just that project. Deliberately does not
    touch the pids controller — an earlier version also set pids.max (max
    process/thread count), but testing showed cgroup pids-controller
    enforcement can itself trigger thread creation failures in some
    environments — the exact class of bug this whole redesign exists to fix.
    Memory (OOM-kill over cap) and CPU (throttle over cap) are both the
    standard, well-tested cgroup use cases and were verified safe for
    threaded processes. Best-effort — logs a warning and continues
    unsandboxed rather than failing the deploy if cgroups aren't available."""
    if _CGROUP_MODE is None:
        return
    mem_bytes = PROJECT_MEM_LIMIT_MB * 1024 * 1024
    period_us = 100000
    quota_us = int(period_us * PROJECT_CPU_CORES)
    try:
        if _CGROUP_MODE == 'v2':
            d = os.path.join(_CGROUP_ROOT, f'sk7-{pid_key}')
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, 'memory.max'), 'w') as f: f.write(str(mem_bytes))
            with open(os.path.join(d, 'cpu.max'), 'w') as f: f.write(f"{quota_us} {period_us}")
            with open(os.path.join(d, 'cgroup.procs'), 'w') as f: f.write(str(os_pid))
        elif _CGROUP_MODE == 'v1':
            dm = os.path.join(_CGROUP_ROOT, 'memory', f'sk7-{pid_key}')
            dc = os.path.join(_CGROUP_ROOT, 'cpu', f'sk7-{pid_key}')
            os.makedirs(dm, exist_ok=True)
            with open(os.path.join(dm, 'memory.limit_in_bytes'), 'w') as f: f.write(str(mem_bytes))
            with open(os.path.join(dm, 'cgroup.procs'), 'w') as f: f.write(str(os_pid))
            if os.path.isdir(os.path.join(_CGROUP_ROOT, 'cpu')):
                os.makedirs(dc, exist_ok=True)
                with open(os.path.join(dc, 'cpu.cfs_period_us'), 'w') as f: f.write(str(period_us))
                with open(os.path.join(dc, 'cpu.cfs_quota_us'), 'w') as f: f.write(str(quota_us))
                with open(os.path.join(dc, 'cgroup.procs'), 'w') as f: f.write(str(os_pid))
    except OSError as e:
        _append_log(pid_key, f"⚠️ تعذر تفعيل عزل الموارد (cgroups) لهذا المشروع: {e}")

def _count_cgroup_procs(pid_key):
    """Count live PIDs in a project's cgroup — approximates worker count for
    cluster-mode gunicorn/pm2 (master + N workers all land in the same
    cgroup). Falls back to 1 (just the main process) when cgroups aren't
    available, since we still know at least one process is running."""
    if _CGROUP_MODE is None:
        return 1
    path = os.path.join(_CGROUP_ROOT, f'sk7-{pid_key}', 'cgroup.procs') if _CGROUP_MODE == 'v2' else \
           os.path.join(_CGROUP_ROOT, 'memory', f'sk7-{pid_key}', 'cgroup.procs')
    try:
        with open(path) as f:
            return max(1, len([l for l in f.read().splitlines() if l.strip()]))
    except OSError:
        return 1

def _cleanup_cgroup(pid_key):
    if _CGROUP_MODE is None:
        return
    paths = [os.path.join(_CGROUP_ROOT, f'sk7-{pid_key}')] if _CGROUP_MODE == 'v2' else \
            [os.path.join(_CGROUP_ROOT, 'memory', f'sk7-{pid_key}'), os.path.join(_CGROUP_ROOT, 'cpu', f'sk7-{pid_key}')]
    for p in paths:
        try:
            os.rmdir(p)
        except OSError:
            pass  # non-empty (process not fully reaped yet) or already gone — harmless

def start_process(pid, proj_dir, port, proj_type, main_file, env_vars, start_cmd=None, framework=None):
    """Launch (or relaunch) the actual project process. Assumes deps are already installed."""
    log_path = os.path.join(proj_dir, 'run.log')
    logf = open(log_path, 'a', buffering=1)
    cmd = resolve_cmd(proj_dir, proj_type, main_file, port, start_cmd, framework)
    env = build_env(proj_dir, proj_type, port, env_vars)
    try:
        proc = subprocess.Popen(cmd, cwd=proj_dir, stdout=logf, stderr=subprocess.STDOUT,
                                 env=env, start_new_session=True)
    except FileNotFoundError as e:
        _append_log(pid, f"❌ فشل التشغيل: {e}")
        PROCESSES[pid]['status'] = 'error'
        PROCESSES[pid]['error'] = str(e)
        return
    PROCESSES[pid].update({
        'proc': proc, 'status': 'running', 'error': None, 'log_file': log_path,
        'cmd': cmd, 'env': env, 'cwd': proj_dir, 'desired': 'running',
        'started_at': time.time(), 'restart_count': 0, 'restart_window_start': time.time(),
    })
    _apply_cgroup_limits(pid, proc.pid)
    _append_log(pid, f"🚀 السيرفر شغال (PID {proc.pid}) على المنفذ {port}")

def build_and_run(project_id, proj_dir, port, proj_type, main_file, env_vars, start_cmd=None, framework=None):
    """Install deps (in a background thread) then launch the process."""
    pid_info = PROCESSES[project_id]
    pid_info['status'] = 'building'
    pid_info['log'].append(f"[{now()}] 🏗️  تجهيز البيئة...")

    # Environment variables also go to a .env file (for python-dotenv / dotenv-node
    # based projects that call load_dotenv() themselves, in addition to being
    # passed as real process env vars either way).
    if env_vars and env_vars.strip():
        try:
            with open(os.path.join(proj_dir, '.env'), 'w') as f:
                f.write(env_vars)
        except OSError:
            pass

    def run_cmd(cmd_list, log_prefix=''):
        proc = subprocess.run(cmd_list, cwd=proj_dir, capture_output=True, text=True)
        out = (proc.stdout or '') + (proc.stderr or '')
        for l in out.strip().split('\n')[-20:]:
            if l.strip():
                pid_info['log'].append(f"[{now()}] {log_prefix}{l}")
        return proc.returncode

    if not start_cmd:
        if proj_type == 'python':
            with open(os.path.join(proj_dir, '_bimo_run.py'), 'w') as f:
                f.write(BIMO_RUNNER.format(port=port))
            venv_dir = os.path.join(proj_dir, 'venv')
            if not os.path.exists(venv_python(proj_dir)):
                pid_info['log'].append(f"[{now()}] 🐍 إنشاء بيئة Python افتراضية...")
                rc = run_cmd([sys.executable, '-m', 'venv', venv_dir], 'VENV: ')
                if rc != 0:
                    pid_info['status'] = 'error'
                    pid_info['error'] = '\n'.join(pid_info['log'][-15:])
                    return
            req = os.path.join(proj_dir, 'requirements.txt')
            if not os.path.exists(req):
                guessed = guess_requirements(proj_dir)
                if guessed:
                    with open(req, 'w') as f:
                        f.write('\n'.join(guessed))
                    pid_info['log'].append(f"[{now()}] 🔍 ما فيه requirements.txt — خمّنّا المكتبات من الاستيرادات: {', '.join(guessed)}")
            if os.path.exists(req):
                pid_info['log'].append(f"[{now()}] 📦 تثبيت المكتبات (pip)...")
                pip = os.path.join(venv_dir, 'bin', 'pip')
                rc = run_cmd([pip, 'install', '-q', '--no-cache-dir', '-r', req], 'PIP: ')
                if rc != 0:
                    pid_info['log'].append(f"[{now()}] ⚠️ بعض المكتبات فشل تثبيتها — راجع السجل، قد يعمل المشروع جزئياً")
            # Production Runtime Manager: install the real production server for
            # the detected web framework, not the dev server. Re-detects the app
            # variable fresh (cheap) rather than trusting a possibly-stale value.
            if framework in ('flask', 'fastapi'):
                _, app_var = detect_python_web_framework(proj_dir, main_file)
                if app_var:
                    server_pkg = 'gunicorn' if framework == 'flask' else 'uvicorn[standard]'
                    server_bin = 'gunicorn' if framework == 'flask' else 'uvicorn'
                    if not os.path.exists(os.path.join(venv_dir, 'bin', server_bin)):
                        pid_info['log'].append(f"[{now()}] ⚙️  تثبيت سيرفر إنتاج ({server_bin}) لمشروع {framework}...")
                        pip = os.path.join(venv_dir, 'bin', 'pip')
                        rc = run_cmd([pip, 'install', '-q', '--no-cache-dir', server_pkg], 'PROD-SERVER: ')
                        if rc != 0:
                            pid_info['log'].append(f"[{now()}] ⚠️ فشل تثبيت {server_bin} — سيعمل المشروع بسيرفر التطوير كبديل آمن")
                else:
                    pid_info['log'].append(f"[{now()}] ℹ️ لم نتأكد من اسم متغير التطبيق ({framework}) — سيعمل بسيرفر التطوير الآمن بدل الإنتاجي")
            if framework == 'django':
                pid_info['log'].append(f"[{now()}] 🗄️  Django: تطبيق migrate...")
                py = venv_python(proj_dir)
                run_cmd([py, 'manage.py', 'migrate', '--noinput'], 'DJANGO: ')
        elif proj_type == 'node':
            if os.path.exists(os.path.join(proj_dir, 'package.json')):
                pid_info['log'].append(f"[{now()}] 📦 تثبيت المكتبات (npm)...")
                rc = run_cmd(['npm', 'install', '--omit=dev'], 'NPM: ')
                if rc != 0:
                    pid_info['log'].append(f"[{now()}] ⚠️ فشل npm install — راجع السجل")
        elif proj_type == 'php':
            if os.path.exists(os.path.join(proj_dir, 'composer.json')) and shutil.which('composer'):
                pid_info['log'].append(f"[{now()}] 📦 تثبيت المكتبات (composer)...")
                run_cmd(['composer', 'install', '--no-dev'], 'COMPOSER: ')
        elif proj_type == 'go':
            if not shutil.which('go'):
                pid_info['status'] = 'error'
                pid_info['error'] = 'Go غير مثبت على السيرفر — راجع install.sh'
                pid_info['log'].append(f"[{now()}] ❌ Go غير مثبت على هذا السيرفر")
                return
            pid_info['log'].append(f"[{now()}] 🛠️  بناء مشروع Go (go build)...")
            bin_path = os.path.join(proj_dir, '_sk7_go_bin')
            genv = os.environ.copy(); genv['CGO_ENABLED'] = '0'
            rc = run_cmd(['go', 'build', '-o', bin_path, '.'], 'GO BUILD: ')
            if rc != 0:
                pid_info['status'] = 'error'
                pid_info['error'] = '\n'.join(pid_info['log'][-15:])
                pid_info['log'].append(f"[{now()}] ❌ فشل بناء مشروع Go")
                return
            os.chmod(bin_path, 0o755)

    pid_info['status'] = 'starting'
    pid_info['log'].append(f"[{now()}] ▶️  جاري التشغيل على المنفذ {port}...")
    if pid_info.get('desired') == 'stopped':
        pid_info['status'] = 'stopped'
        pid_info['log'].append(f"[{now()}] ⏹️  تم إلغاء التشغيل (تم طلب الإيقاف أثناء التجهيز)")
        return
    start_process(project_id, proj_dir, port, proj_type, main_file, env_vars, start_cmd, framework)

# ─── WATCHDOG — keeps hosted projects alive 24/7 ─────
_WATCHDOG_TICK = 0

def _watchdog_loop():
    global _WATCHDOG_TICK
    while True:
        time.sleep(5)
        _WATCHDOG_TICK += 1
        for pid, info in list(PROCESSES.items()):
            if info.get('desired') != 'running':
                continue
            proc = info.get('proc')
            if proc is None:
                continue
            if proc.poll() is None:
                # still running — periodic disk-quota check (every ~30s, not every tick)
                if _WATCHDOG_TICK % 6 == 0:
                    proj = DB['projects'].get(pid)
                    if proj:
                        disk_mb = _dir_size_mb(proj.get('dir', ''), pid, ttl=0)
                        if disk_mb > PROJECT_DISK_QUOTA_MB:
                            _append_log(pid, f"🛑 تجاوز حصة التخزين ({disk_mb} MB > {PROJECT_DISK_QUOTA_MB} MB) — إيقاف المشروع لحماية باقي المشاريع من امتلاء القرص")
                            info['desired'] = 'stopped'
                            info['status'] = 'error'
                            info['error'] = f'تجاوز حصة التخزين المسموحة ({PROJECT_DISK_QUOTA_MB} MB)'
                            kill_process(pid)
                            proj['desired_state'] = 'stopped'
                            save_db(DB)
                continue  # still running or never started yet (still building)
            if info.get('status') in ('building', 'starting'):
                continue

            # process died unexpectedly. Real exponential backoff instead of an
            # immediate retry — 2s/4s/8s/16s/32s/60s(capped) — so a crash-looping
            # project doesn't hammer the CPU with restart attempts, and a
            # per-window flood cap stops it permanently if it never recovers.
            next_retry = info.get('_next_retry_at', 0)
            if time.time() < next_retry:
                continue

            win_start = info.get('restart_window_start', 0)
            if time.time() - win_start > 120:
                info['restart_window_start'] = time.time()
                info['restart_count'] = 0
                info['_backoff'] = 2
            info['restart_count'] = info.get('restart_count', 0) + 1
            if info['restart_count'] > 8:
                info['status'] = 'error'
                info['error'] = 'توقف السيرفر بشكل متكرر — تم إيقاف إعادة التشغيل التلقائي'
                _append_log(pid, "❌ تكرار الأعطال — أوقفنا إعادة التشغيل التلقائي، افحص السجل وشغّله يدوياً")
                info['desired'] = 'crashed'
                continue

            backoff = info.get('_backoff', 2)
            info['_next_retry_at'] = time.time() + backoff
            info['_backoff'] = min(60, backoff * 2)
            info['total_restarts'] = info.get('total_restarts', 0) + 1

            # crash reason: exit code + a short tail of what the process actually
            # printed right before dying, so it's visible without opening logs
            code = proc.returncode
            tail = ''
            log_path = info.get('log_file')
            if log_path and os.path.exists(log_path):
                try:
                    with open(log_path, 'r', errors='replace') as f:
                        tail = f.read()[-300:].strip().split('\n')[-1]
                except OSError:
                    pass
            reason = f"exit code {code}" + (f" — {tail}" if tail else "")
            info['last_crash_reason'] = reason
            _append_log(pid, f"⚠️  توقف السيرفر ({reason}) — إعادة المحاولة خلال {backoff} ثانية...")
            proj = DB['projects'].get(pid)
            if not proj:
                continue
            start_process(pid, proj['dir'], proj['port'], proj['type'], proj.get('main_file'),
                          proj.get('env', ''), proj.get('start_cmd'), proj.get('framework'))

_watchdog_thread = threading.Thread(target=_watchdog_loop, daemon=True)
_watchdog_thread.start()

class _AdoptedProcess:
    """Lightweight stand-in for subprocess.Popen, used when a hosted
    project's process is discovered to still be alive from before a panel
    restart (it survives because it's in its own session/cgroup, which is
    intentional — a panel restart shouldn't interrupt running services).
    Implements just enough of Popen's interface (.pid, .poll(), .returncode)
    for the rest of the code (watchdog, kill_process, stats) to treat it
    exactly like a process we spawned ourselves."""
    def __init__(self, pid):
        self.pid = pid
        self.returncode = None
    def poll(self):
        if self.returncode is not None:
            return self.returncode
        if os.path.exists(f'/proc/{self.pid}'):
            return None
        self.returncode = -1
        return self.returncode

def _find_adopted_pid(pid_key):
    """Look up the OS pid of a project's process via its own cgroup, so we
    can adopt it after a panel restart instead of colliding with it."""
    if _CGROUP_MODE is None:
        return None
    path = os.path.join(_CGROUP_ROOT, f'sk7-{pid_key}', 'cgroup.procs') if _CGROUP_MODE == 'v2' else \
           os.path.join(_CGROUP_ROOT, 'memory', f'sk7-{pid_key}', 'cgroup.procs')
    try:
        with open(path) as f:
            pids = [int(l) for l in f.read().split() if l.strip()]
        return pids[0] if pids else None
    except (OSError, ValueError):
        return None

def resume_projects_on_boot():
    """Called once at process start — relaunches any project that was running
    before the panel itself was restarted (systemd restart, VPS reboot, etc).
    First checks whether the project's process actually survived the panel
    restart (it can — hosted processes run in their own session/cgroup on
    purpose, precisely so a panel deploy/restart doesn't interrupt live
    services) and adopts it instead of spawning a second one into the same
    port, which would just crash-loop both."""
    for pid, proj in DB['projects'].items():
        if proj.get('desired_state') != 'running':
            continue
        port = proj['port']
        if port_in_use(port):
            adopted_pid = _find_adopted_pid(pid)
            if adopted_pid and os.path.exists(f'/proc/{adopted_pid}'):
                PROCESSES[pid] = {
                    "status": "running", "port": port, "error": None, "desired": "running",
                    "proc": _AdoptedProcess(adopted_pid),
                    "log": [f"[{now()}] 🔗 المشروع كان شغال قبل إعادة تشغيل اللوحة (PID {adopted_pid}) — تم تبنّيه بدل إعادة تشغيله"],
                    "log_file": os.path.join(proj['dir'], 'run.log'),
                    "started_at": time.time(), "restart_count": 0, "restart_window_start": time.time(),
                }
            else:
                # port is occupied but we can't identify whose process it is
                # (cgroups unavailable, or it predates this feature) — safest
                # is to leave it alone rather than fight over the port.
                PROCESSES[pid] = {
                    "status": "running", "port": port, "error": None, "desired": "running", "proc": None,
                    "log": [f"[{now()}] 🔗 المنفذ {port} مستخدم مسبقاً — على الأغلب المشروع شغال من قبل، لم نعد تشغيله لتفادي تعارض"],
                    "log_file": os.path.join(proj['dir'], 'run.log'), "started_at": time.time(),
                }
            continue
        PROCESSES[pid] = {"status": "queued", "port": port, "log": [f"[{now()}] 🔄 استئناف بعد إعادة تشغيل اللوحة..."],
                           "error": None, "desired": "running", "started_at": None}
        t = threading.Thread(target=build_and_run, args=(pid, proj['dir'], port, proj['type'],
                              proj.get('main_file'), proj.get('env', ''), proj.get('start_cmd'), proj.get('framework')), daemon=True)
        t.start()

MAX_RUNNING_PER_USER = 8  # regular users; dev/admin unlimited — keeps one account from exhausting the VPS

def _finalize_and_launch_deploy(u, project_id, proj_dir, project_name, proj_type, main_file, env_vars, start_cmd, init_log_lines, files_list=None):
    """Shared tail of both file-upload and git-url deploy: auto-detect,
    persist the project record, and kick off the background build+run."""
    entries = [e for e in os.listdir(proj_dir) if not e.startswith('.')]
    if len(entries) == 1 and os.path.isdir(os.path.join(proj_dir, entries[0])):
        wrapper = os.path.join(proj_dir, entries[0])
        for item in os.listdir(wrapper):
            shutil.move(os.path.join(wrapper, item), os.path.join(proj_dir, item))
        os.rmdir(wrapper)

    detected = detect_project(proj_dir)
    detect_note = None
    if proj_type == 'auto':
        proj_type = detected['type']
        if not main_file:
            main_file = detected['main_file']
        detect_note = f"🔍 تم اكتشاف المشروع تلقائياً: {proj_type}" + (f" ({detected['framework']})" if detected['framework'] else "") + f" — ملف التشغيل: {main_file}"
    elif not main_file and proj_type == detected['type']:
        main_file = detected['main_file']
    framework = detected['framework'] if proj_type == detected['type'] else None
    if not main_file:
        main_file = {'python': 'main.py', 'node': 'index.js', 'php': 'index.php', 'go': 'main.go'}.get(proj_type, 'main.py')

    port = next_port()
    proj_info = {
        "id": project_id, "name": project_name, "type": proj_type, "framework": framework,
        "port": port, "owner": u['username'], "created_at": time.time(),
        "files": files_list or [], "env": env_vars, "main_file": main_file,
        "start_cmd": start_cmd or None, "dir": proj_dir, "desired_state": "running",
    }
    DB['projects'][project_id] = proj_info
    save_db(DB)

    init_log = list(init_log_lines)
    if detect_note:
        init_log.append(f"[{now()}] {detect_note}")
    PROCESSES[project_id] = {"status": "queued", "port": port, "log": init_log, "error": None,
                              "desired": "running", "started_at": None}

    t = threading.Thread(target=build_and_run, args=(project_id, proj_dir, port, proj_type, main_file, env_vars, start_cmd or None, framework), daemon=True)
    t.start()
    return proj_type, main_file, framework, port

def _check_deploy_quota(u):
    if u['role'] != 'user':
        return None
    active = sum(1 for pid, proj in DB['projects'].items()
                 if proj.get('owner') == u['username'] and PROCESSES.get(pid, {}).get('status') in
                 ('running', 'building', 'starting', 'queued'))
    if active >= MAX_RUNNING_PER_USER:
        return f"وصلت للحد الأقصى من المشاريع الشغالة بنفس الوقت ({MAX_RUNNING_PER_USER}) — أوقف مشروع آخر أولاً"
    return None

MIN_FREE_DISK_MB = int(os.environ.get('SK7_MIN_FREE_DISK_MB', 500))

def _check_disk_space():
    try:
        free_mb = shutil.disk_usage(BASE_DIR).free / 1024 / 1024
    except OSError:
        return None
    if free_mb < MIN_FREE_DISK_MB:
        return f"مساحة القرص على السيرفر منخفضة جداً ({free_mb:.0f} MB متبقية) — احذف مشاريع قديمة أو وسّع التخزين قبل نشر مشروع جديد"
    return None

@app.route('/api/deploy', methods=['POST'])
@login_required
def api_deploy():
    u = current_user()
    data = request.form
    files = request.files.getlist('files')
    project_name = (data.get('name') or '').strip()
    proj_type = (data.get('type') or 'auto').strip()
    env_vars = data.get('env','')
    start_cmd = data.get('start_cmd','').strip()
    main_file = data.get('main_file','').strip()

    if not project_name:
        return jsonify({"error":"أدخل اسم المشروع"}),400
    if not files or not any(f.filename for f in files):
        return jsonify({"error":"ارفع ملفات أولاً"}),400

    current_count = len(u.get('files',[]))
    if current_count + len(files) > u['file_limit']:
        return jsonify({"error":f"تجاوزت الحد الأقصى ({u['file_limit']} ملف)"}),400

    quota_err = _check_deploy_quota(u)
    if quota_err:
        return jsonify({"error": quota_err}), 400

    disk_err = _check_disk_space()
    if disk_err:
        return jsonify({"error": disk_err}), 507

    project_id = str(uuid.uuid4())[:8]
    proj_dir = os.path.join(PROJECTS_DIR, project_id)
    os.makedirs(proj_dir, exist_ok=True)

    saved_files = []
    for f in files:
        if f.filename:
            fname = secure_filename(f.filename)
            dest = os.path.join(proj_dir, fname)
            f.save(dest)
            size = os.path.getsize(dest)
            saved_files.append({"name":fname,"size":size})
            if 'files' not in u: u['files']=[]
            u['files'].append({"name":fname,"size":size,"date":datetime.now().strftime('%Y-%m-%d %H:%M'),"path":dest,"project":project_id})

    # Extract archives so projects with subfolders actually work (they were
    # previously just copied as a raw .zip/.tar.gz into the image, which never runs)
    import zipfile, tarfile
    def _safe_members(names, base):
        """Reject any archive entry that would extract outside `base` (zip-slip protection)."""
        base = os.path.realpath(base)
        for n in names:
            target = os.path.realpath(os.path.join(base, n))
            if not (target == base or target.startswith(base + os.sep)):
                raise ValueError(f"مسار غير آمن داخل الأرشيف: {n}")

    for sf in list(saved_files):
        archive_path = os.path.join(proj_dir, sf['name'])
        lower = sf['name'].lower()
        try:
            if lower.endswith('.zip') and zipfile.is_zipfile(archive_path):
                with zipfile.ZipFile(archive_path) as zf:
                    _safe_members(zf.namelist(), proj_dir)
                    zf.extractall(proj_dir)
                os.remove(archive_path)
            elif lower.endswith(('.tar.gz', '.tgz', '.tar')) and tarfile.is_tarfile(archive_path):
                with tarfile.open(archive_path) as tf:
                    _safe_members([m.name for m in tf.getmembers()], proj_dir)
                    tf.extractall(proj_dir)
                os.remove(archive_path)
        except Exception:
            pass  # keep the raw archive if extraction fails; build will just fail loudly instead of silently

    init_log = [f"[{now()}] 📦 استلام {len(saved_files)} ملف..."]
    proj_type, main_file, framework, port = _finalize_and_launch_deploy(
        u, project_id, proj_dir, project_name, proj_type, main_file, env_vars, start_cmd, init_log,
        files_list=[f['name'] for f in saved_files])

    return jsonify({"ok":True,"project_id":project_id,"port":port,"name":project_name,"detected_type":proj_type,"detected_main_file":main_file,"framework":framework})

_GIT_URL_RE = re.compile(r'^https?://(github\.com|gitlab\.com|bitbucket\.org)/[\w.\-]+/[\w.\-]+(\.git)?/?$')

@app.route('/api/deploy_url', methods=['POST'])
@login_required
def api_deploy_url():
    """Deploy directly from a public Git repo URL (GitHub/GitLab/Bitbucket) —
    clones the repo and runs it through the exact same detect+build pipeline
    as a file upload."""
    u = current_user()
    data = request.json or {}
    project_name = (data.get('name') or '').strip()
    repo_url = (data.get('url') or '').strip()
    proj_type = (data.get('type') or 'auto').strip()
    env_vars = data.get('env', '')
    start_cmd = (data.get('start_cmd') or '').strip()
    main_file = (data.get('main_file') or '').strip()

    if not project_name:
        return jsonify({"error": "أدخل اسم المشروع"}), 400
    if not repo_url or not _GIT_URL_RE.match(repo_url):
        return jsonify({"error": "رابط Git غير صالح — لازم يكون رابط GitHub/GitLab/Bitbucket عام"}), 400
    if not shutil.which('git'):
        return jsonify({"error": "Git غير مثبت على هذا السيرفر — ثبّته أو استخدم رفع ZIP بدلاً منه"}), 400

    quota_err = _check_deploy_quota(u)
    if quota_err:
        return jsonify({"error": quota_err}), 400

    disk_err = _check_disk_space()
    if disk_err:
        return jsonify({"error": disk_err}), 507

    project_id = str(uuid.uuid4())[:8]
    proj_dir = os.path.join(PROJECTS_DIR, project_id)

    r = subprocess.run(['git', 'clone', '--depth', '1', repo_url, proj_dir],
                        capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        shutil.rmtree(proj_dir, ignore_errors=True)
        return jsonify({"error": f"فشل استنساخ المستودع: {(r.stderr or '')[-500:]}"}), 400
    shutil.rmtree(os.path.join(proj_dir, '.git'), ignore_errors=True)

    init_log = [f"[{now()}] 🌐 تم استنساخ المستودع: {repo_url}"]
    proj_type, main_file, framework, port = _finalize_and_launch_deploy(
        u, project_id, proj_dir, project_name, proj_type, main_file, env_vars, start_cmd, init_log)
    DB['projects'][project_id]['source_url'] = repo_url
    save_db(DB)

    return jsonify({"ok": True, "project_id": project_id, "port": port, "name": project_name,
                     "detected_type": proj_type, "detected_main_file": main_file, "framework": framework})

_CLOCK_TICKS = os.sysconf('SC_CLK_TCK') if hasattr(os, 'sysconf') else 100

def _cpu_percent(pid_key, p):
    """Delta-based CPU% since the last time this project was sampled (not an
    instant snapshot — /proc only gives cumulative ticks, so we diff against
    the previous poll, same approach `top` uses). Capped at the project's
    actual cgroup CPU allocation (PROJECT_CPU_CORES * 100), not a flat 100%,
    since a project can be allowed more than one core."""
    try:
        with open(f'/proc/{p.pid}/stat') as f:
            parts = f.read().split()
        total_ticks = int(parts[13]) + int(parts[14])
    except (FileNotFoundError, ProcessLookupError, IndexError, ValueError):
        return None
    now_t = time.time()
    info = PROCESSES.get(pid_key, {})
    prev = info.get('_cpu_sample')
    info['_cpu_sample'] = (total_ticks, now_t)
    if not prev:
        return 0.0
    prev_ticks, prev_t = prev
    dt = now_t - prev_t
    if dt <= 0:
        return 0.0
    cap = PROJECT_CPU_CORES * 100
    return round(min(cap, ((total_ticks - prev_ticks) / _CLOCK_TICKS / dt) * 100), 1)

def _io_stats(p):
    """Real per-process disk I/O counters from /proc/pid/io — cumulative
    bytes read/written since the process started (requires the panel to run
    with permission to read it, true for root, which is how install.sh sets
    up the systemd service)."""
    try:
        with open(f'/proc/{p.pid}/io') as f:
            vals = {}
            for line in f:
                k, v = line.split(':')
                vals[k.strip()] = int(v.strip())
        return round(vals.get('read_bytes', 0) / 1024 / 1024, 2), round(vals.get('write_bytes', 0) / 1024 / 1024, 2)
    except (FileNotFoundError, ProcessLookupError, PermissionError, ValueError):
        return None, None

_DISK_CACHE = {}

def _dir_size_mb(path, cache_key, ttl=30):
    """Cached — walking a project's whole directory on every 5s poll would be
    wasteful, so we only recompute every `ttl` seconds."""
    cached = _DISK_CACHE.get(cache_key)
    if cached and time.time() - cached[0] < ttl:
        return cached[1]
    total = 0
    try:
        for root, dirs, files in os.walk(path):
            for f in files:
                full = os.path.join(root, f)
                try:
                    if os.path.islink(full):
                        continue  # don't follow symlinks — venvs commonly symlink to
                                  # shared system libraries; counting the target's full
                                  # size massively overcounts real per-project disk usage
                    total += os.path.getsize(full)
                except OSError:
                    pass
    except OSError:
        pass
    mb = round(total / 1024 / 1024, 1)
    _DISK_CACHE[cache_key] = (time.time(), mb)
    return mb

@app.route('/api/projects', methods=['GET'])
@login_required
def api_projects():
    u = current_user()
    projects = []
    for pid, proj in DB['projects'].items():
        if u['role'] in ('dev','admin') or proj['owner']==u['username']:
            proc = PROCESSES.get(pid, {})
            # real docker status
            status = proc.get('status','unknown')
            error  = proc.get('error','')
            if status == 'running':
                p = proc.get('proc')
                if p is None or p.poll() is not None:
                    status = 'stopped'
                    proc['status'] = 'stopped'
            mem = None
            cpu = None
            p = proc.get('proc')
            if status == 'running' and p is not None:
                try:
                    with open(f'/proc/{p.pid}/status') as fh:
                        for line in fh:
                            if line.startswith('VmRSS:'):
                                mem = round(int(line.split()[1]) / 1024, 1)
                                break
                except (FileNotFoundError, ProcessLookupError):
                    pass
                cpu = _cpu_percent(pid, p)
            disk_mb = _dir_size_mb(proj.get('dir', ''), pid)
            io_read_mb, io_write_mb = (_io_stats(p) if status == 'running' and p is not None else (None, None))
            reachable = None
            if status == 'running':
                reachable, _ = _probe_project(proj['port'], timeout=1.2)

            started_at = proc.get('started_at')
            uptime_s = round(time.time() - started_at, 0) if (status == 'running' and started_at) else 0
            restart_count = proc.get('total_restarts', 0)
            workers = _count_cgroup_procs(pid) if status == 'running' else 0
            pstats = PROXY_STATS.get(pid, {'requests': 0, 'bytes_in': 0, 'bytes_out': 0})

            if status != 'running':
                health = status  # 'stopped' | 'error' | 'crashed' | 'building' | 'starting' | 'queued'
            elif reachable is False:
                health = 'degraded'  # process alive but not answering HTTP (normal for bots/workers too)
            else:
                health = 'healthy'

            alerts = []
            if mem is not None and PROJECT_MEM_LIMIT_MB and mem / PROJECT_MEM_LIMIT_MB > 0.85:
                alerts.append(f"⚠️ الذاكرة قريبة من الحد ({mem}/{PROJECT_MEM_LIMIT_MB} MB)")
            if disk_mb is not None and disk_mb / PROJECT_DISK_QUOTA_MB > 0.85:
                alerts.append(f"⚠️ التخزين قريب من الحد ({disk_mb}/{PROJECT_DISK_QUOTA_MB} MB)")
            if cpu is not None and cpu / (PROJECT_CPU_CORES * 100) > 0.9:
                alerts.append("⚠️ استهلاك CPU قريب من الحد الأقصى المخصص للمشروع")

            projects.append({
                "id": pid,
                "name": proj['name'],
                "type": proj['type'],
                "framework": proj.get('framework'),
                "port": proj['port'],
                "owner": proj['owner'],
                "status": status,
                "health": health,
                "error": error,
                "files": proj.get('files',[]),
                "created_at": proj.get('created_at',0),
                "log": proc.get('log',[])[-30:],
                "mem_mb": mem, "mem_limit_mb": PROJECT_MEM_LIMIT_MB,
                "cpu_percent": cpu, "cpu_limit_cores": PROJECT_CPU_CORES,
                "disk_mb": disk_mb, "disk_quota_mb": PROJECT_DISK_QUOTA_MB,
                "io_read_mb": io_read_mb, "io_write_mb": io_write_mb,
                "net_in_mb": round(pstats['bytes_in']/1024/1024, 3),
                "net_out_mb": round(pstats['bytes_out']/1024/1024, 3),
                "requests_total": pstats['requests'],
                "requests_per_sec": _requests_per_sec(pid) if status == 'running' else 0.0,
                "uptime_seconds": uptime_s,
                "workers": workers,
                "restart_count": restart_count,
                "alerts": alerts,
                "missing_package": detect_missing_package(pid) if status in ('error','stopped') else None,
                "reachable": reachable,
                "proxy_path": f"/app/{pid}/",
            })
    projects.sort(key=lambda x: x['created_at'], reverse=True)
    return jsonify({"projects":projects})

@app.route('/api/projects/<pid>/status')
@login_required
def api_project_status(pid):
    proj = DB['projects'].get(pid)
    if not proj:
        return jsonify({"error": "not found"}), 404
    u = current_user()
    if u['role'] == 'user' and proj['owner'] != u['username']:
        return jsonify({"error": "forbidden"}), 403
    proc = PROCESSES.get(pid,{})
    status = proc.get('status','unknown')
    cpu, mem = '-', '-'
    p = proc.get('proc')
    if status == 'running' and p is not None and p.poll() is None:
        try:
            with open(f'/proc/{p.pid}/status') as f:
                for line in f:
                    if line.startswith('VmRSS:'):
                        mem = f"{int(line.split()[1]) / 1024:.1f} MB"
                        break
        except (FileNotFoundError, ProcessLookupError):
            pass
    return jsonify({
        "status": status,
        "error": proc.get('error',''),
        "log": proc.get('log',[])[-50:],
        "port": proj.get('port',0),
        "cpu": cpu,
        "mem": mem,
    })

@app.route('/api/projects/<pid>/health')
@login_required
def api_project_health(pid):
    """On-demand real check — used right before opening a project's link, so we
    never hand the user a URL that we haven't actually verified responds."""
    proj = DB['projects'].get(pid)
    if not proj:
        return jsonify({"error": "not found"}), 404
    u = current_user()
    if u['role'] == 'user' and proj['owner'] != u['username']:
        return jsonify({"error": "forbidden"}), 403
    proc = PROCESSES.get(pid, {})
    if proc.get('status') != 'running':
        return jsonify({"reachable": False, "reason": "stopped"})
    ok, code = _probe_project(proj['port'], timeout=4)
    return jsonify({"reachable": ok, "status_code": code})

# ─── ENVIRONMENT VARIABLES / SECRETS — editable after deploy, no full
# redeploy needed, matching the "secrets panel" pattern from Railway ───
@app.route('/api/projects/<pid>/env', methods=['GET'])
@login_required
def api_get_env(pid):
    proj, err = _fm_authorize(pid)
    if err: return err
    return jsonify({"env": proj.get('env', '')})

@app.route('/api/projects/<pid>/env', methods=['POST'])
@login_required
def api_set_env(pid):
    proj, err = _fm_authorize(pid)
    if err: return err
    body = request.json or {}
    env_vars = body.get('env', '')
    proj['env'] = env_vars
    save_db(DB)
    try:
        with open(os.path.join(proj['dir'], '.env'), 'w') as f:
            f.write(env_vars)
    except OSError:
        pass
    PROCESSES.setdefault(pid, {}).setdefault('log', []).append(f"[{now()}] 🔐 تم تحديث Environment Variables")
    if body.get('restart', True) and PROCESSES.get(pid, {}).get('status') == 'running':
        kill_process(pid)
        start_process(pid, proj['dir'], proj['port'], proj['type'], proj.get('main_file'),
                      env_vars, proj.get('start_cmd'), proj.get('framework'))
    return jsonify({"ok": True})

@app.route('/api/projects/<pid>/start', methods=['POST'])
@login_required
def api_start(pid):
    proj = DB['projects'].get(pid)
    if not proj: return jsonify({"error":"not found"}),404
    u = current_user()
    if u['role']=='user' and proj['owner']!=u['username']:
        return jsonify({"error":"forbidden"}),403
    proj['desired_state'] = 'running'
    save_db(DB)
    if pid not in PROCESSES:
        PROCESSES[pid] = {"status":"queued","port":proj['port'],"log":[],"error":None,"desired":"running","started_at":None}
    info = PROCESSES[pid]
    p = info.get('proc')
    if p is not None and p.poll() is None:
        return jsonify({"ok":True})  # already running
    # (re)install deps if needed and launch — cheap if venv/node_modules already exist
    info['status'] = 'queued'
    info['desired'] = 'running'
    info.setdefault('log', []).append(f"[{now()}] 🔄 جاري التشغيل...")
    t = threading.Thread(target=build_and_run, args=(pid, proj['dir'], proj['port'], proj['type'], proj.get('main_file','main.py'), proj.get('env',''), proj.get('start_cmd'), proj.get('framework')), daemon=True)
    t.start()
    return jsonify({"ok":True,"starting":True})

@app.route('/api/projects/<pid>/stop', methods=['POST'])
@login_required
def api_stop(pid):
    proj = DB['projects'].get(pid)
    if not proj: return jsonify({"error":"not found"}),404
    proj['desired_state'] = 'stopped'
    save_db(DB)
    if pid in PROCESSES:
        PROCESSES[pid]['desired'] = 'stopped'
        kill_process(pid)
        PROCESSES[pid]['status']='stopped'
        PROCESSES[pid]['log'].append(f"[{now()}] ⏹️  تم الإيقاف")
    return jsonify({"ok":True})

@app.route('/api/projects/<pid>/restart', methods=['POST'])
@login_required
def api_restart(pid):
    api_stop(pid)
    time.sleep(1)
    return api_start(pid)

@app.route('/api/projects/<pid>/exec', methods=['POST'])
@login_required
def api_exec(pid):
    """Run a command inside the project's running container (e.g. pip install X, npm install X)."""
    proj = DB['projects'].get(pid)
    if not proj:
        return jsonify({"error": "not found"}), 404
    u = current_user()
    if u['role'] == 'user' and proj['owner'] != u['username']:
        return jsonify({"error": "forbidden"}), 403

    cmd = (request.json or {}).get('cmd', '').strip()
    if not cmd:
        return jsonify({"error": "أدخل أمر"}), 400

    danger, why = is_dangerous_command(cmd)
    if danger:
        return jsonify({"error": f"🚫 هذا الأمر محظور: {why}"}), 403

    # NOTE: there's no container here — this runs directly on the host, scoped
    # to the project's own folder (and Python venv, if any) via cwd, but the
    # shell itself is NOT sandboxed (no filesystem/network isolation).
    proj_dir = proj.get('dir')
    env = build_env(proj_dir, proj['type'], proj['port'], proj.get('env', ''))
    try:
        r = subprocess.run(
            ["/bin/sh", "-c", cmd],
            cwd=proj_dir, env=env, capture_output=True, text=True, timeout=180,
        )
        output = (r.stdout or '') + (r.stderr or '')
        PROCESSES.get(pid, {}).setdefault('log', []).append(f"[{now()}] 💻 $ {cmd}")
        return jsonify({"ok": True, "exit_code": r.returncode, "output": output[-8000:]})
    except subprocess.TimeoutExpired:
        return jsonify({"error": "انتهت المهلة (180 ثانية) — الأمر طويل جداً"}), 408

@app.route('/api/projects/<pid>/install', methods=['POST'])
@login_required
def api_install(pid):
    """One-click 'مكتبة ناقصة؟' fix — installs a package with the right tool for the
    project type (pip for python venv, npm for node) and optionally restarts the project."""
    proj = DB['projects'].get(pid)
    if not proj:
        return jsonify({"error": "not found"}), 404
    u = current_user()
    if u['role'] == 'user' and proj['owner'] != u['username']:
        return jsonify({"error": "forbidden"}), 403

    body = request.json or {}
    package = (body.get('package') or '').strip()
    if not package or not re.match(r'^[\w\-.@/]+$', package):
        return jsonify({"error": "اسم مكتبة غير صالح"}), 400

    ok, out = install_package_for_project(pid, proj, package)
    if ok and body.get('restart', True):
        api_stop(pid)
        time.sleep(0.5)
        api_start(pid)
    return jsonify({"ok": ok, "output": out})

@app.route('/api/projects/<pid>/logs')
@login_required
def api_logs(pid):
    proj = DB['projects'].get(pid)
    if not proj:
        return jsonify({"error": "not found"}), 404
    u = current_user()
    if u['role'] == 'user' and proj['owner'] != u['username']:
        return jsonify({"error": "forbidden"}), 403
    proc = PROCESSES.get(pid,{})
    proc_log = []
    log_path = proc.get('log_file') or os.path.join(proj.get('dir',''), 'run.log')
    try:
        with open(log_path, 'r', errors='replace') as f:
            proc_log = f.readlines()[-50:]
    except FileNotFoundError:
        pass
    return jsonify({"log": proc.get('log',[]), "docker_log": [l.rstrip('\n') for l in proc_log]})

# ─── PER-PROJECT FILE MANAGER — browse/edit files inside a project's own
# folder from the dashboard, without needing SSH/terminal access ───
_FM_HIDDEN_DIRS = {'venv', 'node_modules', '__pycache__', '.git'}
_FM_MAX_EDIT_BYTES = 300 * 1024  # 300KB — bigger files are for download/terminal, not the inline editor
_FM_BINARY_EXTS = {'.pyc', '.so', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.pdf', '.zip', '.db', '.sqlite3'}

def _fm_resolve(proj_dir, rel_path):
    """Resolve a user-supplied relative path against proj_dir, refusing anything
    that would escape it (path traversal / symlink escape protection)."""
    base = os.path.realpath(proj_dir)
    target = os.path.realpath(os.path.join(base, rel_path or ''))
    if target != base and not target.startswith(base + os.sep):
        return None
    return target

def _fm_authorize(pid):
    proj = DB['projects'].get(pid)
    if not proj:
        return None, (jsonify({"error": "not found"}), 404)
    u = current_user()
    if u['role'] == 'user' and proj['owner'] != u['username']:
        return None, (jsonify({"error": "forbidden"}), 403)
    return proj, None

@app.route('/api/projects/<pid>/fs/list')
@login_required
def api_fm_list(pid):
    proj, err = _fm_authorize(pid)
    if err: return err
    rel = request.args.get('path', '')
    target = _fm_resolve(proj['dir'], rel)
    if target is None or not os.path.isdir(target):
        return jsonify({"error": "مسار غير صالح"}), 400
    entries = []
    for name in sorted(os.listdir(target)):
        if name in _FM_HIDDEN_DIRS or name.startswith('.'):
            continue
        full = os.path.join(target, name)
        try:
            st = os.stat(full)
            entries.append({"name": name, "is_dir": os.path.isdir(full), "size": st.st_size})
        except OSError:
            continue
    return jsonify({"path": rel, "entries": entries})

@app.route('/api/projects/<pid>/fs/read')
@login_required
def api_fm_read(pid):
    proj, err = _fm_authorize(pid)
    if err: return err
    rel = request.args.get('path', '')
    target = _fm_resolve(proj['dir'], rel)
    if target is None or not os.path.isfile(target):
        return jsonify({"error": "ملف غير موجود"}), 404
    if os.path.splitext(target)[1].lower() in _FM_BINARY_EXTS:
        return jsonify({"error": "ملف ثنائي — لا يمكن تحريره هنا"}), 400
    size = os.path.getsize(target)
    if size > _FM_MAX_EDIT_BYTES:
        return jsonify({"error": f"الملف كبير جداً للتحرير ({size//1024} KB) — استخدم التيرمنل"}), 400
    try:
        with open(target, 'r', errors='replace') as f:
            content = f.read()
    except OSError as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"path": rel, "content": content, "size": size})

@app.route('/api/projects/<pid>/fs/write', methods=['POST'])
@login_required
def api_fm_write(pid):
    proj, err = _fm_authorize(pid)
    if err: return err
    body = request.json or {}
    rel = body.get('path', '')
    content = body.get('content', '')
    if len(content.encode('utf-8', errors='ignore')) > _FM_MAX_EDIT_BYTES:
        return jsonify({"error": "المحتوى كبير جداً"}), 400
    target = _fm_resolve(proj['dir'], rel)
    if target is None:
        return jsonify({"error": "مسار غير صالح"}), 400
    if os.path.isdir(target):
        return jsonify({"error": "هذا مجلد وليس ملف"}), 400
    try:
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, 'w') as f:
            f.write(content)
    except OSError as e:
        return jsonify({"error": str(e)}), 500
    PROCESSES.setdefault(pid, {}).setdefault('log', []).append(f"[{now()}] 📝 تم تعديل {rel}")
    return jsonify({"ok": True})

@app.route('/api/projects/<pid>', methods=['DELETE'])
@login_required
def api_delete_project(pid):
    proj = DB['projects'].get(pid)
    if not proj: return jsonify({"error":"not found"}),404
    u = current_user()
    if u['role']=='user' and proj['owner']!=u['username']:
        return jsonify({"error":"forbidden"}),403
    kill_process(pid)
    try: shutil.rmtree(proj.get('dir',''))
    except: pass
    PROCESSES.pop(pid,None)
    # remove files from user
    owner = get_user(proj['owner'])
    if owner:
        owner['files'] = [f for f in owner.get('files',[]) if f.get('project')!=pid]
    del DB['projects'][pid]
    save_db(DB)
    return jsonify({"ok":True})

# ─── USERS MANAGEMENT ────────────────────────────────
@app.route('/api/users', methods=['GET'])
@login_required
@role_required('dev','admin')
def api_users():
    u = current_user()
    users = []
    for usr in DB['users']:
        if u['role']=='admin' and usr['role']=='dev': continue
        exp = datetime.fromtimestamp(usr['created_at']) + timedelta(days=usr['days'])
        users.append({
            "username": usr['username'],
            "role": usr['role'],
            "file_limit": usr['file_limit'],
            "files_used": len(usr.get('files',[])),
            "days": usr['days'],
            "expires": exp.strftime('%Y-%m-%d'),
            "expired": datetime.now() > exp and usr['role']!='dev',
        })
    return jsonify({"users":users})

@app.route('/api/users', methods=['POST'])
@login_required
@role_required('dev','admin')
def api_create_user():
    u = current_user()
    data = request.json or {}
    username = data.get('username','').strip()
    password = data.get('password','') or gen_password()
    role = data.get('role','user')
    file_limit = int(data.get('file_limit',15))
    days = int(data.get('days',30))

    if not username:
        return jsonify({"error":"أدخل اسم المستخدم"}),400
    if get_user(username):
        return jsonify({"error":"اسم المستخدم موجود مسبقاً"}),400
    if u['role']=='admin' and role in ('dev',):
        role='user'
    if u['role']=='admin':
        file_limit = min(file_limit, 50)

    new_user = {"username":username,"password":hashpw(password),"role":role,"file_limit":file_limit,"days":days,"created_at":time.time(),"files":[]}
    DB['users'].append(new_user)
    save_db(DB)
    return jsonify({"ok":True,"username":username,"password":password,"role":role})

@app.route('/api/users/<username>', methods=['DELETE'])
@login_required
@role_required('dev','admin')
def api_delete_user(username):
    u = current_user()
    target = get_user(username)
    if not target: return jsonify({"error":"المستخدم غير موجود"}),404
    if username == u['username']: return jsonify({"error":"لا يمكنك حذف نفسك"}),400
    if u['role']=='admin' and target['role'] in ('dev','admin'): return jsonify({"error":"لا صلاحية"}),403
    DB['users'] = [x for x in DB['users'] if x['username']!=username]
    save_db(DB)
    return jsonify({"ok":True})

@app.route('/api/users/<username>/password', methods=['PUT'])
@login_required
@role_required('dev','admin')
def api_reset_password(username):
    target = get_user(username)
    if not target: return jsonify({"error":"غير موجود"}),404
    new_pw = gen_password()
    target['password'] = hashpw(new_pw)
    save_db(DB)
    return jsonify({"ok":True,"password":new_pw})

# ─── SYSTEM STATS ────────────────────────────────────
@app.route('/api/stats')
@login_required
def api_stats():
    # CPU / RAM via /proc
    try:
        with open('/proc/loadavg') as f: load = f.read().split()[0]
        with open('/proc/meminfo') as f:
            mem = {}
            for line in f:
                parts=line.split()
                if len(parts)>=2: mem[parts[0].rstrip(':')]=int(parts[1])
        total=mem.get('MemTotal',1); avail=mem.get('MemAvailable',0)
        ram_pct=round((1-avail/total)*100,1)
    except:
        load='0'; ram_pct=0
    # disk
    try:
        disk=shutil.disk_usage('/')
        disk_pct=round(disk.used/disk.total*100,1)
        disk_free=round(disk.free/1e9,1)
        disk_total=round(disk.total/1e9,1)
    except:
        disk_pct=0; disk_free=0; disk_total=0
    # live hosted processes (native, no Docker)
    containers=sum(1 for p in PROCESSES.values() if p.get('proc') is not None and p.get('proc').poll() is None)
    u=current_user()
    running = sum(1 for pid,p in PROCESSES.items() if p.get('status')=='running')
    errors  = sum(1 for pid,p in PROCESSES.items() if p.get('status')=='error')
    return jsonify({"load":load,"ram":ram_pct,"disk":disk_pct,"disk_free":disk_free,"disk_total":disk_total,"containers":containers,"running":running,"errors":errors,"users":len(DB['users']),"projects":len(DB['projects'])})

# ─── SETTINGS ────────────────────────────────────────
@app.route('/api/me/password', methods=['PUT'])
@login_required
def api_change_password():
    u = current_user()
    data = request.json or {}
    if u['password'] != hashpw(data.get('current','')):
        return jsonify({"error":"كلمة المرور الحالية خاطئة"}),400
    new = data.get('new','')
    if len(new)<6: return jsonify({"error":"كلمة المرور قصيرة جداً (6 أحرف على الأقل)"}),400
    u['password']=hashpw(new)
    save_db(DB)
    return jsonify({"ok":True})

resume_projects_on_boot()

if __name__=='__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
