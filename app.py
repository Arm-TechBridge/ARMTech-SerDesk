# app.py
import os
import re
import smtplib
import datetime
import json
import tempfile
from email.message import EmailMessage
from functools import wraps
from urllib.parse import urljoin

from flask import (
    Flask, request, redirect, url_for, render_template_string,
    flash, session, abort, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

# Google Generative AI client
try:
    import google.generativeai as genai
except Exception:
    genai = None

# --- Configuration from environment ---
SECRET_KEY = os.environ.get("SECRET_KEY", os.urandom(24).hex())
DATABASE_URL = os.environ.get("DATABASE_URL")  # Supabase Postgres connection string
GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY")
GOOGLE_APPLICATION_CREDENTIALS_JSON = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS_JSON")
SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASS = os.environ.get("SMTP_PASS")
APP_BASE_URL = os.environ.get("APP_BASE_URL", "https://your-render-app.onrender.com")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable is required (Supabase Postgres).")

# Configure Google generative AI client
if genai:
    if GOOGLE_API_KEY:
        genai.configure(api_key=GOOGLE_API_KEY)
    elif GOOGLE_APPLICATION_CREDENTIALS_JSON:
        try:
            creds = json.loads(GOOGLE_APPLICATION_CREDENTIALS_JSON)
            tf = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
            tf.write(json.dumps(creds).encode("utf-8"))
            tf.flush()
            os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = tf.name
            # genai will use ADC (Application Default Credentials)
        except Exception:
            # If JSON is invalid, leave unconfigured and log later
            pass

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
ts = URLSafeTimedSerializer(app.config["SECRET_KEY"])

# --- Models ---
class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(320), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    name = db.Column(db.String(120))
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def check_password(self, pw):
        return check_password_hash(self.password_hash, pw)

class Invite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(320), nullable=False)
    token = db.Column(db.String(512), unique=True, nullable=False)
    invited_by = db.Column(db.Integer, db.ForeignKey("user.id"))
    accepted = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(300), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.String(50), default="open")
    priority = db.Column(db.String(20), default="normal")
    created_by = db.Column(db.Integer, db.ForeignKey("user.id"))
    assigned_to = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(300))
    content = db.Column(db.Text)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

class CalendarEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(300))
    description = db.Column(db.Text)
    start = db.Column(db.DateTime, nullable=False)
    end = db.Column(db.DateTime, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# Create tables on startup
with app.app_context():
    db.create_all()

# --- Utilities ---
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        uid = session.get("user_id")
        if not uid:
            return redirect(url_for("login"))
        user = User.query.get(uid)
        if not user or not user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated

def send_email(to_email, subject, body):
    if not SMTP_HOST or not SMTP_USER or not SMTP_PASS:
        app.logger.warning("SMTP not configured; skipping email send.")
        return False
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = SMTP_USER
    msg["To"] = to_email
    msg.set_content(body)
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
            s.starttls()
            s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
        return True
    except Exception as e:
        app.logger.exception("Failed to send email: %s", e)
        return False

def generate_invite_token(email, inviter_id):
    token = ts.dumps({"email": email, "inviter": inviter_id})
    return token

def verify_invite_token(token, max_age=60*60*24*7):
    try:
        data = ts.loads(token, max_age=max_age)
        return data
    except SignatureExpired:
        return None
    except BadSignature:
        return None

def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    return User.query.get(uid)

# --- Base HTML with Tailwind (embedded) ---
BASE_HTML = """
<!doctype html>
<html lang="en" class="h-full" data-theme="light">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>ITSM - Minimal</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    .dark-mode { background-color: #0b1220; color: #e6eef8; }
    .light-mode { background-color: #f8fafc; color: #0b1220; }
  </style>
</head>
<body class="min-h-screen antialiased" id="body">
<nav class="bg-gray-800 text-white p-4">
  <div class="container mx-auto flex justify-between items-center">
    <div class="flex items-center space-x-4">
      <a href="{{ url_for('index') }}" class="font-bold">ITSM</a>
      {% if user %}
        <a href="{{ url_for('dashboard') }}" class="text-sm">Dashboard</a>
        <a href="{{ url_for('tickets') }}" class="text-sm">Tickets</a>
        <a href="{{ url_for('notes') }}" class="text-sm">Notes</a>
        <a href="{{ url_for('calendar_view') }}" class="text-sm">Calendar</a>
      {% endif %}
    </div>
    <div class="flex items-center space-x-4">
      <button id="theme-toggle" class="px-3 py-1 bg-gray-700 rounded">Toggle</button>
      {% if user %}
        {% if user.is_admin %}
          <a href="{{ url_for('admin_panel') }}" class="text-sm">Admin</a>
        {% endif %}
        <span class="text-sm">{{ user.email }}</span>
        <a href="{{ url_for('logout') }}" class="text-sm">Logout</a>
      {% else %}
        <a href="{{ url_for('login') }}" class="text-sm">Login</a>
        <a href="{{ url_for('signup') }}" class="text-sm">Sign up</a>
      {% endif %}
    </div>
  </div>
</nav>
<main class="container mx-auto p-6">
  {% with messages = get_flashed_messages() %}
    {% if messages %}
      <div class="space-y-2">
      {% for m in messages %}
        <div class="p-3 bg-yellow-100 text-yellow-900 rounded">{{ m }}</div>
      {% endfor %}
      </div>
    {% endif %}
  {% endwith %}
  {{ content|safe }}
</main>
<script>
  const body = document.getElementById('body');
  const toggle = document.getElementById('theme-toggle');
  function applyTheme(t){
    if(t === 'dark'){
      document.documentElement.classList.add('dark');
      body.classList.add('dark-mode');
      body.classList.remove('light-mode');
    } else {
      document.documentElement.classList.remove('dark');
      body.classList.remove('dark-mode');
      body.classList.add('light-mode');
    }
  }
  const saved = localStorage.getItem('theme') || 'light';
  applyTheme(saved);
  toggle && toggle.addEventListener('click', ()=>{
    const cur = localStorage.getItem('theme') || 'light';
    const next = cur === 'light' ? 'dark' : 'light';
    localStorage.setItem('theme', next);
    applyTheme(next);
  });
</script>
</body>
</html>
"""

def render_page(content, **context):
    user = current_user()
    return render_template_string(BASE_HTML, content=content, user=user, **context)

# --- Routes ---
@app.route("/")
def index():
    content = """
    <div class="prose">
      <h1>Welcome to ITSM</h1>
      <p>Simple production-ready ITSM app built with Flask, Tailwind, Supabase Postgres, and Google Generative AI integration.</p>
      {% if not user %}
      <p><a class="text-blue-600" href="{{ url_for('signup') }}">Create an account</a> or <a class="text-blue-600" href="{{ url_for('login') }}">log in</a>.</p>
      {% else %}
      <p><a class="text-blue-600" href="{{ url_for('dashboard') }}">Go to dashboard</a>.</p>
      {% endif %}
    </div>
    """
    return render_page(content)

# --- Auth ---
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        name = request.form.get("name", "").strip()
        password = request.form.get("password", "")
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash("Invalid email")
            return redirect(url_for("signup"))
        if User.query.filter_by(email=email).first():
            flash("Email already registered")
            return redirect(url_for("signup"))
        pw_hash = generate_password_hash(password)
        user = User(email=email, name=name, password_hash=pw_hash)
        db.session.add(user)
        db.session.commit()
        session["user_id"] = user.id
        flash("Account created")
        return redirect(url_for("dashboard"))
    content = """
    <h2>Sign up</h2>
    <form method="post" class="space-y-3 max-w-md">
      <input name="name" placeholder="Full name" class="w-full p-2 border rounded" />
      <input name="email" placeholder="Email" class="w-full p-2 border rounded" required />
      <input name="password" placeholder="Password" type="password" class="w-full p-2 border rounded" required />
      <button class="px-4 py-2 bg-blue-600 text-white rounded">Sign up</button>
    </form>
    """
    return render_page(content)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()
        if not user or not user.check_password(password):
            flash("Invalid credentials")
            return redirect(url_for("login"))
        session["user_id"] = user.id
        flash("Logged in")
        return redirect(url_for("dashboard"))
    content = """
    <h2>Login</h2>
    <form method="post" class="space-y-3 max-w-md">
      <input name="email" placeholder="Email" class="w-full p-2 border rounded" required />
      <input name="password" placeholder="Password" type="password" class="w-full p-2 border rounded" required />
      <button class="px-4 py-2 bg-green-600 text-white rounded">Login</button>
    </form>
    """
    return render_page(content)

@app.route("/logout")
def logout():
    session.pop("user_id", None)
    flash("Logged out")
    return redirect(url_for("index"))

# --- Dashboard ---
@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    tickets_open = Ticket.query.filter_by(status="open").count()
    my_tickets = Ticket.query.filter((Ticket.created_by==user.id)|(Ticket.assigned_to==user.id)).count()
    notes_count = Note.query.filter_by(owner_id=user.id).count()
    events_count = CalendarEvent.query.filter_by(owner_id=user.id).count()
    content = f"""
    <h2>Dashboard</h2>
    <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
      <div class="p-4 bg-white rounded shadow">Open tickets: <strong>{tickets_open}</strong></div>
      <div class="p-4 bg-white rounded shadow">My tickets: <strong>{my_tickets}</strong></div>
      <div class="p-4 bg-white rounded shadow">Notes: <strong>{notes_count}</strong></div>
      <div class="p-4 bg-white rounded shadow">Events: <strong>{events_count}</strong></div>
    </div>
    <div class="mt-6">
      <h3>Quick actions</h3>
      <a class="inline-block mt-2 px-3 py-2 bg-blue-600 text-white rounded" href="{{ url_for('create_ticket') }}">Create Ticket</a>
      <a class="inline-block mt-2 ml-2 px-3 py-2 bg-gray-600 text-white rounded" href="{{ url_for('tickets') }}">View Tickets</a>
    </div>
    """
    return render_page(content)

# --- Admin Panel & Invite ---
@app.route("/admin")
@admin_required
def admin_panel():
    invites = Invite.query.order_by(Invite.created_at.desc()).limit(50).all()
    users = User.query.order_by(User.created_at.desc()).limit(50).all()
    content = """
    <h2>Admin Panel</h2>
    <div class="grid md:grid-cols-2 gap-6">
      <div>
        <h3>Invite user</h3>
        <form method="post" action="{{ url_for('invite_user') }}" class="space-y-2">
          <input name="email" placeholder="Email to invite" class="w-full p-2 border rounded" required />
          <label class="flex items-center space-x-2"><input type="checkbox" name="is_admin" /> <span>Grant admin</span></label>
          <button class="px-3 py-2 bg-blue-600 text-white rounded">Send Invite</button>
        </form>
        <h4 class="mt-4">Recent invites</h4>
        <ul>
        {% for inv in invites %}
          <li class="py-1">{{ inv.email }} - {{ 'Accepted' if inv.accepted else 'Pending' }}</li>
        {% endfor %}
        </ul>
      </div>
      <div>
        <h3>Users</h3>
        <ul>
        {% for u in users %}
          <li class="py-1">{{ u.email }} - {{ 'Admin' if u.is_admin else 'User' }}</li>
        {% endfor %}
        </ul>
      </div>
    </div>
    """
    return render_page(content, invites=invites, users=users)

@app.route("/admin/invite", methods=["POST"])
@admin_required
def invite_user():
    email = request.form.get("email", "").strip().lower()
    is_admin = bool(request.form.get("is_admin"))
    inviter = current_user()
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        flash("Invalid email")
        return redirect(url_for("admin_panel"))
    token = generate_invite_token(email, inviter.id)
    invite = Invite(email=email, token=token, invited_by=inviter.id)
    db.session.add(invite)
    db.session.commit()
    accept_url = urljoin(APP_BASE_URL, url_for("accept_invite", token=token))
    body = f"You have been invited to join ITSM. Click to accept: {accept_url}\n\nThis link expires in 7 days."
    send_email(email, "You're invited to ITSM", body)
    flash("Invite created (email sent if SMTP configured)")
    return redirect(url_for("admin_panel"))

@app.route("/accept-invite/<token>", methods=["GET", "POST"])
def accept_invite(token):
    data = verify_invite_token(token)
    if not data:
        flash("Invalid or expired invite token")
        return redirect(url_for("index"))
    invite = Invite.query.filter_by(token=token).first()
    if not invite or invite.accepted:
        flash("Invite not found or already accepted")
        return redirect(url_for("index"))
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        password = request.form.get("password", "")
        email = data.get("email")
        if User.query.filter_by(email=email).first():
            flash("Account already exists for this email")
            return redirect(url_for("login"))
        pw_hash = generate_password_hash(password)
        user = User(email=email, name=name, password_hash=pw_hash)
        db.session.add(user)
        invite.accepted = True
        db.session.commit()
        session["user_id"] = user.id
        flash("Account created from invite")
        return redirect(url_for("dashboard"))
    content = f"""
    <h2>Accept Invite</h2>
    <p>Creating account for <strong>{data.get('email')}</strong></p>
    <form method="post" class="space-y-3 max-w-md">
      <input name="name" placeholder="Full name" class="w-full p-2 border rounded" />
      <input name="password" placeholder="Password" type="password" class="w-full p-2 border rounded" required />
      <button class="px-4 py-2 bg-blue-600 text-white rounded">Create account</button>
    </form>
    """
    return render_page(content)

# --- Tickets ---
@app.route("/tickets")
@login_required
def tickets():
    q = request.args.get("q", "").strip()
    page = int(request.args.get("page", 1))
    per = 20
    base = Ticket.query.order_by(Ticket.created_at.desc())
    if q:
        base = base.filter((Ticket.title.ilike(f"%{q}%")) | (Ticket.description.ilike(f"%{q}%")))
    items = base.limit(per).offset((page-1)*per).all()
    content = """
    <div class="flex justify-between items-center">
      <h2>Tickets</h2>
      <a class="px-3 py-2 bg-blue-600 text-white rounded" href="{{ url_for('create_ticket') }}">New Ticket</a>
    </div>
    <form method="get" class="mt-3">
      <input name="q" placeholder="Search tickets" value="{{ request.args.get('q','') }}" class="p-2 border rounded w-1/2" />
      <button class="px-3 py-1 bg-gray-600 text-white rounded">Search</button>
      <a href="{{ url_for('ai_search') }}" class="ml-2 text-sm text-blue-600">AI Search</a>
    </form>
    <ul class="mt-4 space-y-3">
    {% for t in items %}
      <li class="p-3 bg-white rounded shadow">
        <a class="font-semibold" href="{{ url_for('view_ticket', ticket_id=t.id) }}">{{ t.title }}</a>
        <div class="text-sm text-gray-600">Status: {{ t.status }} | Priority: {{ t.priority }}</div>
      </li>
    {% endfor %}
    </ul>
    """
    return render_page(content, items=items)

@app.route("/tickets/create", methods=["GET", "POST"])
@login_required
def create_ticket():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        desc = request.form.get("description", "").strip()
        priority = request.form.get("priority", "normal")
        user = current_user()
        t = Ticket(title=title, description=desc, priority=priority, created_by=user.id)
        db.session.add(t)
        db.session.commit()
        admins = User.query.filter_by(is_admin=True).all()
        for a in admins:
            send_email(a.email, f"New ticket: {title}", f"A new ticket was created by {user.email}.\n\n{desc}")
        flash("Ticket created")
        return redirect(url_for("tickets"))
    content = """
    <h2>Create Ticket</h2>
    <form method="post" class="space-y-3 max-w-2xl">
      <input name="title" placeholder="Title" class="w-full p-2 border rounded" required />
      <textarea name="description" placeholder="Description" class="w-full p-2 border rounded" rows="6"></textarea>
      <select name="priority" class="p-2 border rounded">
        <option value="low">Low</option>
        <option value="normal" selected>Normal</option>
        <option value="high">High</option>
      </select>
      <button class="px-4 py-2 bg-blue-600 text-white rounded">Create</button>
    </form>
    """
    return render_page(content)

@app.route("/tickets/<int:ticket_id>", methods=["GET", "POST"])
@login_required
def view_ticket(ticket_id):
    t = Ticket.query.get_or_404(ticket_id)
    if request.method == "POST":
        status = request.form.get("status")
        assigned = request.form.get("assigned_to")
        if status:
            t.status = status
        if assigned:
            try:
                t.assigned_to = int(assigned)
            except:
                t.assigned_to = None
        db.session.commit()
        flash("Ticket updated")
        return redirect(url_for("view_ticket", ticket_id=ticket_id))
    users = User.query.all()
    content = """
    <h2>{{ t.title }}</h2>
    <div class="text-sm text-gray-600">Created: {{ t.created_at }} | Status: {{ t.status }}</div>
    <p class="mt-3">{{ t.description }}</p>
    <form method="post" class="mt-4 space-y-2">
      <label>Status</label>
      <select name="status" class="p-2 border rounded">
        <option value="open" {% if t.status=='open' %}selected{% endif %}>Open</option>
        <option value="in_progress" {% if t.status=='in_progress' %}selected{% endif %}>In Progress</option>
        <option value="closed" {% if t.status=='closed' %}selected{% endif %}>Closed</option>
      </select>
      <label>Assign to</label>
      <select name="assigned_to" class="p-2 border rounded">
        <option value="">Unassigned</option>
        {% for u in users %}
          <option value="{{ u.id }}" {% if t.assigned_to==u.id %}selected{% endif %}>{{ u.email }}</option>
        {% endfor %}
      </select>
      <button class="px-3 py-2 bg-green-600 text-white rounded">Save</button>
    </form>
    """
    return render_page(content, t=t, users=users)

# --- Notes ---
@app.route("/notes")
@login_required
def notes():
    user = current_user()
    items = Note.query.filter_by(owner_id=user.id).order_by(Note.updated_at.desc()).all()
    content = """
    <div class="flex justify-between items-center">
      <h2>Notes</h2>
      <a class="px-3 py-2 bg-blue-600 text-white rounded" href="{{ url_for('create_note') }}">New Note</a>
    </div>
    <ul class="mt-4 space-y-3">
    {% for n in items %}
      <li class="p-3 bg-white rounded shadow">
        <a class="font-semibold" href="{{ url_for('view_note', note_id=n.id) }}">{{ n.title or '(untitled)' }}</a>
        <div class="text-sm text-gray-600">{{ n.updated_at }}</div>
      </li>
    {% endfor %}
    </ul>
    """
    return render_page(content, items=items)

@app.route("/notes/create", methods=["GET", "POST"])
@login_required
def create_note():
    if request.method == "POST":
        title = request.form.get("title", "")
        content = request.form.get("content", "")
        user = current_user()
        n = Note(title=title, content=content, owner_id=user.id)
        db.session.add(n)
        db.session.commit()
        flash("Note saved")
        return redirect(url_for("notes"))
    content = """
    <h2>New Note</h2>
    <form method="post" class="space-y-3">
      <input name="title" placeholder="Title" class="w-full p-2 border rounded" />
      <textarea name="content" placeholder="Content" class="w-full p-2 border rounded" rows="8"></textarea>
      <button class="px-3 py-2 bg-blue-600 text-white rounded">Save</button>
    </form>
    """
    return render_page(content)

@app.route("/notes/<int:note_id>", methods=["GET", "POST"])
@login_required
def view_note(note_id):
    n = Note.query.get_or_404(note_id)
    user = current_user()
    if n.owner_id != user.id:
        abort(403)
    if request.method == "POST":
        n.title = request.form.get("title", n.title)
        n.content = request.form.get("content", n.content)
        db.session.commit()
        flash("Note updated")
        return redirect(url_for("notes"))
    content = """
    <h2>Edit Note</h2>
    <form method="post" class="space-y-3">
      <input name="title" value="{{ n.title }}" class="w-full p-2 border rounded" />
      <textarea name="content" class="w-full p-2 border rounded" rows="8">{{ n.content }}</textarea>
      <button class="px-3 py-2 bg-green-600 text-white rounded">Save</button>
    </form>
    """
    return render_page(content, n=n)

# --- Calendar ---
@app.route("/calendar")
@login_required
def calendar_view():
    user = current_user()
    events = CalendarEvent.query.filter_by(owner_id=user.id).order_by(CalendarEvent.start.asc()).all()
    content = """
    <div class="flex justify-between items-center">
      <h2>Calendar</h2>
      <a class="px-3 py-2 bg-blue-600 text-white rounded" href="{{ url_for('create_event') }}">New Event</a>
    </div>
    <ul class="mt-4 space-y-3">
    {% for e in events %}
      <li class="p-3 bg-white rounded shadow">
        <div class="font-semibold">{{ e.title }}</div>
        <div class="text-sm text-gray-600">{{ e.start }} — {{ e.end }}</div>
        <div class="mt-2">{{ e.description }}</div>
      </li>
    {% endfor %}
    </ul>
    """
    return render_page(content, events=events)

@app.route("/calendar/create", methods=["GET", "POST"])
@login_required
def create_event():
    if request.method == "POST":
        title = request.form.get("title")
        desc = request.form.get("description")
        start = request.form.get("start")
        end = request.form.get("end")
        try:
            start_dt = datetime.datetime.fromisoformat(start)
            end_dt = datetime.datetime.fromisoformat(end)
        except Exception:
            flash("Invalid date format. Use ISO format: YYYY-MM-DDTHH:MM")
            return redirect(url_for("create_event"))
        user = current_user()
        ev = CalendarEvent(title=title, description=desc, start=start_dt, end=end_dt, owner_id=user.id)
        db.session.add(ev)
        db.session.commit()
        flash("Event created")
        return redirect(url_for("calendar_view"))
    content = """
    <h2>New Event</h2>
    <form method="post" class="space-y-3 max-w-2xl">
      <input name="title" placeholder="Title" class="w-full p-2 border rounded" required />
      <textarea name="description" placeholder="Description" class="w-full p-2 border rounded"></textarea>
      <label>Start (ISO) <input name="start" placeholder="2026-03-17T15:00" class="w-full p-2 border rounded" required /></label>
      <label>End (ISO) <input name="end" placeholder="2026-03-17T16:00" class="w-full p-2 border rounded" required /></label>
      <button class="px-3 py-2 bg-blue-600 text-white rounded">Create</button>
    </form>
    """
    return render_page(content)

# --- Google AI powered search ---
@app.route("/ai-search", methods=["GET", "POST"])
@login_required
def ai_search():
    result = None
    query = ""
    if request.method == "POST":
        query = request.form.get("query", "").strip()
        tickets = Ticket.query.filter((Ticket.title.ilike(f"%{query}%")) | (Ticket.description.ilike(f"%{query}%"))).limit(10).all()
        notes = Note.query.filter((Note.title.ilike(f"%{query}%")) | (Note.content.ilike(f"%{query}%"))).limit(10).all()
        snippets = []
        for t in tickets:
            snippets.append(f"TICKET: {t.title}\n{t.description}\nStatus: {t.status}\n")
        for n in notes:
            snippets.append(f"NOTE: {n.title}\n{(n.content or '')}\n")
        context_text = "\n\n".join(snippets) or "No direct matches found in tickets or notes."
        prompt = (
            "You are an ITSM assistant. The user asked: "
            f"\"{query}\". Here are relevant snippets from the system:\n\n{context_text}\n\n"
            "Provide a concise, actionable summary and suggested next steps (who to assign, priority, and a short reply to the user)."
        )
        try:
            if not genai:
                result = "Google Generative AI client not installed."
            elif not (GOOGLE_API_KEY or GOOGLE_APPLICATION_CREDENTIALS_JSON):
                result = "Google Generative AI not configured."
            else:
                # Use text-bison model
                model = "models/text-bison-001"
                resp = genai.generate_text(
                    model=model,
                    prompt=prompt,
                    temperature=0.2,
                    max_output_tokens=400
                )
                # Extract text safely
                if hasattr(resp, "text"):
                    result = resp.text
                elif isinstance(resp, dict) and "candidates" in resp and len(resp["candidates"])>0:
                    result = resp["candidates"][0].get("content", "")
                else:
                    result = str(resp)
        except Exception as e:
            app.logger.exception("Google Generative AI error")
            result = f"Google Generative AI error: {e}"
    content = """
    <h2>AI Search</h2>
    <form method="post" class="space-y-3 max-w-2xl">
      <input name="query" placeholder="Ask about tickets, notes, or incidents" value="{{ query }}" class="w-full p-2 border rounded" />
      <button class="px-3 py-2 bg-indigo-600 text-white rounded">Search with AI</button>
    </form>
    {% if result %}
      <div class="mt-4 p-4 bg-white rounded shadow">
        <h3>AI Result</h3>
        <pre class="whitespace-pre-wrap">{{ result }}</pre>
      </div>
    {% endif %}
    """
    return render_page(content, result=result, query=query)

# --- Simple API endpoint ---
@app.route("/api/tickets", methods=["GET"])
def api_tickets():
    items = Ticket.query.order_by(Ticket.created_at.desc()).limit(100).all()
    out = []
    for t in items:
        out.append({
            "id": t.id,
            "title": t.title,
            "description": t.description,
            "status": t.status,
            "priority": t.priority,
            "created_at": t.created_at.isoformat()
        })
    return jsonify(out)

# --- Error handlers ---
@app.errorhandler(403)
def forbidden(e):
    return render_page("<h2>Forbidden</h2><p>You do not have permission to access this resource.</p>"), 403

@app.errorhandler(404)
def not_found(e):
    return render_page("<h2>Not found</h2><p>The requested resource was not found.</p>"), 404

# --- Run ---
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=os.environ.get("FLASK_DEBUG","0")=="1")
