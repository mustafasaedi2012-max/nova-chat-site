import os, sqlite3, re
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_socketio import SocketIO, emit, join_room
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, 'nova.db')
UPLOAD_DIR = os.path.join(BASE_DIR, 'static', 'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('NOVA_SECRET_KEY', 'change-this-secret-before-public-deployment')
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024
socketio = SocketIO(app, cors_allowed_origins=None, async_mode='threading')


def db():
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    con.execute('PRAGMA foreign_keys = ON')
    return con


def init_db():
    with db() as con:
        con.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            avatar_color TEXT NOT NULL DEFAULT '#70d8ff',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_messages_created ON messages(id DESC);
        ''')


def current_user():
    uid = session.get('user_id')
    if not uid:
        return None
    with db() as con:
        row = con.execute('SELECT id, username, avatar_color FROM users WHERE id=?', (uid,)).fetchone()
        return dict(row) if row else None


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user():
            return redirect(url_for('login'))
        return fn(*args, **kwargs)
    return wrapper


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.after_request
def security_headers(response):
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-Frame-Options', 'SAMEORIGIN')
    response.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
    response.headers.setdefault('Permissions-Policy', 'camera=(), microphone=()')
    return response


@app.route('/')
def index():
    user = current_user()
    if not user:
        return redirect(url_for('login'))
    with db() as con:
        messages = con.execute('''SELECT m.id, m.body, m.created_at, u.id AS user_id, u.username, u.avatar_color
                                  FROM messages m JOIN users u ON u.id=m.user_id
                                  ORDER BY m.id DESC LIMIT 80''').fetchall()
        users = con.execute('SELECT id, username, avatar_color FROM users ORDER BY username COLLATE NOCASE LIMIT 100').fetchall()
    return render_template('index.html', user=user, messages=list(reversed(messages)), users=users)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user():
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not re.fullmatch(r'[A-Za-z0-9_]{3,20}', username):
            flash('نام کاربری باید ۳ تا ۲۰ نویسه و فقط شامل حروف انگلیسی، عدد یا _ باشد.', 'error')
        elif len(password) < 8:
            flash('رمز عبور باید حداقل ۸ نویسه باشد.', 'error')
        else:
            color = ['#70d8ff', '#9b8cff', '#62e6c4', '#ffb86b', '#ff82b2'][sum(map(ord, username)) % 5]
            try:
                with db() as con:
                    cur = con.execute('INSERT INTO users(username,password_hash,avatar_color,created_at) VALUES(?,?,?,?)',
                                      (username, generate_password_hash(password), color, datetime.now().isoformat(timespec='seconds')))
                    session.clear(); session['user_id'] = cur.lastrowid
                flash('حسابت ساخته شد؛ به نوا چت خوش اومدی!', 'success')
                return redirect(url_for('index'))
            except sqlite3.IntegrityError:
                flash('این نام کاربری قبلاً گرفته شده است.', 'error')
    return render_template('auth.html', mode='register')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user():
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        with db() as con:
            user = con.execute('SELECT id, password_hash FROM users WHERE username=? COLLATE NOCASE', (username,)).fetchone()
        if user and check_password_hash(user['password_hash'], password):
            session.clear(); session['user_id'] = user['id']
            return redirect(url_for('index'))
        flash('نام کاربری یا رمز عبور درست نیست.', 'error')
    return render_template('auth.html', mode='login')


@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/api/messages')
@login_required
def api_messages():
    after = request.args.get('after', '0', type=int)
    with db() as con:
        rows = con.execute('''SELECT m.id,m.body,m.created_at,u.id AS user_id,u.username,u.avatar_color
                              FROM messages m JOIN users u ON u.id=m.user_id WHERE m.id>? ORDER BY m.id ASC LIMIT 100''', (after,)).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route('/api/avatar', methods=['POST'])
@login_required
def upload_avatar():
    user = current_user()
    file = request.files.get('avatar')
    if not file or not file.filename or not allowed_file(file.filename):
        flash('یک تصویر PNG، JPG، GIF یا WEBP انتخاب کن.', 'error')
        return redirect(url_for('index'))
    # Keep uploads simple and safe: random-ish user-specific filename, extension allowlist.
    ext = secure_filename(file.filename).rsplit('.', 1)[1].lower()
    filename = f'user_{user["id"]}.{ext}'
    file.save(os.path.join(UPLOAD_DIR, filename))
    flash('تصویر دریافت شد. در نسخهٔ پایه آواتار رنگی همچنان نمایش داده می‌شود؛ برای فعال‌سازی ذخیرهٔ مسیر تصویر می‌توان توسعه داد.', 'success')
    return redirect(url_for('index'))


@socketio.on('connect')
def socket_connect(auth=None):
    user = current_user()
    if not user:
        return False
    join_room('public')
    emit('system_message', {'text': f'{user["username"]} به نوا چت وصل شد.'}, to='public', include_self=False)


@socketio.on('send_message')
def handle_send_message(payload):
    user = current_user()
    if not user:
        emit('error_message', {'text': 'برای ارسال پیام باید وارد حساب شوی.'})
        return
    if not isinstance(payload, dict):
        return
    body = str(payload.get('body', '')).strip()
    if not body:
        return
    body = body[:1200]
    created = datetime.now().strftime('%H:%M')
    with db() as con:
        cur = con.execute('INSERT INTO messages(user_id,body,created_at) VALUES(?,?,?)',
                           (user['id'], body, datetime.now().isoformat(timespec='seconds')))
        message_id = cur.lastrowid
    socketio.emit('new_message', {
        'id': message_id, 'user_id': user['id'], 'username': user['username'],
        'avatar_color': user['avatar_color'], 'body': body, 'time': created
    }, to='public')


@socketio.on('typing')
def handle_typing(_payload=None):
    user = current_user()
    if user:
        emit('typing', {'username': user['username']}, to='public', include_self=False)


@app.errorhandler(413)
def too_large(_error):
    flash('حجم فایل باید کمتر از ۵ مگابایت باشد.', 'error')
    return redirect(url_for('index'))


init_db()

if __name__ == '__main__':
    # Local network access: use the computer's LAN IP from other devices on the same Wi-Fi.
    socketio.run(app, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False, allow_unsafe_werkzeug=True)
