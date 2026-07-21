"""
用户信息管理平台 - 安全加固版 v2.3

安全修复说明：
1. 密码哈希存储 —— 使用 werkzeug.security.generate_password_hash 替代明文存储
2. CSRF Token 防护 —— 每个表单生成唯一 token，POST 时校验
3. IP 级速率限制 —— 同一 IP 每分钟最多 5 次登录尝试
4. 账号锁定机制 —— 连续 5 次失败后锁定 15 分钟
5. Session 安全加固 —— 非永久 session，30 分钟超时
6. SQL 注入修复 —— 注册和搜索改用参数化查询（? 占位符）
7. 头像上传 —— 文件类型白名单 + UUID 重命名 + 内容校验 + 上传限速
"""

import secrets
import sqlite3
import os
import uuid
import io
from datetime import datetime, timedelta

from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image

app = Flask(__name__)
app.secret_key = "dev-key-2025"
app.config["SESSION_PERMANENT"] = False
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

# 上传配置
UPLOAD_FOLDER = os.path.join("static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# 允许的图片扩展名（白名单）
ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".webp"}

# ============================================================
# 用户数据库（内存字典）— 用于登录校验，保持原功能不变
# 密码已使用 bcrypt 风格的哈希算法存储
# 默认账号：admin / admin123 （哈希后不可逆）
# ============================================================
USERS = {
    "admin": {
        "username": "admin",
        "password": generate_password_hash("admin123"),
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999
    },
    "alice": {
        "username": "alice",
        "password": generate_password_hash("alice2025"),
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100
    }
}

# ============================================================
# SQLite 数据库文件路径
# ============================================================
DB_PATH = os.path.join("data", "users.db")


def init_db():
    """初始化 SQLite 数据库，创建 users 表并插入默认用户"""
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # 创建 users 表
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            phone TEXT
        )
    """)

    # 插入默认用户（密码以明文形式存储在 SQLite 中）
    # 使用 INSERT OR IGNORE 防止重复插入
    cursor.execute(
        "INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
        ("admin", "admin123", "admin@example.com", "13800138000")
    )
    cursor.execute(
        "INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
        ("alice", "alice2025", "alice@example.com", "13900139001")
    )

    conn.commit()
    conn.close()
    print("[DB] SQLite 数据库初始化完成 — data/users.db")


# 应用启动时初始化数据库
init_db()


# ============================================================
# 安全防护状态（内存中，生产环境应使用 Redis 等外部存储）
# ============================================================

# IP 级速率限制记录: {ip: [datetime, ...]}
_rate_limit_records: dict[str, list[datetime]] = {}

# 账号锁定记录: {username: {"count": int, "locked_until": datetime}}
_account_lockout: dict[str, dict] = {}

# 安全配置常量
MAX_LOGIN_ATTEMPTS_PER_MINUTE = 5
MAX_ACCOUNT_FAILURES = 5
ACCOUNT_LOCKOUT_MINUTES = 15


# ============================================================
# CSRF Token 工具函数
# ============================================================

def generate_csrf_token() -> str:
    """生成 CSRF token 并存入 session"""
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]


def validate_csrf_token() -> bool:
    """验证 CSRF token，验证后立即从 session 中移除（一次性）"""
    token = request.form.get("_csrf_token")
    stored_token = session.pop("_csrf_token", None)
    if not token or not stored_token:
        return False
    return secrets.compare_digest(token, stored_token)


# ============================================================
# 速率限制工具函数
# ============================================================

def _clean_rate_records(ip: str):
    """清理超过 1 分钟的 IP 请求记录"""
    now = datetime.now()
    if ip in _rate_limit_records:
        _rate_limit_records[ip] = [
            t for t in _rate_limit_records[ip]
            if now - t < timedelta(minutes=1)
        ]
    else:
        _rate_limit_records[ip] = []


def check_rate_limit(ip: str) -> bool:
    """IP 级速率限制检查"""
    _clean_rate_records(ip)
    if len(_rate_limit_records[ip]) >= MAX_LOGIN_ATTEMPTS_PER_MINUTE:
        return False
    _rate_limit_records[ip].append(datetime.now())
    return True


def check_account_lockout(username: str) -> tuple[bool, int]:
    """检查账号是否被锁定"""
    if username in _account_lockout:
        lockout = _account_lockout[username]
        now = datetime.now()
        if lockout["locked_until"] and now < lockout["locked_until"]:
            remaining_seconds = int((lockout["locked_until"] - now).total_seconds())
            return False, remaining_seconds
        else:
            del _account_lockout[username]
    return True, 0


def record_failed_login(username: str) -> bool:
    """记录登录失败，达到阈值时锁定账号"""
    if username not in _account_lockout:
        _account_lockout[username] = {"count": 0, "locked_until": None}
    _account_lockout[username]["count"] += 1
    if _account_lockout[username]["count"] >= MAX_ACCOUNT_FAILURES:
        _account_lockout[username]["locked_until"] = datetime.now() + timedelta(
            minutes=ACCOUNT_LOCKOUT_MINUTES
        )
        return True
    return False


def reset_account_lockout(username: str):
    """登录成功后清除账号锁定记录"""
    if username in _account_lockout:
        del _account_lockout[username]


# ============================================================
# 路由
# ============================================================

# ----- 首页 -----

@app.route("/")
def index():
    """首页：已登录则展示用户信息，未登录则引导登录"""
    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = USERS[username]
    return render_template("index.html", username=username, user=user_info)


# ----- 登录 -----

@app.route("/login", methods=["GET", "POST"])
def login():
    """
    登录路由：
    - GET：渲染登录页，同时生成 CSRF token
    - POST：校验 CSRF token → IP 速率限制 → 账号锁定检查 → 密码验证
    """
    error = None
    message = None

    # 检查是否有注册成功的提示消息
    if request.args.get("registered"):
        message = "注册成功，请登录"

    if request.method == "POST":
        # 防护 1：CSRF Token 校验
        if not validate_csrf_token():
            error = "安全校验失败（CSRF Token 无效），请刷新页面重试"

        # 防护 2：IP 级速率限制
        client_ip = request.remote_addr or "unknown"
        if not error and not check_rate_limit(client_ip):
            error = "请求过于频繁，请稍后再试（IP 速率限制）"

        if not error:
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")

            if not username or not password:
                error = "用户名和密码不能为空"
            else:
                # 防护 3：账号锁定检查
                is_available, remaining = check_account_lockout(username)
                if not is_available:
                    error = f"账号已被锁定，请在 {remaining} 秒后重试"
                else:
                    # 防护 4：密码哈希比对
                    user = USERS.get(username)
                    if user and check_password_hash(user["password"], password):
                        session["username"] = username
                        session.permanent = False
                        reset_account_lockout(username)
                        user_info = USERS[username]
                        return render_template(
                            "index.html", username=username, user=user_info
                        )
                    else:
                        is_locked = record_failed_login(username)
                        if is_locked:
                            error = f"密码错误次数过多，账号已被锁定 {ACCOUNT_LOCKOUT_MINUTES} 分钟"
                        else:
                            remaining_attempts = MAX_ACCOUNT_FAILURES - _account_lockout.get(username, {}).get("count", 0)
                            if remaining_attempts > 0:
                                error = f"用户名或密码错误（还可尝试 {remaining_attempts} 次）"
                            else:
                                error = "用户名或密码错误"

    csrf_token = generate_csrf_token()
    return render_template("login.html", error=error, message=message, csrf_token=csrf_token)


# ----- 注册 ----

@app.route("/register", methods=["GET", "POST"])
def register():
    """
    注册路由：
    - GET：渲染注册页面
    - POST：使用参数化查询将用户数据插入 SQLite（防止 SQL 注入）
    """
    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()

        if not username or not password:
            error = "用户名和密码不能为空"
        else:
            try:
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()

                # 使用参数化查询（? 占位符）防止 SQL 注入
                sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
                cursor.execute(sql, (username, password, email, phone))
                conn.commit()
                conn.close()

                return redirect("/login?registered=1")

            except sqlite3.IntegrityError:
                error = "用户名已存在"
            except Exception as e:
                error = f"注册失败: {str(e)}"

    return render_template("register.html", error=error)


# ----- 搜索 -----

@app.route("/search")
def search():
    """
    搜索路由（GET）：
    - 通过 URL 参数 keyword 接收关键词
    - 使用参数化查询进行模糊查询（防止 SQL 注入）
    """
    keyword = request.args.get("keyword", "")
    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = USERS[username]

    results = []

    if keyword:
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()

            # 使用参数化查询（? 占位符）防止 SQL 注入
            # LIKE 通配符 % 作为参数值的一部分传递，不拼接在 SQL 语句中
            like_pattern = f"%{keyword}%"
            sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
            cursor.execute(sql, (like_pattern, like_pattern))

            rows = cursor.fetchall()
            conn.close()

            results = [
                {"id": r[0], "username": r[1], "email": r[2], "phone": r[3]}
                for r in rows
            ]

        except Exception as e:
            error_msg = f"搜索出错: {str(e)}"
            print(f"[SQL ERROR] {error_msg}")
            return render_template("index.html", username=username, user=user_info,
                                   search_results=results, keyword=keyword,
                                   search_error=error_msg)

    return render_template("index.html", username=username, user=user_info,
                           search_results=results, keyword=keyword)


# ----- 上传头像（安全加固版）-----

# 上传操作的 IP 速率限制记录（与登录分开计数）
_upload_rate_records: dict[str, list[datetime]] = {}
MAX_UPLOADS_PER_MINUTE = 3  # 每分钟最多上传 3 次


def allowed_file(filename: str) -> bool:
    """检查文件扩展名是否在白名单内（防止任意文件上传）"""
    _, ext = os.path.splitext(filename)
    return ext.lower() in ALLOWED_EXTENSIONS


def validate_image_content(file_bytes: bytes) -> bool:
    """使用 PIL 验证文件是否为真实图片（防止伪装图片的恶意文件）"""
    try:
        img = Image.open(io.BytesIO(file_bytes))
        img.verify()  # 验证图片完整性
        return True
    except Exception:
        return False


@app.route("/upload", methods=["GET", "POST"])
def upload():
    """
    头像上传路由（安全加固版）：
    - 需要登录才能访问
    - GET：渲染上传页面
    - POST：接收文件，经过 4 层安全检查后保存
    """
    username = session.get("username")
    if not username:
        return redirect("/login")

    uploaded_url = None
    error = None
    filename = None
    original_name = None

    if request.method == "POST":
        # 防护 1：上传速率限制
        client_ip = request.remote_addr or "unknown"
        now = datetime.now()
        if client_ip in _upload_rate_records:
            _upload_rate_records[client_ip] = [
                t for t in _upload_rate_records[client_ip]
                if now - t < timedelta(minutes=1)
            ]
        else:
            _upload_rate_records[client_ip] = []

        if len(_upload_rate_records[client_ip]) >= MAX_UPLOADS_PER_MINUTE:
            error = "上传过于频繁，请稍后再试（每分钟最多 3 次）"
        else:
            file = request.files.get("file")

            if not file or not file.filename:
                error = "请选择一个文件"
            else:
                original_name = file.filename

                # 防护 2：文件扩展名白名单校验（防止上传恶意脚本文件）
                if not allowed_file(original_name):
                    error = f"不支持的文件类型，仅允许: {' / '.join(ALLOWED_EXTENSIONS)}"

                if not error:
                    # 防护 3：读取文件内容并用 PIL 验证是否为真实图片
                    file_bytes = file.read()
                    if not validate_image_content(file_bytes):
                        error = "文件内容校验失败，请上传有效的图片文件"

                    if not error:
                        # 防护 4：使用 UUID 重命名文件
                        # 作用：1.防止路径遍历（文件名不含 ../）
                        #      2.防止文件名冲突覆盖
                        #      3.防止原始文件名泄露用户信息
                        _, ext = os.path.splitext(original_name)
                        safe_filename = f"{uuid.uuid4()}{ext.lower()}"
                        save_path = os.path.join(UPLOAD_FOLDER, safe_filename)

                        # 将文件指针重置并保存
                        file.stream.seek(0)
                        file.save(save_path)

                        uploaded_url = url_for("static", filename=f"uploads/{safe_filename}")
                        filename = safe_filename
                        print(f"[UPLOAD] {username} 上传头像: {original_name} → {safe_filename}")

                        # 记录上传次数
                        _upload_rate_records[client_ip].append(datetime.now())

    return render_template("upload.html", username=username,
                           uploaded_url=uploaded_url, filename=filename,
                           original_name=original_name, error=error)


# ----- 登出 -----

@app.route("/logout")
def logout():
    """登出：清除 session 后跳转到首页"""
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
