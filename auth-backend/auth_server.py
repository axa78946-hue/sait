import os
import sys
import json
import sqlite3
import hashlib
import secrets
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingTCPServer
import urllib.parse

# Setup Database path
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "auth.db")
DATABASE_URL = os.environ.get("DATABASE_URL")

# In-memory captcha challenges mapping
ACTIVE_CAPTCHAS = {}

class SafeCursor:
    def __init__(self, cursor, is_postgres):
        self.cursor = cursor
        self.is_postgres = is_postgres

    def execute(self, query, params=None):
        if params is None:
            params = ()
        if self.is_postgres:
            # Replace placeholder ? with %s for PostgreSQL
            query = query.replace('?', '%s')
        self.cursor.execute(query, params)

    def fetchone(self):
        return self.cursor.fetchone()

    def fetchall(self):
        return self.cursor.fetchall()

    def __getattr__(self, name):
        return getattr(self.cursor, name)

class SafeConnection:
    def __init__(self, conn, is_postgres):
        self.conn = conn
        self.is_postgres = is_postgres

    def cursor(self):
        return SafeCursor(self.conn.cursor(), self.is_postgres)

    def commit(self):
        self.conn.commit()

    def close(self):
        self.conn.close()

    def __getattr__(self, name):
        return getattr(self.conn, name)

def get_db_connection():
    if DATABASE_URL:
        import psycopg2
        conn = psycopg2.connect(DATABASE_URL)
        return SafeConnection(conn, is_postgres=True)
    else:
        import sqlite3
        conn = sqlite3.connect(DB_PATH)
        return SafeConnection(conn, is_postgres=False)

def init_db():
    is_postgres = bool(DATABASE_URL)
    if is_postgres:
        print("[Auth Server] Initializing database in PostgreSQL...")
    else:
        print(f"[Auth Server] Initializing database at {DB_PATH}...")
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if is_postgres:
        # Create tables for PostgreSQL
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(255) UNIQUE NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at BIGINT NOT NULL
        )
        """)
        
        # Check columns
        cursor.execute("""
            SELECT column_name FROM information_schema.columns 
            WHERE table_name = 'users'
        """)
        columns = [row[0] for row in cursor.fetchall()]
    else:
        # Create tables for SQLite
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
        """)
        
        # Check columns
        cursor.execute("PRAGMA table_info(users)")
        columns = [col[1] for col in cursor.fetchall()]

    # Add new profile columns if they don't exist
    if "avatar_index" not in columns:
        print("[Auth Server] Migrating DB: Adding avatar_index column...")
        cursor.execute("ALTER TABLE users ADD COLUMN avatar_index INTEGER DEFAULT 0")
    if "hwid" not in columns:
        print("[Auth Server] Migrating DB: Adding hwid column...")
        cursor.execute("ALTER TABLE users ADD COLUMN hwid TEXT DEFAULT 'Не привязан (Запустите лаунчер)'")
    if "subscription_tier" not in columns:
        print("[Auth Server] Migrating DB: Adding subscription_tier column...")
        cursor.execute("ALTER TABLE users ADD COLUMN subscription_tier TEXT DEFAULT NULL")
    if "role" not in columns:
        print("[Auth Server] Migrating DB: Adding role column...")
        cursor.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'Игрок'")
    if "configs" not in columns:
        print("[Auth Server] Migrating DB: Adding configs column...")
        cursor.execute("ALTER TABLE users ADD COLUMN configs TEXT DEFAULT '[]'")
    if "is_banned" not in columns:
        print("[Auth Server] Migrating DB: Adding is_banned column...")
        cursor.execute("ALTER TABLE users ADD COLUMN is_banned INTEGER DEFAULT 0")
    if "last_ip" not in columns:
        print("[Auth Server] Migrating DB: Adding last_ip column...")
        cursor.execute("ALTER TABLE users ADD COLUMN last_ip TEXT DEFAULT NULL")
    if "last_country" not in columns:
        print("[Auth Server] Migrating DB: Adding last_country column...")
        cursor.execute("ALTER TABLE users ADD COLUMN last_country TEXT DEFAULT NULL")
    if "violation_count" not in columns:
        print("[Auth Server] Migrating DB: Adding violation_count column...")
        cursor.execute("ALTER TABLE users ADD COLUMN violation_count INTEGER DEFAULT 0")

    # Create sessions table
    if is_postgres:
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token VARCHAR(255) PRIMARY KEY,
            username VARCHAR(255) NOT NULL,
            expires_at BIGINT NOT NULL
        )
        """)
    else:
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            expires_at INTEGER NOT NULL
        )
        """)
    
    # Create keys table
    if is_postgres:
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS keys (
            key VARCHAR(255) PRIMARY KEY,
            subscription_tier VARCHAR(255) NOT NULL,
            used_by VARCHAR(255) DEFAULT NULL,
            used_at BIGINT DEFAULT NULL
        )
        """)
    else:
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS keys (
            key TEXT PRIMARY KEY,
            subscription_tier TEXT NOT NULL,
            used_by TEXT DEFAULT NULL,
            used_at INTEGER DEFAULT NULL
        )
        """)
    
    # Seed/Update Vixdim as Creator with active subscription
    try:
        cursor.execute("UPDATE users SET role = 'Создатель', subscription_tier = 'Навсегда' WHERE username = 'Vixdim'")
    except Exception as e:
        print(f"[Auth Server] Warning: Could not update Vixdim default role/sub: {e}")

    # Seed/Update vxidm as Creator with active subscription
    try:
        cursor.execute("SELECT id FROM users WHERE username = 'vxidm'")
        vxidm_exists = cursor.fetchone()
        if not vxidm_exists:
            h, s = hash_password("пароль")
            cursor.execute(
                "INSERT INTO users (username, email, password_hash, salt, created_at, role, subscription_tier) VALUES (?, ?, ?, ?, ?, ?, ?)",
                ("vxidm", "vxidm@funik.xyz", h, s, int(time.time()), "Создатель", "Навсегда")
            )
            print("[Auth Server] Seeded default user 'vxidm' (password: пароль)")
        else:
            cursor.execute("UPDATE users SET role = 'Создатель', subscription_tier = 'Навсегда' WHERE username = 'vxidm'")
    except Exception as e:
        print(f"[Auth Server] Warning: Could not seed/update vxidm: {e}")

        
    conn.commit()
    conn.close()

# Password hashing helper using PBKDF2
def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    # 100k iterations of SHA256
    pwd_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000
    ).hex()
    return pwd_hash, salt

def verify_password(password, stored_hash, salt):
    test_hash, _ = hash_password(password, salt)
    return test_hash == stored_hash

def safe_str(val):
    if val is None:
        return ""
    return str(val).strip()

# Stunning glassmorphic HTML page content
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Funik Client - Регистрация</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&family=Roboto:wght@300;400;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #0b0c18;
            --card-bg: rgba(14, 14, 22, 0.65);
            --border-color: rgba(32, 32, 42, 0.8);
            --accent-color: #0096ff;
            --accent-glow: rgba(0, 150, 255, 0.4);
            --text-primary: #e0e0e6;
            --text-secondary: #707080;
            --success-color: #2ed573;
            --error-color: #ff4b6e;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: 'Roboto', 'Tahoma', sans-serif;
            -webkit-font-smoothing: antialiased;
        }

        body {
            background: radial-gradient(circle at 50% 50%, #1a1b36 0%, var(--bg-color) 70%);
            color: var(--text-primary);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            overflow-x: hidden;
            position: relative;
        }

        /* Ambient geometric lights in background */
        body::before {
            content: '';
            position: absolute;
            width: 300px;
            height: 300px;
            background: var(--accent-color);
            filter: blur(150px);
            opacity: 0.15;
            top: 20%;
            left: 20%;
            pointer-events: none;
            z-index: 0;
        }

        body::after {
            content: '';
            position: absolute;
            width: 250px;
            height: 250px;
            background: #8f70ff;
            filter: blur(120px);
            opacity: 0.12;
            bottom: 20%;
            right: 20%;
            pointer-events: none;
            z-index: 0;
        }

        .container {
            width: 100%;
            max-width: 450px;
            padding: 20px;
            z-index: 1;
        }

        .card {
            background: var(--card-bg);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 40px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.5);
            transition: transform 0.3s ease, border-color 0.3s ease, box-shadow 0.3s ease;
        }

        .card:hover {
            border-color: rgba(0, 150, 255, 0.25);
            box-shadow: 0 12px 45px rgba(0, 150, 255, 0.08);
        }

        .header {
            text-align: center;
            margin-bottom: 30px;
        }

        .logo-text {
            font-family: 'Outfit', sans-serif;
            font-weight: 800;
            font-size: 2.2rem;
            letter-spacing: 4px;
            background: linear-gradient(45deg, #fff 30%, var(--accent-color));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 8px;
            text-transform: uppercase;
        }

        .subtitle {
            font-size: 0.85rem;
            color: var(--text-secondary);
            font-weight: bold;
            letter-spacing: 1px;
            text-transform: uppercase;
        }

        .form-group {
            margin-bottom: 20px;
            position: relative;
        }

        .form-group label {
            display: block;
            font-size: 0.8rem;
            font-weight: bold;
            color: var(--text-secondary);
            margin-bottom: 8px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            transition: color 0.3s;
        }

        .input-wrapper {
            position: relative;
        }

        .form-group input {
            width: 100%;
            background: rgba(8, 8, 12, 0.6);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 12px 16px;
            color: var(--text-primary);
            font-size: 0.95rem;
            outline: none;
            transition: all 0.3s cubic-bezier(0.25, 0.8, 0.25, 1);
        }

        .form-group input:focus {
            border-color: var(--accent-color);
            box-shadow: 0 0 10px var(--accent-glow);
            background: rgba(8, 8, 12, 0.8);
        }

        .form-group input:focus + label {
            color: var(--accent-color);
        }

        .btn-submit {
            width: 100%;
            background: linear-gradient(45deg, var(--accent-color), #0076c8);
            border: none;
            border-radius: 8px;
            padding: 14px;
            color: #fff;
            font-size: 0.95rem;
            font-weight: bold;
            letter-spacing: 1px;
            cursor: pointer;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(0, 150, 255, 0.2);
            margin-top: 10px;
            text-transform: uppercase;
        }

        .btn-submit:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(0, 150, 255, 0.4);
            filter: brightness(1.1);
        }

        .btn-submit:active {
            transform: translateY(0);
        }

        .btn-submit:disabled {
            background: #1e1e28;
            color: var(--text-secondary);
            cursor: not-allowed;
            box-shadow: none;
            transform: none;
        }

        .message {
            margin-top: 20px;
            padding: 12px;
            border-radius: 8px;
            font-size: 0.9rem;
            display: none;
            text-align: center;
            line-height: 1.4;
            animation: fadeIn 0.4s ease;
        }

        .message.success {
            display: block;
            background: rgba(46, 213, 115, 0.15);
            border: 1px solid rgba(46, 213, 115, 0.3);
            color: var(--success-color);
        }

        .message.error {
            display: block;
            background: rgba(255, 75, 110, 0.15);
            border: 1px solid rgba(255, 75, 110, 0.3);
            color: var(--error-color);
        }

        .footer-links {
            margin-top: 25px;
            text-align: center;
            font-size: 0.85rem;
            color: var(--text-secondary);
        }

        .footer-links a {
            color: var(--accent-color);
            text-decoration: none;
            transition: color 0.3s;
            font-weight: bold;
        }

        .footer-links a:hover {
            color: #fff;
            text-decoration: underline;
        }

        /* Success State */
        .success-overlay {
            display: none;
            text-align: center;
            animation: scaleUp 0.5s cubic-bezier(0.34, 1.56, 0.64, 1);
        }

        .success-icon {
            width: 70px;
            height: 70px;
            background: rgba(46, 213, 115, 0.12);
            border: 2px solid var(--success-color);
            border-radius: 50%;
            display: flex;
            justify-content: center;
            align-items: center;
            margin: 0 auto 24px auto;
            color: var(--success-color);
            font-size: 2.2rem;
            animation: pulseSuccess 2s infinite;
        }

        .download-box {
            margin-top: 30px;
            background: rgba(255, 255, 255, 0.03);
            border: 1px dashed var(--border-color);
            border-radius: 12px;
            padding: 20px;
        }

        .btn-download {
            display: inline-block;
            background: linear-gradient(45deg, #2ed573, #26af5f);
            border: none;
            border-radius: 8px;
            padding: 12px 24px;
            color: #fff;
            font-size: 0.9rem;
            font-weight: bold;
            text-decoration: none;
            margin-top: 15px;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(46, 213, 115, 0.2);
            text-transform: uppercase;
        }

        .btn-download:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(46, 213, 115, 0.4);
            filter: brightness(1.1);
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        @keyframes scaleUp {
            from { opacity: 0; transform: scale(0.8); }
            to { opacity: 1; transform: scale(1); }
        }

        @keyframes pulseSuccess {
            0% { box-shadow: 0 0 0 0 rgba(46, 213, 115, 0.4); }
            70% { box-shadow: 0 0 0 15px rgba(46, 213, 115, 0); }
            100% { box-shadow: 0 0 0 0 rgba(46, 213, 115, 0); }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="card" id="formCard">
            <div class="header">
                <div class="logo-text">Funik</div>
                <div class="subtitle">Приватный клиент нового поколения</div>
            </div>

            <form id="registerForm" onsubmit="handleRegister(event)">
                <div class="form-group">
                    <label for="username">Имя пользователя (Ник)</label>
                    <input type="text" id="username" required autocomplete="username" placeholder="Пример: FunikPlayer">
                </div>

                <div class="form-group">
                    <label for="email">Электронная почта</label>
                    <input type="email" id="email" required autocomplete="email" placeholder="example@mail.ru">
                </div>

                <div class="form-group">
                    <label for="password">Пароль</label>
                    <input type="password" id="password" required autocomplete="new-password" placeholder="••••••••">
                </div>

                <div class="form-group">
                    <label for="password_confirm">Подтверждение пароля</label>
                    <input type="password" id="password_confirm" required autocomplete="new-password" placeholder="••••••••">
                </div>

                <button type="submit" class="btn-submit" id="submitBtn">Зарегистрироваться</button>
            </form>

            <div class="message" id="msgBox"></div>

            <div class="footer-links">
                Уже есть аккаунт? Просто запустите лаунчер и авторизуйтесь.
            </div>
        </div>

        <!-- Success Screen -->
        <div class="card success-overlay" id="successCard">
            <div class="success-icon">✓</div>
            <h2>Регистрация успешна!</h2>
            <p style="color: var(--text-secondary); margin-top: 10px; line-height: 1.5;">
                Ваш аккаунт успешно создан. Теперь вы можете войти в игру через лаунчер, используя свои учетные данные.
            </p>

            <div class="download-box">
                <p style="font-size: 0.9rem; font-weight: bold;">Скачать Funik Launcher</p>
                <p style="font-size: 0.8rem; color: var(--text-secondary); margin-top: 5px;">Версия 1.0.0-BETA для Windows / Wine</p>
                <a href="/FunikLoader.exe" class="btn-download" download>Скачать .EXE</a>
            </div>
        </div>
    </div>

    <script>
        async function handleRegister(event) {
            event.preventDefault();
            
            const username = document.getElementById('username').value.trim();
            const email = document.getElementById('email').value.trim();
            const password = document.getElementById('password').value;
            const passwordConfirm = document.getElementById('password_confirm').value;
            
            const submitBtn = document.getElementById('submitBtn');
            const msgBox = document.getElementById('msgBox');
            
            msgBox.className = 'message';
            msgBox.style.display = 'none';

            // Validations
            if (password !== passwordConfirm) {
                msgBox.innerText = 'Пароли не совпадают!';
                msgBox.className = 'message error';
                return;
            }

            if (password.length < 6) {
                msgBox.innerText = 'Пароль должен быть не менее 6 символов!';
                msgBox.className = 'message error';
                return;
            }

            if (username.length < 3) {
                msgBox.innerText = 'Имя пользователя должно быть не менее 3 символов!';
                msgBox.className = 'message error';
                return;
            }

            submitBtn.disabled = true;
            submitBtn.innerText = 'Регистрация...';

            try {
                const response = await fetch('/api/auth/register', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ username, email, password })
                });

                const data = await response.json();

                if (response.ok && data.success) {
                    // Show success card with animations
                    document.getElementById('formCard').style.display = 'none';
                    document.getElementById('successCard').style.display = 'block';
                } else {
                    msgBox.innerText = data.message || 'Произошла ошибка при регистрации.';
                    msgBox.className = 'message error';
                    submitBtn.disabled = false;
                    submitBtn.innerText = 'Зарегистрироваться';
                }
            } catch (err) {
                console.error(err);
                msgBox.innerText = 'Не удалось подключиться к серверу.';
                msgBox.className = 'message error';
                submitBtn.disabled = false;
                submitBtn.innerText = 'Зарегистрироваться';
            }
        }
    </script>
</body>
</html>
"""

# Custom Request Handler to handle API requests and serve static files
class AuthHTTPRequestHandler(BaseHTTPRequestHandler):
    
    # Enable CORS headers
    def _set_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _get_client_ip_and_country(self):
        ip = self.headers.get("CF-Connecting-IP")
        if not ip:
            x_forwarded = self.headers.get("X-Forwarded-For")
            if x_forwarded:
                ip = x_forwarded.split(",")[0].strip()
        if not ip:
            ip = self.client_address[0]
            
        country = self.headers.get("CF-IPCountry", "??")
        return ip, country

    def _check_is_creator(self, token):
        if not token:
            return False, "Отсутствует токен!"
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT username FROM sessions WHERE token = ? AND expires_at > ?", (token, int(time.time())))
            session = cursor.fetchone()
            if not session:
                return False, "Неверный или просроченный токен сессии!"
            username = session[0]
            cursor.execute("SELECT role FROM users WHERE username = ?", (username,))
            user_row = cursor.fetchone()
            if not user_row or user_row[0] != "Создатель":
                return False, "Недостаточно прав! Требуется роль Создатель."
            return True, username
        except Exception as e:
            return False, f"Ошибка авторизации: {e}"
        finally:
            conn.close()

    def do_OPTIONS(self):
        self.send_response(200)
        self._set_cors_headers()
        self.end_headers()

    def do_GET(self):
        url_path = urllib.parse.urlparse(self.path).path

        # Static files folder
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        site_dir = os.path.join(base_dir, "funik.xyz")
        if not os.path.exists(site_dir):
            site_dir = "/home/vxidm/Рабочий стол/funik.xyz"

        # Override for FunikLoader.exe to search other compiled directories first
        if url_path == "/FunikLoader.exe":
            launcher_paths = [
                os.path.join(base_dir, "FunikLoader.exe"),
                os.path.join(base_dir, "loader", "FunikLoader.exe"),
                os.path.join(base_dir, "out", "FunikLoader.exe"),
                os.path.join(site_dir, "FunikLoader.exe"),
                "/home/vxidm/Загрузки/skycore-release-main/FunikLoader.exe"
            ]
            file_to_serve = None
            for p in launcher_paths:
                if os.path.exists(p):
                    file_to_serve = p
                    break

            if file_to_serve:
                try:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Disposition", "attachment; filename=FunikLoader.exe")
                    self.send_header("Content-Length", str(os.path.getsize(file_to_serve)))
                    self._set_cors_headers()
                    self.end_headers()
                    with open(file_to_serve, "rb") as f:
                        while True:
                            chunk = f.read(65536)
                            if not chunk:
                                break
                            self.wfile.write(chunk)
                    return
                except Exception as e:
                    print(f"[Auth Server] Error streaming launcher file: {e}")
                    self.send_error(500, "Internal Server Error during file streaming")
                    return
            else:
                self.send_response(404)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write("Файл FunikLoader.exe не найден на сервере. Соберите лаунчер.".encode("utf-8"))
                return

        # Serve client.bin downloads
        if url_path in ["/client.bin", "/api/client/download"]:
            client_paths = [
                os.path.join(base_dir, "client.bin"),
                os.path.join(base_dir, "loader", "client.bin"),
                "/home/vxidm/Загрузки/skycore-release-main/client.bin"
            ]
            file_to_serve = None
            for p in client_paths:
                if os.path.exists(p):
                    file_to_serve = p
                    break

            if file_to_serve:
                try:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Disposition", "attachment; filename=client.bin")
                    self.send_header("Content-Length", str(os.path.getsize(file_to_serve)))
                    self._set_cors_headers()
                    self.end_headers()
                    with open(file_to_serve, "rb") as f:
                        while True:
                            chunk = f.read(65536)
                            if not chunk:
                                break
                            self.wfile.write(chunk)
                    return
                except Exception as e:
                    print(f"[Auth Server] Error streaming client payload: {e}")
                    self.send_error(500, "Internal Server Error during file streaming")
                    return
            else:
                self.send_response(404)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write("Файл client.bin не найден на сервере.".encode("utf-8"))
                return

        # Serve captcha token/equation
        if url_path == "/api/auth/captcha/get":
            import random
            num1 = random.randint(1, 9)
            num2 = random.randint(1, 9)
            op = random.choice(['+', '-', '*'])
            if op == '+':
                question = f"{num1} + {num2} = ?"
                answer = num1 + num2
            elif op == '-':
                max_n = max(num1, num2)
                min_n = min(num1, num2)
                question = f"{max_n} - {min_n} = ?"
                answer = max_n - min_n
            else:
                question = f"{num1} * {num2} = ?"
                answer = num1 * num2

            captcha_id = secrets.token_hex(16)
            ACTIVE_CAPTCHAS[captcha_id] = {
                "answer": answer,
                "expires_at": time.time() + 300
            }
            self.send_json_response(200, {
                "success": True,
                "captcha_id": captcha_id,
                "question": question
            })
            return

        # Serve static files from /home/vxidm/Рабочий стол/funik.xyz
        requested_file = url_path.lstrip("/")
        if not requested_file or requested_file == "index.html":
            requested_file = "index.html"
            
        # Prevent directory traversal attacks
        full_path = os.path.abspath(os.path.join(site_dir, requested_file))
        if not full_path.startswith(os.path.abspath(site_dir)):
            self.send_response(403)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write("403 Forbidden".encode("utf-8"))
            return

        if os.path.exists(full_path) and os.path.isfile(full_path):
            # Determine content type
            ext = os.path.splitext(full_path)[1].lower()
            content_type = "application/octet-stream"
            if ext == ".html":
                content_type = "text/html; charset=utf-8"
            elif ext == ".css":
                content_type = "text/css; charset=utf-8"
            elif ext == ".js":
                content_type = "application/javascript; charset=utf-8"
            elif ext == ".png":
                content_type = "image/png"
            elif ext in [".jpg", ".jpeg"]:
                content_type = "image/jpeg"
            elif ext == ".gif":
                content_type = "image/gif"
            elif ext == ".svg":
                content_type = "image/svg+xml"
            elif ext == ".ico":
                content_type = "image/x-icon"
            elif ext == ".json":
                content_type = "application/json; charset=utf-8"

            try:
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(os.path.getsize(full_path)))
                self._set_cors_headers()
                self.end_headers()
                with open(full_path, "rb") as f:
                    while True:
                        chunk = f.read(65536)
                        if not chunk:
                            break
                        self.wfile.write(chunk)
                return
            except Exception as e:
                print(f"[Auth Server] Error serving static file {requested_file}: {e}")
                self.send_error(500, "Internal Server Error")
                return
        
        # If not found in site_dir, check if we should fallback to the hardcoded HTML_TEMPLATE for root-like paths
        if url_path in ["/", "/index.html"]:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(HTML_TEMPLATE.encode("utf-8"))
            return

        # 404 fallback
        self.send_response(404)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write("404 Not Found".encode("utf-8"))

    def do_POST(self):
        url_path = urllib.parse.urlparse(self.path).path
        
        # Parse content length to read JSON body
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        
        try:
            req_data = json.loads(post_data) if post_data else {}
        except Exception:
            self.send_json_response(400, {"success": False, "message": "Некорректный JSON"})
            return

        # 1. API: REGISTER
        if url_path == "/api/auth/register":
            username = safe_str(req_data.get("username"))
            email = safe_str(req_data.get("email"))
            password = req_data.get("password", "")

            # Server-side validation
            if not username or not email or not password:
                self.send_json_response(400, {"success": False, "message": "Все поля обязательны для заполнения!"})
                return
                
            if len(username) < 3:
                self.send_json_response(400, {"success": False, "message": "Никнейм должен быть не менее 3 символов!"})
                return

            if len(password) < 6:
                self.send_json_response(400, {"success": False, "message": "Пароль должен быть не менее 6 символов!"})
                return

            # Captcha Verification
            captcha_id = req_data.get("captcha_id")
            captcha_answer = req_data.get("captcha_answer")
            
            if not captcha_id or captcha_answer is None:
                self.send_json_response(400, {"success": False, "message": "Подтвердите, что вы не робот!"})
                return
                
            # Clean expired captchas
            now = time.time()
            expired = [k for k, v in ACTIVE_CAPTCHAS.items() if v["expires_at"] < now]
            for k in expired:
                ACTIVE_CAPTCHAS.pop(k, None)
                
            captcha = ACTIVE_CAPTCHAS.pop(captcha_id, None)
            if not captcha:
                self.send_json_response(400, {"success": False, "message": "Капча устарела, попробуйте еще раз!"})
                return
                
            try:
                user_ans = int(captcha_answer)
            except ValueError:
                user_ans = -9999
                
            if user_ans != captcha["answer"]:
                self.send_json_response(400, {"success": False, "message": "Неверный ответ капчи!"})
                return

            conn = get_db_connection()
            cursor = conn.cursor()
            try:
                # Check if username or email already exists
                cursor.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email))
                existing = cursor.fetchone()
                if existing:
                    self.send_json_response(400, {"success": False, "message": "Никнейм или почта уже зарегистрированы!"})
                    return

                # Hash password securely
                pwd_hash, salt = hash_password(password)
                
                # Insert user
                cursor.execute(
                    "INSERT INTO users (username, email, password_hash, salt, created_at) VALUES (?, ?, ?, ?, ?)",
                    (username, email, pwd_hash, salt, int(time.time()))
                )
                conn.commit()
                
                print(f"[Auth Server] Registered new user: {username} ({email})")
                self.send_json_response(200, {"success": True, "message": "Регистрация успешна!"})
                
            except Exception as e:
                print(f"[Auth Server] Registration database error: {e}")
                self.send_json_response(500, {"success": False, "message": f"Ошибка базы данных: {str(e)}"})
            finally:
                conn.close()

        # 1.2 API: CAPTCHA VERIFY
        elif url_path == "/api/auth/captcha/verify":
            captcha_id = req_data.get("captcha_id")
            answer = req_data.get("answer")
            
            if not captcha_id or answer is None:
                self.send_json_response(400, {"success": False, "message": "Не указаны параметры капчи!"})
                return
                
            # Clean expired captchas
            now = time.time()
            expired = [k for k, v in ACTIVE_CAPTCHAS.items() if v["expires_at"] < now]
            for k in expired:
                ACTIVE_CAPTCHAS.pop(k, None)
                
            captcha = ACTIVE_CAPTCHAS.get(captcha_id)
            if not captcha:
                self.send_json_response(400, {"success": False, "message": "Капча устарела, обновите страницу!"})
                return
                
            try:
                user_ans = int(answer)
            except ValueError:
                user_ans = -9999
                
            if user_ans == captcha["answer"]:
                self.send_json_response(200, {"success": True, "message": "Капча пройдена!"})
            else:
                self.send_json_response(400, {"success": False, "message": "Неверный ответ!"})
            return
                
        # 2. API: LOGIN
        elif url_path == "/api/auth/login":
            username_or_email = safe_str(req_data.get("username")) # can be username or email
            password = req_data.get("password", "")
            req_hwid = safe_str(req_data.get("hwid"))

            if not username_or_email or not password:
                self.send_json_response(400, {"success": False, "message": "Укажите имя пользователя и пароль!"})
                return

            conn = get_db_connection()
            cursor = conn.cursor()
            try:
                # Find user by username or email
                cursor.execute(
                    "SELECT username, password_hash, salt, hwid, role, subscription_tier, is_banned, id FROM users WHERE username = ? OR email = ?", 
                    (username_or_email, username_or_email)
                )
                user = cursor.fetchone()
                
                if not user:
                    self.send_json_response(400, {"success": False, "message": "Неверное имя пользователя или пароль!"})
                    return
                
                actual_username, stored_hash, salt, db_hwid, role, sub_tier, is_banned, user_id = user
                
                if is_banned == 1:
                    self.send_json_response(403, {"success": False, "message": "Ваш аккаунт заблокирован!"})
                    return
                
                # Verify password
                if not verify_password(password, stored_hash, salt):
                    self.send_json_response(400, {"success": False, "message": "Неверное имя пользователя или пароль!"})
                    return
                
                # Update IP and Country
                ip, country = self._get_client_ip_and_country()
                cursor.execute("UPDATE users SET last_ip = ?, last_country = ? WHERE username = ?", (ip, country, actual_username))
                conn.commit()
                
                # HWID check if login request came from loader (which passes a non-empty hwid)
                if req_hwid:
                    if not db_hwid or db_hwid == 'Не привязан (Запустите лаунчер)' or db_hwid == 'Ожидает привязки при первом запуске':
                        cursor.execute("UPDATE users SET hwid = ? WHERE username = ?", (req_hwid, actual_username))
                        conn.commit()
                        db_hwid = req_hwid
                        print(f"[Auth Server] Auto-bound HWID '{req_hwid}' to user: {actual_username}")
                    elif db_hwid != req_hwid:
                        self.send_json_response(400, {"success": False, "message": "Ошибка HWID! Сбросьте привязку в личном кабинете на сайте."})
                        return

                # Generate session token
                token = secrets.token_hex(32)
                # 30-day session lifetime
                expires_at = int(time.time()) + (30 * 24 * 60 * 60)
                
                # Insert session
                cursor.execute(
                    "INSERT OR REPLACE INTO sessions (token, username, expires_at) VALUES (?, ?, ?)",
                    (token, actual_username, expires_at)
                )
                conn.commit()
                
                print(f"[Auth Server] User logged in successfully: {actual_username}")
                self.send_json_response(200, {
                    "success": True, 
                    "token": token, 
                    "username": actual_username,
                    "role": role,
                    "subscription_tier": sub_tier,
                    "id": user_id,
                    "message": "Вход выполнен успешно!"
                })
                
            except Exception as e:
                print(f"[Auth Server] Login database error: {e}")
                self.send_json_response(500, {"success": False, "message": f"Ошибка базы данных: {str(e)}"})
            finally:
                conn.close()
                
        # 3. API: VERIFY
        elif url_path == "/api/auth/verify":
            token = safe_str(req_data.get("token"))
            req_hwid = safe_str(req_data.get("hwid"))
            
            if not token:
                self.send_json_response(400, {"success": False, "message": "Отсутствует авторизационный токен!"})
                return

            conn = get_db_connection()
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT username, expires_at FROM sessions WHERE token = ?", (token,))
                session = cursor.fetchone()
                
                if not session:
                    self.send_json_response(400, {"success": False, "message": "Неверный или просроченный токен!"})
                    return
                
                username, expires_at = session
                
                # Check expiration
                if expires_at < int(time.time()):
                    # Delete expired session
                    cursor.execute("DELETE FROM sessions WHERE token = ?", (token,))
                    conn.commit()
                    self.send_json_response(400, {"success": False, "message": "Срок действия сессии истек!"})
                    return
                
                # Fetch user details
                cursor.execute("SELECT hwid, role, subscription_tier, is_banned FROM users WHERE username = ?", (username,))
                user_info = cursor.fetchone()
                if not user_info:
                    self.send_json_response(400, {"success": False, "message": "Пользователь не найден!"})
                    return
                
                db_hwid, role, sub_tier, is_banned = user_info
                
                if is_banned == 1:
                    self.send_json_response(403, {"success": False, "message": "Ваш аккаунт заблокирован!"})
                    return
                
                # Update IP and Country
                ip, country = self._get_client_ip_and_country()
                cursor.execute("UPDATE users SET last_ip = ?, last_country = ? WHERE username = ?", (ip, country, username))
                conn.commit()
                
                # HWID check if verify request came from loader with hwid
                if req_hwid:
                    if not db_hwid or db_hwid == 'Не привязан (Запустите лаунчер)' or db_hwid == 'Ожидает привязки при первом запуске':
                        cursor.execute("UPDATE users SET hwid = ? WHERE username = ?", (req_hwid, username))
                        conn.commit()
                        db_hwid = req_hwid
                        print(f"[Auth Server] Auto-bound HWID '{req_hwid}' during verification to user: {username}")
                    elif db_hwid != req_hwid:
                        self.send_json_response(400, {"success": False, "message": "Ошибка HWID! Сбросьте привязку в личном кабинете на сайте."})
                        return

                self.send_json_response(200, {
                    "success": True, 
                    "username": username,
                    "role": role,
                    "subscription_tier": sub_tier,
                    "message": "Токен действителен!"
                })
                
            except Exception as e:
                print(f"[Auth Server] Verification database error: {e}")
                self.send_json_response(500, {"success": False, "message": f"Ошибка базы данных: {str(e)}"})
            finally:
                conn.close()

        # 4. API: CHANGE PASSWORD
        elif url_path == "/api/auth/change_password":
            username = safe_str(req_data.get("username"))
            current_password = req_data.get("current_password", "")
            new_password = req_data.get("new_password", "")

            if not username or not current_password or not new_password:
                self.send_json_response(400, {"success": False, "message": "Все поля обязательны!"})
                return

            if len(new_password) < 6:
                self.send_json_response(400, {"success": False, "message": "Новый пароль должен быть не менее 6 символов!"})
                return

            conn = get_db_connection()
            cursor = conn.cursor()
            try:
                # Find user
                cursor.execute("SELECT password_hash, salt FROM users WHERE username = ?", (username,))
                user = cursor.fetchone()
                
                if not user:
                    self.send_json_response(400, {"success": False, "message": "Пользователь не найден!"})
                    return
                
                stored_hash, salt = user
                
                # Verify current password
                if not verify_password(current_password, stored_hash, salt):
                    self.send_json_response(400, {"success": False, "message": "Неверный текущий пароль!"})
                    return
                
                # Hash new password
                new_hash, new_salt = hash_password(new_password)
                
                # Update database
                cursor.execute(
                    "UPDATE users SET password_hash = ?, salt = ? WHERE username = ?",
                    (new_hash, new_salt, username)
                )
                conn.commit()
                
                print(f"[Auth Server] Password changed successfully for user: {username}")
                self.send_json_response(200, {"success": True, "message": "Пароль успешно изменен!"})
                
            except Exception as e:
                print(f"[Auth Server] Password change database error: {e}")
                self.send_json_response(500, {"success": False, "message": f"Ошибка базы данных: {str(e)}"})
            finally:
                conn.close()

        # 5. API: PROFILE GET
        elif url_path == "/api/auth/profile/get":
            username = safe_str(req_data.get("username"))
            token = safe_str(req_data.get("token"))

            conn = get_db_connection()
            cursor = conn.cursor()
            try:
                if token:
                    cursor.execute("SELECT username FROM sessions WHERE token = ? AND expires_at > ?", (token, int(time.time())))
                    row = cursor.fetchone()
                    if row:
                        username = row[0]

                if not username:
                    self.send_json_response(400, {"success": False, "message": "Пользователь не найден или не авторизован!"})
                    return

                cursor.execute("""
                    SELECT email, avatar_index, hwid, subscription_tier, role, configs, is_banned, id 
                    FROM users WHERE username = ?
                """, (username,))
                user = cursor.fetchone()
                if not user:
                    self.send_json_response(400, {"success": False, "message": "Пользователь не найден в базе данных!"})
                    return

                email, avatar_index, hwid, subscription_tier, role, configs_str, is_banned, user_id = user
                
                if is_banned == 1:
                    self.send_json_response(403, {"success": False, "message": "Ваш аккаунт заблокирован!"})
                    return
                
                # Update IP and Country
                ip, country = self._get_client_ip_and_country()
                cursor.execute("UPDATE users SET last_ip = ?, last_country = ? WHERE username = ?", (ip, country, username))
                conn.commit()
                
                try:
                    configs = json.loads(configs_str)
                except Exception:
                    configs = []

                self.send_json_response(200, {
                    "success": True,
                    "username": username,
                    "email": email,
                    "avatarIndex": avatar_index,
                    "hwid": hwid,
                    "subscription": {"tier": subscription_tier} if subscription_tier else None,
                    "role": role,
                    "configs": configs,
                    "id": user_id
                })
            except Exception as e:
                print(f"[Auth Server] Profile get error: {e}")
                self.send_json_response(500, {"success": False, "message": f"Ошибка базы данных: {str(e)}"})
            finally:
                conn.close()

        # 6. API: PROFILE UPDATE
        elif url_path == "/api/auth/profile/update":
            username = safe_str(req_data.get("username"))
            token = safe_str(req_data.get("token"))

            conn = get_db_connection()
            cursor = conn.cursor()
            try:
                if token:
                    cursor.execute("SELECT username FROM sessions WHERE token = ? AND expires_at > ?", (token, int(time.time())))
                    row = cursor.fetchone()
                    if row:
                        username = row[0]

                if not username:
                    self.send_json_response(400, {"success": False, "message": "Пользователь не найден или не авторизован!"})
                    return

                cursor.execute("SELECT avatar_index, hwid, subscription_tier, configs FROM users WHERE username = ?", (username,))
                existing = cursor.fetchone()
                if not existing:
                    self.send_json_response(400, {"success": False, "message": "Пользователь не найден в базе данных!"})
                    return

                cur_avatar_index, cur_hwid, cur_subscription_tier, cur_configs = existing

                avatar_index = req_data.get("avatarIndex", cur_avatar_index)
                hwid = req_data.get("hwid", cur_hwid)

                if "subscription" in req_data:
                    sub = req_data.get("subscription")
                    subscription_tier = sub.get("tier") if sub else None
                else:
                    subscription_tier = cur_subscription_tier

                if "configs" in req_data:
                    configs_str = json.dumps(req_data.get("configs"))
                else:
                    configs_str = cur_configs

                cursor.execute("""
                    UPDATE users 
                    SET avatar_index = ?, hwid = ?, subscription_tier = ?, configs = ?
                    WHERE username = ?
                """, (avatar_index, hwid, subscription_tier, configs_str, username))
                conn.commit()

                print(f"[Auth Server] Profile updated successfully for: {username}")
                self.send_json_response(200, {"success": True, "message": "Профиль успешно обновлен!"})
            except Exception as e:
                print(f"[Auth Server] Profile update error: {e}")
                self.send_json_response(500, {"success": False, "message": f"Ошибка базы данных: {str(e)}"})
            finally:
                conn.close()

        # 7. API: KEY ACTIVATE
        elif url_path == "/api/auth/key/activate":
            token = safe_str(req_data.get("token"))
            key_val = safe_str(req_data.get("key")).strip()
            
            if not token or not key_val:
                self.send_json_response(400, {"success": False, "message": "Токен и ключ обязательны!"})
                return
                
            conn = get_db_connection()
            cursor = conn.cursor()
            try:
                # Resolve user
                cursor.execute("SELECT username FROM sessions WHERE token = ? AND expires_at > ?", (token, int(time.time())))
                session = cursor.fetchone()
                if not session:
                    self.send_json_response(400, {"success": False, "message": "Неверный или истекший токен сессии!"})
                    return
                username = session[0]
                
                # Check key
                cursor.execute("SELECT subscription_tier, used_by FROM keys WHERE key = ?", (key_val,))
                key_row = cursor.fetchone()
                if not key_row:
                    self.send_json_response(400, {"success": False, "message": "Указанный ключ не найден!"})
                    return
                    
                sub_tier, used_by = key_row
                if used_by is not None:
                    self.send_json_response(400, {"success": False, "message": "Этот ключ уже активирован!"})
                    return
                    
                # Mark key as used and update user subscription or reset HWID
                cursor.execute("UPDATE keys SET used_by = ?, used_at = ? WHERE key = ?", (username, int(time.time()), key_val))
                if sub_tier == "Сброс HWID":
                    cursor.execute("UPDATE users SET hwid = 'Не привязан (Запустите лаунчер)' WHERE username = ?", (username,))
                    message = "Ключ успешно активирован! Ваш HWID сброшен."
                else:
                    cursor.execute("UPDATE users SET subscription_tier = ? WHERE username = ?", (sub_tier, username))
                    message = f"Ключ успешно активирован! Ваша подписка: {sub_tier}"
                conn.commit()
                
                print(f"[Auth Server] User '{username}' successfully activated key '{key_val}' for tier '{sub_tier}'")
                self.send_json_response(200, {
                    "success": True, 
                    "message": message,
                    "subscription_tier": None if sub_tier == "Сброс HWID" else sub_tier,
                    "is_hwid_reset": (sub_tier == "Сброс HWID")
                })
            except Exception as e:
                print(f"[Auth Server] Key activation error: {e}")
                self.send_json_response(500, {"success": False, "message": f"Ошибка базы данных: {str(e)}"})
            finally:
                conn.close()

        # 8. API: ADMIN KEY GENERATE
        elif url_path == "/api/admin/key/generate":
            token = safe_str(req_data.get("token"))
            sub_tier = safe_str(req_data.get("subscription_tier"))
            
            if not token or not sub_tier:
                self.send_json_response(400, {"success": False, "message": "Токен и тип подписки обязательны!"})
                return
                
            is_ok, res = self._check_is_creator(token)
            if not is_ok:
                self.send_json_response(403, {"success": False, "message": res})
                return
                
            # Generate key FUNIK-XXXX-XXXX-XXXX
            generated_key = f"FUNIK-{secrets.token_hex(4).upper()}-{secrets.token_hex(4).upper()}-{secrets.token_hex(4).upper()}"
            
            conn = get_db_connection()
            cursor = conn.cursor()
            try:
                cursor.execute("INSERT INTO keys (key, subscription_tier) VALUES (?, ?)", (generated_key, sub_tier))
                conn.commit()
                self.send_json_response(200, {"success": True, "key": generated_key, "subscription_tier": sub_tier})
            except Exception as e:
                self.send_json_response(500, {"success": False, "message": f"Ошибка базы данных: {str(e)}"})
            finally:
                conn.close()

        # 9. API: ADMIN KEY LIST
        elif url_path == "/api/admin/key/list":
            token = safe_str(req_data.get("token"))
            is_ok, res = self._check_is_creator(token)
            if not is_ok:
                self.send_json_response(403, {"success": False, "message": res})
                return
                
            conn = get_db_connection()
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT key, subscription_tier, used_by, used_at FROM keys")
                keys = []
                for row in cursor.fetchall():
                    keys.append({
                        "key": row[0],
                        "subscription_tier": row[1],
                        "used_by": row[2],
                        "used_at": row[3]
                    })
                self.send_json_response(200, {"success": True, "keys": keys})
            except Exception as e:
                self.send_json_response(500, {"success": False, "message": f"Ошибка базы данных: {str(e)}"})
            finally:
                conn.close()

        # 10. API: ADMIN USER LIST
        elif url_path == "/api/admin/user/list":
            token = safe_str(req_data.get("token"))
            is_ok, res = self._check_is_creator(token)
            if not is_ok:
                self.send_json_response(403, {"success": False, "message": res})
                return
                
            conn = get_db_connection()
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT id, username, email, role, subscription_tier, hwid, is_banned, last_ip, last_country FROM users")
                users = []
                for row in cursor.fetchall():
                    users.append({
                        "id": row[0],
                        "username": row[1],
                        "email": row[2],
                        "role": row[3],
                        "subscription_tier": row[4],
                        "hwid": row[5],
                        "is_banned": row[6],
                        "last_ip": row[7],
                        "last_country": row[8]
                    })
                self.send_json_response(200, {"success": True, "users": users})
            except Exception as e:
                self.send_json_response(500, {"success": False, "message": f"Ошибка базы данных: {str(e)}"})
            finally:
                conn.close()

        # 11. API: ADMIN USER SET SUB
        elif url_path == "/api/admin/user/set_sub":
            token = safe_str(req_data.get("token"))
            target_username = safe_str(req_data.get("target_username"))
            sub_tier = req_data.get("subscription_tier") # can be None
            
            is_ok, res = self._check_is_creator(token)
            if not is_ok:
                self.send_json_response(403, {"success": False, "message": res})
                return
                
            if target_username.lower() in ['vixdim', 'vxidm']:
                self.send_json_response(400, {"success": False, "message": "Нельзя изменять подписку создателя проекта!"})
                return

            conn = get_db_connection()
            cursor = conn.cursor()
            try:
                if sub_tier == "Сброс HWID":
                    cursor.execute("UPDATE users SET hwid = 'Не привязан (Запустите лаунчер)' WHERE username = ?", (target_username,))
                    message = f"HWID для {target_username} успешно сброшен!"
                else:
                    cursor.execute("UPDATE users SET subscription_tier = ? WHERE username = ?", (sub_tier, target_username))
                    message = f"Подписка для {target_username} обновлена!"
                conn.commit()
                self.send_json_response(200, {"success": True, "message": message})
            except Exception as e:
                self.send_json_response(500, {"success": False, "message": f"Ошибка базы данных: {str(e)}"})
            finally:
                conn.close()

        # 12. API: ADMIN USER RESET HWID
        elif url_path == "/api/admin/user/reset_hwid":
            token = safe_str(req_data.get("token"))
            target_username = safe_str(req_data.get("target_username"))
            
            is_ok, res = self._check_is_creator(token)
            if not is_ok:
                self.send_json_response(403, {"success": False, "message": res})
                return
                
            if target_username.lower() in ['vixdim', 'vxidm']:
                self.send_json_response(400, {"success": False, "message": "Нельзя сбрасывать HWID создателя проекта!"})
                return

            conn = get_db_connection()
            cursor = conn.cursor()
            try:
                cursor.execute("UPDATE users SET hwid = 'Не привязан (Запустите лаунчер)' WHERE username = ?", (target_username,))
                conn.commit()
                self.send_json_response(200, {"success": True, "message": f"HWID для {target_username} сброшен!"})
            except Exception as e:
                self.send_json_response(500, {"success": False, "message": f"Ошибка базы данных: {str(e)}"})
            finally:
                conn.close()

        # 13. API: ADMIN USER RESET PWD
        elif url_path == "/api/admin/user/reset_pwd":
            token = safe_str(req_data.get("token"))
            target_username = safe_str(req_data.get("target_username"))
            
            is_ok, res = self._check_is_creator(token)
            if not is_ok:
                self.send_json_response(403, {"success": False, "message": res})
                return
                
            if target_username.lower() in ['vixdim', 'vxidm']:
                self.send_json_response(400, {"success": False, "message": "Нельзя сбрасывать пароль создателя проекта!"})
                return

            conn = get_db_connection()
            cursor = conn.cursor()
            try:
                h, s = hash_password("пароль")
                cursor.execute("UPDATE users SET password_hash = ?, salt = ? WHERE username = ?", (h, s, target_username))
                conn.commit()
                self.send_json_response(200, {"success": True, "message": f"Пароль для {target_username} сброшен на 'пароль'!"})
            except Exception as e:
                self.send_json_response(500, {"success": False, "message": f"Ошибка базы данных: {str(e)}"})
            finally:
                conn.close()

        # 14. API: ADMIN USER DELETE
        elif url_path == "/api/admin/user/delete":
            token = safe_str(req_data.get("token"))
            target_username = safe_str(req_data.get("target_username"))
            
            is_ok, res = self._check_is_creator(token)
            if not is_ok:
                self.send_json_response(403, {"success": False, "message": res})
                return
                
            if target_username.lower() in ['vixdim', 'vxidm']:
                self.send_json_response(400, {"success": False, "message": "Нельзя удалить создателя проекта!"})
                return
                
            conn = get_db_connection()
            cursor = conn.cursor()
            try:
                cursor.execute("DELETE FROM users WHERE username = ?", (target_username,))
                cursor.execute("DELETE FROM sessions WHERE username = ?", (target_username,))
                conn.commit()
                self.send_json_response(200, {"success": True, "message": f"Пользователь {target_username} успешно удален!"})
            except Exception as e:
                self.send_json_response(500, {"success": False, "message": f"Ошибка базы данных: {str(e)}"})
            finally:
                conn.close()

        # 15. API: ADMIN GLOBAL RESET ALL PASSWORDS
        elif url_path == "/api/admin/global/reset_all_passwords":
            token = safe_str(req_data.get("token"))
            is_ok, res = self._check_is_creator(token)
            if not is_ok:
                self.send_json_response(403, {"success": False, "message": res})
                return
                
            conn = get_db_connection()
            cursor = conn.cursor()
            try:
                h, s = hash_password("пароль")
                cursor.execute("UPDATE users SET password_hash = ?, salt = ? WHERE lower(username) NOT IN ('vixdim', 'vxidm')", (h, s))
                conn.commit()
                self.send_json_response(200, {"success": True, "message": "Все пароли успешно сброшены на слово 'пароль'!"})
            except Exception as e:
                self.send_json_response(500, {"success": False, "message": f"Ошибка базы данных: {str(e)}"})
            finally:
                conn.close()

        # 16. API: ADMIN USER TOGGLE BAN
        elif url_path == "/api/admin/user/toggle_ban":
            token = safe_str(req_data.get("token"))
            target_username = safe_str(req_data.get("target_username"))
            
            is_ok, res = self._check_is_creator(token)
            if not is_ok:
                self.send_json_response(403, {"success": False, "message": res})
                return
                
            if target_username.lower() in ['vixdim', 'vxidm']:
                self.send_json_response(400, {"success": False, "message": "Нельзя заблокировать создателя проекта!"})
                return
                
            conn = get_db_connection()
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT is_banned FROM users WHERE username = ?", (target_username,))
                row = cursor.fetchone()
                if not row:
                    self.send_json_response(400, {"success": False, "message": "Пользователь не найден!"})
                    return
                
                new_ban = 1 if row[0] == 0 else 0
                cursor.execute("UPDATE users SET is_banned = ? WHERE username = ?", (new_ban, target_username))
                
                # If banned, invalidate sessions immediately
                if new_ban == 1:
                    cursor.execute("DELETE FROM sessions WHERE username = ?", (target_username,))
                
                conn.commit()
                status_text = "заблокирован" if new_ban == 1 else "разблокирован"
                self.send_json_response(200, {"success": True, "message": f"Пользователь {target_username} успешно {status_text}!"})
            except Exception as e:
                self.send_json_response(500, {"success": False, "message": f"Ошибка базы данных: {str(e)}"})
            finally:
                conn.close()

        # 17. API: SECURITY REPORT VIOLATION (ANTI-TAMPER AUTO-BAN)
        elif url_path == "/api/security/report_violation":
            username = safe_str(req_data.get("username"))
            token = safe_str(req_data.get("token"))
            hwid = safe_str(req_data.get("hwid"))
            reason = safe_str(req_data.get("reason"))

            if not username or not token:
                self.send_json_response(400, {"success": False, "message": "Параметры авторизации не указаны!"})
                return

            # Verify session
            conn = get_db_connection()
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT expires_at FROM sessions WHERE token = ? AND username = ?", (token, username))
                session = cursor.fetchone()
                if not session or session[0] < time.time():
                    self.send_json_response(401, {"success": False, "message": "Сессия недействительна!"})
                    return

                # Increment violation_count
                cursor.execute("SELECT violation_count, subscription_tier FROM users WHERE username = ?", (username,))
                user_row = cursor.fetchone()
                if not user_row:
                    self.send_json_response(400, {"success": False, "message": "Пользователь не найден!"})
                    return
                
                current_violations = user_row[0] or 0
                new_violations = current_violations + 1
                
                is_banned = 0
                if new_violations >= 10:
                    is_banned = 1
                    # Ban user and revoke sub
                    cursor.execute("UPDATE users SET is_banned = 1, subscription_tier = NULL, violation_count = ? WHERE username = ?", (new_violations, username))
                    # Invalidate sessions
                    cursor.execute("DELETE FROM sessions WHERE username = ?", (username,))
                    print(f"[Auth Server] BANNED user {username} for security violations.")
                else:
                    cursor.execute("UPDATE users SET violation_count = ? WHERE username = ?", (new_violations, username))
                    print(f"[Auth Server] Security violation logged for user {username}: {reason} (Violations: {new_violations}/10)")

                conn.commit()
                self.send_json_response(200, {
                    "success": True, 
                    "violation_count": new_violations, 
                    "is_banned": bool(is_banned)
                })
            except Exception as e:
                print(f"[Auth Server] Security report DB error: {e}")
                self.send_json_response(500, {"success": False, "message": str(e)})
            finally:
                conn.close()

        # 404 fallback for POST
        else:
            self.send_json_response(404, {"success": False, "message": "API эндпоинт не найден"})

    def send_json_response(self, status_code, data):
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self._set_cors_headers()
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False).encode("utf-8"))

def run_server(port=8080):
    init_db()
    # Threading server allows handling multiple API and static requests concurrently without blocking
    server_address = ('', port)
    class ThreadingHTTPServer(ThreadingTCPServer, HTTPServer):
        pass

    httpd = ThreadingHTTPServer(server_address, AuthHTTPRequestHandler)
    print(f"[Auth Server] Authentication backend successfully running on port {port}...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[Auth Server] Shutting down server...")
        httpd.shutdown()
        sys.exit(0)

if __name__ == "__main__":
    port = 8080
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass
    run_server(port)
