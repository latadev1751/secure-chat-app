import os
import base64
import logging
from typing import Optional

import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from Crypto.Cipher import AES

# ---------- Logging ----------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------- DB config (prefer environment variables) ----------
DB_CONFIG = dict(
    user=os.environ.get("DB_USER", "root"),
    password=os.environ.get("DB_PASSWORD", "Sonudev2002@"),
    host=os.environ.get("DB_HOST", "localhost"),
    database=os.environ.get("DB_NAME", "msep_038"),
    port=int(os.environ.get("DB_PORT", "3306")),
)

# ---------- paths ----------
STATIC_PROFILE_DIR = os.environ.get("STATIC_PROFILE_DIR", "static/profile_pic")
os.makedirs(STATIC_PROFILE_DIR, exist_ok=True)

# ---------- SECRET KEY (require a stable value) ----------
# AES_SECRET_KEY must be set in environment. Prefer a base64-encoded 32-byte value.
_ENV = os.environ.get("AES_SECRET_KEY")
if not _ENV:
    logger.error(
        "AES_SECRET_KEY environment variable not set. Aborting to avoid accidental message loss.\n"
        'Generate one by running: python3 -c "import base64,os;print(base64.b64encode(os.urandom(32)).decode())"\n'
        "Then export AES_SECRET_KEY in the environment before starting your app."
    )
    raise RuntimeError(
        "AES_SECRET_KEY is required. Set environment variable and restart."
    )

try:
    # try base64 decode first
    SECRET_KEY = base64.b64decode(_ENV)
    if len(SECRET_KEY) != 32:
        logger.warning(
            "AES_SECRET_KEY decoded length != 32 bytes, will pad/truncate to 32 bytes."
        )
        SECRET_KEY = (SECRET_KEY + b"\0" * 32)[:32]
except Exception:
    # fallback: treat value as raw string bytes and pad/truncate
    logger.warning(
        "AES_SECRET_KEY is not valid base64; treating it as raw string and padding/truncating to 32 bytes."
    )
    b = _ENV.encode("utf-8")
    SECRET_KEY = (b + b"\0" * 32)[:32]


def init_db():
    conn = sqlite3.connect("chat.db")
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        mobile TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        profile_pic TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS messages(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER,
        receiver_id INTEGER,
        encrypted_message TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.commit()
    conn.close()


init_db()


# ---------- AES-GCM helpers ----------
def encrypt_message(message: str) -> str:
    """Encrypt a UTF-8 string and return a base64 payload: nonce(16) + tag(16) + ciphertext"""
    cipher = AES.new(SECRET_KEY, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode("utf-8"))
    payload = cipher.nonce + tag + ciphertext  # type: ignore
    return base64.b64encode(payload).decode("utf-8")


def decrypt_message(encrypted_message: str) -> str:
    """Return decrypted plaintext or a descriptive error token. Logs exceptions for debugging."""
    try:
        raw = base64.b64decode(encrypted_message)
        if len(raw) < 32:
            raise ValueError("encrypted payload too short")
        nonce, tag, ciphertext = raw[:16], raw[16:32], raw[32:]
        cipher = AES.new(SECRET_KEY, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode("utf-8")
    except Exception:
        logger.exception("decrypt_message failed for payload (truncated for log)")
        return "[decryption error]"


# ---------- helper to produce web url for profile ----------
def make_profile_url(stored_value: Optional[str]) -> Optional[str]:
    if not stored_value:
        return None

    filename = os.path.basename(stored_value)
    path = os.path.join(STATIC_PROFILE_DIR, filename)

    if not os.path.exists(path):
        return None  # 🔥 THIS IS IMPORTANT

    return f"/static/profile_pic/{filename}"


# ---------- DB connection ----------
def get_db_connection():
    try:
        conn = sqlite3.connect("chat.db")
        conn.row_factory = sqlite3.Row
        return conn
    except Exception:
        logger.exception("DB connect error")
        return None


# ---------- Users ----------
def create_user(name, mobile, password, profile_pic=None):
    conn = get_db_connection()
    if not conn:
        return {"status": "error", "message": "DB connection failed"}
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE mobile=?", (mobile,))
        if cursor.fetchone():
            return {"status": "error", "message": "Mobile number already registered"}
        hashed = generate_password_hash(password)
        pic_filename = os.path.basename(profile_pic) if profile_pic else None
        cursor.execute(
            "INSERT INTO users (name, mobile, password_hash, profile_pic) VALUES (?,?,?,?)",
            (name, mobile, hashed, pic_filename),
        )
        conn.commit()
        user_id = cursor.lastrowid
        return {
            "status": "success",
            "message": "User registered successfully",
            "user_id": user_id,
        }
    except Error:
        logger.exception("create_user DB error")
        return {"status": "error", "message": "DB error during create_user"}
    finally:
        try:
            conn.close()
        except Exception:
            pass


def verify_user(mobile, password):
    conn = get_db_connection()
    if not conn:
        return {"status": "error", "message": "DB connection failed"}

    try:
        cursor = conn.cursor()

        cursor.execute(
            "SELECT id, name, password_hash, profile_pic FROM users WHERE mobile=?",
            (mobile,),
        )

        row = cursor.fetchone()

        if not row:
            return {"status": "error", "message": "Invalid credentials"}

        if not check_password_hash(row["password_hash"], password):
            return {"status": "error", "message": "Invalid credentials"}

        return {
            "status": "success",
            "id": row["id"],
            "name": row["name"],
            "profile_pic": make_profile_url(row["profile_pic"])
            or "static/profile_pic/default.png",
        }

    except Exception:
        logger.exception("verify_user DB error")
        return {"status": "error", "message": "DB error during verify_user"}

    finally:
        try:
            conn.close()
        except Exception:
            pass


# ---------- Messaging ----------
def store_message(sender_id, receiver_id, message):
    conn = get_db_connection()
    if not conn:
        return {"status": "error", "message": "DB connection failed"}

    try:
        cursor = conn.cursor()

        enc = encrypt_message(message)

        cursor.execute(
            "INSERT INTO messages (sender_id, receiver_id, encrypted_message) VALUES (?, ?, ?)",
            (sender_id, receiver_id, enc),
        )

        conn.commit()

        return {"status": "success", "message": "Message stored"}

    except Exception:
        logger.exception("store_message DB error")
        return {"status": "error", "message": "DB error during store_message"}

    finally:
        try:
            conn.close()
        except Exception:
            pass


def fetch_messages(sender_id, receiver_id):
    conn = get_db_connection()

    if not conn:
        return {"status": "error", "message": "DB connection failed"}

    try:
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT id, sender_id, receiver_id,
                   encrypted_message, timestamp
            FROM messages
            WHERE (sender_id=? AND receiver_id=?)
               OR (sender_id=? AND receiver_id=?)
            ORDER BY timestamp ASC
            """,
            (sender_id, receiver_id, receiver_id, sender_id),
        )

        rows = cursor.fetchall()

        out = []

        for r in rows:
            out.append(
                {
                    "id": r["id"],
                    "sender_id": r["sender_id"],
                    "receiver_id": r["receiver_id"],
                    "encrypted": r["encrypted_message"],
                    "decrypted": decrypt_message(r["encrypted_message"]),
                    "timestamp": str(r["timestamp"]),
                }
            )

        return {"status": "success", "messages": out}

    except Exception:
        logger.exception("fetch_messages DB error")
        return {"status": "error", "message": "DB error during fetch_messages"}

    finally:
        try:
            conn.close()
        except Exception:
            pass


def fetch_users(current_user_id):
    conn = get_db_connection()

    if not conn:
        return {"status": "error", "message": "DB connection failed"}

    try:
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT id, name,
                   COALESCE(profile_pic, '') AS profile_pic
            FROM users
            WHERE id != ?
            """,
            (current_user_id,),
        )

        rows = cursor.fetchall()

        users = []

        for row in rows:

            user = {
                "id": row["id"],
                "name": row["name"],
                "profile_pic": row["profile_pic"],
            }

            try:
                cursor.execute(
                    """
                    SELECT encrypted_message, timestamp
                    FROM messages
                    WHERE (sender_id=? AND receiver_id=?)
                       OR (sender_id=? AND receiver_id=?)
                    ORDER BY timestamp DESC
                    LIMIT 1
                    """,
                    (
                        current_user_id,
                        user["id"],
                        user["id"],
                        current_user_id,
                    ),
                )

                msg = cursor.fetchone()

                if msg:
                    user["last_message"] = decrypt_message(msg["encrypted_message"])
                    user["last_time"] = msg["timestamp"]
                else:
                    user["last_message"] = ""
                    user["last_time"] = None

            except Exception:
                logger.exception(
                    "Error fetching last message for user %s",
                    user["id"],
                )
                user["last_message"] = ""
                user["last_time"] = None

            user["profile_pic"] = (
                make_profile_url(user["profile_pic"])
                or "static/profile_pic/default.png"
            )

            users.append(user)

        users.sort(
            key=lambda x: (
                x["last_time"] is not None,
                x["last_time"],
            ),
            reverse=True,
        )

        return {
            "status": "success",
            "users": users,
        }

    except Exception:
        logger.exception("fetch_users failed")
        return {
            "status": "error",
            "message": "DB query failed in fetch_users",
        }

    finally:
        try:
            conn.close()
        except Exception:
            pass


def fetch_all_messages_monitor():
    conn = get_db_connection()

    if not conn:
        return {"status": "error", "message": "DB connection failed"}

    try:
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                m.id,
                m.sender_id,
                m.receiver_id,
                m.encrypted_message,
                m.timestamp,
                s.name AS sender_name,
                r.name AS receiver_name
            FROM messages m
            JOIN users s ON s.id = m.sender_id
            JOIN users r ON r.id = m.receiver_id
            ORDER BY m.timestamp DESC
        """)

        rows = cursor.fetchall()

        out = []

        for r in rows:
            out.append(
                {
                    "id": r["id"],
                    "sender_id": r["sender_id"],
                    "receiver_id": r["receiver_id"],
                    "sender_name": r["sender_name"],
                    "receiver_name": r["receiver_name"],
                    "encrypted": r["encrypted_message"],
                    "decrypted": decrypt_message(r["encrypted_message"]),
                    "timestamp": str(r["timestamp"]),
                }
            )

        return {
            "status": "success",
            "messages": out,
        }

    except Exception:
        logger.exception("fetch_all_messages_monitor failed")
        return {
            "status": "error",
            "message": "DB query failed in monitor",
        }

    finally:
        try:
            conn.close()
        except Exception:
            pass
