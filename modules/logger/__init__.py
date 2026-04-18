import sqlite3
import logging
import os
import json
from datetime import datetime
from config.settings import DB_PATH

os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

logging.basicConfig(
    filename=DB_PATH.replace('.db', '.log'),
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS sessions (
        id          TEXT PRIMARY KEY,
        name        TEXT,
        target      TEXT,
        target_type TEXT,
        scope       TEXT,
        status      TEXT,
        created_at  TEXT,
        updated_at  TEXT
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS logs (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT,
        timestamp  TEXT,
        module     TEXT,
        level      TEXT,
        message    TEXT
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS findings (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id  TEXT,
        timestamp   TEXT,
        module      TEXT,
        finding_type TEXT,
        severity    TEXT,
        title       TEXT,
        description TEXT,
        data        TEXT
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS reports (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT,
        timestamp  TEXT,
        file_path  TEXT,
        ai_summary TEXT
    )''')

    conn.commit()
    conn.close()

def log(session_id: str, module: str, message: str, level: str = "INFO"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if level == "INFO":
        logging.info(f"[{session_id}][{module}] {message}")
    elif level == "WARNING":
        logging.warning(f"[{session_id}][{module}] {message}")
    elif level == "ERROR":
        logging.error(f"[{session_id}][{module}] {message}")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "INSERT INTO logs (session_id,timestamp,module,level,message) VALUES (?,?,?,?,?)",
        (session_id, timestamp, module, level, message)
    )
    conn.commit()
    conn.close()

def save_finding(session_id: str, module: str,
                 finding_type: str, severity: str,
                 title: str, description: str, data: dict):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        '''INSERT INTO findings
           (session_id,timestamp,module,finding_type,severity,title,description,data)
           VALUES (?,?,?,?,?,?,?,?)''',
        (session_id, timestamp, module, finding_type,
         severity, title, description, json.dumps(data))
    )
    conn.commit()
    conn.close()

def get_logs(session_id: str, limit: int = 200):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "SELECT * FROM logs WHERE session_id=? ORDER BY id DESC LIMIT ?",
        (session_id, limit)
    )
    rows = c.fetchall()
    conn.close()
    return rows

def get_findings(session_id: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "SELECT * FROM findings WHERE session_id=? ORDER BY id DESC",
        (session_id,)
    )
    rows = c.fetchall()
    conn.close()
    return rows

def get_all_sessions():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM sessions ORDER BY created_at DESC")
    rows = c.fetchall()
    conn.close()
    return rows

def create_session(session_id: str, name: str,
                   target: str, target_type: str, scope: str):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        '''INSERT INTO sessions
           (id,name,target,target_type,scope,status,created_at,updated_at)
           VALUES (?,?,?,?,?,?,?,?)''',
        (session_id, name, target, target_type, scope,
         'active', timestamp, timestamp)
    )
    conn.commit()
    conn.close()

def update_session_status(session_id: str, status: str):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "UPDATE sessions SET status=?, updated_at=? WHERE id=?",
        (status, timestamp, session_id)
    )
    conn.commit()
    conn.close()

init_db()
