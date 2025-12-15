import sqlite3

DB_PATH = "blocked.db"


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    return conn


def init_db():
    conn = get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS blocked (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def add_ip(ip: str) -> bool:
    conn = get_conn()
    try:
        conn.execute("INSERT INTO blocked (ip) VALUES (?)", (ip,))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def remove_ip(ip: str) -> bool:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM blocked WHERE ip = ?", (ip,))
    conn.commit()
    deleted = cur.rowcount > 0
    conn.close()
    return deleted


def get_blocked_ips() -> set[str]:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("SELECT ip FROM blocked")
    rows = cur.fetchall()

    conn.close()

    return {row[0] for row in rows}
