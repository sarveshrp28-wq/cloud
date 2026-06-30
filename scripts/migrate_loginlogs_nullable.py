"""
Migration helper: make login_logs.user_id nullable in SQLite DB.
- Backs up `cloud_security.db` to `cloud_security.db.bak`.
- Creates new table `login_logs_new` with `user_id` nullable.
- Copies rows, drops old table, renames new to `login_logs`.

Run from project root:
  python scripts/migrate_loginlogs_nullable.py
"""
import sqlite3
import shutil
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'cloud_security.db')
DB_PATH = os.path.abspath(DB_PATH)

# If DB is not at root, check the instance folder (common Flask layout)
if not os.path.exists(DB_PATH):
    alt = os.path.join(os.path.dirname(__file__), '..', 'instance', 'cloud_security.db')
    alt = os.path.abspath(alt)
    if os.path.exists(alt):
        DB_PATH = alt
    else:
        print(f"Database not found at {DB_PATH} or {alt}")
        raise SystemExit(1)

bak_path = DB_PATH + ".bak"
print(f"Backing up {DB_PATH} -> {bak_path}")
shutil.copy2(DB_PATH, bak_path)

conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row
cur = conn.cursor()

# Check current schema for login_logs
cur.execute("PRAGMA table_info('login_logs')")
cols = cur.fetchall()
if not cols:
    print("Table 'login_logs' does not exist. Nothing to do.")
    conn.close()
    raise SystemExit(0)

for c in cols:
    if c['name'] == 'user_id':
        notnull = c['notnull']
        print(f"login_logs.user_id notnull={notnull}")
        break
else:
    print("Column user_id not found in login_logs. Exiting.")
    conn.close()
    raise SystemExit(1)

if notnull == 0:
    print("Column is already nullable. No migration needed.")
    conn.close()
    raise SystemExit(0)

print("Starting migration: creating new table with nullable user_id...")
try:
    cur.execute('BEGIN')

    # Create new table with nullable user_id
    cur.execute('''
    CREATE TABLE IF NOT EXISTS login_logs_new (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        username VARCHAR(120) NOT NULL,
        ip_address VARCHAR(45) NOT NULL,
        user_agent VARCHAR(500),
        success INTEGER NOT NULL,
        timestamp DATETIME,
        reason VARCHAR(255)
    );
    ''')

    # Copy data (user_id may already have NULLs or values)
    cur.execute('''
    INSERT INTO login_logs_new (id, user_id, username, ip_address, user_agent, success, timestamp, reason)
    SELECT id, user_id, username, ip_address, user_agent, success, timestamp, reason FROM login_logs;
    ''')

    # Drop old table and rename
    cur.execute('DROP TABLE login_logs;')
    cur.execute('ALTER TABLE login_logs_new RENAME TO login_logs;')

    # Recreate index on timestamp if previously existed
    try:
        cur.execute('CREATE INDEX IF NOT EXISTS ix_login_logs_timestamp ON login_logs(timestamp);')
    except Exception:
        pass

    conn.commit()
    print('Migration completed successfully.')
except Exception as e:
    conn.rollback()
    print('Migration failed:', str(e))
    print('Restoring backup...')
    conn.close()
    shutil.copy2(bak_path, DB_PATH)
    print('Backup restored.')
    raise
finally:
    conn.close()

print('Done.')
