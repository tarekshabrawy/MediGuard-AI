import sqlite3
import shutil
import os

db_path = "secure_logs.db"
backup_path = "secure_logs_backup_before_tamper.db"

if not os.path.exists(db_path):
    print("ERROR: secure_logs.db not found.")
    raise SystemExit

shutil.copy2(db_path, backup_path)
print(f"Backup created: {backup_path}")

conn = sqlite3.connect(db_path)
cur = conn.cursor()

cur.execute("SELECT id, attack_status FROM secure_logs ORDER BY id LIMIT 1")
row = cur.fetchone()

if row is None:
    print("ERROR: No secure logs found.")
else:
    log_id = row[0]
    old_status = row[1]

    cur.execute(
        "UPDATE secure_logs SET attack_status = ? WHERE id = ?",
        ("TAMPERED_LOG_FOR_TEST", log_id)
    )

    conn.commit()

    print("Tampering completed.")
    print(f"Tampered log ID: {log_id}")
    print(f"Old attack_status: {old_status}")
    print("New attack_status: TAMPERED_LOG_FOR_TEST")

conn.close()
